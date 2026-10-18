import { expect } from "vitest";
import { PoppyAgent, type SigningKey, type Store } from "../src/index.ts";

/**
 * In-memory Company that enforces what the spec requires of one: ES256 signatures on assertions and DPoP
 * Proofs, `aud` equal to the issuer, single-use `jti`, DPoP `htm`/`htu`/`ath`/`nonce`, and tokens bound to the
 * RFC 7638 thumbprint.
 */
export const WEBSITE = "https://example.com";
export const ISSUER = "https://auth.example.com/tenants/t1";
export const METADATA_URL =
  "https://auth.example.com/.well-known/oauth-authorization-server/tenants/t1";
export const TOKEN_ENDPOINT = "https://auth.example.com/token";
export const DEVICE_ENDPOINT = "https://auth.example.com/device";
export const REVOCATION_ENDPOINT = "https://auth.example.com/revoke";
export const API = "https://api.example.com";
export const CLIENT_ID = "https://agent.example.net/client.json";
export const USER_ID = "usr_7Fq2";

const ES256 = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;
const decoder = new TextDecoder();

export interface Call {
  method: string;
  url: string;
  headers: Headers;
  form: URLSearchParams | undefined;
  /** `Date.now()` when the call was made. */
  at: number;
}

type DevicePoll =
  | "authorization_pending"
  | "slow_down"
  | "access_denied"
  | "expired_token"
  | "account_mismatch"
  | "approve";

interface Decoded {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

export function poppyJson(): Record<string, unknown> {
  return {
    protocol_version: "0.1",
    organization: { name: "Example", domain: "example.com" },
    auth: {
      issuer: ISSUER,
      device: { scopes: ["poppy:read", "poppy:write"] },
    },
    apis: [{ type: "openapi", url: `${API}/openapi.json` }],
  };
}

export function oauthMetadata(): Record<string, unknown> {
  return {
    issuer: ISSUER,
    token_endpoint: TOKEN_ENDPOINT,
    revocation_endpoint: REVOCATION_ENDPOINT,
    device_authorization_endpoint: DEVICE_ENDPOINT,
    dpop_signing_alg_values_supported: ["ES256"],
    poppy_domains: ["example.com"],
  };
}

function b64urlJson(part: string): Record<string, unknown> {
  return JSON.parse(decoder.decode(Buffer.from(part, "base64url"))) as Record<string, unknown>;
}

async function verifyJws(jws: string, key: CryptoKey): Promise<Decoded> {
  const [h, p, s] = jws.split(".");
  if (h === undefined || p === undefined || s === undefined) throw new Error("not a JWS");
  const ok = await crypto.subtle.verify(
    ES256,
    key,
    Buffer.from(s, "base64url"),
    new TextEncoder().encode(`${h}.${p}`),
  );
  if (!ok) throw new Error("bad signature");
  return { header: b64urlJson(h), payload: b64urlJson(p) };
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(digest).toString("base64url");
}

export function thumbprint(jwk: JsonWebKey): Promise<string> {
  return sha256(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function oauthError(error: string, status = 400, headers: Record<string, string> = {}): Response {
  return json(status, { error, error_description: `mock: ${error}` }, headers);
}

class Rejected extends Error {
  constructor(readonly response: Response) {
    super("rejected");
  }
}

export class MockCompany {
  readonly calls: Call[] = [];
  readonly signingKey: SigningKey;
  readonly #publicKey: CryptoKey;

  /** Overrides for served documents and redirects, by URL. */
  readonly routes = new Map<string, () => Response>();
  poppy = poppyJson();
  metadata = oauthMetadata();

  /** `once`: demand a nonce until the agent sends the current one. `always`: a fresh nonce every time. */
  tokenNonce: "off" | "once" | "always" = "off";
  apiNonce: "off" | "once" | "always" = "off";
  expiresIn = 3600;
  /** Polls answered in order; the last one repeats. */
  devicePolls: DevicePoll[] = ["approve"];
  grantedScope: string | undefined;
  rotateRefresh = false;
  readonly endedSessions = new Set<string>();
  /** Refresh tokens that answer `invalid_grant`. */
  readonly revokedRefresh = new Set<string>();
  /** Access tokens that answer `invalid_token` at the API. */
  readonly invalidAccess = new Set<string>();

  readonly #seenJti = new Set<string>();
  readonly #accessTokens = new Map<string, { jkt: string; signedIn: boolean }>();
  readonly #refreshTokens = new Map<string, string>();
  #nonceCounter = 0;
  #tokenNonce = "";
  #apiNonce = "";
  #sessionCounter = 0;
  #tokenCounter = 0;
  #devicePoll = 0;
  /** Every refresh token issued, for leak checks. */
  readonly issuedSecrets: string[] = [];

  private constructor(signingKey: SigningKey, publicKey: CryptoKey) {
    this.signingKey = signingKey;
    this.#publicKey = publicKey;
  }

  static async create(): Promise<MockCompany> {
    const pair = await crypto.subtle.generateKey(ES256, true, ["sign", "verify"]);
    return new MockCompany({ privateKey: pair.privateKey, kid: "agent-key-1" }, pair.publicKey);
  }

  agent(options: { store?: Store } = {}): PoppyAgent {
    return new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: this.signingKey,
      fetch: this.fetch,
      ...options,
    });
  }

  callsTo(url: string): Call[] {
    return this.calls.filter((call) => call.url === url);
  }

  fetch = async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    expect(init.redirect).toBe("manual");
    const url = String(input);
    const method = init.method ?? "GET";
    const headers = new Headers(init.headers);
    const form = init.body instanceof URLSearchParams ? init.body : undefined;
    this.calls.push({ method, url, headers, form, at: Date.now() });
    try {
      return await this.#route(method, url, headers, form);
    } catch (error) {
      if (error instanceof Rejected) return error.response;
      throw error;
    }
  };

  async #route(
    method: string,
    url: string,
    headers: Headers,
    form: URLSearchParams | undefined,
  ): Promise<Response> {
    const override = this.routes.get(url);
    if (override !== undefined) return override();
    if (method === "GET" && url === `${WEBSITE}/.well-known/poppy.json`)
      return json(200, this.poppy);
    if (method === "GET" && url === METADATA_URL) return json(200, this.metadata);
    if (method === "POST" && url === TOKEN_ENDPOINT) return this.#token(headers, form);
    if (method === "POST" && url === DEVICE_ENDPOINT) return this.#device(headers, form);
    if (method === "POST" && url === REVOCATION_ENDPOINT) return this.#revoke(headers, form);
    if (url.startsWith(`${API}/`)) return this.#api(method, url, headers);
    return new Response("not found", { status: 404 });
  }

  #useJti(payload: Record<string, unknown>): void {
    const { jti } = payload;
    if (typeof jti !== "string" || Buffer.from(jti, "base64url").length < 16) {
      throw new Rejected(oauthError("invalid_grant"));
    }
    if (this.#seenJti.has(jti)) throw new Rejected(oauthError("invalid_grant"));
    this.#seenJti.add(jti);
  }

  async #agentJwt(jws: string | null | undefined, sub: string): Promise<void> {
    if (!jws) throw new Rejected(oauthError("invalid_client", 401));
    const { header, payload } = await verifyJws(jws, this.#publicKey).catch(() => {
      throw new Rejected(oauthError("invalid_client", 401));
    });
    expect(header).toMatchObject({ alg: "ES256", kid: this.signingKey.kid });
    expect(payload["iss"]).toBe(CLIENT_ID);
    expect(payload["sub"]).toBe(sub);
    expect(payload["aud"]).toBe(ISSUER);
    const now = Math.floor(Date.now() / 1000);
    expect(payload["exp"]).toBeGreaterThan(now);
    expect(payload["exp"]).toBeLessThanOrEqual(now + 300);
    this.#useJti(payload);
  }

  async #clientAuth(form: URLSearchParams | undefined): Promise<URLSearchParams> {
    if (form === undefined) throw new Error("expected a form body");
    expect(form.get("client_id")).toBe(CLIENT_ID);
    expect(form.get("client_assertion_type")).toBe(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );
    await this.#agentJwt(form.get("client_assertion"), CLIENT_ID);
    return form;
  }

  #freshNonce(): string {
    this.#nonceCounter += 1;
    return `nonce-${this.#nonceCounter}`;
  }

  async #dpop(
    headers: Headers,
    method: string,
    url: string,
    accessToken: string | undefined,
  ): Promise<{ jkt: string; nonce: unknown }> {
    const proof = headers.get("dpop");
    if (proof === null) throw new Rejected(oauthError("invalid_dpop_proof"));
    const [h] = proof.split(".");
    const jwk = b64urlJson(h ?? "")["jwk"] as JsonWebKey;
    expect(jwk).not.toHaveProperty("d");
    const key = await crypto.subtle.importKey("jwk", jwk, ES256, false, ["verify"]);
    const { header, payload } = await verifyJws(proof, key);
    expect(header).toMatchObject({ typ: "dpop+jwt", alg: "ES256" });
    const target = new URL(url);
    expect(payload["htm"]).toBe(method);
    expect(payload["htu"]).toBe(`${target.origin}${target.pathname}`);
    if (accessToken === undefined) expect(payload).not.toHaveProperty("ath");
    else expect(payload["ath"]).toBe(await sha256(accessToken));
    this.#useJti(payload);
    return { jkt: await thumbprint(jwk), nonce: payload["nonce"] };
  }

  #issue(jkt: string, signedIn: boolean, sessionId: string, extra: Record<string, unknown> = {}) {
    this.#tokenCounter += 1;
    const accessToken = `at-${this.#tokenCounter}`;
    this.#accessTokens.set(accessToken, { jkt, signedIn });
    return json(
      200,
      {
        access_token: accessToken,
        token_type: "DPoP",
        expires_in: this.expiresIn,
        session_id: sessionId,
        signed_in: signedIn,
        scope: "",
        ...extra,
      },
      { "cache-control": "no-store", "dpop-nonce": this.#tokenNonce || this.#freshNonce() },
    );
  }

  #newRefresh(sessionId: string): string {
    const token = `rt-secret-${this.#tokenCounter}-${sessionId}`;
    this.#refreshTokens.set(token, sessionId);
    this.issuedSecrets.push(token);
    return token;
  }

  async #token(headers: Headers, form: URLSearchParams | undefined): Promise<Response> {
    const { jkt, nonce } = await this.#dpop(headers, "POST", TOKEN_ENDPOINT, undefined);
    if (
      this.tokenNonce === "always" ||
      (this.tokenNonce === "once" && nonce !== this.#tokenNonce)
    ) {
      this.#tokenNonce = this.#freshNonce();
      return oauthError("use_dpop_nonce", 400, { "dpop-nonce": this.#tokenNonce });
    }
    const params = await this.#clientAuth(form);
    const sessionParam = params.get("session_id");
    if (sessionParam !== null && this.endedSessions.has(sessionParam)) {
      return oauthError("invalid_session");
    }
    const sessionId = sessionParam ?? `ses-${++this.#sessionCounter}`;
    switch (params.get("grant_type")) {
      case "urn:ietf:params:oauth:grant-type:jwt-bearer":
        await this.#agentJwt(params.get("assertion"), USER_ID);
        return this.#issue(jkt, false, sessionId);
      case "refresh_token": {
        const token = params.get("refresh_token") ?? "";
        if (!this.#refreshTokens.has(token) || this.revokedRefresh.has(token)) {
          return oauthError("invalid_grant");
        }
        if (!this.rotateRefresh) {
          return this.#issue(jkt, true, sessionId, { scope: this.grantedScope ?? "poppy:read" });
        }
        this.#refreshTokens.delete(token);
        return this.#issue(jkt, true, sessionId, {
          scope: this.grantedScope ?? "poppy:read",
          refresh_token: this.#newRefresh(sessionId),
        });
      }
      case "urn:ietf:params:oauth:grant-type:device_code":
        return this.#deviceGrant(params, jkt, sessionId);
      default:
        return oauthError("unsupported_grant_type");
    }
  }

  #deviceGrant(params: URLSearchParams, jkt: string, sessionId: string): Response {
    expect(params.get("device_code")).toBe("dc-secret-1");
    expect(params.get("session_id")).not.toBeNull();
    const step = this.devicePolls[Math.min(this.#devicePoll, this.devicePolls.length - 1)];
    this.#devicePoll += 1;
    if (step !== "approve") return oauthError(step ?? "authorization_pending");
    return this.#issue(jkt, true, sessionId, {
      scope: this.grantedScope ?? "poppy:read poppy:write",
      refresh_token: this.#newRefresh(sessionId),
    });
  }

  async #device(headers: Headers, form: URLSearchParams | undefined): Promise<Response> {
    expect(headers.has("dpop")).toBe(false);
    const params = await this.#clientAuth(form);
    expect(params.has("session_id")).toBe(false);
    return json(200, {
      device_code: "dc-secret-1",
      user_code: "WDJB-MJHT",
      verification_uri: "https://example.com/device",
      verification_uri_complete: "https://example.com/device?user_code=WDJB-MJHT",
      expires_in: 600,
      interval: 5,
    });
  }

  async #revoke(headers: Headers, form: URLSearchParams | undefined): Promise<Response> {
    expect(headers.has("dpop")).toBe(false);
    const params = await this.#clientAuth(form);
    this.revokedRefresh.add(params.get("token") ?? "");
    return new Response(null, { status: 200 });
  }

  async #api(method: string, url: string, headers: Headers): Promise<Response> {
    const authorization = headers.get("authorization") ?? "";
    const token = authorization.startsWith("DPoP ") ? authorization.slice(5) : "";
    const bound = this.#accessTokens.get(token);
    const challenge = (error: string, extra: Record<string, string> = {}) =>
      new Response(null, {
        status: 401,
        headers: { "www-authenticate": `DPoP error="${error}"`, ...extra },
      });
    if (bound === undefined || this.invalidAccess.has(token)) return challenge("invalid_token");
    const { jkt, nonce } = await this.#dpop(headers, method, url, token);
    if (jkt !== bound.jkt) return challenge("invalid_dpop_proof");
    if (this.apiNonce === "always" || (this.apiNonce === "once" && nonce !== this.#apiNonce)) {
      this.#apiNonce = this.#freshNonce();
      return challenge("use_dpop_nonce", { "dpop-nonce": this.#apiNonce });
    }
    return json(200, { ok: true, signedIn: bound.signedIn, path: new URL(url).pathname });
  }
}
