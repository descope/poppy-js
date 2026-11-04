import { decodeJwt, thumbprint } from "../src/jose.ts";

/**
 * An in-memory Company with a working OAuth server, for signed-in flows the conformance fake doesn't
 * cover. It verifies client assertions, delegations, Session JWTs (including `ath`), PKCE and DPoP proofs,
 * and issues, rotates and revokes tokens.
 */
export const DOMAIN = "example.com";
export const ISSUER = "https://auth.example.com";
export const API = "https://api.example.com";
export const MCP = "https://mcp.example.com/mcp";
export const CONVERSATIONS = "https://api.example.com/poppy/conversations";
export const CLIENT_ID = "https://agent.example/agent.json";

const ES256 = { name: "ECDSA", hash: "SHA-256" } as const;
const P256 = { name: "ECDSA", namedCurve: "P-256" } as const;
const encoder = new TextEncoder();

export interface MockOptions {
  /** Token type the server issues; `DPoP` also requires a proof. */
  tokenType?: "Bearer" | "DPoP";
  /** Return a new refresh token on every refresh. */
  rotate?: boolean;
  /** Grant fewer scopes than requested at sign-in. */
  grantOnly?: string[];
  /** Require a DPoP nonce on the first token request. */
  dpopNonce?: boolean;
  /** Mediated Sign-In asks for a one-time code. */
  mediatedCode?: boolean;
  /** Changes the `poppy.json` the Company serves. */
  poppy?: (doc: Record<string, unknown>) => Record<string, unknown>;
}

export interface Issued {
  value: string;
  scope: string[];
  resource: string | undefined;
  revoked: boolean;
  jkt: string | undefined;
}

async function verify(jwt: string, jwk: JsonWebKey): Promise<boolean> {
  const [h, p, s] = jwt.split(".");
  if (h === undefined || p === undefined || s === undefined) return false;
  const key = await crypto.subtle.importKey("jwk", jwk, P256, false, ["verify"]);
  return crypto.subtle.verify(ES256, key, Buffer.from(s, "base64url"), encoder.encode(`${h}.${p}`));
}

async function sha256(value: string): Promise<string> {
  return Buffer.from(await crypto.subtle.digest("SHA-256", encoder.encode(value))).toString(
    "base64url",
  );
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

export class MockCompany {
  readonly options: MockOptions;
  readonly agentKey: CryptoKeyPair;
  agentJwk!: JsonWebKey;
  readonly accessTokens = new Map<string, Issued>();
  readonly refreshTokens = new Map<string, Issued>();
  readonly revoked: string[] = [];
  readonly requests: { method: string; url: string; headers: Headers; body: string }[] = [];
  readonly sessionClaims: Record<string, unknown>[] = [];
  readonly delegationJtis = new Set<string>();
  readonly codes = new Map<string, { challenge: string; scope: string[]; redirectUri: string }>();
  device: "pending" | "slow_down" | "approved" | "denied" = "pending";
  deviceScope: string[] = [];
  /** Fail the next resource request with invalid_token. */
  rejectNextToken = false;
  #counter = 0;
  #nonceIssued = false;

  constructor(agentKey: CryptoKeyPair, options: MockOptions = {}) {
    this.agentKey = agentKey;
    this.options = options;
  }

  static async create(options: MockOptions = {}): Promise<MockCompany> {
    const pair = await crypto.subtle.generateKey(P256, true, ["sign", "verify"]);
    const company = new MockCompany(pair, options);
    company.agentJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    return company;
  }

  poppyJson(): Record<string, unknown> {
    return {
      protocol_version: "0.3",
      organization: { name: "Example Company", domain: DOMAIN },
      auth: {
        scopes: { "orders:read": "See your orders", "orders:write": "Change your orders" },
        scope_hints: {
          "orders:read": { changes: "none", personal_data: true },
          "orders:write": { changes: "something-new", personal_data: false },
        },
      },
      agent: { protocols: [{ type: "poppy", endpoint: CONVERSATIONS, access: "signed_in" }] },
      apis: [
        { type: "openapi", url: `${API}/openapi.json`, description: "Orders" },
        { type: "mcp", url: MCP, description: "Search" },
        { type: "graphql", url: `${API}/graphql` },
      ],
      extensions: {
        operations: { version: "2" },
        "mediated-sign-in": {
          version: "1",
          fields: [
            { name: "email", label: "Email", secret: false },
            { name: "password", label: "Password", secret: true },
          ],
          scopes: ["orders:read"],
        },
      },
    };
  }

  metadata(): Record<string, unknown> {
    return {
      issuer: ISSUER,
      token_endpoint: `${ISSUER}/token`,
      revocation_endpoint: `${ISSUER}/revoke`,
      authorization_endpoint: `${ISSUER}/authorize`,
      device_authorization_endpoint: `${ISSUER}/device`,
      grant_types_supported: [
        "refresh_token",
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code",
        "https://personalagentprotocol.org/grant/mediated-sign-in",
      ],
      scopes_supported: ["orders:read", "orders:write"],
      protected_resources: [`https://${DOMAIN}`, MCP],
      ...(this.options.tokenType === "DPoP"
        ? { dpop_signing_alg_values_supported: ["ES256"] }
        : {}),
    };
  }

  readonly fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    const body = init.body === undefined || init.body === null ? "" : String(init.body);
    this.requests.push({ method, url: url.href, headers, body });
    return this.#route(url, method, headers, body);
  }) as typeof fetch;

  async #route(url: URL, method: string, headers: Headers, body: string): Promise<Response> {
    const here = `${url.origin}${url.pathname}`;
    switch (here) {
      case `https://${DOMAIN}/.well-known/poppy.json`:
        return json(200, this.options.poppy?.(this.poppyJson()) ?? this.poppyJson());
      case `https://${DOMAIN}/.well-known/oauth-protected-resource`:
        return json(200, { resource: `https://${DOMAIN}`, authorization_servers: [ISSUER] });
      case `${ISSUER}/.well-known/oauth-authorization-server`:
        return json(200, this.metadata());
      case "https://mcp.example.com/.well-known/oauth-protected-resource/mcp":
        return json(200, {
          resource: MCP,
          authorization_servers: [ISSUER],
          ...(this.options.tokenType === "DPoP"
            ? { dpop_signing_alg_values_supported: ["ES256"] }
            : {}),
        });
      case `${API}/openapi.json`:
        return json(200, { openapi: "3.1.0", servers: [{ url: `${API}/v1` }], paths: {} });
      case `${ISSUER}/token`:
        return this.#token(new URLSearchParams(body), headers);
      case `${ISSUER}/revoke`:
        return this.#revoke(new URLSearchParams(body));
      case `${ISSUER}/device`:
        if (!(await this.#clientOk(new URLSearchParams(body))))
          return json(401, { error: "invalid_client" });
        this.deviceScope = (new URLSearchParams(body).get("scope") ?? "").split(" ");
        return json(200, {
          device_code: "dc_secret",
          user_code: "WDJB-MJHT",
          verification_uri: `${ISSUER}/activate`,
          verification_uri_complete: `${ISSUER}/activate?user_code=WDJB-MJHT`,
          expires_in: 600,
          interval: 0.01,
        });
      case `${API}/v1/orders`:
        return this.#resource(url, method, headers, "orders:read", undefined);
      case MCP:
        return this.#resource(url, method, headers, "orders:read", MCP);
      case `${API}/v1/exchanges`: {
        const denied = await this.#resource(url, method, headers, "orders:write", undefined);
        if (denied.status !== 200) return denied;
        if (headers.get("poppy-approval") === 'operation_id="exc_1", revision="r1"')
          return json(201, { exchanged: true });
        return json(403, {
          error: "approval_required",
          operation: {
            operation_id: "exc_1",
            revision: "r1",
            summary: "Exchange the jacket for **$70** more. [Details](https://evil.test)",
            terms: { price_difference: 70 },
            expires_at: "2099-01-01T00:00:00Z",
          },
        });
      }
      default:
        return json(404, { error: "not_found" });
    }
  }

  async #clientOk(form: URLSearchParams): Promise<boolean> {
    const assertion = form.get("client_assertion");
    if (form.get("client_id") !== CLIENT_ID || assertion === null) return false;
    if (
      form.get("client_assertion_type") !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
      return false;
    if (!(await verify(assertion, this.agentJwk))) return false;
    const { payload } = decodeJwt(assertion);
    return (
      payload["iss"] === CLIENT_ID &&
      payload["sub"] === CLIENT_ID &&
      payload["aud"] === ISSUER &&
      typeof payload["jti"] === "string" &&
      typeof payload["iat"] === "number"
    );
  }

  async #dpopJkt(
    headers: Headers,
    method: string,
    url: string,
    tokenEndpoint = false,
  ): Promise<string | undefined | Response> {
    if (this.options.tokenType !== "DPoP") return undefined;
    const proof = headers.get("dpop");
    if (proof === null) return json(400, { error: "invalid_dpop_proof" });
    const { header, payload } = decodeJwt(proof);
    const jwk = header["jwk"] as JsonWebKey;
    if (header["typ"] !== "dpop+jwt" || !(await verify(proof, jwk)))
      return json(400, { error: "invalid_dpop_proof" });
    const target = new URL(url);
    if (payload["htm"] !== method || payload["htu"] !== `${target.origin}${target.pathname}`)
      return json(400, { error: "invalid_dpop_proof" });
    if (tokenEndpoint && this.options.dpopNonce && !this.#nonceIssued) {
      this.#nonceIssued = true;
      return json(400, { error: "use_dpop_nonce" }, { "dpop-nonce": "n1" });
    }
    if (tokenEndpoint && this.options.dpopNonce && payload["nonce"] !== "n1")
      return json(400, { error: "use_dpop_nonce" });
    return thumbprint(jwk);
  }

  #issue(scope: string[], resource: string | undefined, jkt: string | undefined, refresh: boolean) {
    const n = ++this.#counter;
    const access: Issued = { value: `at_${n}`, scope, resource, revoked: false, jkt };
    this.accessTokens.set(access.value, access);
    let refreshToken: string | undefined;
    if (refresh) {
      refreshToken = `rt_${n}`;
      this.refreshTokens.set(refreshToken, {
        value: refreshToken,
        scope,
        resource: undefined,
        revoked: false,
        jkt,
      });
    }
    return {
      access_token: access.value,
      token_type: this.options.tokenType ?? "Bearer",
      expires_in: 3600,
      ...(refreshToken === undefined ? {} : { refresh_token: refreshToken }),
      scope: scope.join(" "),
    };
  }

  async #token(form: URLSearchParams, headers: Headers): Promise<Response> {
    if (!(await this.#clientOk(form))) return json(401, { error: "invalid_client" });
    const jkt = await this.#dpopJkt(headers, "POST", `${ISSUER}/token`, true);
    if (jkt instanceof Response) return jkt;
    const grant = form.get("grant_type");
    const resource = form.get("resource") ?? undefined;
    if (grant === "authorization_code") {
      const code = this.codes.get(form.get("code") ?? "");
      if (code === undefined) return json(400, { error: "invalid_grant" });
      this.codes.delete(form.get("code") ?? "");
      if ((await sha256(form.get("code_verifier") ?? "")) !== code.challenge)
        return json(400, { error: "invalid_grant" });
      if (form.get("redirect_uri") !== code.redirectUri)
        return json(400, { error: "invalid_grant" });
      return json(200, this.#issue(this.options.grantOnly ?? code.scope, undefined, jkt, true));
    }
    if (grant === "urn:ietf:params:oauth:grant-type:device_code") {
      if (form.get("device_code") !== "dc_secret") return json(400, { error: "invalid_grant" });
      if (this.device === "pending") return json(400, { error: "authorization_pending" });
      if (this.device === "slow_down") {
        this.device = "approved";
        return json(400, { error: "slow_down" });
      }
      if (this.device === "denied") return json(400, { error: "access_denied" });
      return json(200, this.#issue(this.deviceScope, undefined, jkt, true));
    }
    if (grant === "refresh_token") {
      const token = this.refreshTokens.get(form.get("refresh_token") ?? "");
      if (token === undefined || token.revoked) return json(400, { error: "invalid_grant" });
      const scope = form.get("scope")?.split(" ") ?? token.scope;
      if (scope.some((s) => !token.scope.includes(s))) return json(400, { error: "invalid_scope" });
      if (resource !== undefined && resource !== MCP) return json(400, { error: "invalid_target" });
      const issued = this.#issue(scope, resource, jkt, this.options.rotate === true);
      if (this.options.rotate) token.revoked = true;
      // RFC 6749 section 5.1: scope left out when it is exactly what was asked for.
      const { scope: _, ...rest } = issued;
      return json(200, form.has("scope") ? issued : rest);
    }
    if (grant === "https://personalagentprotocol.org/grant/mediated-sign-in") {
      if (form.has("sign_in_id")) {
        if (form.get("sign_in_id") !== "sgn_1") return json(400, { error: "invalid_grant" });
        if (form.has("email") || form.has("password") || form.has("scope"))
          return json(400, { error: "invalid_request" });
        if (form.get("one_time_code") !== "123456")
          return json(400, { error: "code_required", sign_in_id: "sgn_1", expires_in: 600 });
        return json(200, this.#issue(["orders:read"], undefined, jkt, true));
      }
      if (form.get("email") !== "dana@example.net" || form.get("password") !== "hunter2")
        return json(400, { error: "invalid_grant" });
      if (this.options.mediatedCode)
        return json(400, {
          error: "code_required",
          sign_in_id: "sgn_1",
          sent_to: "Text to the phone number ending in 71",
          expires_in: 600,
        });
      return json(200, this.#issue((form.get("scope") ?? "").split(" "), undefined, jkt, true));
    }
    return json(400, { error: "unsupported_grant_type" });
  }

  async #revoke(form: URLSearchParams): Promise<Response> {
    if (!(await this.#clientOk(form))) return json(401, { error: "invalid_client" });
    if (form.get("token_type_hint") !== "refresh_token")
      return json(400, { error: "invalid_request" });
    const token = form.get("token") ?? "";
    this.revoked.push(token);
    const refresh = this.refreshTokens.get(token);
    if (refresh !== undefined) refresh.revoked = true;
    return new Response(null, { status: 200 });
  }

  /** Approves a Direct Sign-In at the authorization endpoint and returns the redirect back. */
  async approve(
    authorizeUrl: string,
    options: { iss?: string; deny?: boolean } = {},
  ): Promise<string> {
    const url = new URL(authorizeUrl);
    const redirect = new URL(url.searchParams.get("redirect_uri") ?? "");
    redirect.searchParams.set("state", url.searchParams.get("state") ?? "");
    redirect.searchParams.set("iss", options.iss ?? ISSUER);
    if (options.deny) {
      redirect.searchParams.set("error", "access_denied");
      return redirect.href;
    }
    const code = `code_${++this.#counter}`;
    this.codes.set(code, {
      challenge: url.searchParams.get("code_challenge") ?? "",
      scope: (url.searchParams.get("scope") ?? "").split(" "),
      redirectUri: url.searchParams.get("redirect_uri") ?? "",
    });
    redirect.searchParams.set("code", code);
    return redirect.href;
  }

  /** Verifies the Session header, and the access token if any, as spec 5.3 describes. */
  async #resource(
    url: URL,
    method: string,
    headers: Headers,
    scope: string,
    resource: string | undefined,
  ): Promise<Response> {
    const jwt = headers.get("poppy-session");
    if (jwt === null) return json(400, { error: "invalid_session" });
    const { header, payload } = decodeJwt(jwt);
    const delegation = header["poppy_dlg"];
    if (typeof delegation !== "string" || !(await verify(delegation, this.agentJwk)))
      return json(400, { error: "invalid_session", error_description: "delegation" });
    const dlg = decodeJwt(delegation);
    const cnf = (dlg.payload["cnf"] as { jwk: JsonWebKey }).jwk;
    if (
      dlg.header["typ"] !== "poppy-delegation+jwt" ||
      dlg.payload["iss"] !== CLIENT_ID ||
      Number(dlg.payload["exp"]) - Number(dlg.payload["iat"]) > 86400 ||
      "d" in cnf
    )
      return json(400, { error: "invalid_session", error_description: "delegation claims" });
    this.delegationJtis.add(String(dlg.payload["jti"]));
    if (!(await verify(jwt, cnf)) || header["kid"] !== (await thumbprint(cnf)))
      return json(400, { error: "invalid_session", error_description: "signature" });
    if (
      header["typ"] !== "poppy-session+jwt" ||
      payload["iss"] !== CLIENT_ID ||
      payload["aud"] !== ISSUER ||
      payload["htm"] !== method ||
      payload["htu"] !== `${url.origin}${url.pathname}`
    )
      return json(400, { error: "invalid_session", error_description: "claims" });
    this.sessionClaims.push(payload);

    const authorization = headers.get("authorization");
    const challenge =
      resource === undefined
        ? ""
        : `, resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`;
    if (authorization === null) {
      if (payload["ath"] !== undefined) return json(400, { error: "invalid_session" });
      return new Response(null, {
        status: 401,
        headers: { "www-authenticate": `Bearer scope="${scope}"${challenge}` },
      });
    }
    const [scheme, value = ""] = authorization.split(" ");
    const token = this.accessTokens.get(value);
    if (payload["ath"] !== (await sha256(value))) return json(400, { error: "invalid_session" });
    const invalid = () =>
      new Response(null, {
        status: 401,
        headers: { "www-authenticate": `${scheme} error="invalid_token"${challenge}` },
      });
    if (this.rejectNextToken) {
      this.rejectNextToken = false;
      return invalid();
    }
    if (token === undefined || token.revoked || token.resource !== resource) return invalid();
    if ((this.options.tokenType === "DPoP") !== (scheme === "DPoP")) return invalid();
    if (scheme === "DPoP") {
      const jkt = await this.#dpopJkt(headers, method, url.href);
      if (jkt instanceof Response || jkt !== token.jkt) return invalid();
      const proof = decodeJwt(headers.get("dpop") ?? "");
      if (proof.payload["ath"] !== (await sha256(value))) return invalid();
    }
    if (!token.scope.includes(scope))
      return new Response(null, {
        status: 403,
        headers: { "www-authenticate": `Bearer error="insufficient_scope", scope="${scope}"` },
      });
    return json(200, { ok: true, scope: token.scope });
  }
}
