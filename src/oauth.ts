import type { Company, OAuthServer } from "./discovery.ts";
import { DpopKey } from "./dpop.ts";
import { errorFromResponse, PoppyError, PoppyProtocolError } from "./errors.ts";
import { type Fetch, isObject, isRedirect, originOf, postForm } from "./http.ts";
import { nowSeconds, randomId, type Signer, signJwt } from "./jose.ts";

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ASSERTION_LIFETIME = 60;

export interface OAuthContext {
  clientId: string;
  signer: Signer;
  fetch: Fetch;
  company: Company;
  oauth: OAuthServer;
}

export function requireOAuth(company: Company): OAuthServer {
  if (company.oauth === undefined)
    throw new PoppyProtocolError(`${company.domain} has no OAuth issuer, so it offers no sign-in`);
  return company.oauth;
}

/**
 * A client assertion (RFC 7523 section 3, spec 4.1): short-lived, with a unique `jti`, and `aud` set to the
 * Company's issuer as a single string, never an endpoint (spec 10.4).
 */
export async function clientAuth(context: OAuthContext): Promise<Record<string, string>> {
  const iat = nowSeconds();
  const assertion = await signJwt(
    { typ: "JWT", kid: context.signer.kid },
    {
      iss: context.clientId,
      sub: context.clientId,
      aud: context.oauth.issuer,
      iat,
      exp: iat + ASSERTION_LIFETIME,
      jti: randomId(),
    },
    context.signer,
  );
  return {
    client_id: context.clientId,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: assertion,
  };
}

export interface TokenResponse {
  accessToken: string;
  /** `Bearer` or `DPoP` (spec 4.5). */
  tokenType: "Bearer" | "DPoP";
  /** Seconds, or undefined when the Company didn't say. */
  expiresIn: number | undefined;
  refreshToken: string | undefined;
  /** The granted scopes. */
  scope: string[];
}

export function splitScope(scope: string | readonly string[]): string[] {
  const list = typeof scope === "string" ? scope.split(" ") : scope;
  return [...new Set(list.filter((item) => item !== ""))];
}

/**
 * Parses a token response (spec 4.7). `scope` is left out only when the Company granted exactly what was
 * requested. A sign-in grants at least one scope, and never more than requested.
 */
export function parseTokenResponse(body: unknown, requested: readonly string[]): TokenResponse {
  if (!isObject(body)) throw new PoppyProtocolError("token response must be an object");
  const { access_token, token_type, expires_in, refresh_token, scope } = body;
  if (typeof access_token !== "string" || access_token === "")
    throw new PoppyProtocolError("access_token is missing");
  const type = typeof token_type === "string" ? token_type.toLowerCase() : "";
  if (type !== "bearer" && type !== "dpop")
    throw new PoppyProtocolError("token_type must be Bearer or DPoP");
  const granted = typeof scope === "string" ? splitScope(scope) : [...requested];
  if (granted.length === 0) throw new PoppyProtocolError("the token response grants no scope");
  const extra = granted.filter((item) => !requested.includes(item));
  if (extra.length > 0)
    throw new PoppyProtocolError(`the Company granted scopes not requested: ${extra.join(" ")}`);
  return {
    accessToken: access_token,
    tokenType: type === "dpop" ? "DPoP" : "Bearer",
    expiresIn: typeof expires_in === "number" && expires_in > 0 ? expires_in : undefined,
    refreshToken:
      typeof refresh_token === "string" && refresh_token !== "" ? refresh_token : undefined,
    scope: granted,
  };
}

/** Whether the issuer lists ES256 for DPoP, so token requests carry a proof (spec 4.5). */
export function issuerUsesDpop(oauth: OAuthServer): boolean {
  return oauth.dpopSigningAlgValuesSupported?.includes("ES256") === true;
}

/** Sends a token request with a fresh client assertion, retrying once on a DPoP nonce challenge. */
export async function tokenRequest(
  context: OAuthContext,
  params: Record<string, string>,
  dpop: { key: DpopKey; nonces: Map<string, string> } | undefined,
): Promise<unknown> {
  const url = context.oauth.tokenEndpoint;
  const origin = new URL(url).origin;
  for (let attempt = 0; ; attempt++) {
    const headers: Record<string, string> = {};
    if (dpop !== undefined)
      headers["dpop"] = await dpop.key.proof("POST", url, { nonce: dpop.nonces.get(origin) });
    const body = new URLSearchParams({ ...params, ...(await clientAuth(context)) });
    const response = await postForm(context.fetch, url, body, headers);
    const nonce = response.headers.get("dpop-nonce");
    if (nonce !== null) dpop?.nonces.set(origin, nonce);
    if (isRedirect(response)) {
      await response.body?.cancel();
      throw new PoppyProtocolError("the token endpoint redirected");
    }
    if (response.ok) {
      try {
        return await response.json();
      } catch {
        throw new PoppyProtocolError("token response is not JSON");
      }
    }
    const error = await errorFromResponse(response);
    if (error.error !== "use_dpop_nonce" || dpop === undefined || attempt > 0) throw error;
  }
}

/** Revokes a refresh token (RFC 7009, spec 4.6). */
export async function revokeRefreshToken(context: OAuthContext, token: string): Promise<void> {
  const body = new URLSearchParams({
    token,
    token_type_hint: "refresh_token",
    ...(await clientAuth(context)),
  });
  const response = await postForm(context.fetch, context.oauth.revocationEndpoint, body);
  if (!response.ok) throw await errorFromResponse(response);
  await response.body?.cancel();
}

/**
 * Checks a link the User will open for Device Sign-In (spec 4.3).
 *
 * From 0.4 its host must be the issuer's host or `organization.domain`, or a subdomain of either. The
 * hosts of the issuer's other `protected_resources` no longer qualify: that list can name domains that
 * share the issuer and services such as MCP servers, so a link there could pass off a page the Company
 * doesn't control as its sign-in page. On 0.3 those hosts are still allowed, as that version says.
 */
export function checkSignInUrl(company: Company, value: unknown, what: string): string {
  const oauth = requireOAuth(company);
  if (typeof value !== "string") throw new PoppyProtocolError(`${what} is missing`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new PoppyProtocolError(`${what} is not a URL`);
  }
  if (url.protocol !== "https:") throw new PoppyProtocolError(`${what} must use https`);
  if (url.username !== "" || url.password !== "")
    throw new PoppyProtocolError(`${what} must not contain credentials`);
  const sources =
    company.protocolVersion === "0.3"
      ? [oauth.issuer, ...oauth.protectedResources]
      : [oauth.issuer, originOf(company.domain)];
  const allowed = sources.flatMap((entry) => {
    try {
      return [new URL(entry).hostname.toLowerCase()];
    } catch {
      return [];
    }
  });
  const host = url.hostname.toLowerCase();
  if (!allowed.some((domain) => host === domain || host.endsWith(`.${domain}`)))
    throw new PoppyProtocolError(
      `${what} host ${host} is not the Company's issuer or ${company.domain}`,
    );
  return url.href;
}

/** PKCE S256 (RFC 7636). */
export async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = `${randomId()}${randomId()}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: Buffer.from(digest).toString("base64url") };
}

export function oauthError(error: unknown, code: string): boolean {
  return error instanceof PoppyError && error.error === code;
}
