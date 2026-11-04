import { PoppyProtocolError } from "./errors.ts";
import { httpsUrl } from "./http.ts";

export interface ClientMetadataInput {
  /** The HTTPS URL this document is served from. */
  clientId: string;
  clientName: string;
  /** HTTPS URL of the key set from {@link jwks}, on the same host as `clientId`. */
  jwksUri: string;
  logoUri?: string;
  /**
   * Where Direct Sign-In may return the User (spec 4.2): HTTPS URLs on the same host as `clientId`, or
   * loopback redirect URIs for an app on the User's computer (RFC 8252 section 7.3).
   */
  redirectUris?: readonly string[];
  /** Extensions this agent supports, by name (spec 3.3), such as `{ operations: { version: "2" } }`. */
  extensions?: Readonly<Record<string, { version: string }>>;
}

function sameHost(clientId: URL, value: string, what: string): string {
  const url = httpsUrl(value, what);
  if (url.hostname !== clientId.hostname)
    throw new PoppyProtocolError(`${what} must be on ${clientId.hostname}`);
  return url.href;
}

/** RFC 8252 section 7.3: `http` to an IP loopback literal. Any port is allowed when used. */
export function isLoopbackRedirect(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "[::1]");
}

/**
 * Builds the client metadata document. Serve the result as JSON at exactly `clientId` (spec 4.1), without
 * redirects.
 */
export function clientMetadata(input: ClientMetadataInput): Record<string, unknown> {
  const clientId = httpsUrl(input.clientId, "clientId");
  if (clientId.href !== input.clientId)
    throw new PoppyProtocolError("clientId must be a normalized URL");
  const redirectUris = (input.redirectUris ?? []).map((uri, index) =>
    isLoopbackRedirect(uri) ? uri : sameHost(clientId, uri, `redirectUris[${index}]`),
  );
  return {
    client_id: input.clientId,
    client_name: input.clientName,
    ...(input.logoUri === undefined ? {} : { logo_uri: httpsUrl(input.logoUri, "logoUri").href }),
    jwks_uri: sameHost(clientId, input.jwksUri, "jwksUri"),
    ...(redirectUris.length === 0 ? {} : { redirect_uris: redirectUris }),
    token_endpoint_auth_method: "private_key_jwt",
    ...(input.extensions === undefined || Object.keys(input.extensions).length === 0
      ? {}
      : { extensions: input.extensions }),
  };
}

/**
 * Builds the key set to serve at `jwks_uri`. Takes ECDSA P-256 keys (ES256) and RSA-PSS keys (PS384).
 * Only public members are included (spec 4.1).
 */
export async function jwks(
  keys: { publicKey: CryptoKey; kid: string }[],
): Promise<{ keys: JsonWebKey[] }> {
  return {
    keys: await Promise.all(
      keys.map(async ({ publicKey, kid }) => {
        const jwk = await crypto.subtle.exportKey("jwk", publicKey);
        if (jwk.kty === "EC") {
          return {
            kty: "EC",
            crv: jwk.crv,
            x: jwk.x,
            y: jwk.y,
            kid,
            alg: "ES256",
            use: "sig",
          } as JsonWebKey;
        }
        if (jwk.kty === "RSA") {
          return { kty: "RSA", n: jwk.n, e: jwk.e, kid, alg: "PS384", use: "sig" } as JsonWebKey;
        }
        throw new TypeError(`unsupported key type ${String(jwk.kty)}`);
      }),
    ),
  };
}
