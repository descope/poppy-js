import { PoppyProtocolError } from "./errors.ts";
import { httpsUrl } from "./http.ts";
import { publicJwk } from "./jose.ts";

/** What {@link clientMetadata} puts in the agent's client metadata document. */
export interface ClientMetadataInput {
  /** The HTTPS URL this document is served from. */
  clientId: string;
  clientName: string;
  /** HTTPS URL of the key set from {@link jwks}, on the same host as `clientId`. */
  jwksUri: string;
  logoUri?: string;
}

function sameHost(clientId: URL, value: string, what: string): string {
  const url = httpsUrl(value, what);
  if (url.hostname !== clientId.hostname)
    throw new PoppyProtocolError(`${what} must be on ${clientId.hostname}`);
  return url.href;
}

/**
 * Builds the client metadata document the agent publishes at its `client_id` URL (spec 4.1).
 * Serve it as JSON at exactly `clientId`.
 */
export function clientMetadata(input: ClientMetadataInput): Record<string, unknown> {
  const clientId = httpsUrl(input.clientId, "clientId");
  if (clientId.href !== input.clientId)
    throw new PoppyProtocolError("clientId must be a normalized URL");
  return {
    client_id: input.clientId,
    client_name: input.clientName,
    ...(input.logoUri === undefined ? {} : { logo_uri: httpsUrl(input.logoUri, "logoUri").href }),
    jwks_uri: sameHost(clientId, input.jwksUri, "jwksUri"),
    token_endpoint_auth_method: "private_key_jwt",
  };
}

/** Builds the JSON Web Key Set served at `jwks_uri`. Only public members are included. */
export async function jwks(
  keys: { publicKey: CryptoKey; kid: string }[],
): Promise<{ keys: JsonWebKey[] }> {
  return {
    keys: await Promise.all(
      keys.map(async ({ publicKey, kid }) => ({
        ...(await publicJwk(publicKey)),
        kid,
        alg: "ES256",
        use: "sig",
      })),
    ),
  };
}
