/** How strongly the spec states a rule. */
export type Level = "MUST" | "SHOULD";

/** One rule the spec sets for Personal Agents, as the conformance suite checks it. */
export interface Check {
  id: string;
  /** The spec section, such as `5.2`, or an extension's name and section. */
  section: string;
  level: Level;
  title: string;
}

/** Every check the suite runs, in the order they appear in a report. */
export const CHECKS: readonly Check[] = [
  // Agent identity
  {
    id: "identity.metadata",
    section: "4.1",
    level: "MUST",
    title:
      "The client metadata document's client_id is its own URL, and its jwks_uri and redirect_uris are on the same host",
  },
  {
    id: "identity.public-keys",
    section: "4.1",
    level: "MUST",
    title: "The key set at jwks_uri holds public keys only",
  },

  // Discovery
  {
    id: "discovery.well-known-path",
    section: "3",
    level: "MUST",
    title: "Refuses a poppy.json whose redirects end anywhere but /.well-known/poppy.json",
  },
  {
    id: "discovery.domain",
    section: "3.1",
    level: "MUST",
    title: "Refuses a poppy.json whose organization.domain isn't the host that served it",
  },
  {
    id: "discovery.version",
    section: "3.1",
    level: "MUST",
    title: "Refuses a protocol_version it doesn't support",
  },
  {
    id: "discovery.issuer-link",
    section: "3.2",
    level: "MUST",
    title: "Refuses an issuer whose protected_resources doesn't list the domain",
  },
  {
    id: "discovery.no-fallback",
    section: "3.2",
    level: "MUST",
    title: "Doesn't fall back to the domain identifier when protected resource metadata fails",
  },
  {
    id: "discovery.private-address",
    section: "3",
    level: "MUST",
    title: "Doesn't connect to a private or loopback address a Company names",
  },

  // Versions (0.4)
  {
    id: "versions.selection",
    section: "3.4",
    level: "MUST",
    title:
      "Chooses the newest version it supports from protocol_version and supported_versions, and uses that version's document",
  },
  {
    id: "versions.linked-host",
    section: "3.4",
    level: "MUST",
    title: "Doesn't use a supported_versions document on another host",
  },
  {
    id: "versions.linked-version",
    section: "3.4",
    level: "MUST",
    title:
      "Doesn't use a supported_versions document whose protocol_version isn't the version it was listed under",
  },
  {
    id: "versions.header",
    section: "3.4",
    level: "MUST",
    title:
      "Sends Poppy-Version on every request with the Session header, naming a version the Company serves, the same throughout a Session",
  },
  {
    id: "versions.unsupported",
    section: "3.4",
    level: "MUST",
    title:
      "Fetches poppy.json again after version_unsupported, and stops when it chooses the same version",
  },

  // Sessions
  {
    id: "session.header",
    section: "5.2",
    level: "MUST",
    title: "Sends the Poppy-Session header on every request to APIs and protocol endpoints",
  },
  {
    id: "session.jwt",
    section: "5.2",
    level: "MUST",
    title:
      "Session JWTs have typ poppy-session+jwt, alg ES256, a kid that is the delegated key's thumbprint, and poppy_dlg",
  },
  {
    id: "session.claims",
    section: "5.2",
    level: "MUST",
    title:
      "Session JWTs carry iss, aud set to the Company identifier, sid, sub, htm, htu, a fresh iat and a unique jti",
  },
  {
    id: "session.ath",
    section: "5.2",
    level: "MUST",
    title: "ath is the access token's hash when the request carries one, and absent otherwise",
  },
  {
    id: "session.delegation",
    section: "5.2",
    level: "MUST",
    title:
      "Delegations verify with a jwks_uri key, have typ poppy-delegation+jwt and the agent's iss, haven't expired, and last at most 24 hours",
  },
  {
    id: "session.delegation-privacy",
    section: "5.2",
    level: "MUST",
    title: "Delegations name no User or Company, and their cnf.jwk has no private members",
  },
  {
    id: "session.key-per-user",
    section: "5.2",
    level: "MUST",
    title: "Each delegated key signs for one User ID only",
  },
  {
    id: "session.stable-ids",
    section: "5.2",
    level: "MUST",
    title: "Every Session JWT of a Session has the same sub and agent_id",
  },
  {
    id: "session.not-to-oauth",
    section: "5.2",
    level: "MUST",
    title: "Doesn't send the Session header to OAuth endpoints",
  },
  {
    id: "session.no-secrets-in-url",
    section: "5.6",
    level: "MUST",
    title: "Never puts a token or Session JWT in a URL",
  },
  {
    id: "session.destinations",
    section: "5.2",
    level: "MUST",
    title:
      "Sends the Session header only to URLs poppy.json lists or its APIs describe, not to other URLs on the same host",
  },
  {
    id: "session.ended",
    section: "5.5",
    level: "MUST",
    title: "Starts a new Session with a new sid once on session_ended, and stops if that fails too",
  },
  {
    id: "session.invalid-session",
    section: "5.3",
    level: "SHOULD",
    title:
      "Doesn't send the request again after invalid_session, since a new Session doesn't fix it",
  },

  // OAuth
  {
    id: "oauth.client-assertion",
    section: "4.1",
    level: "MUST",
    title:
      "Client assertions verify with a jwks_uri key, have aud set to the issuer as a string, iss and sub set to client_id, iat, a unique jti, and a short lifetime",
  },
  {
    id: "oauth.direct-request",
    section: "4.2",
    level: "MUST",
    title: "Direct Sign-In uses PKCE S256, state, scope, and a redirect_uri from redirect_uris",
  },
  {
    id: "oauth.iss-check",
    section: "4.2",
    level: "MUST",
    title: "Doesn't exchange a code from a response whose iss isn't the Company's issuer",
  },
  {
    id: "oauth.extra-scopes",
    section: "4.7",
    level: "MUST",
    title: "Doesn't use tokens that grant scopes it didn't request",
  },
  {
    id: "oauth.refresh-rotation",
    section: "4.4",
    level: "MUST",
    title: "Uses a rotated refresh token from then on, never the old one",
  },
  {
    id: "oauth.revocation",
    section: "4.6",
    level: "MUST",
    title: "Signs out by revoking the refresh token, with token_type_hint=refresh_token",
  },
  {
    id: "oauth.dpop",
    section: "4.5",
    level: "SHOULD",
    title:
      "Supports DPoP: proofs on token requests when advertised, and on requests with DPoP-bound tokens",
  },
  {
    id: "oauth.resource-token",
    section: "4.5, 7",
    level: "MUST",
    title: "Uses a token issued for an MCP server's resource there, and nowhere else",
  },

  // Requests
  {
    id: "http.redirects",
    section: "3",
    level: "MUST",
    title: "Doesn't send a token or Session JWT to the target of a redirect",
  },

  // Task coverage
  {
    id: "tasks.session",
    section: "9",
    level: "MUST",
    title: "Gets tasks.endpoint with a GET and the Session header, and sends no access token (0.4)",
  },

  // Conversations
  {
    id: "conversation.messages",
    section: "8.2, 8.4",
    level: "MUST",
    title: "Messages have a valid, unique id and an author.type, and have content",
  },
  {
    id: "conversation.request-id",
    section: "8.3",
    level: "MUST",
    title:
      "Every conversation POST carries a unique top-level request id, and its message carries none of its own (0.4)",
  },

  // Extensions
  {
    id: "extensions.declared",
    section: "3.3, 3.4",
    level: "MUST",
    title: "Declares the extensions it uses in Poppy-Extensions, as an RFC 9651 List (0.4)",
  },

  // Operations extension
  {
    id: "operations.approval",
    section: "Operations 6",
    level: "MUST",
    title:
      "Sends the approval in Poppy-Approval with the same method, URL and body as the refused request",
  },
];

export function checkById(id: string): Check {
  const check = CHECKS.find((candidate) => candidate.id === id);
  if (check === undefined) throw new Error(`unknown check ${id}`);
  return check;
}
