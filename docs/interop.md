# Interoperability

The SDK is tested two ways.

## The spec project's conformance fake

`test/interop/` runs the SDK against `fake-company.ts` from the
[spec repository](https://github.com/personal-agent-protocol/personal-agent-protocol), vendored in
`test/interop/kit/`. It is the in-memory Company the spec's own validator tests itself with, so it
checks the SDK against the spec authors' reading of draft 0.3:

- discovery, including the www redirect, redirects to uploads or to `http`, a mismatched domain,
  several issuers, a trailing slash on `resource`, and a Company with no issuer;
- delegations and Session JWTs, with ES256 and PS384 keys and a custom `Signer`;
- client assertions at the token endpoint;
- `invalid_session`, which the SDK returns without retrying;
- conversations: start, read, message ID retries and conflicts, operations in messages, handoff,
  close, SSE streaming, and continuing in another Session;
- browser join, end to end with a fake browser;
- excluded tasks, feedback, and alternatives that name unlisted APIs.

The fake refuses every grant, so signed-in flows run against `test/mock-company.ts` instead: Direct,
Device and Mediated Sign-In, refresh and rotation, revocation, `resource` tokens for MCP servers,
DPoP with server nonces, and the Operations extension.

## A real OAuth server

No live run exists yet. Sign-in, refresh and revocation are plain OAuth, so an existing server can
cover them. A server needs:

- RFC 8414 metadata with `protected_resources` listing the Company's domain, and RFC 9728 metadata
  on the domain naming the issuer;
- Client ID Metadata Documents, with `private_key_jwt` and ES256 keys from the client's `jwks_uri`;
- client assertions addressed to the issuer, not the token endpoint (draft-ietf-oauth-rfc7523bis);
- RFC 9207 `iss` on authorization responses, and RFC 8628 for Device Sign-In.

Keycloak 26.8 supports most of these, with Client ID Metadata Documents behind the experimental
`cimd` feature. Whether it accepts the issuer as a client assertion's `aud` is unconfirmed.

Session JWTs, browser join, conversations and task coverage are Poppy's own, so only a Poppy
Company can check them. A live test against one should be gated on an environment variable and kept
out of the default `pnpm test` run, since CI enforces coverage floors.
