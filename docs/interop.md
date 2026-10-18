# Interoperability

The test suite runs against a mocked Company (`test/mock-company.ts`). This page records which
parts of the SDK can also be checked against a real, third-party OAuth server, and which parts
stay mock-only.

Status: proposal. No live interop run exists yet. Everything below about Keycloak comes from its
documentation and source, not from a run against this SDK.

## Candidate server: Keycloak 26.8.1

Image `quay.io/keycloak/keycloak:26.8.1` (released 2026-10-13).

| SDK behavior                                         | Standard                          | Keycloak 26.8.1                                                                  | Source                                                                                                                         |
| ---------------------------------------------------- | --------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Authorization server metadata                        | RFC 8414                          | Served at `/realms/{realm}/.well-known/oauth-authorization-server`               | [26.4 changes](https://github.com/keycloak/keycloak/blob/main/docs/documentation/upgrading/topics/changes/changes-26_4_0.adoc) |
| DPoP-bound tokens and API calls                      | RFC 9449                          | Supported, feature `dpop` on by default                                          | [DPoP guide](https://www.keycloak.org/securing-apps/dpop)                                                                      |
| DPoP server nonce retry (`use_dpop_nonce`)           | RFC 9449 section 8                | Not implemented on the token endpoint, so the retry path is not exercised        | [keycloak#39042](https://github.com/keycloak/keycloak/issues/39042)                                                            |
| Device sign-in, `authorization_pending`, `slow_down` | RFC 8628                          | Supported, feature `device-flow` on by default; enable per client                | [Specifications](https://www.keycloak.org/securing-apps/specifications)                                                        |
| `private_key_jwt` client auth, ES256                 | RFC 7523 section 2.2              | "Signed JWT" client authenticator; ES256 with keys from a JWKS URL not confirmed | [Server admin guide](https://www.keycloak.org/docs/latest/server_admin/index.html)                                             |
| URL as `client_id`                                   | Client ID Metadata Document draft | Experimental, feature `cimd` off by default, needs a client policy               | [MCP authorization server](https://www.keycloak.org/securing-apps/mcp-authz-server)                                            |
| Signed-out Session start (jwt-bearer grant)          | RFC 7523 section 2.1              | Supported since 26.6, feature `jwt-authorization-grant` on by default            | [JWT authorization grant](https://www.keycloak.org/securing-apps/jwt-authorization-grant)                                      |
| Sign-out                                             | RFC 7009                          | `/realms/{realm}/protocol/openid-connect/revoke`                                 | [OIDC layers](https://www.keycloak.org/securing-apps/oidc-layers)                                                              |
| Account Token rotation                               | RFC 6749 section 6                | Realm setting "Revoke Refresh Token"                                             | [Server admin guide](https://www.keycloak.org/docs/latest/server_admin/index.html)                                             |

Keycloak's jwt-bearer grant has constraints a run must satisfy:

- the client must be confidential and have "JWT Authorization Grant" switched on;
- an identity provider of type "JWT Authorization Grant" must trust the assertion issuer (the
  agent's `clientId`) and its JWKS URL;
- the assertion `sub` (the SDK's `userId`) must be a Keycloak user already linked to that
  identity provider;
- the assertion needs a single `aud` and a `jti`, and lives at most 5 minutes. The SDK sends
  `aud` = issuer, a fresh `jti`, and a 60-second lifetime.

## Poppy-only, mock-only

No third-party server has these, so they stay covered by the mock until a live Descope run is
added under the same gate:

- `/.well-known/poppy.json` discovery and the `poppy_domains` check in the OAuth metadata;
- the `session_id` and `signed_in` token response fields;
- the `invalid_session` and `account_mismatch` error codes.

## What a live run needs

1. HTTPS. The SDK rejects `http:` issuers, endpoints and API URLs, and `start-dev` serves plain
   HTTP, so Keycloak must sit behind a TLS proxy with a certificate the test process trusts.
2. A hand-built `Company` passed to `agent.session(company, userId)`, since `discover` requires
   `poppy.json`. Device sign-in also needs `deviceScopes` set on it.
3. The agent's client metadata and JWKS served over HTTPS at the `clientId` URL, for `cimd` and
   the jwt-bearer identity provider to fetch.
4. Gate the test on `POPPY_INTEROP_ISSUER` and keep it out of the default `pnpm test` run: CI
   enforces coverage floors, and a skipped file must not count against them.

Start Keycloak (admin password from the environment):

```bash
docker run --rm -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PASSWORD" quay.io/keycloak/keycloak:26.8.1 start-dev --features=cimd
```

Open questions:

- Does Keycloak accept the issuer URL as `aud` for both the client assertion and the jwt-bearer
  assertion, or only the token endpoint URL?
- Does the "Signed JWT" authenticator accept ES256 keys from a CIMD client's `jwks_uri`?
