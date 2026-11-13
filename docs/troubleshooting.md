# Troubleshooting

Errors are `PoppyError`, with the `error` code, HTTP `status`, `errorDescription`, `retryAfter`, and `scope`, `extension` or `conversationId` where the spec defines them. A `PoppyProtocolError` means a document or response broke the protocol, and has no `status`.

## Discovery

| Error                                                            | Cause                                                                           | Fix                                                                                       |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `poppy.json redirected away from /.well-known/poppy.json`        | The well-known URL redirects to another path.                                   | The Company must serve the document at the well-known path, after any redirects (spec 3). |
| `organization.domain ... does not match the host that served it` | The document was copied from another domain, or `organization.domain` is wrong. | Discover the domain the document names.                                                   |
| `... is not a protocol version this client supports`             | The Company serves no version this SDK implements.                              | Use an SDK release for that version.                                                      |
| `protected_resources does not list https://...`                  | The issuer doesn't list the domain.                                             | The Company must add it to its issuer's metadata (spec 3.2).                              |
| `the domain lists several issuers, so auth.issuer is required`   | The domain's metadata names several authorization servers.                      | The Company must set `auth.issuer` in `poppy.json`.                                       |
| `... is a private address`                                       | A URL points at `localhost` or a private network.                               | In tests, pass `allowPrivateAddresses: true`.                                             |

## Requests

| Symptom                                             | Cause                                                                                  | Fix                                                                                                                                     |
| --------------------------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `... is not an API or endpoint ... lists`           | `session.fetch` only sends to URLs `poppy.json` lists or its APIs describe (spec 5.2). | Check the URL against the API's description. A different Company needs its own `discover()`.                                            |
| HTTP 401 with no error, or 403 `insufficient_scope` | The request needs the User's account, or more scopes.                                  | `scopesNeeded(response)` names the scopes. Sign the User in for them.                                                                   |
| HTTP 400 `invalid_session`                          | The Company refuses your `client_id`, or your Session JWTs fail its checks.            | Check that `agent.json` is served at exactly your `clientId`, without redirects, and that `jwks.json` has the key whose `kid` you pass. |
| HTTP 403 `extension_required`                       | The Company needs an extension your agent doesn't list.                                | Read `authChallenge(response).extension`, and add the extension to your client metadata and `extensions` option if you support it.      |
| HTTP 403 `approval_required`                        | An operation needs the User's approval.                                                | See [Operations](how-it-works.md#operations).                                                                                           |
| HTTP 429                                            | Rate limited.                                                                          | Wait `Retry-After` seconds before retrying (spec 5.6).                                                                                  |
| A `3xx` response                                    | The SDK never follows redirects with credentials.                                      | Use the URL the Company lists in `poppy.json`.                                                                                          |

## Sign-in

| Error                                                    | Cause                                                                       | Fix                                                                                            |
| -------------------------------------------------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `invalid_client`                                         | The Company can't verify your client assertion.                             | Check your published metadata and key set, and that the issuer accepts your `client_id`.       |
| `the sign-in response is not from this Company's issuer` | The redirect's `iss` doesn't match.                                         | Don't complete a sign-in for a different Company. Start again.                                 |
| `unknown or already used sign-in state`                  | The callback was used twice, or the store doesn't hold the pending sign-in. | Share the store between the process that starts sign-in and the one that handles the callback. |
| `access_denied`                                          | The User declined.                                                          | Ask the User before trying again.                                                              |
| `expired_token`                                          | The User took too long.                                                     | Start sign-in again.                                                                           |
| `the Company granted scopes not requested`               | The token response granted more than you asked for.                         | The Company must not grant extra scopes (spec 4.7). Report it to the Company.                  |

## Conversations

| Error                      | Cause                                                 | Fix                                                                         |
| -------------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------- |
| `conversation_closed`      | The conversation takes no more messages.              | Start a new one.                                                            |
| `direct_conversation_open` | A Direct Conversation is open on this one.            | Send to `error.conversationId` instead, or close it.                        |
| `message_id_conflict`      | You reused a message ID with different content.       | Give each new message a new ID. Reuse an ID only to retry the same message. |
| `conversation_not_found`   | Another User or account owns it, or it never existed. | Resume it with the User that started it.                                    |
