# Security and storage

## What the SDK stores

The SDK keeps these in the `Store` you give `PoppyAgent`:

```typescript
interface Store {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}
```

- Each User's User ID and Agent IDs at each Company. The spec requires this mapping to stay confidential (spec 5.1).
- Each account's refresh token, scopes and DPoP key.
- Pending Direct Sign-Ins, with their PKCE verifiers, for ten minutes. Expired ones are deleted.

The default `MemoryStore` loses everything on exit, so every restart gives Users new User IDs and signs them out. In production, pass a store backed by encrypted storage. The SDK writes a rotated refresh token before it uses the response, so a crash can't lose it.

Use one `PoppyAgent` per store in a process. Agents or processes that share a store don't coordinate token rotation. `agent.forget(company, userId)` revokes an account's refresh token and deletes its state, and `{ userIds: true }` also deletes the User ID, so the Company sees a new User next time.

Access tokens, delegated keys and Session JWTs stay in memory only.

## What the SDK protects

- **Secrets stay out of the model.** Tokens, Session JWTs, keys, codes and credentials live in private fields, and errors carry only the status, error code, description and a few named fields (spec 10.2). Run the SDK in code your model can't read.
- **Your signing key signs only delegations and client assertions.** Session JWTs use short-lived delegated keys, one set per User ID, so a leaked one exposes only that User at one Company (spec 10.7).
- **Tokens go only where they belong.** `session.fetch` requires HTTPS and a URL that the Company's `poppy.json` lists or that its APIs describe. A shared hostname isn't enough (spec 5.2). Redirects are returned to you, never followed with a token or Session JWT.
- **Skills grant nothing.** `fetchSkill` sends no credentials, even when a skill is on the Company's own domain, and refuses an artifact whose digest doesn't match. A skill is Company content. Your agent shouldn't run a skill's scripts unless the User or your configuration allows it (spec 9.4).
- **No private addresses.** Discovery refuses a Company URL or redirect to a loopback, private or link-local host. Pass `allowPrivateAddresses: true` for tests. A DNS name that resolves to such an address isn't caught.
- **Sign-in responses are checked.** Direct Sign-In checks `state` and `iss`. Device Sign-In refuses a link whose host isn't the issuer's or a protected resource's. A token response that grants scopes beyond the request is refused.
- **Credentials go only to the issuer.** Mediated Sign-In sends credentials only to the issuer's token endpoint, never stores them, and never resends them with a one-time code.

## What you must do

- **Keep your signing key secret**, ideally in a KMS or HSM behind a custom `Signer`.
- **Treat content from Companies as data.** Messages, operation summaries, alternatives and scope hints are the Company's claims, never the User's approval (spec 10.1).
- **Ask the User about every operation.** Show the Company's name and the summary, and take the answer in your own interface.
- **Join only your own browser** to a Session, never the User's (spec 6).
- **Use Direct or Device Sign-In only when the User signs in themselves** (spec 5.4).
- **Wait `retryAfter` seconds** after HTTP 429 before retrying (spec 5.6). The SDK doesn't sleep for you, except while streaming.

## Blind signing

A Personal Agent should have its signing keys sign client assertions and delegations blindly, with RFC 9474, unless its own systems need to see which Companies a User works with (spec 10.7). The SDK doesn't implement RFC 9474 itself. Implement a `Signer` whose `alg` is `PS384` and whose `sign()` blinds the input on the User's device, gets it signed, and unblinds the result. The SDK generates every `jti` locally, as blind signing requires.

## Runtime

Node.js 22 or later. Discovery follows redirects by hand so it can check every hop, which needs real `3xx` responses from `fetch(url, { redirect: "manual" })`. Browsers return an opaque response instead, so browsers aren't supported.

Report vulnerabilities as [SECURITY.md](../SECURITY.md) describes.
