# @descope/poppy

TypeScript client for the [Personal Agent Protocol (Poppy)](https://personalagentprotocol.org/docs/spec.md), for people building Personal Agents.

Point it at a Company's website and it discovers the Company, opens a Session for your User, signs the User in with Device Sign-In, and calls the Company's APIs with DPoP-bound Session Tokens.

- Zero runtime dependencies: `fetch` and WebCrypto only.
- ESM, Node.js 22 or later.
- Follows the spec, not any one Company's implementation.

> Status: 0.1, pre-release. The API may change before 1.0.

## Install

```sh
pnpm add @descope/poppy
```

## Quickstart

Your agent needs an identity first (spec 4.1): an ES256 key pair, and two documents served over HTTPS from your agent's domain. The SDK builds both:

```ts
import { clientMetadata, jwks } from "@descope/poppy";

const { publicKey, privateKey } = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"],
);

// Serve at https://agent.example.net/client.json
const metadata = clientMetadata({
  clientId: "https://agent.example.net/client.json",
  clientName: "Example Agent",
  jwksUri: "https://agent.example.net/jwks.json",
});

// Serve at https://agent.example.net/jwks.json
const keySet = await jwks([{ publicKey, kid: "agent-key-1" }]);
```

Keep the private key in your secret store. Then, per User and Company:

```ts
import { PoppyAgent } from "@descope/poppy";

const agent = new PoppyAgent({
  clientId: "https://agent.example.net/client.json",
  signingKey: { privateKey, kid: "agent-key-1" },
});

const company = await agent.discover("example.com");
const session = await agent.session(company, userId);

if (!session.signedIn) {
  const signIn = await session.startDeviceSignIn("poppy:read");
  console.log(`Open ${signIn.verificationUri} and enter ${signIn.userCode}`);
  const { scope } = await signIn.wait();
}

const response = await session.fetch("https://api.example.com/orders");

await session.signOut();
```

A full runnable version is in [examples/device-sign-in.ts](examples/device-sign-in.ts).

## What it does

| Spec               | SDK                                                                                                                                                                                                                                                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 3, 3.2 Discovery   | `agent.discover(website)` fetches `/.well-known/poppy.json` and the issuer's RFC 8414 metadata, and refuses a Company that fails a required check: unsupported major version, `organization.domain` not the host that served it, issuer mismatch, `poppy_domains` not listing the domain, no ES256 DPoP, a non-HTTPS URL or redirect. |
| 4.1 Agent identity | `clientMetadata()` and `jwks()` build the documents you publish. Client assertions use `private_key_jwt` with `aud` set to the issuer.                                                                                                                                                                                                |
| 4.2 Sessions       | `agent.session(company, userId)` starts a signed-out Session with a JWT bearer assertion, or resumes a stored one.                                                                                                                                                                                                                    |
| 4.3 DPoP           | Every token request and API call carries a DPoP Proof. Server nonces are cached per origin and retried once.                                                                                                                                                                                                                          |
| 4.6 Device Sign-In | `session.startDeviceSignIn(scope)` and `signIn.wait()`, with `slow_down` handling, a deadline and an `AbortSignal`.                                                                                                                                                                                                                   |
| 4.8 Renewing       | `session.renew()`, and automatically before a Session Token expires. Signed in: the Account Token. Signed out: a fresh assertion. An expired Account Token drops the Session to signed out; an ended Session starts a new one.                                                                                                        |
| 4.9 Sign-out       | `session.signOut()` revokes the Account Token (RFC 7009).                                                                                                                                                                                                                                                                             |
| 6 APIs             | `session.fetch(url)` calls an API with the Session Token.                                                                                                                                                                                                                                                                             |

Errors are `PoppyError` with the OAuth `error` code, the HTTP `status`, `errorDescription`, and `retryAfter` on HTTP 429. The spec requires you to wait `retryAfter` seconds before retrying; the SDK does not sleep for you.

## Storage

Each Session keeps its DPoP private key, Session ID and Account Token in a `Store`:

```ts
interface Store {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}
```

The default `MemoryStore` loses everything on exit, so every restart starts new Sessions. In production, pass a store backed by encrypted storage. The SDK writes the new state before it uses a token response, so a crash cannot lose an Account Token the Company already rotated.

Use one `PoppyAgent` per store in a process. The agent keeps one live Session per User and Company, but agents or processes that share a store do not coordinate, and can overwrite each other's Account Token. State is stored under the key `poppy:<clientId>:<issuer>:<userId>`; call `store.delete()` with that key to forget a User at a Company.

## User IDs

`userId` is the ID your agent gives this User at this Company (spec 4.2). It must be:

- stable, so the Company sees the same User across Sessions;
- different for each Company, so Companies cannot match Users with each other;
- opaque: never containing or derived from personal information such as an email address, phone number or name, even with a keyed hash.

A random ID per User per Company, stored by your agent, meets all three. The SDK does not generate or derive it.

## Security notes

- **Your signing key stays yours.** You pass the agent's private signing key in; the SDK never exports or stores it.
- **DPoP keys are extractable.** The SDK generates one DPoP key pair per User per Company and keeps the private key in your `Store` as a JWK, so a Session survives a restart. Protect the store accordingly.
- **Tokens go only where they belong.** `session.fetch` requires `https` and a host that is the Company's domain, one of its subdomains, or a host listed in its `poppy.json` APIs or Company Agent. Redirects are returned to you, never followed with the token.
- **Secrets stay out of errors and logs.** Session Tokens, Account Tokens, device codes and assertions are held in private fields. Errors carry only the status, error code and description.
- **A replaced Account Token is not revoked.** When Device Sign-In replaces an existing Account Token, the spec suggests revoking the old one (4.4). The SDK does not do this yet; call `signOut()` first if you need it.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Runtime

Node.js 22 or later. Discovery follows redirects by hand so it can check that every hop stays on HTTPS, which needs real `3xx` responses from `fetch(url, { redirect: "manual" })`. Browsers return an opaque response instead, so browsers are not supported.

## Not yet supported

These parts of the spec are not in this release:

- Direct Sign-In and Mediated Sign-In (4.5, 4.7)
- Bearer Session Tokens for MCP servers (4.3). `session.fetch` sends DPoP to every host.
- Session Tokens issued for a specific `resource` (4.3). `session.fetch` never requests one, so APIs or Company Agents that require one will refuse its token.
- Web browsing (5)
- Conversations with Company Agents (7)
- Extensions (3.3)
- Request timeouts. Pass a `fetch` that adds one, such as `(url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(10_000) })`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This project follows a [Code of Conduct](CODE_OF_CONDUCT.md).

## Contact Us

If you need help you can email [Descope Support](mailto:support@descope.com)

## License

[Apache-2.0](LICENSE)
