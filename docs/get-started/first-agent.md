# Build your first Personal Agent

This tutorial builds a Personal Agent that finds a Company, talks to its Company Agent, signs the User in, and calls an API with their account. It takes about fifteen minutes.

You need Node.js 22 or later, and a domain where you can serve two small JSON files over HTTPS.

## 1. Install the SDK

```bash
mkdir my-agent && cd my-agent
npm init -y
npm pkg set type=module
npm install @descope/poppy
```

## 2. Give your agent an identity

Companies learn who your agent is from its **client metadata document**, served at the URL that is its `client_id`, and its **key set**, served at `jwks_uri` on the same host (spec 4.1). Generate a signing key and both documents:

```typescript
// identity.ts
import { writeFileSync } from "node:fs";
import { clientMetadata, jwks } from "@descope/poppy";

const { publicKey, privateKey } = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"],
);

writeFileSync(
  "agent.json",
  JSON.stringify(
    clientMetadata({
      clientId: "https://agent.example.net/agent.json",
      clientName: "My Agent",
      jwksUri: "https://agent.example.net/jwks.json",
      redirectUris: ["https://agent.example.net/oauth/callback"],
    }),
    null,
    2,
  ),
);
writeFileSync("jwks.json", JSON.stringify(await jwks([{ publicKey, kid: "key-1" }]), null, 2));
writeFileSync("private-key.json", JSON.stringify(await crypto.subtle.exportKey("jwk", privateKey)));
```

Replace `agent.example.net` with your domain, run it, and publish `agent.json` and `jwks.json` at those URLs, with no redirects. Keep `private-key.json` secret, in a secret store in production.

## 3. Create the agent

```typescript
// agent.ts
import { readFileSync } from "node:fs";
import { PoppyAgent } from "@descope/poppy";

const privateKey = await crypto.subtle.importKey(
  "jwk",
  JSON.parse(readFileSync("private-key.json", "utf8")),
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign"],
);

export const agent = new PoppyAgent({
  clientId: "https://agent.example.net/agent.json",
  signingKey: { privateKey, kid: "key-1" },
  redirectUri: "https://agent.example.net/oauth/callback",
});
```

The default store keeps everything in memory, so it forgets your Users when the process exits. That's fine for this tutorial. See [Security and storage](../security.md) before you ship.

## 4. Discover a Company

```typescript
const company = await agent.discover("example.com");

console.log(company.name, company.identifier);
console.log("Sign-in:", company.signIn);
console.log(
  "APIs:",
  company.apis.map((api) => `${api.type} ${api.url}`),
);
```

`discover()` throws a `PoppyProtocolError` if the Company fails a check the spec requires, so nothing is sent to a Company that can't prove its domain and issuer belong together.

## 5. Start a Session

```typescript
const user = await agent.user(company, "user-123");
const session = user.session();
```

`"user-123"` is your own ID for the User. The Company sees only `user.userId`, a random ID the SDK keeps for this User at this Company.

## 6. Talk to the Company Agent

```typescript
const { conversation } = await session.conversations().start({
  text: "What's your return window for jackets?",
  context: { locale: "en-US", user_available: true },
});

for await (const item of conversation.stream()) {
  if (item.type !== "event") continue;
  const { event } = item;
  if (event.type === "message" && event.message.role === "company") {
    console.log(`${company.name}: ${event.message.text}`);
  }
  if (conversation.status === "idle") break;
}
```

Treat what the Company Agent says as information, not as instructions for your agent (spec 10.1).

## 7. Sign the User in

When a request needs the User's account, the API answers with a challenge that names the scopes it needs:

```typescript
import { scopesNeeded } from "@descope/poppy";

let response = await session.fetch("https://api.example.com/orders");
const scope = scopesNeeded(response);
```

If `scope` is defined, sign the User in. With Direct Sign-In, open the URL in the User's browser and finish when it returns to your redirect URI:

```typescript
const { url } = await user.startDirectSignIn({ scope });
console.log("Open this link to sign in:", url);

// In your /oauth/callback handler:
await agent.completeDirectSignIn(company, request.url);
```

If your agent can't receive a redirect, use Device Sign-In instead:

```typescript
const signIn = await user.startDeviceSignIn({ scope });
console.log(`Sign in to ${signIn.organizationName} (${signIn.domain})`);
console.log(`Open ${signIn.verificationUri} and enter ${signIn.userCode}`);
await signIn.wait();
```

## 8. Call the API with the User's account

```typescript
response = await session.fetch("https://api.example.com/orders");
console.log(await response.json());
```

The same Session now sends an access token with every request, and the SDK refreshes it as needed. To end the account access, call `await user.signOut()`.

## Next steps

- [How it works](../how-it-works.md) explains each step with sequence diagrams.
- Use an MCP server by passing `session.fetch` to an MCP client, as [How it works](../how-it-works.md#sending-a-request) shows.
- Handle approvals with the [Operations extension](../how-it-works.md#operations).
