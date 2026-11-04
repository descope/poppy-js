/**
 * Discovers a Company, asks its Company Agent a question signed out, and signs the User in with Device
 * Sign-In if the Company Agent needs their account.
 *
 *   AGENT_CLIENT_ID=https://agent.example.net/agent.json AGENT_KEY_JWK='{"kty":"EC",...}' \
 *     node examples/quickstart.ts example.com
 */
import { PoppyAgent } from "../src/index.ts";

const website = process.argv[2] ?? "example.com";
const clientId = process.env["AGENT_CLIENT_ID"];
const keyJwk = process.env["AGENT_KEY_JWK"];
if (clientId === undefined || keyJwk === undefined) {
  throw new Error(
    "set AGENT_CLIENT_ID and AGENT_KEY_JWK (the private JWK of a key in your jwks_uri)",
  );
}

const privateKey = await crypto.subtle.importKey(
  "jwk",
  JSON.parse(keyJwk) as JsonWebKey,
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign"],
);
const agent = new PoppyAgent({ clientId, signingKey: { privateKey, kid: "agent-key-1" } });

const company = await agent.discover(website);
console.log(`${company.name} (${company.domain})`);

const user = await agent.user(company, "example-user");
const session = user.session();
const conversations = session.conversations();
const { conversation } = await conversations.start({
  text: "What is your return policy?",
  context: { locale: "en-US", user_available: true },
});

for await (const item of conversation.stream()) {
  if (item.type !== "event") continue;
  const { event } = item;
  if (event.type === "message" && event.message.role === "company") {
    console.log(`${event.message.author.name ?? company.name}: ${event.message.text ?? ""}`);
  }
  if (event.type === "authorization" && company.signIn.device) {
    const signIn = await user.startDeviceSignIn({ scope: event.scope });
    console.log(
      `Sign in to ${signIn.organizationName} (${signIn.domain}) at ${signIn.verificationUri}`,
    );
    console.log(`and enter ${signIn.userCode}`);
    await signIn.wait();
  }
  if (conversation.status === "idle") break;
}

await conversation.close();
