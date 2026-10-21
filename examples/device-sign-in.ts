/**
 * Environment:
 *   POPPY_CLIENT_ID          HTTPS URL of the agent's client metadata document
 *   POPPY_AGENT_PRIVATE_JWK  ES256 private key as a JWK
 *   POPPY_AGENT_KID          kid of its public half in the agent's jwks_uri
 *   POPPY_WEBSITE            Company website, such as example.com
 *   POPPY_USER_ID            opaque ID for this User at this Company
 *   POPPY_API_URL            API on the Company's domain or listed in its poppy.json
 *
 * Run: node examples/device-sign-in.ts (Node.js 22.18 or later)
 */
import { PoppyAgent } from "../src/index.ts";

function env(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`set ${name}`);
  return value;
}

const privateKey = await crypto.subtle.importKey(
  "jwk",
  JSON.parse(env("POPPY_AGENT_PRIVATE_JWK")) as JsonWebKey,
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign"],
);

const agent = new PoppyAgent({
  clientId: env("POPPY_CLIENT_ID"),
  signingKey: { privateKey, kid: env("POPPY_AGENT_KID") },
});

const company = await agent.discover(env("POPPY_WEBSITE"));
const session = await agent.session(company, env("POPPY_USER_ID"));
console.log(`Session with ${company.name} started, signed in: ${session.signedIn}`);

if (!session.signedIn && company.deviceScopes !== undefined) {
  const signIn = await session.startDeviceSignIn(company.deviceScopes.join(" "));
  console.log(`Open ${signIn.verificationUri} and enter ${signIn.userCode}`);
  const { scope } = await signIn.wait({ signal: AbortSignal.timeout(signIn.expiresIn * 1000) });
  console.log(`Signed in with scopes: ${scope || "(none)"}`);
}

const response = await session.fetch(env("POPPY_API_URL"));
console.log(`API answered HTTP ${response.status}`);

await session.signOut();
console.log("Signed out");
