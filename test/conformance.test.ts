import { describe, expect, it } from "vitest";
import { type AgentFactory, formatReport, runConformance } from "../src/conformance/index.ts";
import {
  approvalFor,
  clientMetadata,
  jwks,
  operationFromResponse,
  PoppyAgent,
  type PoppyUser,
  type Session,
} from "../src/index.ts";

const CLIENT_ID = "https://agent.test/agent.json";

/** Serves the agent's client metadata and key set, as its own web server would. */
async function identity() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const documents: Record<string, unknown> = {
    [CLIENT_ID]: clientMetadata({
      clientId: CLIENT_ID,
      clientName: "Conformance Agent",
      jwksUri: "https://agent.test/jwks.json",
      redirectUris: ["https://agent.test/callback"],
      extensions: { operations: { version: "2" } },
    }),
    "https://agent.test/jwks.json": await jwks([{ publicKey: pair.publicKey, kid: "k1" }]),
  };
  const agentFetch = (async (input: string | URL | Request) => {
    const body = documents[String(input)];
    return body === undefined ? new Response(null, { status: 404 }) : Response.json(body);
  }) as typeof fetch;
  return { privateKey: pair.privateKey, agentFetch };
}

/** This SDK, driven through the suite's adapter interface. */
function sdkFactory(privateKey: CryptoKey): AgentFactory {
  return async ({ fetch }) => {
    const agent = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey, kid: "k1" },
      fetch,
      redirectUri: "https://agent.test/callback",
      extensions: { operations: { version: "2" } },
    });
    let user: PoppyUser | undefined;
    let session: Session | undefined;
    const ready = () => {
      if (user === undefined || session === undefined) throw new Error("discover first");
      return { user, session };
    };
    return {
      async discover(website) {
        const company = await agent.discover(website);
        user = await agent.user(company, "user-1");
        session = user.session();
      },
      async request(url, init = {}) {
        const response = await ready().session.fetch(url, init);
        await response.body?.cancel();
        return response.status;
      },
      async signInDirect(scope, browser) {
        const { user: u } = ready();
        const { url } = await u.startDirectSignIn({ scope });
        await agent.completeDirectSignIn(u.company, await browser(url));
      },
      async signOut() {
        await ready().user.signOut();
      },
      async converse(text) {
        const { conversation } = await ready().session.conversations().start({ text });
        await conversation.send({ text: "Thanks" });
        await conversation.readAll();
      },
      async requestWithApproval(url, init) {
        const { session: s } = ready();
        const refused = await s.fetch(url, init);
        const operation = await operationFromResponse(refused);
        if (operation === undefined) return refused.status;
        const approved = await s.fetch(url, { ...init, approval: approvalFor(operation) });
        return approved.status;
      },
    };
  };
}

describe("conformance suite", () => {
  it("passes this SDK on every check", async () => {
    const { privateKey, agentFetch } = await identity();
    const report = await runConformance(sdkFactory(privateKey), { agentFetch });
    const failed = report.results.filter((r) => r.status !== "pass");
    expect(failed, formatReport(report)).toEqual([]);
    expect(report.passed).toBe(report.results.length);
  });

  it("catches an agent that breaks the rules", async () => {
    const { agentFetch } = await identity();
    // Accepts any Company and sends bare requests: no Session header, follows redirects.
    const careless: AgentFactory = async ({ fetch }) => ({
      async discover(website) {
        await fetch(new URL("/.well-known/poppy.json", website));
      },
      async request(url, init = {}) {
        const response = await fetch(url, {
          ...init,
          headers: { authorization: "Bearer guessed" },
        });
        const location = response.headers.get("location");
        if (location !== null)
          await fetch(location, { headers: { authorization: "Bearer guessed" } });
        return response.status;
      },
    });
    const report = await runConformance(careless, { agentFetch });
    const status = Object.fromEntries(report.results.map((r) => [r.id, r.status]));
    expect(status).toMatchObject({
      "discovery.well-known-path": "fail",
      "discovery.domain": "fail",
      "discovery.version": "fail",
      "discovery.issuer-link": "fail",
      "session.header": "fail",
      "http.redirects": "fail",
      "oauth.direct-request": "skip",
      "conversation.messages": "skip",
    });
    expect(formatReport(report)).toMatch(
      /^Personal Agent Protocol 0\.3 conformance: \d+ passed, \d+ failed, \d+ skipped/,
    );
  });
});
