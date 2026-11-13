import { describe, expect, it } from "vitest";
import { type AgentFactory, formatReport, runConformance } from "../src/conformance/index.ts";
import { BROWSER_SESSION } from "../src/conformance/company.ts";
import {
  approvalFor,
  clientMetadata,
  jwks,
  operationFromResponse,
  operatorKeyId,
  type OperatorSignatureOptions,
  PoppyAgent,
  PoppyError,
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
  // Web Bot Auth signs with Ed25519, separately from the keys that sign assertions (spec 5.3).
  const operator = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
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
  return {
    privateKey: pair.privateKey,
    agentFetch,
    operatorSignature: {
      privateKey: operator.privateKey,
      keyId: await operatorKeyId(operator.publicKey),
      signatureAgent: "https://agent.test/keys",
    },
  };
}

/** This SDK, driven through the suite's adapter interface. */
function sdkFactory(
  privateKey: CryptoKey,
  operatorSignature: OperatorSignatureOptions,
): AgentFactory {
  return async ({ fetch }) => {
    const agent = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey, kid: "k1" },
      fetch,
      redirectUri: "https://agent.test/callback",
      extensions: { operations: { version: "2" } },
      operatorSignature,
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
      async taskCoverage() {
        await ready().session.taskCoverage();
      },
      async reportTask(report) {
        await ready().session.sendFeedback(report);
      },
      async joinBrowser() {
        const { session: s } = ready();
        // A fake browser: the conformance Company serves the page with the form, and this reads the
        // code from it exactly as a real browser's DOM would be read (section 6).
        const page = await (await fetch(BROWSER_SESSION)).text();
        const code = /name="code" value="([^"]+)"/.exec(page)?.[1] ?? "";
        try {
          await s.authorizeBrowserCode(code);
        } catch (error) {
          // From 0.4 a signed-in join needs poppy:browser-sign-in. Without it, this agent takes the
          // other answer the spec allows and joins signed out rather than asking for the scope.
          if (!(error instanceof PoppyError) || error.error !== "insufficient_scope") throw error;
          await s.authorizeBrowserCode(code, { signedOut: true });
        }
        await fetch(`${BROWSER_SESSION}/submit`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ code }).toString(),
        });
      },
      async fetchPage(url) {
        const response = await ready().session.fetchPage(url);
        await response.body?.cancel();
      },
      async handoffThenCancel(text) {
        const { session: s } = ready();
        const { conversation } = await s.conversations().start({ text });
        // Read until the Company has no work in progress before deciding anything (8.7).
        let update = await conversation.readAll({ wait: 1 });
        while (update.working) update = await conversation.readAll({ wait: 1 });
        await conversation.handoff();
        await conversation.cancelHandoff();
      },
      async readSkill(name) {
        await ready().session.fetchSkill(name);
      },
      async signInDevice(scope) {
        const { user: u } = ready();
        const started = await u.startDeviceSignIn({ scope });
        // A real agent shows `verificationUri` and `userCode` with the Company's name and domain,
        // which the SDK has already checked the host of (spec 4.3). Here the User simply approves.
        await started.wait();
      },
      async newSession() {
        const { user: u } = ready();
        session = u.session();
      },
      async requestRateLimited(url) {
        const { session: s } = ready();
        const first = await s.fetch(url);
        await first.body?.cancel();
        if (first.status === 429) {
          // Retry-After is a floor, not a suggestion (spec 5.6).
          const seconds = Number(first.headers.get("retry-after") ?? 0);
          await new Promise((resolve) => setTimeout(resolve, seconds * 1000 + 50));
        }
        const again = await s.fetch(url);
        await again.body?.cancel();
      },
      async converseWithApproval(text) {
        const { session: s } = ready();
        const { conversation, update } = await s.conversations().start({ text }, { wait: 2 });
        let events = update.events;
        if (!events.some((e) => e.type === "message"))
          events = (await conversation.readAll({ wait: 2 })).events;
        const operation = events
          .flatMap((e) =>
            e.type === "message" && e.message.operation ? [e.message.operation] : [],
          )
          .at(-1);
        if (operation === undefined) throw new Error("the Company Agent asked for no approval");
        // The User approved; the approval travels in the message's extensions (spec 8.4).
        await conversation.send({
          text: "The user approved this.",
          approval: approvalFor(operation),
        });
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
    const { privateKey, agentFetch, operatorSignature } = await identity();
    const report = await runConformance(sdkFactory(privateKey, operatorSignature), { agentFetch });
    const failed = report.results.filter((r) => r.status !== "pass");
    expect(failed, formatReport(report)).toEqual([]);
    expect(report.passed).toBe(report.results.length);
    // The rate-limit scenario waits out a real Retry-After, so the suite outlives the 5s default.
  }, 30_000);

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
      /^Personal Agent Protocol 0\.4 and 0\.3 conformance: \d+ passed, \d+ failed, \d+ skipped/,
    );
  });
});
