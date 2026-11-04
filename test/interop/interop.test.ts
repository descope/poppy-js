import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  clientMetadata,
  type Company,
  jwks,
  PoppyAgent,
  PoppyError,
  PoppyProtocolError,
  poppyTools,
  runTool,
  type Signer,
} from "../../src/index.ts";
import { fakeCompany, type Flaws } from "./kit/test/fake-company.ts";

/**
 * Runs the SDK against the spec repository's conformance fake, an in-memory Company that verifies
 * delegations, Session JWTs and client assertions as draft 0.3 requires.
 */
const CLIENT_ID = "https://agent.test/agent.json";

interface Harness {
  agent: PoppyAgent;
  calls: { method: string; url: string; headers: Headers }[];
  fetch: typeof fetch;
}

async function harness(
  flaws: Flaws = {},
  keyType: "EC" | "RSA" = "EC",
  signer?: (privateKey: CryptoKey) => Signer,
): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "poppy-interop-"));
  const pair =
    keyType === "EC"
      ? await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
          "sign",
          "verify",
        ])
      : await crypto.subtle.generateKey(
          {
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-384",
          },
          true,
          ["sign", "verify"],
        );
  writeFileSync(
    join(dir, "agent.json"),
    JSON.stringify(
      clientMetadata({
        clientId: CLIENT_ID,
        clientName: "Interop Agent",
        jwksUri: "https://agent.test/jwks.json",
        redirectUris: ["https://agent.test/callback"],
      }),
    ),
  );
  writeFileSync(
    join(dir, "jwks.json"),
    JSON.stringify(await jwks([{ publicKey: pair.publicKey, kid: "k1" }])),
  );
  const fake = fakeCompany(dir, flaws);
  const calls: Harness["calls"] = [];
  const fetchFn = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = input instanceof Request ? input.url : String(input);
    const headers = new Headers(init.headers);
    calls.push({ method: (init.method ?? "GET").toUpperCase(), url, headers });
    // The fake reads string bodies only, as a real fetch would send them.
    const body = init.body instanceof URLSearchParams ? init.body.toString() : init.body;
    return fake(url, { ...init, headers, ...(body === undefined ? {} : { body }) });
  }) as typeof fetch;
  return {
    agent: new PoppyAgent({
      clientId: CLIENT_ID,
      ...(signer === undefined
        ? { signingKey: { privateKey: pair.privateKey, kid: "k1" } }
        : { signer: signer(pair.privateKey) }),
      fetch: fetchFn,
      redirectUri: "https://agent.test/callback",
    }),
    calls,
    fetch: fetchFn,
  };
}

async function shop(
  flaws: Flaws = {},
  keyType: "EC" | "RSA" = "EC",
  signer?: (privateKey: CryptoKey) => Signer,
) {
  const h = await harness(flaws, keyType, signer);
  const company = await h.agent.discover("www.shop.test");
  const user = await h.agent.user(company, "local-user-1");
  return { ...h, company, user, session: user.session() };
}

describe("discovery against the conformance fake", () => {
  it("follows the www redirect and reads every part of poppy.json", async () => {
    const { agent } = await harness();
    const company: Company = await agent.discover("www.shop.test");
    expect(company.domain).toBe("shop.test");
    expect(company.identifier).toBe("https://shop.test");
    expect(company.oauth?.issuer).toBe("https://shop.test");
    expect(company.signIn.direct).toBe(true);
    expect(company.signIn.device).toBe(true);
    expect(company.signIn.mediated?.fields.map((f) => f.name)).toEqual(["email", "password"]);
    expect(company.signIn.mediated?.scopes).toEqual(["orders:read"]);
    expect(company.apis.map((api) => api.type)).toContain("mcp");
    expect(company.browserSessionEndpoint).toBe("https://shop.test/poppy/browser-session");
    expect(company.feedbackEndpoint).toBe("https://shop.test/poppy/feedback");
    expect(company.extensions["shop.test/gift-wrap"]?.version).toBe("1");
  });

  it.each<[string, Flaws]>([
    ["a redirect to an uploaded file", { redirectToUpload: true }],
    ["a redirect to http", { httpRedirect: true }],
    ["a domain that isn't the host", { domain: "elsewhere.test" }],
    ["several issuers and no auth.issuer", { twoAuthorizationServers: true }],
    [
      "an issuer that doesn't list the domain",
      { metadata: (doc) => (doc["protected_resources"] = []) },
    ],
    ["a resource with a trailing slash", { resourceWithSlash: true }],
    ["missing issuer metadata", { noIssuerMetadata: true }],
    ["a failing resource metadata request", { resourceMetadataStatus: 500 }],
    ["an unsupported version", { poppy: (doc) => (doc["protocol_version"] = "0.2") }],
  ])("refuses %s", async (_name, flaws) => {
    const { agent } = await harness(flaws);
    await expect(agent.discover("www.shop.test")).rejects.toBeInstanceOf(PoppyProtocolError);
  });

  it("treats a domain without resource metadata as a Company with no issuer", async () => {
    const { agent } = await harness({
      noResourceMetadata: true,
      poppy: (doc) => delete doc["auth"],
    });
    const company = await agent.discover("shop.test");
    expect(company.oauth).toBeUndefined();
    expect(company.identifier).toBe("https://shop.test");
    expect(company.signIn).toEqual({
      disabled: false,
      direct: false,
      device: false,
      mediated: undefined,
    });
  });
});

describe("Sessions against the conformance fake", () => {
  it("signs Session JWTs the Company verifies", async () => {
    const { session } = await shop({ apiRequiresSession: true });
    const response = await session.fetch("https://shop.test/api/orders");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ orders: [] });
  });

  it("signs delegations with PS384, for blind signing", async () => {
    const { session } = await shop({ apiRequiresSession: true }, "RSA");
    expect((await session.fetch("https://shop.test/api/orders")).status).toBe(200);
  });

  it("works with a custom Signer, such as one backed by a KMS", async () => {
    let signed = 0;
    const { session } = await shop({ apiRequiresSession: true }, "EC", (privateKey) => ({
      kid: "k1",
      alg: "ES256",
      sign: async (input) => {
        signed++;
        return new Uint8Array(
          await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, input),
        );
      },
    }));
    expect((await session.fetch("https://shop.test/api/orders")).status).toBe(200);
    // One delegation; the Session JWT is signed with the delegated key.
    expect(signed).toBe(1);
  });

  it("returns invalid_session without retrying, since a new Session doesn't fix it", async () => {
    const { session, calls } = await shop({ apiRequiresSession: true, refuseClient: true });
    const first = session.id;
    const response = await session.fetch("https://shop.test/api/orders");
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_session" });
    expect(calls.filter((c) => c.url === "https://shop.test/api/orders")).toHaveLength(1);
    expect(session.id).toBe(first);
  });

  it("refuses hosts the Company didn't list", async () => {
    const { session } = await shop();
    await expect(session.fetch("https://evil.test/steal")).rejects.toBeInstanceOf(
      PoppyProtocolError,
    );
  });
});

describe("conversations against the conformance fake", () => {
  it("starts, reads, hands off and closes a conversation", async () => {
    const { session } = await shop();
    const { conversation } = await session
      .conversations()
      .start(
        { text: "Where is my order?", context: { locale: "en-US", user_available: true } },
        { wait: 5 },
      );
    expect(conversation.id).toMatch(/^[A-Za-z0-9_-]+$/);
    const first = await conversation.readAll({ wait: 5 });
    const roles = first.events.flatMap((e) => (e.type === "message" ? [e.message.role] : []));
    expect(roles).toEqual(["user", "company"]);
    expect(conversation.status).toBe("idle");
    expect(conversation.responder).toBe("agent");

    await conversation.send({ text: "Thanks" });
    const next = await conversation.read();
    expect(next.events.map((e) => e.type)).toEqual(["message"]);
    expect((await conversation.read()).events).toEqual([]);

    expect(await conversation.handoff()).toEqual({ status: "queued", responder: "human" });
    const closed = await conversation.close();
    expect(closed.status).toBe("closed");
    await expect(conversation.send({ text: "Hello?" })).rejects.toMatchObject({
      error: "conversation_closed",
      status: 409,
    });
  });

  it("streams events with server-sent events and stops once closed", async () => {
    const { session } = await shop();
    const { conversation } = await session.conversations().start({ text: "Hi" });
    await conversation.close();
    const resumed = session.conversations().resume(conversation.id);
    const types: string[] = [];
    for await (const item of resumed.stream()) {
      if (item.type === "event") types.push(item.event.type);
    }
    expect(types).toEqual(["message", "message", "state", "state"]);
    expect(resumed.status).toBe("closed");
  });

  it("retries a message with the same id without adding it twice", async () => {
    const { session } = await shop();
    const { conversation } = await session.conversations().start({ text: "Hi" });
    await conversation.send({ id: "msg_retry1", text: "Once" });
    await conversation.send({ id: "msg_retry1", text: "Once" });
    await expect(conversation.send({ id: "msg_retry1", text: "Different" })).rejects.toMatchObject({
      error: "message_id_conflict",
    });
    const all = await conversation.readAll();
    const mine = all.events.filter((e) => e.type === "message" && e.message.id === "msg_retry1");
    expect(mine.length).toBeLessThanOrEqual(1);
  });

  it("reads operations from Company messages", async () => {
    const { session } = await shop({ returnOperations: true });
    const { conversation } = await session.conversations().start({ text: "Exchange it" });
    const { events } = await conversation.readAll();
    const operations = events.flatMap((e) =>
      e.type === "message" && e.message.operation !== undefined ? [e.message.operation] : [],
    );
    expect(operations).toEqual([
      {
        operationId: "exc_5Rt2",
        revision: "1",
        summary: "Exchange a test item.",
        terms: undefined,
        expiresAt: "2026-10-08T20:00:00Z",
      },
    ]);
  });

  it("continues a conversation in a new Session of the same User", async () => {
    const { user, session } = await shop();
    const { conversation } = await session.conversations().start({ text: "Hi" });
    const other = user.session().conversations().resume(conversation.id);
    const update = await other.readAll();
    expect(update.events.length).toBeGreaterThan(0);
  });
});

describe("browser join against the conformance fake", () => {
  it("joins the agent's browser to the Session", async () => {
    const { session, fetch: browserFetch } = await shop();
    let page = "";
    let cookie = "";
    let finalStatus = 0;
    let sessionCookie = "";
    const code = () =>
      (/name="code" value="([^"]*)"/.exec(page)?.[1] ?? "").replace(/&#(\d+);/g, (_m, n: string) =>
        String.fromCharCode(Number(n)),
      );
    await session.joinBrowser({
      open: async (url) => {
        const response = await browserFetch(url, { redirect: "manual" });
        cookie = (response.headers.getSetCookie()[0] ?? "").split(";")[0] ?? "";
        page = await response.text();
      },
      readCode: async () => code(),
      submit: async () => {
        const response = await browserFetch("https://shop.test/poppy/browser-session", {
          method: "POST",
          redirect: "manual",
          headers: { "content-type": "application/x-www-form-urlencoded", cookie },
          body: new URLSearchParams({ code: code() }).toString(),
        });
        finalStatus = response.status;
        sessionCookie =
          response.headers.getSetCookie().find((c) => c.includes("shop_session")) ?? "";
      },
    });
    expect(finalStatus).toBe(303);
    expect(sessionCookie).toContain("__Host-shop_session=");
  });

  it("refuses a code the Company didn't issue", async () => {
    const { session } = await shop();
    await expect(session.authorizeBrowserCode("bc_made_up")).rejects.toMatchObject({
      error: "invalid_request",
    });
  });
});

describe("task coverage against the conformance fake", () => {
  it("reads excluded tasks and keeps only references to listed APIs", async () => {
    const { session } = await shop();
    const tasks = await session.excludedTasks();
    expect(tasks.map((t) => t.task)).toEqual(["Send a wire transfer", "Close an account"]);
    expect(tasks[0]?.alternative?.references.map((r) => r.type)).toEqual(["web", "openapi"]);
    const unlisted = await (await shop({ unlistedAlternativeApi: true })).session.excludedTasks();
    expect(unlisted[0]?.alternative?.references.map((r) => r.type)).toEqual(["web"]);
  });

  it("sends feedback and reads an alternative", async () => {
    const report = {
      task: "Pay with a gift card",
      description: "The checkout has no gift card field.",
    };
    expect(await (await shop()).session.sendFeedback(report)).toBeUndefined();
    const alternative = await (
      await shop({ feedbackAlternative: "listed" })
    ).session.sendFeedback(report);
    expect(alternative?.references[0]).toMatchObject({
      type: "openapi",
      operationId: "listOrders",
    });
    const unlisted = await (
      await shop({ feedbackAlternative: "unlisted" as never })
    ).session.sendFeedback(report);
    expect(unlisted?.references).toEqual([]);
  });
});

describe("sign-in against the conformance fake", () => {
  it("authenticates to the token endpoint with a client assertion it accepts", async () => {
    const { user } = await shop();
    // The fake verifies the assertion, then refuses the grant itself: invalid_client would mean the
    // assertion failed.
    await expect(
      user.mediatedSignIn({
        scope: "orders:read",
        credentials: { email: "a@b.test", password: "pw" },
      }),
    ).rejects.toMatchObject({ error: "unsupported_grant_type" });
  });

  it("checks Mediated Sign-In scopes and fields before sending credentials", async () => {
    const { user, calls } = await shop();
    const before = calls.length;
    await expect(
      user.mediatedSignIn({ scope: "addresses", credentials: { email: "a", password: "b" } }),
    ).rejects.toBeInstanceOf(PoppyError);
    await expect(
      user.mediatedSignIn({ scope: "orders:read", credentials: { email: "a" } }),
    ).rejects.toBeInstanceOf(PoppyProtocolError);
    expect(calls.length).toBe(before);
  });

  it("builds a Direct Sign-In URL for the issuer's authorization endpoint", async () => {
    const { user } = await shop();
    const { url, state } = await user.startDirectSignIn({ scope: "orders:read" });
    const parsed = new URL(url);
    expect(parsed.origin + parsed.pathname).toBe("https://shop.test/oauth/authorize");
    expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
    expect(parsed.searchParams.get("state")).toBe(state);
  });
});

describe("model tools against the conformance fake", () => {
  it("talks to the Company Agent and reports a task", async () => {
    const { user } = await shop();
    const tools = poppyTools({ user, conversationWait: 2 });
    const sent = await runTool(tools, "poppy_conversation_send", {
      text: "Where is my order?",
      user_available: true,
    });
    expect(sent).toMatchObject({
      status: "idle",
      events: expect.arrayContaining([
        { type: "message", from: "company_agent", text: "Thanks. This is a test Company." },
      ]),
    });
    const id = sent["conversation_id"];
    expect(await runTool(tools, "poppy_conversation_read", { conversation_id: id })).toMatchObject({
      conversation_id: id,
      events: [],
    });
    expect(
      await runTool(tools, "poppy_conversation_handoff", { conversation_id: id }),
    ).toMatchObject({ status: "queued", responder: "human" });
    expect(await runTool(tools, "poppy_conversation_read", {})).toMatchObject({
      error: "invalid_input",
    });
    expect(await runTool(tools, "poppy_conversation_close", { conversation_id: id })).toMatchObject(
      { status: "closed" },
    );
    expect(
      await runTool(tools, "poppy_report_unsupported_task", {
        task: "Pay with a gift card",
        description: "The checkout has no gift card field.",
      }),
    ).toEqual({ reported: true });
    const info = await runTool(tools, "poppy_company", {});
    expect(info["excluded_tasks"]).toHaveLength(2);
  });
});
