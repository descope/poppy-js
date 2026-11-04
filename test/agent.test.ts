import { describe, expect, it, vi } from "vitest";
import {
  approvalFor,
  MemoryStore,
  operationFromResponse,
  PoppyAgent,
  PoppyError,
  PoppyProtocolError,
  renderSummary,
  scopesNeeded,
} from "../src/index.ts";
import { decodeJwt } from "../src/jose.ts";
import {
  API,
  CLIENT_ID,
  CONVERSATIONS,
  ISSUER,
  MCP,
  MockCompany,
  type MockOptions,
} from "./mock-company.ts";

async function setup(options: MockOptions = {}, store = new MemoryStore()) {
  const mock = await MockCompany.create(options);
  const agent = new PoppyAgent({
    clientId: CLIENT_ID,
    signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
    fetch: mock.fetch,
    store,
    redirectUri: "https://agent.example/callback",
    extensions: { operations: { version: "2" } },
  });
  const company = await agent.discover("example.com");
  const user = await agent.user(company, "alice");
  return { mock, agent, company, user, store };
}

async function signIn(
  mock: MockCompany,
  user: Awaited<ReturnType<typeof setup>>["user"],
  scope = "orders:read",
) {
  const { url } = await user.startDirectSignIn({ scope });
  return user.completeDirectSignIn(await mock.approve(url));
}

describe("discovery", () => {
  it("reads scopes, hints, sign-in types and extensions", async () => {
    const { company } = await setup();
    expect(company.identifier).toBe(ISSUER);
    expect(company.scopes["orders:read"]).toBe("See your orders");
    // Unknown `changes` values read as irreversible (spec 4.7).
    expect(company.scopeHints["orders:write"]).toEqual({
      changes: "irreversible",
      personalData: false,
    });
    expect(company.conversationProtocols[0]?.access).toBe("signed_in");
    // Unknown API types are skipped (spec 7).
    expect(company.apis.map((api) => api.type)).toEqual(["openapi", "mcp"]);
    expect(company.signIn).toMatchObject({ direct: true, device: true });
    expect(company.signIn.mediated?.fields[1]).toEqual({
      name: "password",
      label: "Password",
      secret: true,
    });
  });
});

describe("User IDs", () => {
  it("gives each User a stable, random User ID per Company, and Agent IDs per agent", async () => {
    const store = new MemoryStore();
    const { agent, company, user } = await setup({}, store);
    expect(user.userId).toMatch(/^usr_[A-Za-z0-9_-]{22}$/);
    expect(user.userId).not.toContain("alice");
    expect((await agent.user(company, "alice")).userId).toBe(user.userId);
    expect((await agent.user(company, "bob")).userId).not.toBe(user.userId);
    const travel = await agent.user(company, "alice", { agent: "travel" });
    expect(travel.userId).toBe(user.userId);
    expect(travel.agentId).toMatch(/^agt_/);
    expect((await agent.user(company, "alice", { agent: "travel" })).agentId).toBe(travel.agentId);
    expect(user.agentId).toBeUndefined();
  });

  it("gives anonymous Users a new ID each time and never signs them in", async () => {
    const { agent, company } = await setup();
    const a = agent.anonymousUser(company);
    expect(a.userId).not.toBe(agent.anonymousUser(company).userId);
    expect(() => a.startDirectSignIn({ scope: "orders:read" })).toThrow(PoppyProtocolError);
  });
});

describe("Session header", () => {
  it("sends a fresh Session JWT with the right claims on every request", async () => {
    const { mock, user } = await setup();
    const session = user.session();
    await session.fetch(`${API}/v1/orders?page=2`);
    await session.fetch(`${API}/v1/orders`, { method: "POST", body: "{}" });
    const [first, second] = mock.sessionClaims;
    expect(first).toMatchObject({
      iss: CLIENT_ID,
      aud: ISSUER,
      sid: session.id,
      sub: user.userId,
      htm: "GET",
      htu: `${API}/v1/orders`,
    });
    expect(first?.["agent_id"]).toBeUndefined();
    expect(first?.["ath"]).toBeUndefined();
    expect(second?.["htm"]).toBe("POST");
    expect(second?.["jti"]).not.toBe(first?.["jti"]);
    // One delegation serves many requests.
    expect(mock.delegationJtis.size).toBe(1);
  });

  it("uses separate delegated keys for separate User IDs", async () => {
    const { mock, agent, company } = await setup();
    await (await agent.user(company, "alice")).session().fetch(`${API}/v1/orders`);
    await (await agent.user(company, "bob")).session().fetch(`${API}/v1/orders`);
    expect(mock.delegationJtis.size).toBe(2);
    const kids = mock.requests
      .filter((r) => r.url.startsWith(`${API}/v1/orders`))
      .map((r) => decodeJwt(r.headers.get("poppy-session") ?? "").header["kid"]);
    expect(new Set(kids).size).toBe(2);
  });

  it("gives each Session its own sid", async () => {
    const { user } = await setup();
    expect(user.session().id).not.toBe(user.session().id);
  });

  it("reports the scopes a signed-out request needs", async () => {
    const { user } = await setup();
    const response = await user.session().fetch(`${API}/v1/orders`);
    expect(response.status).toBe(401);
    expect(scopesNeeded(response)).toBe("orders:read");
  });

  it("refuses an ended Session and tokens in URLs", async () => {
    const { user } = await setup();
    const session = user.session();
    await expect(session.fetch(`${API}/v1/orders?access_token=x`)).rejects.toThrow(
      PoppyProtocolError,
    );
    session.end();
    await expect(session.fetch(`${API}/v1/orders`)).rejects.toThrow("ended");
  });
});

describe("Direct Sign-In", () => {
  it("signs in with PKCE and sends the access token with ath", async () => {
    const { mock, user } = await setup();
    expect(await signIn(mock, user)).toEqual({ scope: ["orders:read"] });
    expect(user.signedIn).toBe(true);
    const response = await user.session().fetch(`${API}/v1/orders`);
    expect(response.status).toBe(200);
    expect(mock.sessionClaims.at(-1)?.["ath"]).toBeDefined();
  });

  it("checks iss, including on a decline", async () => {
    const { mock, user } = await setup();
    const { url } = await user.startDirectSignIn({ scope: "orders:read" });
    await expect(
      user.completeDirectSignIn(await mock.approve(url, { iss: "https://evil.test" })),
    ).rejects.toThrow("issuer");
    const second = await user.startDirectSignIn({ scope: "orders:read" });
    await expect(
      user.completeDirectSignIn(await mock.approve(second.url, { deny: true })),
    ).rejects.toMatchObject({
      error: "access_denied",
    });
    expect(user.signedIn).toBe(false);
  });

  it("uses each state once", async () => {
    const { mock, user } = await setup();
    const { url } = await user.startDirectSignIn({ scope: "orders:read" });
    const callback = await mock.approve(url);
    await user.completeDirectSignIn(callback);
    await expect(user.completeDirectSignIn(callback)).rejects.toThrow("state");
  });

  it("completes in another process that shares the store", async () => {
    const store = new MemoryStore();
    const { mock, user } = await setup({}, store);
    const { url } = await user.startDirectSignIn({ scope: "orders:read" });
    const other = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
      fetch: mock.fetch,
      store,
    });
    const company = await other.discover("example.com");
    const { user: restored, scope } = await other.completeDirectSignIn(
      company,
      await mock.approve(url),
    );
    expect(scope).toEqual(["orders:read"]);
    expect(restored.userId).toBe(user.userId);
  });

  it("rejects scopes the Company granted beyond the request", async () => {
    const { mock, user } = await setup({ grantOnly: ["orders:read", "orders:write"] });
    await expect(signIn(mock, user)).rejects.toThrow("not requested");
    expect(user.signedIn).toBe(false);
  });

  it("returns fewer scopes when the User approves fewer", async () => {
    const { mock, user } = await setup({ grantOnly: ["orders:read"] });
    expect(await signIn(mock, user, "orders:read orders:write")).toEqual({
      scope: ["orders:read"],
    });
  });

  it("requests the scopes already held and revokes the replaced refresh token", async () => {
    const { mock, user } = await setup();
    await signIn(mock, user, "orders:read");
    const { url } = await user.startDirectSignIn({ scope: "orders:write" });
    expect(new URL(url).searchParams.get("scope")).toBe("orders:read orders:write");
    const first = [...mock.refreshTokens.keys()][0];
    await user.completeDirectSignIn(await mock.approve(url));
    expect(mock.revoked).toEqual([first]);
    expect(user.scope).toEqual(["orders:read", "orders:write"]);
  });
});

describe("Device Sign-In", () => {
  it("polls until approved and shows only the Company's own sign-in host", async () => {
    const { mock, user } = await setup();
    const device = await user.startDeviceSignIn({ scope: "orders:read" });
    expect(device).toMatchObject({
      organizationName: "Example Company",
      domain: "example.com",
      userCode: "WDJB-MJHT",
      verificationUri: `${ISSUER}/activate`,
    });
    expect(JSON.stringify(device)).not.toContain("dc_secret");
    setTimeout(() => (mock.device = "approved"), 30);
    expect(await device.wait()).toEqual({ scope: ["orders:read"] });
    expect(user.signedIn).toBe(true);
  });

  it("rejects on access_denied", async () => {
    const { mock, user } = await setup();
    mock.device = "denied";
    const device = await user.startDeviceSignIn({ scope: "orders:read" });
    await expect(device.wait()).rejects.toMatchObject({ error: "access_denied" });
  });
});

describe("Mediated Sign-In", () => {
  it("signs in with credentials", async () => {
    const { user } = await setup();
    const result = await user.mediatedSignIn({
      scope: "orders:read",
      credentials: { email: "dana@example.net", password: "hunter2" },
    });
    expect(result).toEqual({ status: "signed_in", scope: ["orders:read"] });
  });

  it("continues with a one-time code, without resending credentials", async () => {
    const { mock, user } = await setup({ mediatedCode: true });
    const first = await user.mediatedSignIn({
      scope: "orders:read",
      credentials: { email: "dana@example.net", password: "hunter2" },
    });
    if (first.status !== "code_required") throw new Error("expected code_required");
    expect(first).toMatchObject({
      sentTo: "Text to the phone number ending in 71",
      domain: "example.com",
    });
    const wrong = await first.submitCode("000000");
    expect(wrong.status).toBe("code_required");
    expect(await first.submitCode("123456")).toEqual({
      status: "signed_in",
      scope: ["orders:read"],
    });
    const codeRequests = mock.requests.filter((r) => r.body.includes("sign_in_id"));
    expect(codeRequests.every((r) => !r.body.includes("hunter2"))).toBe(true);
  });

  it("never puts credentials in errors", async () => {
    const { user } = await setup();
    const error = await user
      .mediatedSignIn({
        scope: "orders:read",
        credentials: { email: "dana@example.net", password: "wrong" },
      })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(PoppyError);
    expect(JSON.stringify(error) + String(error)).not.toContain("wrong");
  });
});

describe("tokens", () => {
  it("refreshes after invalid_token and retries", async () => {
    const { mock, user } = await setup();
    await signIn(mock, user);
    mock.rejectNextToken = true;
    const response = await user.session().fetch(`${API}/v1/orders`);
    expect(response.status).toBe(200);
    expect(mock.requests.filter((r) => r.body.includes("grant_type=refresh_token"))).toHaveLength(
      1,
    );
  });

  it("keeps using a rotated refresh token", async () => {
    const { mock, user } = await setup({ rotate: true });
    await signIn(mock, user);
    const session = user.session();
    mock.rejectNextToken = true;
    await session.fetch(`${API}/v1/orders`);
    mock.rejectNextToken = true;
    expect((await session.fetch(`${API}/v1/orders`)).status).toBe(200);
  });

  it("continues signed out when the refresh token is revoked", async () => {
    const { mock, user } = await setup();
    await signIn(mock, user);
    for (const token of mock.refreshTokens.values()) token.revoked = true;
    mock.rejectNextToken = true;
    const response = await user.session().fetch(`${API}/v1/orders`);
    expect(response.status).toBe(401);
    expect(user.signedIn).toBe(false);
    expect(mock.sessionClaims.at(-1)?.["ath"]).toBeUndefined();
  });

  it("gets a token for the MCP server's own resource", async () => {
    const { mock, user } = await setup();
    await signIn(mock, user);
    const response = await user.session().fetch(MCP, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(response.status).toBe(200);
    const refresh = mock.requests.find((r) => r.body.includes("resource="));
    expect(new URLSearchParams(refresh?.body).get("resource")).toBe(MCP);
  });

  it("uses the default token where the OpenAPI server has no own resource", async () => {
    const { mock, user } = await setup();
    await signIn(mock, user);
    await user.session().fetch(`${API}/v1/orders`);
    expect(mock.requests.some((r) => r.body.includes("resource="))).toBe(false);
  });

  it("asks for fewer scopes when told to", async () => {
    const { mock, user } = await setup();
    await signIn(mock, user, "orders:read orders:write");
    const response = await user.session().fetch(`${API}/v1/orders`, { scope: "orders:read" });
    expect(await response.json()).toMatchObject({ scope: ["orders:read"] });
  });

  it("sends no token when signedOut is set", async () => {
    const { mock, user } = await setup();
    await signIn(mock, user);
    expect((await user.session().fetch(`${API}/v1/orders`, { signedOut: true })).status).toBe(401);
  });

  it("binds tokens with DPoP when the issuer offers it, including after a nonce challenge", async () => {
    const { mock, user } = await setup({ tokenType: "DPoP", dpopNonce: true });
    await signIn(mock, user);
    const response = await user.session().fetch(`${API}/v1/orders`);
    expect(response.status).toBe(200);
    const last = mock.requests.at(-1);
    expect(last?.headers.get("authorization")).toMatch(/^DPoP at_/);
    expect(last?.headers.get("dpop")).toBeTruthy();
  });

  it("signs out by revoking the refresh token, and Sessions continue signed out", async () => {
    const { mock, user } = await setup();
    await signIn(mock, user);
    const session = user.session();
    await user.signOut();
    expect(mock.revoked).toEqual([...mock.refreshTokens.keys()]);
    expect(user.signedIn).toBe(false);
    expect((await session.fetch(`${API}/v1/orders`)).status).toBe(401);
  });

  it("keeps the refresh token across agent restarts, and forget removes it", async () => {
    const store = new MemoryStore();
    const { mock, agent, company, user } = await setup({}, store);
    await signIn(mock, user);
    const restarted = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
      fetch: mock.fetch,
      store,
    });
    const again = await restarted.user(company, "alice");
    expect(again.signedIn).toBe(true);
    expect(again.userId).toBe(user.userId);
    await agent.forget(company, "alice", { userIds: true });
    expect(mock.revoked).toEqual([...mock.refreshTokens.keys()]);
    expect((await agent.user(company, "alice")).userId).not.toBe(user.userId);
  });

  it("keeps separate accounts apart", async () => {
    const { mock, agent, company, user } = await setup();
    await signIn(mock, user);
    const business = await agent.user(company, "alice", { account: "business" });
    expect(business.userId).toBe(user.userId);
    expect(business.signedIn).toBe(false);
  });

  it("drops a pending sign-in on sign-out, so a late callback can't sign back in", async () => {
    const { mock, user } = await setup();
    const { url } = await user.startDirectSignIn({ scope: "orders:read" });
    await user.signOut();
    await expect(user.completeDirectSignIn(await mock.approve(url))).rejects.toThrow("state");
    expect(user.signedIn).toBe(false);
  });

  it("forgetting User IDs drops every account's cached users", async () => {
    const { mock, agent, company, user } = await setup();
    await signIn(mock, user);
    const business = await agent.user(company, "alice", { account: "business" });
    await agent.forget(company, "alice", { userIds: true });
    const after = await agent.user(company, "alice", { account: "business" });
    expect(after).not.toBe(business);
    expect(after.userId).not.toBe(user.userId);
  });

  it("refuses to send a request to a private host", async () => {
    const { user } = await setup();
    await expect(user.session().fetch("https://10.0.0.5/v1/orders")).rejects.toThrow(
      "private address",
    );
  });
});

describe("Operations extension", () => {
  it("retries with the User's approval of the exact revision", async () => {
    const { mock, user } = await setup();
    await signIn(mock, user, "orders:write");
    const session = user.session();
    const request = { method: "POST", body: JSON.stringify({ item: "itm_1" }) };
    const refused = await session.fetch(`${API}/v1/exchanges`, request);
    const operation = await operationFromResponse(refused);
    expect(operation).toMatchObject({
      operationId: "exc_1",
      revision: "r1",
      terms: { price_difference: 70 },
    });
    if (operation === undefined) return;
    // Links stay text, so the summary can't send the User elsewhere.
    expect(renderSummary(operation.summary)).toBe(
      "<p>Exchange the jacket for <strong>$70</strong> more. [Details](https://evil.test)</p>",
    );
    const approved = await session.fetch(`${API}/v1/exchanges`, {
      ...request,
      approval: approvalFor(operation),
    });
    expect(approved.status).toBe(201);
    expect(mock.requests.at(-1)?.headers.get("poppy-approval")).toBe(
      'operation_id="exc_1", revision="r1"',
    );
  });
});

describe("conversation streaming", () => {
  it("yields text pieces, reconnects with Last-Event-ID, and skips repeated events", async () => {
    const { mock, user } = await setup();
    const streams = [
      'id: evt_1\ndata: {"id":"evt_1","type":"message","created_at":"t","message":{"id":"m1","role":"company","author":{"type":"agent"},"text":"Hi"}}\n\n' +
        'event: text-delta\ndata: {"message_id":"m2","text":"Work"}\n\n',
      'id: evt_1\ndata: {"id":"evt_1","type":"message","created_at":"t","message":{"id":"m1","role":"company","author":{"type":"agent"},"text":"Hi"}}\n\n' +
        'id: evt_2\ndata: {"id":"evt_2","type":"state","created_at":"t","status":"closed","responder":"agent"}\n\n',
    ];
    const lastEventIds: (string | null)[] = [];
    const original = mock.fetch;
    const fetchFn = (async (input: string | URL | Request, init: RequestInit = {}) => {
      const url = String(input);
      if (url.includes("/poppy/conversations/cnv_1/events")) {
        lastEventIds.push(new Headers(init.headers).get("last-event-id"));
        return new Response(streams.shift() ?? "", {
          headers: { "content-type": "text/event-stream" },
        });
      }
      return original(input, init);
    }) as typeof fetch;
    const agent = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
      fetch: fetchFn,
    });
    const company = await agent.discover("example.com");
    void user;
    const conversation = (await agent.user(company, "alice"))
      .session()
      .conversations()
      .resume("cnv_1");
    const items = [];
    for await (const item of conversation.stream()) items.push(item);
    expect(items.map((item) => item.type)).toEqual(["event", "text-delta", "reconnected", "event"]);
    expect(lastEventIds).toEqual([null, "evt_1"]);
    expect(conversation.cursor).toBe("evt_2");
    expect(conversation.status).toBe("closed");
  });
});

describe("review regressions", () => {
  it("shares one account between agent names, so rotation and sign-out stay consistent", async () => {
    const { mock, agent, company, user } = await setup({ rotate: true });
    await signIn(mock, user);
    const travel = await agent.user(company, "alice", { agent: "travel" });
    mock.rejectNextToken = true;
    expect((await user.session().fetch(`${API}/v1/orders`)).status).toBe(200);
    mock.rejectNextToken = true;
    expect((await travel.session().fetch(`${API}/v1/orders`)).status).toBe(200);
    expect(user.signedIn && travel.signedIn).toBe(true);
    await travel.signOut();
    expect(user.signedIn).toBe(false);
  });

  it("keeps each domain's poppy.json for domains that share an issuer", async () => {
    const { agent, company, user } = await setup();
    const uk = { ...company, domain: "example.co.uk", allowedHosts: ["example.co.uk"] };
    const ukUser = await agent.user(uk, "alice");
    expect(ukUser.company.domain).toBe("example.co.uk");
    expect(ukUser.userId).toBe(user.userId);
  });

  it("retries an OpenAPI description that failed to load", async () => {
    const mock = await MockCompany.create();
    let failures = 1;
    const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input) === `${API}/openapi.json` && failures-- > 0)
        return new Response(null, { status: 503 });
      return mock.fetch(input, init);
    }) as typeof fetch;
    const agent = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
      fetch: fetchFn,
      redirectUri: "https://agent.example/callback",
    });
    const user = await agent.user(await agent.discover("example.com"), "alice");
    await signIn(mock, user);
    // Until the description loads, the URL isn't a known destination for the Session header (spec 5.2).
    await expect(user.session().fetch(`${API}/v1/orders`)).rejects.toThrow(PoppyProtocolError);
    expect((await user.session().fetch(`${API}/v1/orders`)).status).toBe(200);
    expect((await user.session().fetch(`${API}/v1/orders`)).status).toBe(200);
    expect(mock.requests.filter((r) => r.url === `${API}/openapi.json`)).toHaveLength(1);
  });

  it("skips handled events after cursor_expired, and writes as the User in a Direct Conversation", async () => {
    const mock = await MockCompany.create();
    const sent: unknown[] = [];
    const event = (id: string) => ({ id, type: "user_requested", created_at: "t", reason: id });
    const fetchFn = (async (input: string | URL | Request, init: RequestInit = {}) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith("/cnv_1/events")) {
        if (url.searchParams.get("cursor") === "evt_old")
          return Response.json({ error: "cursor_expired" }, { status: 410 });
        return Response.json({
          conversation_id: "cnv_1",
          events: [event("evt_1"), event("evt_2")],
          cursor: "evt_2",
          has_more: false,
          status: "idle",
          responder: "agent",
        });
      }
      if (url.pathname.endsWith("/cnv_1/messages")) {
        sent.push(JSON.parse(String(init.body)));
        return Response.json(
          { conversation_id: "cnv_1", status: "idle", responder: "human" },
          { status: 202 },
        );
      }
      return mock.fetch(input, init);
    }) as typeof fetch;
    const agent = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
      fetch: fetchFn,
    });
    const session = (await agent.user(await agent.discover("example.com"), "alice")).session();
    const conversation = session
      .conversations()
      .resume("cnv_1", { cursor: "evt_old", direct: true, handledEventIds: ["evt_1"] });
    const { events } = await conversation.read();
    expect(events.map((e) => e.id)).toEqual(["evt_2"]);
    expect(conversation.handledEventIds).toEqual(["evt_1", "evt_2"]);
    await conversation.send({ text: "Medium, please." });
    expect(sent).toEqual([{ message: expect.objectContaining({ author: { type: "human" } }) }]);
  });

  it("deletes abandoned Direct Sign-In records once they expire", async () => {
    const { store, user } = await setup();
    const { state } = await user.startDirectSignIn({ scope: "orders:read" });
    expect(await store.get(`poppy:0.3:direct:${state}`)).toBeDefined();
    const later = Date.now() + 11 * 60_000;
    const now = vi.spyOn(Date, "now").mockReturnValue(later);
    try {
      await user.startDirectSignIn({ scope: "orders:read" });
    } finally {
      now.mockRestore();
    }
    expect(await store.get(`poppy:0.3:direct:${state}`)).toBeUndefined();
  });
});

describe("draft 0.3 updates", () => {
  type Handler = (
    url: URL,
    init: RequestInit,
  ) => Response | undefined | Promise<Response | undefined>;

  async function userAt(mock: MockCompany, handler: Handler = () => undefined) {
    const fetchFn = (async (input: string | URL | Request, init: RequestInit = {}) =>
      (await handler(new URL(String(input)), init)) ?? mock.fetch(input, init)) as typeof fetch;
    const agent = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
      fetch: fetchFn,
      redirectUri: "https://agent.example/callback",
      extensions: { operations: { version: "2" } },
    });
    return agent.user(await agent.discover("example.com"), "alice");
  }

  it("starts a new Session once on session_ended, then returns the error", async () => {
    const sids: unknown[] = [];
    const user = await userAt(await MockCompany.create(), (url, init) => {
      if (url.href !== `${API}/v1/orders`) return undefined;
      const jwt = new Headers(init.headers).get("poppy-session") ?? "";
      sids.push(decodeJwt(jwt).payload["sid"]);
      return Response.json({ error: "session_ended" }, { status: 400 });
    });
    const session = user.session();
    const first = session.id;
    const response = await session.fetch(`${API}/v1/orders`);
    expect(response.status).toBe(400);
    expect(sids).toHaveLength(2);
    expect(sids[0]).toBe(first);
    expect(sids[1]).toBe(session.id);
    expect(session.id).not.toBe(first);
  });

  it("sends the Session header only to the APIs and endpoints poppy.json lists", async () => {
    const user = await userAt(await MockCompany.create());
    const session = user.session();
    // Same host as the API, but not under its OpenAPI server; and a subdomain nothing lists.
    for (const url of ["https://api.example.com/admin", "https://cdn.example.com/x"])
      await expect(session.fetch(url)).rejects.toThrow(PoppyProtocolError);
    expect((await session.fetch(`${API}/v1/orders`)).status).toBe(401);
    expect((await session.fetch(`${CONVERSATIONS}/cnv_1/events`)).status).not.toBe(0);
  });

  it("starts no sign-in at a Company that sets auth.disabled", async () => {
    const mock = await MockCompany.create({
      poppy: (doc) => ({
        ...doc,
        auth: { ...(doc["auth"] as object), disabled: true },
        agent: { protocols: [{ type: "poppy", endpoint: CONVERSATIONS }] },
      }),
    });
    const user = await userAt(mock);
    expect(user.company.signIn).toEqual({
      disabled: true,
      direct: false,
      device: false,
      mediated: undefined,
    });
    await expect(user.startDirectSignIn({ scope: "orders:read" })).rejects.toThrow(
      PoppyProtocolError,
    );
    await expect(user.startDeviceSignIn({ scope: "orders:read" })).rejects.toThrow(
      PoppyProtocolError,
    );
  });

  it("reads the logo and skill index, and checks each skill's digest", async () => {
    const content = "# Orders\n\nList orders, then pick one.\n";
    const hash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content)),
    );
    const digest = `sha256:${[...hash].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
    const skill = (name: string, extra: Record<string, unknown>) => ({
      name,
      description: `The ${name} skill`,
      type: "skill-md",
      url: `skills/${name}/SKILL.md`,
      digest,
      ...extra,
    });
    const mock = await MockCompany.create({
      poppy: (doc) => ({
        ...doc,
        organization: {
          ...(doc["organization"] as object),
          logo_uri: "https://example.com/logo.png",
        },
        skill_index: {
          $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
          skills: [
            skill("orders", {}),
            skill("tampered", {}),
            skill("future", { type: "plugin" }),
            skill("short", { digest: "sha256:abc" }),
            skill("plain", { url: "http://example.com/SKILL.md" }),
          ],
        },
      }),
    });
    const headers: Headers[] = [];
    const user = await userAt(mock, (url, init) => {
      if (!url.pathname.startsWith("/.well-known/skills/")) return undefined;
      headers.push(new Headers(init.headers));
      return new Response(url.pathname.includes("tampered") ? `${content}!` : content);
    });
    expect(user.company.logoUri).toBe("https://example.com/logo.png");
    expect(user.company.skills.map((s) => [s.name, s.url])).toEqual([
      ["orders", "https://example.com/.well-known/skills/orders/SKILL.md"],
      ["tampered", "https://example.com/.well-known/skills/tampered/SKILL.md"],
    ]);
    const session = user.session();
    expect(await session.fetchSkill("orders")).toMatchObject({ text: content });
    await expect(session.fetchSkill("tampered")).rejects.toThrow(PoppyProtocolError);
    expect(headers.every((h) => !h.has("poppy-session") && !h.has("authorization"))).toBe(true);
  });

  it("ignores a skill index with an unknown $schema", async () => {
    const mock = await MockCompany.create({
      poppy: (doc) => ({ ...doc, skill_index: { $schema: "https://example.com/v9", skills: [] } }),
    });
    expect((await userAt(mock)).company.skills).toEqual([]);
  });

  it("carries extension content in conversation messages", async () => {
    const bodies: Record<string, unknown>[] = [];
    const message = {
      id: "msg_1",
      role: "company",
      author: { type: "agent" },
      text: "Your jacket shipped. The trail bar contains peanuts.",
      extensions: {
        links: {
          items: [
            { url: "https://example.com/orders/ord_1/tracking", title: "Tracking" },
            { url: "http://example.com/insecure" },
          ],
        },
        disclosures: { items: [{ text: "Contains peanuts." }] },
        operations: {
          operation: {
            operation_id: "exc_1",
            revision: "r1",
            summary: "Exchange the jacket",
            expires_at: "2099-01-01T00:00:00Z",
          },
        },
      },
    };
    const user = await userAt(await MockCompany.create(), (url, init) => {
      if (!url.href.startsWith(CONVERSATIONS)) return undefined;
      bodies.push(JSON.parse(String(init.body ?? "{}")) as Record<string, unknown>);
      return Response.json(
        {
          conversation_id: "cnv_1",
          events: [{ id: "evt_1", type: "message", created_at: "t", message }],
          cursor: "evt_1",
          has_more: false,
          status: "idle",
          responder: "agent",
        },
        { status: 201 },
      );
    });
    const conversations = user.session().conversations();
    const { conversation, update } = await conversations.start({ text: "Where's my jacket?" });
    const received = update.events[0];
    if (received?.type !== "message") throw new Error("expected a message");
    expect(received.message.links).toEqual([
      { url: "https://example.com/orders/ord_1/tracking", title: "Tracking" },
    ]);
    expect(received.message.disclosures).toEqual([{ text: "Contains peanuts." }]);
    expect(received.message.operation?.operationId).toBe("exc_1");

    await conversation.send({ approval: approvalFor(received.message.operation!) });
    expect(bodies[1]).toEqual({
      message: {
        id: expect.any(String),
        author: { type: "agent" },
        extensions: { operations: { approval: { operation_id: "exc_1", revision: "r1" } } },
      },
    });

    // Accepting a user_requested event, so the Company speaks first.
    await conversation.openDirect(undefined, { userRequestedEventId: "evt_9" });
    expect(bodies[2]).toEqual({
      parent_conversation_id: "cnv_1",
      user_requested_event_id: "evt_9",
    });
    await expect(conversation.openDirect(undefined)).rejects.toThrow(PoppyProtocolError);
  });

  it("sends an approval in a message only to a Company that lists Operations version 2", async () => {
    const mock = await MockCompany.create({ poppy: (doc) => ({ ...doc, extensions: {} }) });
    const user = await userAt(mock, (url) =>
      url.href.startsWith(CONVERSATIONS) ? Response.json({}, { status: 500 }) : undefined,
    );
    const conversation = user.session().conversations().resume("cnv_1");
    await expect(
      conversation.send({ approval: { operationId: "exc_1", revision: "r1" } }),
    ).rejects.toThrow(PoppyProtocolError);
  });
});
