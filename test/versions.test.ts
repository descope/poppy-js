import { describe, expect, it } from "vitest";
import {
  companySupports,
  MemoryStore,
  parseEvent,
  PoppyAgent,
  PoppyProtocolError,
  SUPPORTED_PROTOCOL_VERSIONS,
  supportedScopes,
} from "../src/index.ts";
import { decodeJwt } from "../src/jose.ts";
import { checkSignInUrl } from "../src/oauth.ts";
import { extensionsHeader, throwable } from "../src/session.ts";
import {
  API,
  CLIENT_ID,
  CONVERSATIONS,
  EXCLUDED_TASKS,
  EXTRA_MCP,
  FEEDBACK,
  LINKED_DOC,
  MockCompany,
  type MockOptions,
  TASKS,
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
  return { mock, agent, company, user, session: user.session() };
}

/** Signs a User in through Direct Sign-In, as the Company's own authorization endpoint would. */
async function signInFor(mock: MockCompany, user: Awaited<ReturnType<typeof setup>>["user"]) {
  const { url } = await user.startDirectSignIn({ scope: "orders:read" });
  await user.completeDirectSignIn(await mock.approve(url));
}

describe("choosing a protocol version (spec 3.4)", () => {
  it("implements 0.4 and 0.3, newest first", () => {
    expect(SUPPORTED_PROTOCOL_VERSIONS).toEqual(["0.4", "0.3"]);
  });

  it("uses poppy.json when the Company prefers a version this client implements", async () => {
    const { company } = await setup({ version: "0.4" });
    expect(company.protocolVersion).toBe("0.4");
    expect(company.supportedVersions).toEqual({});
    expect(company.documentUrl).toBe("https://example.com/.well-known/poppy.json");
    expect(company.tasksEndpoint).toBe(TASKS);
    // 0.4 moved these out of poppy.json, so they're only in the tasks response.
    expect(company.feedbackEndpoint).toBeUndefined();
    expect(company.excludedTasksUrl).toBeUndefined();
    expect(company.webUnscoped).toBe(true);
  });

  it("follows supported_versions to the newest version's document", async () => {
    // poppy.json is 0.3 and links 0.4, so the agent has to fetch the linked document and use it.
    const { company, mock } = await setup({ version: "0.3", linkOtherVersion: true });
    expect(company.protocolVersion).toBe("0.4");
    expect(company.documentUrl).toBe(LINKED_DOC);
    expect(company.supportedVersions).toEqual({ "0.4": LINKED_DOC });
    expect(company.tasksEndpoint).toBe(TASKS);
    expect(mock.requests.some((r) => r.url === LINKED_DOC)).toBe(true);
  });

  it("stays on poppy.json when it already carries the newest version", async () => {
    // poppy.json is 0.4 and links 0.3, which is older, so there's nothing to fetch.
    const { company, mock } = await setup({ version: "0.4", linkOtherVersion: true });
    expect(company.protocolVersion).toBe("0.4");
    expect(mock.requests.some((r) => r.url === LINKED_DOC)).toBe(false);
  });

  it("ignores a supported_versions entry on another host, and keeps poppy.json's version", async () => {
    const { company, mock } = await setup({
      version: "0.3",
      linkOtherVersion: true,
      linkedUrl: "https://elsewhere.test/poppy/0.4.json",
    });
    expect(company.protocolVersion).toBe("0.3");
    expect(company.supportedVersions).toEqual({});
    expect(mock.requests.some((r) => r.url.includes("elsewhere.test"))).toBe(false);
  });

  it("refuses a linked document that declares another version, and falls back", async () => {
    const { company } = await setup({
      version: "0.3",
      linkOtherVersion: true,
      linkedDoc: (doc) => ({ ...doc, protocol_version: "0.3" }),
    });
    // The document listed under 0.4 isn't a 0.4 document, so 0.4 drops out and 0.3 is used.
    expect(company.protocolVersion).toBe("0.3");
  });

  it("refuses a linked document that carries supported_versions of its own", async () => {
    const { company } = await setup({
      version: "0.3",
      linkOtherVersion: true,
      linkedDoc: (doc) => ({ ...doc, supported_versions: { "0.2": LINKED_DOC } }),
    });
    expect(company.protocolVersion).toBe("0.3");
  });

  it("refuses a Company that serves no version it implements", async () => {
    const mock = await MockCompany.create({
      poppy: (doc) => ({
        ...doc,
        protocol_version: "9.9",
        supported_versions: { "0.1": LINKED_DOC },
      }),
    });
    const agent = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
      fetch: mock.fetch,
    });
    await expect(agent.discover("example.com")).rejects.toThrow(PoppyProtocolError);
  });
});

describe("version and extension headers (spec 3.4)", () => {
  it("sends Poppy-Version and Poppy-Extensions on 0.4, and neither on 0.3", async () => {
    const v4 = await setup({ version: "0.4" });
    await (await v4.session.fetch(`${API}/v1/orders`)).body?.cancel();
    const request = v4.mock.requests.find((r) => r.url === `${API}/v1/orders`);
    expect(request?.headers.get("poppy-version")).toBe("0.4");
    expect(request?.headers.get("poppy-extensions")).toBe('"operations";v="2"');

    const v3 = await setup({ version: "0.3" });
    await (await v3.session.fetch(`${API}/v1/orders`)).body?.cancel();
    const older = v3.mock.requests.find((r) => r.url === `${API}/v1/orders`);
    expect(older?.headers.get("poppy-version")).toBeNull();
    expect(older?.headers.get("poppy-extensions")).toBeNull();
  });

  it("declares only extensions both sides list, at the version the agent uses", async () => {
    const { company } = await setup({ version: "0.4" });
    // The Company lists operations 3 and 2; this agent uses 2, so that is what it declares.
    expect(companySupports(company, "operations", "3")).toBe(true);
    expect(companySupports(company, "operations", "2")).toBe(true);
    expect(extensionsHeader(company, { operations: { version: "2" } })).toBe('"operations";v="2"');
    // An extension the Company doesn't list isn't declared, and nor is a version it doesn't list.
    expect(extensionsHeader(company, { operations: { version: "9" } })).toBeUndefined();
    expect(extensionsHeader(company, { "other.test/gift": { version: "1" } })).toBeUndefined();
    expect(
      extensionsHeader(company, {
        operations: { version: "2" },
        "mediated-sign-in": { version: "1" },
      }),
    ).toBe('"operations";v="2", "mediated-sign-in";v="1"');
  });

  it("discovers again on version_unsupported, and gives up when the version is the same", async () => {
    const { session, mock } = await setup({ version: "0.4", versionUnsupported: true });
    const response = await session.fetch(`${API}/v1/orders`);
    await response.body?.cancel();
    expect(response.status).toBe(400);
    // One retry's worth of discovery, then it stops rather than looping (spec 3.4).
    const discoveries = mock.requests.filter((r) =>
      r.url.endsWith("/.well-known/poppy.json"),
    ).length;
    expect(discoveries).toBe(2);
    expect(mock.requests.filter((r) => r.url === `${API}/v1/orders`)).toHaveLength(1);
  });

  it("continues in a new Session at the version a fresh discovery chooses", async () => {
    // The Company stops serving 0.4 between the refusal and the fresh discovery.
    const { session, mock } = await setup({
      version: "0.4",
      versionUnsupported: true,
      versionAfterError: "0.3",
    });
    const first = session.id;
    const response = await session.fetch(`${API}/v1/orders`);
    await response.body?.cancel();
    // The retry got through: 401 is the Company asking this signed-out Session to sign in, not a
    // version error.
    expect(response.status).toBe(401);
    expect(session.protocolVersion).toBe("0.3");
    expect(session.company.protocolVersion).toBe("0.3");
    // A new version means a new Session, since the old one's state doesn't carry over.
    expect(session.id).not.toBe(first);
    expect(mock.declaredVersions).toEqual(["0.4", null]);
  });
});

describe("task coverage (spec section 9)", () => {
  it("reads 0.3's excluded tasks document, and 0.4's per-Session tasks endpoint", async () => {
    const older = await setup({ version: "0.3" });
    const v3 = await older.session.taskCoverage();
    expect(v3.excludedTasks).toEqual([{ task: "Send a wire transfer", alternative: undefined }]);
    expect(v3.feedbackEndpoint).toBe(FEEDBACK);
    const document = older.mock.requests.find((r) => r.url === EXCLUDED_TASKS);
    // The 0.3 document is the same for every User, so it carries no Session header (spec 9.1).
    expect(document?.headers.get("poppy-session")).toBeNull();

    const { session, mock } = await setup({ version: "0.4" });
    const v4 = await session.taskCoverage();
    expect(v4.excludedTasks).toEqual([{ task: "Send a wire transfer", alternative: undefined }]);
    expect(v4.feedbackEndpoint).toBe(FEEDBACK);
    const tasks = mock.requests.find((r) => r.url === TASKS);
    expect(tasks?.method).toBe("GET");
    expect(tasks?.headers.get("poppy-session")).not.toBeNull();
    // The response describes what the Company offers, not the account, so it carries no token.
    expect(tasks?.headers.get("authorization")).toBeNull();
  });

  it("keeps a Session's tasks response for that Session only", async () => {
    const { user, mock } = await setup({ version: "0.4" });
    const first = user.session();
    await first.taskCoverage();
    await first.taskCoverage();
    expect(mock.requests.filter((r) => r.url === TASKS)).toHaveLength(1);
    // A second Session asks again, since the answer belongs to the Session it was given to.
    await user.session().taskCoverage();
    expect(mock.requests.filter((r) => r.url === TASKS)).toHaveLength(2);
  });

  it("reads skills from the tasks response, resolved against tasks.endpoint", async () => {
    const { session } = await setup({
      version: "0.4",
      tasks: {
        skill_index: {
          $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
          skills: [
            {
              name: "manage-bookings",
              description: "Manage bookings.",
              type: "skill-md",
              url: "skills/manage-bookings/SKILL.md",
              digest: `sha256:${"1".repeat(64)}`,
            },
          ],
        },
      },
    });
    const { skills, feedbackEndpoint } = await session.taskCoverage();
    expect(skills[0]?.url).toBe(`${API}/poppy/skills/manage-bookings/SKILL.md`);
    expect(feedbackEndpoint).toBeUndefined();
  });

  it("carries on with empty coverage when the tasks endpoint answers with nothing usable", async () => {
    const { session } = await setup({ version: "0.4", tasks: { excluded_tasks: "not a list" } });
    await expect(session.taskCoverage()).resolves.toEqual({
      excludedTasks: [],
      skills: [],
      feedbackEndpoint: undefined,
    });
  });

  it("sends feedback to the endpoint the tasks response names, with no access token", async () => {
    const { session, mock } = await setup({ version: "0.4" });
    await expect(
      session.sendFeedback({ task: "Pay with a gift card", description: "No API offered one." }),
    ).resolves.toBeUndefined();
    const report = mock.requests.find((r) => r.url === FEEDBACK);
    expect(report?.method).toBe("POST");
    expect(report?.headers.get("poppy-session")).not.toBeNull();
    expect(report?.headers.get("authorization")).toBeNull();
  });
});

describe("conversation state and request IDs (spec 8.3, 8.7)", () => {
  it("reads 0.3's status and 0.4's four fields into the same state", () => {
    const base = { id: "evt_1", created_at: "2026-11-10T00:00:00Z", type: "state" };
    // 0.3 carries one status at a time, which says everything.
    expect(parseEvent({ ...base, status: "queued", responder: "agent" })).toMatchObject({
      status: "queued",
      working: false,
      handoff: "pending",
      closed: false,
      responder: "agent",
    });
    expect(parseEvent({ ...base, status: "working", responder: "agent" })).toMatchObject({
      working: true,
      handoff: "none",
    });
    // 0.4 carries handoff, responder and closed, and says nothing about working.
    expect(
      parseEvent({ ...base, handoff: "pending", responder: "agent", closed: false }),
    ).toMatchObject({ status: "queued", working: undefined, handoff: "pending", closed: false });
    expect(
      parseEvent({ ...base, handoff: "none", responder: "human", closed: true }),
    ).toMatchObject({ status: "closed", closed: true, responder: "human" });
    // An unrecognized handoff reads as pending, the more cautious answer (spec 8.7).
    expect(parseEvent({ ...base, handoff: "looking", responder: "agent" })).toMatchObject({
      handoff: "pending",
    });
  });

  it("reads as_of_request and as_of_cursor, and a message id the Company set", () => {
    const event = parseEvent({
      id: "evt_2",
      created_at: "2026-11-10T00:00:00Z",
      type: "message",
      message: {
        id: "msg_1",
        role: "company",
        author: { type: "agent" },
        as_of_request: "msg_a",
        text: "Done",
      },
    });
    expect(event).toMatchObject({
      type: "message",
      message: { id: "msg_1", asOfRequest: "msg_a", asOfCursor: undefined },
    });
  });

  it("puts the request id on the body from 0.4, and on the message on 0.3", async () => {
    for (const version of ["0.3", "0.4"] as const) {
      const { session, mock } = await setup({ version });
      const { conversation } = await session
        .conversations()
        .start({ id: "req_1", text: "Hello", asOfCursor: "evt_c1" });
      const start = mock.requests.find((r) => r.url === CONVERSATIONS);
      const body = JSON.parse(start?.body ?? "{}") as Record<string, Record<string, unknown>>;
      if (version === "0.3") {
        expect(body["id"]).toBeUndefined();
        expect(body["message"]).toMatchObject({ id: "req_1", text: "Hello" });
        // as_of_cursor is 0.4 only, so a 0.3 Company never sees it (spec 8.4).
        expect(body["message"]?.["as_of_cursor"]).toBeUndefined();
      } else {
        expect(body["id"]).toBe("req_1");
        expect(body["message"]?.["id"]).toBeUndefined();
        expect(body["message"]?.["as_of_cursor"]).toBe("evt_c1");
      }
      // Handoff and close carry a request id from 0.4, and an empty object on 0.3 (spec 8.9, 8.12).
      await conversation.handoff({ id: "hnd_1" });
      const handoff = mock.requests.find((r) => r.url.endsWith("/handoff"));
      expect(JSON.parse(handoff?.body ?? "{}")).toEqual(version === "0.3" ? {} : { id: "hnd_1" });
      // Withdrawing a handoff is 0.4 only (spec 8.9).
      if (version === "0.3")
        await expect(conversation.cancelHandoff()).rejects.toThrow(PoppyProtocolError);
      else {
        await conversation.cancelHandoff({ id: "hnc_1" });
        const cancel = mock.requests.find((r) => r.url.endsWith("/handoff/cancel"));
        expect(JSON.parse(cancel?.body ?? "{}")).toEqual({ id: "hnc_1" });
      }
    }
  });

  it("doesn't put as_of_cursor on a message a person wrote", async () => {
    const { session, mock } = await setup({ version: "0.4" });
    await session
      .conversations()
      .openDirect("cnv_1", { text: "Hi", author: { type: "human" }, asOfCursor: "evt_c1" });
    const body = JSON.parse(
      mock.requests.find((r) => r.url === CONVERSATIONS)?.body ?? "{}",
    ) as Record<string, Record<string, unknown>>;
    expect(body["message"]?.["as_of_cursor"]).toBeUndefined();
  });
});

describe("errors and links (spec 3.3, 4.3, 4.5, 8.13)", () => {
  it("reads extension_required from a JSON body at an API, as 0.4 sends it", async () => {
    const response = Response.json(
      { error: "extension_required", extension: "operations" },
      {
        status: 403,
      },
    );
    const error = await throwable(response);
    expect(error).toMatchObject({ error: "extension_required", extension: "operations" });
  });

  it("still reads insufficient_scope from the challenge, which both versions send there", async () => {
    const response = new Response(null, {
      status: 403,
      headers: { "www-authenticate": 'Bearer error="insufficient_scope", scope="orders:write"' },
    });
    const error = await throwable(response);
    expect(error).toMatchObject({ error: "insufficient_scope", scope: "orders:write" });
  });

  it("keeps protocol_version from version_mismatch", async () => {
    const error = await throwable(
      Response.json({ error: "version_mismatch", protocol_version: "0.4" }, { status: 409 }),
    );
    expect(error).toMatchObject({ error: "version_mismatch", protocolVersion: "0.4" });
  });

  it("narrows the Device Sign-In link rule on 0.4 (spec 4.3)", async () => {
    // The issuer serves another domain of the Company's too, as a shared issuer often does.
    const withSibling = (company: Awaited<ReturnType<typeof setup>>["company"]) => ({
      ...company,
      oauth: {
        ...company.oauth!,
        protectedResources: ["https://example.com", "https://example.co.uk"],
      },
    });
    const older = withSibling((await setup({ version: "0.3" })).company);
    const newer = withSibling((await setup({ version: "0.4" })).company);
    // Both versions allow the issuer's host, a subdomain of it, and organization.domain.
    for (const company of [older, newer]) {
      expect(checkSignInUrl(company, "https://auth.example.com/activate", "link")).toBe(
        "https://auth.example.com/activate",
      );
      expect(checkSignInUrl(company, "https://shop.example.com/activate", "link")).toBe(
        "https://shop.example.com/activate",
      );
    }
    // 0.3 also allows the host of any URL in protected_resources.
    expect(checkSignInUrl(older, "https://example.co.uk/activate", "link")).toBe(
      "https://example.co.uk/activate",
    );
    // 0.4 doesn't: that list can name domains that only share the issuer, so a link there could pass
    // off a page the Company doesn't control as its sign-in page (spec 4.3).
    expect(() => checkSignInUrl(newer, "https://example.co.uk/activate", "link")).toThrow(
      PoppyProtocolError,
    );
  });
});

describe("scopes (spec 3.2, 4.7)", () => {
  it("takes the scopes the issuer and the domain's resource metadata list", async () => {
    const mock = await MockCompany.create({ version: "0.4" });
    const agent = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
      fetch: ((input: string | URL | Request, init?: RequestInit) => {
        const url = String(input instanceof Request ? input.url : input);
        if (url === "https://example.com/.well-known/oauth-protected-resource")
          return Promise.resolve(
            Response.json({
              resource: "https://example.com",
              authorization_servers: ["https://auth.example.com"],
              scopes_supported: ["poppy:browser-sign-in", "orders:read"],
            }),
          );
        return mock.fetch(input, init);
      }) as typeof fetch,
    });
    const company = await agent.discover("example.com");
    expect(company.resourceScopesSupported).toEqual(["poppy:browser-sign-in", "orders:read"]);
    // Either list may name a scope the agent can request, so it uses both (spec 4.7).
    expect(supportedScopes(company).sort()).toEqual([
      "orders:read",
      "orders:write",
      "poppy:browser-sign-in",
    ]);
  });
});

describe("review findings (PR #15)", () => {
  it("rechecks the destination against the new version's document before resending", async () => {
    // tasks.endpoint is a 0.4 destination and doesn't exist on 0.3, so after the downgrade this
    // URL is one the new document doesn't list (spec 5.2).
    const { session } = await setup({
      version: "0.4",
      versionUnsupported: true,
      versionAfterError: "0.3",
    });
    await expect(session.fetch(TASKS)).rejects.toThrow(/is not an API or endpoint/);
    expect(session.protocolVersion).toBe("0.3");
  });

  it("doesn't resend a body built for the version that went away", async () => {
    const { session, mock } = await setup({
      version: "0.4",
      versionUnsupported: true,
      versionAfterError: "0.3",
    });
    // A 0.4 conversation POST carries a top-level id and a message with none, which is the wrong
    // shape for 0.3. The Session moves version, and the caller rebuilds (spec 3.4, 8.3).
    await expect(session.conversations().start({ text: "Hello" })).rejects.toMatchObject({
      error: "version_unsupported",
      protocolVersion: "0.3",
    });
    expect(session.protocolVersion).toBe("0.3");
    // Sent once, under the version it was built for; never replayed to the other one.
    expect(mock.requests.filter((r) => r.url === CONVERSATIONS)).toHaveLength(1);
    expect(mock.declaredVersions).toEqual(["0.4"]);
  });

  it("keeps 0.3 skills and the feedback endpoint when the excluded tasks document fails", async () => {
    const { session } = await setup({ version: "0.3", excludedTasksFails: true });
    const coverage = await session.taskCoverage();
    // Only the tasks needed that request; the other two are already in poppy.json (spec 9.1).
    expect(coverage.excludedTasks).toEqual([]);
    expect(coverage.feedbackEndpoint).toBe(FEEDBACK);
    await expect(
      session.sendFeedback({ task: "Pay with a gift card", description: "No API offered one." }),
    ).resolves.toBeUndefined();
  });

  it("keeps the challenge's scope when a 403 carries a JSON body too", async () => {
    // RFC 6750 servers often send both. The body names the error, the challenge the scope.
    const error = await throwable(
      new Response(JSON.stringify({ error: "insufficient_scope" }), {
        status: 403,
        headers: {
          "content-type": "application/json",
          "www-authenticate": 'Bearer error="insufficient_scope", scope="orders:write"',
        },
      }),
    );
    expect(error).toMatchObject({ error: "insufficient_scope", scope: "orders:write" });
  });

  it("doesn't hand a downgraded Session's resolver to the Company others still hold", async () => {
    const { user, session } = await setup({
      version: "0.4",
      versionUnsupported: true,
      versionAfterError: "0.3",
    });
    await expect(session.fetch(TASKS)).rejects.toThrow(/is not an API or endpoint/);
    // This PoppyUser still holds the 0.4 Company, so its next Session still reaches 0.4's endpoints.
    const next = user.session();
    expect(next.protocolVersion).toBe("0.4");
    const response = await next.fetch(TASKS);
    await response.body?.cancel();
    expect(response.status).toBe(200);
  });

  it("ignores a supported_versions entry for the document's own version", async () => {
    // Following a link for the version already in hand would fetch a second copy, and could fail
    // over one that is broken (spec 3.4).
    const { company, mock } = await setup({
      version: "0.4",
      poppy: (doc) => ({ ...doc, supported_versions: { "0.4": LINKED_DOC } }),
    });
    expect(company.protocolVersion).toBe("0.4");
    expect(company.supportedVersions).toEqual({});
    expect(mock.requests.some((r) => r.url === LINKED_DOC)).toBe(false);
  });

  it("falls back when a linked document fails a check beyond its version", async () => {
    // The linked 0.4 document is a 0.4 document, but names another domain, so it is one this
    // client must not use (spec 3.1) — and the published 0.3 document still works.
    const { company } = await setup({
      version: "0.3",
      linkOtherVersion: true,
      linkedDoc: (doc) => ({
        ...doc,
        organization: { name: "Example Company", domain: "elsewhere.test" },
      }),
    });
    expect(company.protocolVersion).toBe("0.3");
  });

  it("gives a 0.4 state event the status its merged state implies", async () => {
    const { session } = await setup({ version: "0.4" });
    const { conversation } = await session.conversations().start({ text: "Hi" });
    // A new conversation is working; a state event that says nothing about working leaves it so,
    // and the event must not read as idle (spec 8.7).
    const update = conversation.apply({
      events: [
        {
          id: "evt_s1",
          type: "state",
          created_at: "2026-11-12T00:00:00Z",
          handoff: "none",
          responder: "agent",
          closed: false,
        },
      ],
      working: true,
      handoff: "none",
      responder: "agent",
      closed: false,
    });
    expect(update.events[0]).toMatchObject({ type: "state", status: "working" });
    expect(conversation.status).toBe("working");
  });

  it("yields working items when streaming falls back to polling", async () => {
    const { session } = await setup({ version: "0.4", workingFirstRead: true });
    const { conversation } = await session.conversations().start({ text: "Hi" });
    const controller = new AbortController();
    const seen: string[] = [];
    for await (const item of conversation.stream({ signal: controller.signal })) {
      seen.push(item.type);
      // The Company doesn't stream, so working arrives from each read's body (spec 8.6).
      if (item.type === "working" && !item.working) {
        controller.abort();
        break;
      }
    }
    expect(seen).toContain("working");
  });
});

describe("continuing a Session across processes (spec 5.2, 5.5)", () => {
  it("resumes the sid it is given, and sends it on the wire", async () => {
    const { user, mock } = await setup({ version: "0.4" });
    const first = user.session();
    const id = first.id;
    await (await first.fetch(`${API}/v1/orders`)).body?.cancel();

    // A second process, with the same stored User: the Session carries on rather than starting over.
    const resumed = user.session({ id });
    expect(resumed.id).toBe(id);
    await (await resumed.fetch(`${API}/v1/orders`)).body?.cancel();
    const sids = mock.sessionClaims.map((claims) => claims["sid"]);
    expect(sids).toEqual([id, id]);
    // Every Session JWT of a Session carries the same sub, which a Company checks (spec 5.3).
    expect(new Set(mock.sessionClaims.map((claims) => claims["sub"])).size).toBe(1);
  });

  it("makes a fresh one when no id is given", async () => {
    const { user } = await setup({ version: "0.4" });
    expect(user.session().id).not.toBe(user.session().id);
  });

  it("refuses an id a Company would reject", async () => {
    const { user } = await setup({ version: "0.4" });
    for (const id of ["", "has spaces", "slash/es", "x".repeat(257)])
      expect(() => user.session({ id })).toThrow(PoppyProtocolError);
    expect(user.session({ id: "x".repeat(256) }).id).toBe("x".repeat(256));
  });

  it("leaves a resumed Session behind when the Company says it ended", async () => {
    // session_ended means the old Session's state doesn't carry over, so the SDK starts a new one
    // with a new sid and sends the request again, once (spec 5.5).
    const { user, mock } = await setup({ version: "0.4", endedSids: ["sid_from_last_run"] });
    const session = user.session({ id: "sid_from_last_run" });
    // The tasks endpoint needs no scope, so a 200 says the retry was handled rather than merely
    // getting past the Session check and stopping at a challenge.
    const response = await session.fetch(TASKS);
    await response.body?.cancel();
    expect(response.status).toBe(200);
    expect(session.id).not.toBe("sid_from_last_run");
    expect(mock.sessionClaims.map((c) => c["sid"])).toEqual(["sid_from_last_run", session.id]);
  });
});

describe("rediscovery reads past the caches (spec 3.4, 5.2)", () => {
  it("builds the resolver again rather than reusing one from an earlier discovery", async () => {
    // An earlier 0.3 discovery lists an API the Company later drops. Rediscovering into 0.3 must
    // follow the document it just read, not the one a cached resolver was built from.
    let listExtra = true;
    const mock = await MockCompany.create({
      version: "0.3",
      poppy: (doc) => ({
        ...doc,
        apis: listExtra
          ? [...(doc["apis"] as unknown[]), { type: "mcp", url: EXTRA_MCP }]
          : (doc["apis"] as unknown[]),
      }),
    });
    const agent = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
      fetch: mock.fetch,
      store: new MemoryStore(),
    });

    // 1. A 0.3 Session, which caches a resolver under this Company's 0.3 key.
    const older = await agent.discover("example.com");
    expect(older.protocolVersion).toBe("0.3");
    (await agent.user(older, "alice")).session();

    // 2. A 0.4 Session for the same Company, still listing the extra API.
    mock.options.version = "0.4";
    const newer = await agent.discover("example.com");
    const session = (await agent.user(newer, "bob")).session();

    // 3. The Company stops serving 0.4 and drops the extra API from its 0.3 document.
    mock.options.versionUnsupported = true;
    mock.options.versionAfterError = "0.3";
    listExtra = false;

    // The request is a destination under 0.4, so it goes out; the Company refuses the version, and
    // the fresh 0.3 document no longer lists it. A resolver reused from step 1 would still say yes.
    await expect(session.fetch(EXTRA_MCP)).rejects.toThrow(/is not an API or endpoint/);
    expect(session.protocolVersion).toBe("0.3");
    // Sent once, under 0.4 where the document listed it, and never retried under the 0.3 document
    // that dropped it. A reused resolver would have let the retry through.
    expect(mock.requests.filter((r) => r.url.startsWith(EXTRA_MCP))).toHaveLength(1);
  });
});

describe("review round two (PR #15)", () => {
  it("refuses to resume an anonymous User's Session", async () => {
    const { agent, company } = await setup({ version: "0.4" });
    expect(() => agent.anonymousUser(company).session({ id: "sid_x" })).toThrow(PoppyProtocolError);
    // Without an id it is fine: an anonymous User just never continues one.
    expect(agent.anonymousUser(company).session().id).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("starts a new Session when the saved id belongs to another version", async () => {
    const { user } = await setup({ version: "0.4" });
    // Saved while the Company served 0.3; it serves 0.4 now, and a Session keeps one version
    // throughout (spec 3.4), so the old sid is not sent under this one.
    const session = user.session({ id: "sid_from_0_3", protocolVersion: "0.3" });
    expect(session.id).not.toBe("sid_from_0_3");
    // The same version resumes as before.
    expect(user.session({ id: "sid_now", protocolVersion: "0.4" }).id).toBe("sid_now");
  });

  it("chooses again on a second version_unsupported in one Session", async () => {
    // The retry budget is per request, so a Session that switched once isn't stuck afterwards.
    const { session, mock } = await setup({
      version: "0.4",
      versionUnsupported: true,
      versionAfterError: "0.3",
    });
    await (await session.fetch(`${API}/v1/orders`)).body?.cancel();
    expect(session.protocolVersion).toBe("0.3");
    mock.options.versionUnsupported = true;
    mock.options.versionAfterError = "0.4";
    await (await session.fetch(`${API}/v1/orders`)).body?.cancel();
    expect(session.protocolVersion).toBe("0.4");
  });

  it("drops a Session's task coverage when the Company ends it", async () => {
    const { user, mock } = await setup({ version: "0.4", endedSids: ["sid_one"] });
    const session = user.session({ id: "sid_one" });
    await session.taskCoverage();
    // The Session that answered is gone, so its excluded tasks don't carry into the new one.
    await (await session.fetch(TASKS)).body?.cancel();
    await session.taskCoverage();
    expect(mock.requests.filter((r) => r.url === TASKS).length).toBeGreaterThan(1);
  });

  it("doesn't remember a tasks endpoint that failed", async () => {
    const { session, mock } = await setup({ version: "0.4", tasksRateLimited: true });
    await expect(session.taskCoverage()).resolves.toMatchObject({ excludedTasks: [] });
    // A later call asks again rather than serving the failure for the rest of the Session.
    await session.taskCoverage();
    expect(mock.requests.filter((r) => r.url === TASKS).length).toBeGreaterThan(1);
  });

  it("reads 0.3 skills and feedback without fetching the excluded tasks document", async () => {
    const { session, mock } = await setup({ version: "0.3", excludedTasksFails: true });
    await expect(
      session.sendFeedback({ task: "Pay with a gift card", description: "No API offered one." }),
    ).resolves.toBeUndefined();
    expect(mock.requests.some((r) => r.url === EXCLUDED_TASKS)).toBe(false);
  });

  it("keeps status on what close and handoff return", async () => {
    const { session } = await setup({ version: "0.3" });
    const { conversation } = await session.conversations().start({ text: "Hi" });
    expect(await conversation.handoff()).toMatchObject({ status: expect.any(String) });
    expect(await conversation.close()).toMatchObject({ status: expect.any(String) });
  });

  it("is working once the Company has accepted a request it hasn't answered", async () => {
    // A 0.4 POST without wait answers with only conversation_id (spec 8.3), and the Company has
    // work in progress from the moment it accepts (8.7).
    const { session } = await setup({ version: "0.4" });
    const { update } = await session.conversations().start({ text: "Hi" });
    expect(update.working).toBe(true);
  });

  it("ignores a malformed scopes_supported on the domain's metadata", async () => {
    const mock = await MockCompany.create({ version: "0.3" });
    const agent = new PoppyAgent({
      clientId: CLIENT_ID,
      signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
      fetch: ((input: string | URL | Request, init?: RequestInit) => {
        const url = String(input instanceof Request ? input.url : input);
        if (url === "https://example.com/.well-known/oauth-protected-resource")
          return Promise.resolve(
            Response.json({
              resource: "https://example.com",
              authorization_servers: ["https://auth.example.com"],
              // 0.3 defines nothing here, so whatever a Company put in it can't refuse discovery.
              scopes_supported: "orders:read",
            }),
          );
        return mock.fetch(input, init);
      }) as typeof fetch,
    });
    const company = await agent.discover("example.com");
    expect(company.protocolVersion).toBe("0.3");
    expect(company.resourceScopesSupported).toBeUndefined();
  });

  it("refuses a linked document on another port of the same host", async () => {
    const { company } = await setup({
      version: "0.3",
      linkOtherVersion: true,
      linkedUrl: "https://example.com:8443/poppy/other.json",
    });
    // Spec 3.4 says the host that served poppy.json, which a different port is not.
    expect(company.protocolVersion).toBe("0.3");
    expect(company.supportedVersions).toEqual({});
  });
});

describe("a Session forgets what the last one was told (spec 5.2, 9)", () => {
  // The 0.4 tasks response names a feedback endpoint of its own, which no 0.3 document lists, so
  // whether it is still a destination says exactly whether the reset happened.
  const V4_FEEDBACK = `${API}/poppy/feedback-v4`;

  it("stops treating the old feedback endpoint as a destination after session_ended", async () => {
    const { user, mock } = await setup({
      version: "0.4",
      tasks: { feedback: { endpoint: V4_FEEDBACK } },
    });
    const session = user.session();
    // Stored under a live sid, so there is something to lose.
    expect((await session.taskCoverage()).feedbackEndpoint).toBe(V4_FEEDBACK);
    // Now the Company ends that Session, and its next answer names no feedback endpoint.
    mock.options.endedSids = [session.id];
    mock.options.tasks = { excluded_tasks: [] };
    await (await session.fetch(TASKS)).body?.cancel();
    await expect(session.fetch(V4_FEEDBACK)).rejects.toThrow(/is not an API or endpoint/);
  });

  it("stops treating it as a destination after a version switch", async () => {
    const { user, mock } = await setup({
      version: "0.4",
      tasks: { feedback: { endpoint: V4_FEEDBACK } },
    });
    const session = user.session();
    expect((await session.taskCoverage()).feedbackEndpoint).toBe(V4_FEEDBACK);
    mock.options.versionUnsupported = true;
    mock.options.versionAfterError = "0.3";
    await (await session.fetch(`${API}/v1/orders`)).body?.cancel();
    expect(session.protocolVersion).toBe("0.3");
    // 0.3 names its own endpoint in poppy.json; the one the 0.4 answer named is gone.
    await expect(session.fetch(V4_FEEDBACK)).rejects.toThrow(/is not an API or endpoint/);
    expect((await session.taskCoverage()).feedbackEndpoint).toBe(FEEDBACK);
  });
});

describe("website pages fetched without a browser (spec 5.2, 5.6)", () => {
  const PAGE = `https://${"example.com"}/help/returns`;

  it("carries the Session header and never a token, on 0.4", async () => {
    const { user, mock } = await setup({ version: "0.4" });
    await signInFor(mock, user);
    const session = user.session();
    await (await session.fetchPage(PAGE)).body?.cancel();
    const page = mock.requests.find((r) => r.url === PAGE);
    expect(page?.headers.get("poppy-session")).not.toBeNull();
    expect(page?.headers.get("poppy-version")).toBe("0.4");
    // Signed in or not, a page request is signed out, so the JWT has no ath.
    expect(page?.headers.get("authorization")).toBeNull();
    // Read the JWT the page actually got: a page isn't a resource, so the mock records no claims.
    const { payload } = decodeJwt(page?.headers.get("poppy-session") ?? "");
    expect(payload["ath"]).toBeUndefined();
    expect(payload["sid"]).toBe(session.id);
    expect(payload["htu"]).toBe(PAGE);
  });

  it("sends no header on 0.3, where pages carry none", async () => {
    const { session, mock } = await setup({ version: "0.3" });
    await (await session.fetchPage(PAGE)).body?.cancel();
    expect(mock.requests.find((r) => r.url === PAGE)?.headers.get("poppy-session")).toBeNull();
  });

  it("drops the header on a hop that leaves the Company's domain", async () => {
    const { session, mock } = await setup({ version: "0.4" });
    await (await session.fetchPage(`https://example.com/offsite`)).body?.cancel();
    const away = mock.requests.find((r) => new URL(r.url).host === "elsewhere.test");
    expect(away).toBeDefined();
    expect(away?.headers.get("poppy-session")).toBeNull();
  });

  it("asks again without the header when the page refuses it", async () => {
    const { session, mock } = await setup({ version: "0.4", pageRejectsSession: true });
    const response = await session.fetchPage(PAGE);
    await response.body?.cancel();
    expect(response.status).toBe(200);
    const tries = mock.requests.filter((r) => r.url === PAGE);
    expect(tries).toHaveLength(2);
    expect(tries[0]?.headers.get("poppy-session")).not.toBeNull();
    expect(tries[1]?.headers.get("poppy-session")).toBeNull();
  });

  it("refuses a page that isn't an HTTPS URL on a public host", async () => {
    const { session } = await setup({ version: "0.4" });
    await expect(session.fetchPage("http://example.com/x")).rejects.toThrow(PoppyProtocolError);
  });
});

describe("a tasks request the Session outlived (spec 5.5, 9)", () => {
  const V4_FEEDBACK = `${API}/poppy/feedback-v4`;

  it("keeps the answer when its own request was retried under a new sid", async () => {
    // The tasks GET meets session_ended, so fetch() starts a new Session and sends it again. The
    // answer that comes back is this Session's, and must not be thrown away for being late.
    const { user, mock } = await setup({
      version: "0.4",
      tasks: { feedback: { endpoint: V4_FEEDBACK } },
    });
    const session = user.session();
    mock.options.endedSids = [session.id];
    const coverage = await session.taskCoverage();
    expect(coverage.feedbackEndpoint).toBe(V4_FEEDBACK);
    expect(session.id).not.toBe(mock.options.endedSids[0]);
    // The endpoint it returned is one this Session will actually send to.
    const response = await session.fetch(V4_FEEDBACK, { method: "POST", body: "{}" });
    await response.body?.cancel();
    // Asked again, it is already known: no second trip for an answer this Session kept.
    const before = mock.requests.filter((r) => r.url === TASKS).length;
    await session.taskCoverage();
    expect(mock.requests.filter((r) => r.url === TASKS)).toHaveLength(before);
  });
});
