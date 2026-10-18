import { inspect } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  PoppyAgent,
  PoppyError,
  PoppyProtocolError,
  type Session,
  type Store,
} from "../src/index.ts";
import {
  API,
  CLIENT_ID,
  DEVICE_ENDPOINT,
  ISSUER,
  MockCompany,
  REVOCATION_ENDPOINT,
  TOKEN_ENDPOINT,
  USER_ID,
} from "./mock-company.ts";

class InspectableStore implements Store {
  readonly values = new Map<string, string>();
  async get(key: string) {
    return this.values.get(key);
  }
  async set(key: string, value: string) {
    this.values.set(key, value);
  }
  async delete(key: string) {
    this.values.delete(key);
  }
  /** The single stored Session state. */
  state(): Record<string, unknown> {
    const [value] = this.values.values();
    return JSON.parse(value ?? "{}") as Record<string, unknown>;
  }
}

async function setup(store = new InspectableStore()) {
  const mock = await MockCompany.create();
  const agent = mock.agent({ store });
  const company = await agent.discover("example.com");
  return { mock, agent, company, store };
}

/** Runs Device Sign-In to completion under fake timers. */
async function signIn(mock: MockCompany, session: Session) {
  vi.useFakeTimers({ toFake: ["setTimeout"] });
  const pending = await session.startDeviceSignIn("poppy:read poppy:write");
  const done = pending.wait();
  await vi.advanceTimersByTimeAsync(5_000);
  vi.useRealTimers();
  return { pending, result: await done };
}

function grant(mock: MockCompany): (string | null)[] {
  return mock.callsTo(TOKEN_ENDPOINT).map((call) => call.form?.get("grant_type") ?? null);
}

/** Drops `fields` from the token responses to `grantType`, as a Company may. */
function omitFromGrant(mock: MockCompany, grantType: string, fields: string[]) {
  const { fetch } = mock;
  mock.fetch = async (input, init) => {
    const response = await fetch(input, init);
    if (!(init?.body instanceof URLSearchParams) || init.body.get("grant_type") !== grantType)
      return response;
    const body = (await response.json()) as Record<string, unknown>;
    for (const field of fields) delete body[field];
    return Response.json(body, { status: response.status, headers: response.headers });
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("PoppyAgent", () => {
  it("requires a normalized clientId, so assertions match the published client_id", async () => {
    const mock = await MockCompany.create();
    expect(
      () => new PoppyAgent({ clientId: "https://Agent.example.net", signingKey: mock.signingKey }),
    ).toThrow(PoppyProtocolError);
    expect(
      () => new PoppyAgent({ clientId: "http://agent.example.net/", signingKey: mock.signingKey }),
    ).toThrow(/https/);
  });

  it("starts a signed-out Session with a Session assertion", async () => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    expect(session.signedIn).toBe(false);
    expect(session.sessionId).toBe("ses-1");
    expect(session.scope).toBe("");
    expect(grant(mock)).toEqual(["urn:ietf:params:oauth:grant-type:jwt-bearer"]);
    expect(mock.callsTo(TOKEN_ENDPOINT)[0]?.form?.has("session_id")).toBe(false);
  });

  it("resumes a stored Session with the same DPoP key", async () => {
    const store = new InspectableStore();
    const { mock, company } = await setup(store);
    await mock.agent({ store }).session(company, USER_ID);
    const resumed = await mock.agent({ store }).session(company, USER_ID);
    expect(resumed.sessionId).toBe("ses-1");
    expect(mock.callsTo(TOKEN_ENDPOINT)[1]?.form?.get("session_id")).toBe("ses-1");
    const response = await resumed.fetch(`${API}/orders`);
    expect(response.status).toBe(200);
  });

  it("rejects an empty userId", async () => {
    const { agent, company } = await setup();
    await expect(agent.session(company, "")).rejects.toThrow(/userId/);
  });

  it("returns one Session per User, so a second one cannot drop the Account Token", async () => {
    const { mock, agent, company, store } = await setup();
    const [a, b] = await Promise.all([
      agent.session(company, USER_ID),
      agent.session(company, USER_ID),
    ]);
    await signIn(mock, a);
    await b.renew();
    expect(b).toBe(a);
    expect(store.state()["accountToken"]).toBe(mock.issuedSecrets[0]);
  });
});

describe("Session renew", () => {
  it("shares one request between concurrent renews", async () => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    await Promise.all([session.renew(), session.renew(), session.fetch(`${API}/a`)]);
    expect(mock.callsTo(TOKEN_ENDPOINT)).toHaveLength(2);
  });

  it("retries once with the nonce the token endpoint asks for", async () => {
    const { mock, agent, company } = await setup();
    mock.tokenNonce = "once";
    await agent.session(company, USER_ID);
    expect(mock.callsTo(TOKEN_ENDPOINT)).toHaveLength(2);
  });

  it("gives up after one nonce retry", async () => {
    const { mock, agent, company } = await setup();
    mock.tokenNonce = "always";
    const error = await agent.session(company, USER_ID).catch((e: unknown) => e);
    expect(error).toMatchObject({ error: "use_dpop_nonce", status: 400 });
    expect(mock.callsTo(TOKEN_ENDPOINT)).toHaveLength(2);
  });

  it("starts a new Session once when the Company says it ended", async () => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    mock.endedSessions.add("ses-1");
    await session.renew();
    expect(session.sessionId).toBe("ses-2");
    const forms = mock.callsTo(TOKEN_ENDPOINT).map((call) => call.form?.get("session_id"));
    expect(forms).toEqual([null, "ses-1", null]);
  });

  it("starts a new Session once on account_mismatch", async () => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    mock.routes.set(TOKEN_ENDPOINT, () => {
      mock.routes.delete(TOKEN_ENDPOINT);
      return Response.json({ error: "account_mismatch" }, { status: 400 });
    });
    await session.renew();
    expect(session.sessionId).toBe("ses-2");
    const forms = mock.callsTo(TOKEN_ENDPOINT).map((call) => call.form?.get("session_id"));
    expect(forms).toEqual([null, "ses-1", null]);
  });

  it("refuses a token that is not DPoP-bound", async () => {
    const { mock, agent, company } = await setup();
    mock.routes.set(TOKEN_ENDPOINT, () =>
      Response.json({ access_token: "at-x", token_type: "Bearer", expires_in: 60 }),
    );
    await expect(agent.session(company, USER_ID)).rejects.toThrow(/DPoP/);
  });

  it("exposes Retry-After on 429", async () => {
    const { mock, agent, company } = await setup();
    mock.routes.set(
      TOKEN_ENDPOINT,
      () => new Response(null, { status: 429, headers: { "retry-after": "30" } }),
    );
    const error = await agent.session(company, USER_ID).catch((e: unknown) => e);
    expect(error).toMatchObject({ error: "rate_limited", status: 429, retryAfter: 30 });
  });
});

describe("Session.fetch", () => {
  it("sends the Session Token with a bound DPoP Proof", async () => {
    const { agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    const response = await session.fetch(`${API}/orders?limit=1`, { method: "post", body: "{}" });
    expect(await response.json()).toEqual({ ok: true, signedIn: false, path: "/orders" });
  });

  it.each([
    ["an http URL", "http://api.example.com/orders", /https/],
    ["an unlisted host", "https://example.org/orders", /not a host/],
    ["a lookalike host", "https://evilexample.com/orders", /not a host/],
    ["credentials in the URL", "https://user:pw@api.example.com/orders", /credentials/],
  ])("refuses %s without sending anything", async (_, url, message) => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    const before = mock.calls.length;
    await expect(session.fetch(url)).rejects.toThrow(message);
    expect(mock.calls).toHaveLength(before);
  });

  it("refuses a streaming body, which a retry could not resend", async () => {
    const { agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    const body = new ReadableStream() as unknown as string;
    await expect(session.fetch(`${API}/upload`, { method: "POST", body })).rejects.toThrow(
      /streaming/,
    );
  });

  it("retries once on a DPoP nonce challenge", async () => {
    const { mock, agent, company } = await setup();
    mock.apiNonce = "once";
    const session = await agent.session(company, USER_ID);
    expect((await session.fetch(`${API}/a`)).status).toBe(200);
    expect(mock.calls.filter((call) => call.url === `${API}/a`)).toHaveLength(2);
  });

  it("returns the second nonce challenge instead of looping", async () => {
    const { mock, agent, company } = await setup();
    mock.apiNonce = "always";
    const session = await agent.session(company, USER_ID);
    expect((await session.fetch(`${API}/a`)).status).toBe(401);
    expect(mock.calls.filter((call) => call.url === `${API}/a`)).toHaveLength(2);
  });

  it("renews once on invalid_token", async () => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    mock.invalidAccess.add("at-1");
    expect((await session.fetch(`${API}/a`)).status).toBe(200);
    expect(mock.callsTo(TOKEN_ENDPOINT)).toHaveLength(2);
  });

  it("returns redirects unfollowed", async () => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    mock.routes.set(
      `${API}/moved`,
      () => new Response(null, { status: 302, headers: { location: "https://example.org/" } }),
    );
    expect((await session.fetch(`${API}/moved`)).status).toBe(302);
    expect(mock.calls.at(-1)?.url).toBe(`${API}/moved`);
  });

  it("sends to a host that poppy.json lists as an API", async () => {
    const mock = await MockCompany.create();
    mock.poppy = { ...mock.poppy, apis: [{ type: "openapi", url: "https://api.example.net/o" }] };
    const company = await mock.agent().discover("example.com");
    const session = await mock.agent().session(company, USER_ID);
    await session.fetch("https://api.example.net/orders");
    expect(mock.calls.at(-1)?.url).toBe("https://api.example.net/orders");
    await expect(session.fetch("https://sub.api.example.net/orders")).rejects.toThrow(/not a host/);
  });
});

describe("Device Sign-In", () => {
  it("signs the Session in and keeps the Account Token in the store", async () => {
    const { mock, agent, company, store } = await setup();
    const session = await agent.session(company, USER_ID);
    const { pending, result } = await signIn(mock, session);
    expect(pending).toMatchObject({ userCode: "WDJB-MJHT", expiresIn: 600 });
    expect(result.scope).toBe("poppy:read poppy:write");
    expect(session.signedIn).toBe(true);
    expect(session.sessionId).toBe("ses-1");
    expect(store.state()["accountToken"]).toBe(mock.issuedSecrets[0]);
    const device = mock.callsTo(DEVICE_ENDPOINT)[0];
    expect(device?.form?.get("scope")).toBe("poppy:read poppy:write");
    expect((await (await session.fetch(`${API}/a`)).json()).signedIn).toBe(true);
  });

  it("is not overwritten by a signed-out renew that lands after it", async () => {
    const { mock, company, store } = await setup();
    let release = () => {};
    const held = new Promise<void>((resolve) => (release = resolve));
    let polled = () => {};
    const approved = new Promise<void>((resolve) => (polled = resolve));
    let holding = false;
    const { fetch } = mock;
    mock.fetch = async (input, init) => {
      const response = await fetch(input, init);
      const grantType = init?.body instanceof URLSearchParams && init.body.get("grant_type");
      if (holding && grantType === "urn:ietf:params:oauth:grant-type:jwt-bearer") await held;
      if (grantType === "urn:ietf:params:oauth:grant-type:device_code") polled();
      return response;
    };
    const session = await mock.agent({ store }).session(company, USER_ID);
    vi.useFakeTimers({ toFake: ["setTimeout"] });
    const done = (await session.startDeviceSignIn("poppy:read")).wait();
    holding = true;
    const renewing = session.renew();
    await vi.advanceTimersByTimeAsync(5_000);
    vi.useRealTimers();
    await approved;
    // Let the approved poll reach its completion step before the held renew lands.
    await new Promise((resolve) => setTimeout(resolve, 20));
    release();
    await Promise.all([renewing, done]);
    expect(session.signedIn).toBe(true);
    expect(store.state()["accountToken"]).toBe(mock.issuedSecrets[0]);
    expect((await (await session.fetch(`${API}/a`)).json()).signedIn).toBe(true);
  });

  it("returns a partial grant instead of failing", async () => {
    const { mock, agent, company } = await setup();
    mock.grantedScope = "poppy:read";
    const session = await agent.session(company, USER_ID);
    expect((await signIn(mock, session)).result.scope).toBe("poppy:read");
  });

  it("returns the requested scopes when the Company omits scope", async () => {
    const { mock, company, store } = await setup();
    omitFromGrant(mock, "urn:ietf:params:oauth:grant-type:device_code", ["scope"]);
    const session = await mock.agent({ store }).session(company, USER_ID);
    expect((await signIn(mock, session)).result.scope).toBe("poppy:read poppy:write");
    expect(session.scope).toBe("poppy:read poppy:write");
  });

  it("waits the interval, and 5 seconds more after slow_down", async () => {
    const { mock, agent, company } = await setup();
    mock.devicePolls = ["authorization_pending", "slow_down", "approve"];
    const session = await agent.session(company, USER_ID);
    vi.useFakeTimers({ toFake: ["setTimeout", "Date"] });
    const start = Date.now();
    const done = (await session.startDeviceSignIn("poppy:read")).wait();
    for (let poll = 0; poll < 3; poll++) {
      // Signing a proof is real async work: let each poll finish and schedule the next sleep first.
      await vi.waitFor(() => expect(vi.getTimerCount()).toBe(1));
      await vi.advanceTimersToNextTimerAsync();
    }
    await expect(done).resolves.toEqual({ scope: "poppy:read poppy:write" });
    const times = [
      start,
      ...mock
        .callsTo(TOKEN_ENDPOINT)
        .slice(1)
        .map((call) => call.at),
    ];
    // waitFor moves fake time in small steps too, so compare whole seconds between polls.
    const gaps = times.slice(1).map((time, i) => Math.floor((time - (times[i] ?? 0)) / 1000));
    expect(gaps).toEqual([5, 5, 10]);
  });

  it("rejects with access_denied", async () => {
    const { mock, agent, company } = await setup();
    mock.devicePolls = ["access_denied"];
    const session = await agent.session(company, USER_ID);
    vi.useFakeTimers({ toFake: ["setTimeout"] });
    const done = (await session.startDeviceSignIn("poppy:read")).wait();
    const assertion = expect(done).rejects.toMatchObject({ error: "access_denied" });
    await vi.advanceTimersByTimeAsync(5_000);
    await assertion;
    expect(session.signedIn).toBe(false);
  });

  it("stops when the signal aborts", async () => {
    const { mock, agent, company } = await setup();
    mock.devicePolls = ["authorization_pending"];
    const session = await agent.session(company, USER_ID);
    const controller = new AbortController();
    const done = (await session.startDeviceSignIn("poppy:read")).wait({
      signal: controller.signal,
    });
    controller.abort(new Error("cancelled"));
    await expect(done).rejects.toThrow("cancelled");
  });

  it("refuses scopes the Company does not offer, before any request", async () => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    await expect(session.startDeviceSignIn("openid poppy:read")).rejects.toMatchObject({
      error: "invalid_scope",
    });
    await expect(session.startDeviceSignIn("")).rejects.toMatchObject({ error: "invalid_scope" });
    expect(mock.callsTo(DEVICE_ENDPOINT)).toHaveLength(0);
  });

  it("refuses an http verification_uri", async () => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    mock.routes.set(DEVICE_ENDPOINT, () =>
      Response.json({
        device_code: "dc-secret-1",
        user_code: "WDJB-MJHT",
        verification_uri: "http://example.com/device",
        expires_in: 600,
      }),
    );
    await expect(session.startDeviceSignIn("poppy:read")).rejects.toThrow(/https/);
  });

  it("forgets the Session when the User signed in to a different account", async () => {
    const { mock, agent, company, store } = await setup();
    mock.devicePolls = ["account_mismatch"];
    const session = await agent.session(company, USER_ID);
    vi.useFakeTimers({ toFake: ["setTimeout"] });
    const done = (await session.startDeviceSignIn("poppy:read")).wait();
    const assertion = expect(done).rejects.toMatchObject({ error: "account_mismatch" });
    await vi.advanceTimersByTimeAsync(5_000);
    await assertion;
    expect(session.sessionId).toBeUndefined();
    expect(store.state()).not.toHaveProperty("sessionId");
    expect(session.signedIn).toBe(false);
  });
});

describe("signed-in renew and sign-out", () => {
  it("renews with the Account Token and the session_id", async () => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    await signIn(mock, session);
    await session.renew();
    const last = mock.callsTo(TOKEN_ENDPOINT).at(-1)?.form;
    expect(last?.get("grant_type")).toBe("refresh_token");
    expect(last?.get("refresh_token")).toBe(mock.issuedSecrets[0]);
    expect(last?.get("session_id")).toBe("ses-1");
    expect(session.signedIn).toBe(true);
  });

  it("keeps the previous scope when a refresh omits scope", async () => {
    const { mock, company, store } = await setup();
    omitFromGrant(mock, "refresh_token", ["scope"]);
    const session = await mock.agent({ store }).session(company, USER_ID);
    await signIn(mock, session);
    await session.renew();
    expect(grant(mock).at(-1)).toBe("refresh_token");
    expect(session.scope).toBe("poppy:read poppy:write");
  });

  it("is empty after a Session assertion that omits scope", async () => {
    const { mock, company, store } = await setup();
    omitFromGrant(mock, "urn:ietf:params:oauth:grant-type:device_code", ["refresh_token"]);
    omitFromGrant(mock, "urn:ietf:params:oauth:grant-type:jwt-bearer", ["scope"]);
    const session = await mock.agent({ store }).session(company, USER_ID);
    await signIn(mock, session);
    expect(session.scope).toBe("poppy:read poppy:write");
    await session.renew();
    expect(grant(mock).at(-1)).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    expect(session.scope).toBe("");
  });

  it("continues signed out when the Account Token is no longer valid", async () => {
    const { mock, agent, company, store } = await setup();
    const session = await agent.session(company, USER_ID);
    await signIn(mock, session);
    mock.revokedRefresh.add(mock.issuedSecrets[0] ?? "");
    await session.renew();
    expect(grant(mock).slice(-2)).toEqual([
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:jwt-bearer",
    ]);
    expect(session.signedIn).toBe(false);
    expect(session.scope).toBe("");
    expect(store.state()).not.toHaveProperty("accountToken");
  });

  it("revokes the Account Token on sign-out", async () => {
    const { mock, agent, company, store } = await setup();
    const session = await agent.session(company, USER_ID);
    await signIn(mock, session);
    await session.signOut();
    const revoke = mock.callsTo(REVOCATION_ENDPOINT)[0]?.form;
    expect(revoke?.get("token")).toBe(mock.issuedSecrets[0]);
    expect(revoke?.get("token_type_hint")).toBe("refresh_token");
    expect(session.signedIn).toBe(false);
    expect(store.state()).not.toHaveProperty("accountToken");
    expect((await (await session.fetch(`${API}/a`)).json()).signedIn).toBe(false);
  });

  it("does nothing on sign-out when signed out", async () => {
    const { mock, agent, company } = await setup();
    await (await agent.session(company, USER_ID)).signOut();
    expect(mock.callsTo(REVOCATION_ENDPOINT)).toHaveLength(0);
  });

  it("uses the new Account Token after the Company rotates it", async () => {
    const { mock, agent, company, store } = await setup();
    const session = await agent.session(company, USER_ID);
    await signIn(mock, session);
    mock.rotateRefresh = true;
    await session.renew();
    const rotated = mock.issuedSecrets[1];
    expect(store.state()["accountToken"]).toBe(rotated);
    await session.renew();
    expect(mock.callsTo(TOKEN_ENDPOINT).at(-1)?.form?.get("refresh_token")).toBe(rotated);
    expect(session.signedIn).toBe(true);
  });

  it("keeps the Account Token when revocation fails", async () => {
    const { mock, agent, company, store } = await setup();
    const session = await agent.session(company, USER_ID);
    await signIn(mock, session);
    mock.routes.set(REVOCATION_ENDPOINT, () => new Response(null, { status: 503 }));
    await expect(session.signOut()).rejects.toMatchObject({ status: 503 });
    expect(session.signedIn).toBe(true);
    expect(store.state()["accountToken"]).toBe(mock.issuedSecrets[0]);
  });

  it("signs out after a refresh in flight lands, not before", async () => {
    const { mock, company, store } = await setup();
    let release = () => {};
    const held = new Promise<void>((resolve) => (release = resolve));
    let refreshing = () => {};
    const refreshHeld = new Promise<void>((resolve) => (refreshing = resolve));
    const { fetch } = mock;
    mock.fetch = async (input, init) => {
      const response = await fetch(input, init);
      if (
        init?.body instanceof URLSearchParams &&
        init.body.get("grant_type") === "refresh_token"
      ) {
        refreshing();
        await held;
      }
      return response;
    };
    const session = await mock.agent({ store }).session(company, USER_ID);
    await signIn(mock, session);
    const renewing = session.renew();
    await refreshHeld;
    const signingOut = session.signOut();
    // Give a sign-out that does not wait for the refresh time to revoke first.
    await new Promise((resolve) => setTimeout(resolve, 20));
    release();
    await Promise.all([renewing, signingOut]);
    expect(session.signedIn).toBe(false);
    expect(store.state()).not.toHaveProperty("accountToken");
    expect(mock.callsTo(REVOCATION_ENDPOINT)).toHaveLength(1);
  });

  it("renews signed out when the renew starts during sign-out", async () => {
    const { mock, company, store } = await setup();
    let release = () => {};
    const held = new Promise<void>((resolve) => (release = resolve));
    let revoking = () => {};
    const revokeHeld = new Promise<void>((resolve) => (revoking = resolve));
    const { fetch } = mock;
    mock.fetch = async (input, init) => {
      if (String(input) === REVOCATION_ENDPOINT) {
        revoking();
        await held;
      }
      return fetch(input, init);
    };
    const session = await mock.agent({ store }).session(company, USER_ID);
    await signIn(mock, session);
    const signingOut = session.signOut();
    await revokeHeld;
    const renewing = session.renew();
    await new Promise((resolve) => setTimeout(resolve, 20));
    release();
    await Promise.all([signingOut, renewing]);
    expect(grant(mock).at(-1)).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    expect(session.signedIn).toBe(false);
    expect(store.state()).not.toHaveProperty("accountToken");
  });
});

describe("forget", () => {
  it("signs out, deletes the state, and stops old Session handles", async () => {
    const { mock, agent, company, store } = await setup();
    const session = await agent.session(company, USER_ID);
    await signIn(mock, session);
    await agent.forget(company, USER_ID);
    expect(mock.callsTo(REVOCATION_ENDPOINT)[0]?.form?.get("token")).toBe(mock.issuedSecrets[0]);
    expect(store.values.size).toBe(0);
    await expect(session.renew()).rejects.toBeInstanceOf(PoppyProtocolError);
    await expect(session.fetch(`${API}/a`)).rejects.toBeInstanceOf(PoppyProtocolError);
    expect(store.values.size).toBe(0);
  });

  it("deletes the state and stops old handles when revocation fails", async () => {
    const { mock, agent, company, store } = await setup();
    const session = await agent.session(company, USER_ID);
    await signIn(mock, session);
    mock.routes.set(REVOCATION_ENDPOINT, () => new Response(null, { status: 503 }));
    await agent.forget(company, USER_ID);
    expect(store.values.size).toBe(0);
    const tokenCalls = mock.callsTo(TOKEN_ENDPOINT).length;
    await expect(session.fetch(`${API}/a`)).rejects.toBeInstanceOf(PoppyProtocolError);
    await expect(session.renew()).rejects.toBeInstanceOf(PoppyProtocolError);
    expect(mock.callsTo(TOKEN_ENDPOINT)).toHaveLength(tokenCalls);
  });

  it("opens a Session requested during forget only after the state is deleted", async () => {
    const { mock, company, store } = await setup();
    let release = () => {};
    const held = new Promise<void>((resolve) => (release = resolve));
    let revoking = () => {};
    const revokeHeld = new Promise<void>((resolve) => (revoking = resolve));
    const { fetch } = mock;
    mock.fetch = async (input, init) => {
      if (String(input) === REVOCATION_ENDPOINT) {
        revoking();
        await held;
      }
      return fetch(input, init);
    };
    const agent = mock.agent({ store });
    await signIn(mock, await agent.session(company, USER_ID));
    const forgetting = agent.forget(company, USER_ID);
    await revokeHeld;
    const opening = agent.session(company, USER_ID);
    await new Promise((resolve) => setTimeout(resolve, 20));
    release();
    await forgetting;
    const next = await opening;
    expect(store.values.size).toBe(1);
    expect(store.state()).not.toHaveProperty("accountToken");
    expect((await (await next.fetch(`${API}/a`)).json()).signedIn).toBe(false);
  });

  it("deletes stored state it cannot read", async () => {
    const { agent, company, store } = await setup();
    await store.set(`poppy:${CLIENT_ID}:${ISSUER}:${USER_ID}`, "not json");
    await agent.forget(company, USER_ID);
    expect(store.values.size).toBe(0);
  });

  it("does not write the state back from a renew queued behind the sign-out", async () => {
    const { mock, company, store } = await setup();
    let release = () => {};
    const held = new Promise<void>((resolve) => (release = resolve));
    let revoking = () => {};
    const revokeHeld = new Promise<void>((resolve) => (revoking = resolve));
    const { fetch } = mock;
    mock.fetch = async (input, init) => {
      if (String(input) === REVOCATION_ENDPOINT) {
        revoking();
        await held;
      }
      return fetch(input, init);
    };
    const agent = mock.agent({ store });
    const session = await agent.session(company, USER_ID);
    await signIn(mock, session);
    const forgetting = agent.forget(company, USER_ID);
    await revokeHeld;
    const renewing = session.renew().catch((error: unknown) => error);
    release();
    await forgetting;
    expect(await renewing).toBeInstanceOf(PoppyProtocolError);
    expect(store.values.size).toBe(0);
  });

  it("starts a new signed-out Session afterwards", async () => {
    const { mock, agent, company, store } = await setup();
    const session = await agent.session(company, USER_ID);
    await signIn(mock, session);
    await agent.forget(company, USER_ID);
    const next = await agent.session(company, USER_ID);
    expect(next).not.toBe(session);
    expect(next.signedIn).toBe(false);
    expect(store.state()).not.toHaveProperty("accountToken");
  });

  it("revokes a stored Account Token without an open Session", async () => {
    const { mock, agent, company, store } = await setup();
    await signIn(mock, await agent.session(company, USER_ID));
    await mock.agent({ store }).forget(company, USER_ID);
    expect(mock.callsTo(REVOCATION_ENDPOINT)).toHaveLength(1);
    expect(store.values.size).toBe(0);
  });

  it("opens no Session when there is no Account Token to revoke", async () => {
    const { mock, agent, company, store } = await setup();
    await agent.session(company, USER_ID);
    const tokenCalls = mock.callsTo(TOKEN_ENDPOINT).length;
    await mock.agent({ store }).forget(company, USER_ID);
    expect(mock.callsTo(TOKEN_ENDPOINT)).toHaveLength(tokenCalls);
    expect(store.values.size).toBe(0);
  });
});

describe("secrets", () => {
  it("never appear in errors or inspected objects", async () => {
    const { mock, agent, company } = await setup();
    const session = await agent.session(company, USER_ID);
    const { pending } = await signIn(mock, session);
    mock.routes.set(TOKEN_ENDPOINT, () =>
      Response.json({ error: "invalid_grant", error_description: "nope" }, { status: 400 }),
    );
    const error = await session.renew().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(PoppyError);

    const assertions = mock.calls.flatMap((call) =>
      ["assertion", "client_assertion"].map((key) => call.form?.get(key)).filter(Boolean),
    ) as string[];
    const secrets = [...mock.issuedSecrets, "dc-secret-1", ...assertions];
    const rendered = [
      String(error),
      JSON.stringify(error),
      inspect(error, { depth: 10 }),
      inspect(session, { depth: 10, showHidden: true }),
      inspect(pending, { depth: 10, showHidden: true }),
      JSON.stringify(session),
      JSON.stringify(pending),
    ].join("\n");
    for (const secret of secrets) expect(rendered).not.toContain(secret);
  });
});
