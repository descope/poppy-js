import { API, type ConformanceCompany, MCP, PAGE, type Scenario } from "./company.ts";

/**
 * One thing the agent under test does. Agents in any language carry out steps in order, and keep going
 * when one fails: a refused discovery should make later steps fail, never crash the agent.
 */
export type Step =
  /** Discover the Company at `website`, and get ready to act for a User there. */
  | { action: "discover"; website: string }
  /** Send a request through the agent's Session, signed in if it is. */
  | { action: "request"; url: string; method?: string; body?: string }
  /**
   * Sign in with Direct Sign-In. Act as the User's browser: GET the authorization URL without following
   * redirects, and complete sign-in with the `Location` it returns.
   */
  | { action: "sign_in"; scopes: string[] }
  /** Sign out of the account. */
  | { action: "sign_out" }
  /** Start a conversation with the Company Agent with `text`, then send one more message. */
  | { action: "converse"; text: string }
  /**
   * Send a request the Company refuses with `approval_required`, approve the operation as if the User
   * said yes, and send it again with the approval.
   */
  | { action: "request_with_approval"; url: string; method: string; body: string }
  /**
   * Read the Company's task coverage for this Session: its excluded tasks, its skills and where to send
   * feedback. On 0.4 that is a GET to `tasks.endpoint` with the Session header and no access token.
   */
  | { action: "task_coverage" }
  /** Report a task the User couldn't do, to the feedback endpoint the Company names (spec 9.3). */
  | { action: "report_task"; task: string; description: string }
  /** Join the agent's own browser to the Session (spec section 6). Never the User's own browser. */
  | { action: "join_browser" }
  /** Fetch a page of the Company's website with the agent's own HTTP client, not a browser (5.2). */
  | { action: "fetch_page"; url: string }
  /** Ask for a person at the Company, then withdraw the request (spec 8.9). */
  | { action: "handoff_then_cancel"; text: string }
  /** Fetch one of the Company's skills and check it against its digest (spec 9.4). */
  | { action: "read_skill"; name: string }
  /** Sign in with Device Sign-In: show the User the link, then poll until it is approved (4.3). */
  | { action: "sign_in_device"; scopes: string[] }
  /** Open a new Session, as a later run of the same agent for the same User would (spec 5.2). */
  | { action: "new_session" }
  /** Send a request the Company rate-limits, wait out `Retry-After`, and send it again (5.6). */
  | { action: "request_rate_limited"; url: string }
  /** Talk to the Company Agent, and approve the operation it asks for in a message (8.4). */
  | { action: "converse_with_approval"; text: string };

/** Which parts of the protocol a scenario exercises. */
export type Suite = "core" | "oauth" | "interactions" | "versions";

/** A scenario: how the Company behaves, what the agent does, and the checks it decides. */
export interface ScenarioDefinition {
  name: string;
  description: string;
  suite: Suite;
  company: Scenario;
  steps: Step[];
  /** Checks this scenario decides, beyond those the Company records as the agent talks to it. */
  evaluate?: (company: ConformanceCompany) => void;
}

const WEBSITE = "https://www.shop.test";
const discover: Step = { action: "discover", website: WEBSITE };
const orders: Step = { action: "request", url: `${API}/orders` };

/** A discovery the agent must refuse: after it, nothing may reach the Company's APIs. */
function refusal(
  name: string,
  check: string,
  company: Scenario,
  description: string,
): ScenarioDefinition {
  return {
    name,
    description,
    suite: "core",
    company,
    steps: [discover, orders],
    evaluate(c) {
      if (c.resourceRequests() > 0) c.fail(check, "used a Company it should have refused");
      else c.pass(check);
    },
  };
}

export const SCENARIOS: readonly ScenarioDefinition[] = [
  refusal(
    "discovery-well-known-path",
    "discovery.well-known-path",
    { redirectToUpload: true },
    "www redirects poppy.json to an uploaded file.",
  ),
  refusal(
    "discovery-domain",
    "discovery.domain",
    { wrongDomain: true },
    "organization.domain names another host.",
  ),
  refusal(
    "discovery-version",
    "discovery.version",
    { futureVersion: true },
    "poppy.json declares a protocol version this draft doesn't define.",
  ),
  refusal(
    "discovery-issuer-link",
    "discovery.issuer-link",
    { issuerUnlinked: true },
    "The issuer's protected_resources leaves out the domain.",
  ),
  refusal(
    "discovery-no-fallback",
    "discovery.no-fallback",
    { resourceMetadataFails: true },
    "The domain's protected resource metadata fails with HTTP 500.",
  ),
  {
    name: "discovery-private-address",
    description: "poppy.json lists an API on a loopback address.",
    suite: "core",
    company: { privateApi: true },
    steps: [discover, { action: "request", url: "https://127.0.0.1/orders" }],
    evaluate(c) {
      if (c.offsite().some((r) => r.url.hostname === "127.0.0.1"))
        c.fail("discovery.private-address", "connected to a loopback address the Company named");
      else c.pass("discovery.private-address");
    },
  },
  {
    name: "signed-out",
    description: "Signed-out requests, a redirecting API, and a conversation.",
    suite: "interactions",
    company: {},
    steps: [
      discover,
      orders,
      { action: "request", url: `${API}/redirect` },
      { action: "converse", text: "Do you have the jacket in medium?" },
    ],
    evaluate(c) {
      if (c.offsite().some((r) => r.headers.has("poppy-session") || r.headers.has("authorization")))
        c.fail("http.redirects", "followed a redirect with credentials");
      else if (c.requests.some((r) => r.url.pathname === "/api/redirect")) c.pass("http.redirects");
    },
  },
  {
    name: "session-ended-once",
    description: "The API answers session_ended to the first request of each Session.",
    suite: "core",
    company: { sessionEnded: "once" },
    steps: [discover, orders],
    evaluate: (c) => c.checkSessionErrors(`${API}/orders`),
  },
  {
    name: "session-ended-always",
    description: "The API answers session_ended to every request.",
    suite: "core",
    company: { sessionEnded: "always" },
    steps: [discover, orders],
    evaluate: (c) => c.checkSessionErrors(`${API}/orders`),
  },
  {
    name: "invalid-session",
    description: "The API answers invalid_session to every request.",
    suite: "core",
    company: { invalidSession: true },
    steps: [discover, orders],
    evaluate: (c) => c.checkSessionErrors(`${API}/orders`),
  },
  {
    name: "unlisted-url",
    description:
      "Requests to a page on the Company's domain and a path on the API's host that no API describes.",
    suite: "core",
    company: {},
    steps: [
      discover,
      { action: "request", url: "https://shop.test/account" },
      { action: "request", url: "https://shop.test/admin/orders" },
      orders,
    ],
    evaluate(c) {
      const unlisted = c.requests.filter(
        (r) =>
          (r.url.pathname === "/account" || r.url.pathname.startsWith("/admin/")) &&
          r.headers.has("poppy-session"),
      );
      if (unlisted.length > 0)
        c.fail(
          "session.destinations",
          `sent the Session header to ${unlisted.map((r) => r.url.pathname).join(", ")}`,
        );
      else if (c.resourceRequests() > 0) c.pass("session.destinations");
    },
  },
  {
    name: "sign-in",
    description:
      "Direct Sign-In, a refresh with rotation, an MCP resource token, an operation, and sign-out.",
    suite: "oauth",
    company: { rotate: true, expireTokensOnce: true },
    steps: [
      discover,
      { action: "sign_in", scopes: ["orders:read", "orders:write"] },
      orders,
      orders,
      {
        action: "request",
        url: MCP,
        method: "POST",
        body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
      },
      {
        action: "request_with_approval",
        url: `${API}/exchanges`,
        method: "POST",
        body: '{"item":"itm_1"}',
      },
      { action: "sign_out" },
    ],
  },
  {
    name: "sign-in-wrong-iss",
    description: "The authorization response names another issuer in iss.",
    suite: "oauth",
    company: { wrongIss: true },
    steps: [discover, { action: "sign_in", scopes: ["orders:read"] }, orders],
    evaluate(c) {
      if (!c.results().has("oauth.iss-check") && c.authorizeRequests() > 0)
        c.pass("oauth.iss-check");
    },
  },
  {
    name: "sign-in-extra-scope",
    description: "Sign-in grants a scope the agent didn't ask for.",
    suite: "oauth",
    company: { extraScope: true },
    steps: [discover, { action: "sign_in", scopes: ["orders:read"] }, orders],
    evaluate(c) {
      if (!c.results().has("oauth.extra-scopes") && c.authorizeRequests() > 0)
        c.pass("oauth.extra-scopes");
    },
  },
  {
    name: "sign-in-dpop",
    description: "The issuer advertises DPoP and binds tokens to the proof's key.",
    suite: "oauth",
    company: { dpop: true },
    steps: [discover, { action: "sign_in", scopes: ["orders:read"] }, orders],
  },

  // 0.4. These run beside the 0.3 scenarios above, since a Company serves one version while an agent
  // meets many, and both versions are published and frozen.
  {
    name: "v04-signed-out",
    description:
      "0.4: signed-out requests, task coverage per Session, feedback, and a conversation with request IDs.",
    suite: "interactions",
    company: { version: "0.4" },
    steps: [
      discover,
      { action: "task_coverage" },
      orders,
      { action: "converse", text: "Do you have the jacket in medium?" },
      {
        action: "report_task",
        task: "Pay with a gift card",
        description: "No API or conversation offered a way to use a gift card.",
      },
    ],
  },
  {
    name: "v04-sign-in",
    description: "0.4: Direct Sign-In, an MCP resource token, an operation, and sign-out.",
    suite: "oauth",
    company: { version: "0.4", rotate: true, expireTokensOnce: true },
    steps: [
      discover,
      { action: "sign_in", scopes: ["orders:read", "orders:write"] },
      { action: "task_coverage" },
      orders,
      {
        action: "request",
        url: MCP,
        method: "POST",
        body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
      },
      {
        action: "request_with_approval",
        url: `${API}/exchanges`,
        method: "POST",
        body: '{"item":"itm_1"}',
      },
      { action: "sign_out" },
    ],
  },
  {
    name: "v04-chosen-over-0.3",
    description: "poppy.json is the 0.3 document and supported_versions links the 0.4 one.",
    suite: "versions",
    company: { version: "0.4", linkPreferredVersion: true },
    steps: [discover, orders],
    evaluate: (c) => c.checkVersionSelection(),
  },
  {
    name: "v04-linked-on-another-host",
    description: "supported_versions links the 0.4 document to a file on another host.",
    suite: "versions",
    company: { version: "0.4", linkedVersionOffsite: true },
    steps: [discover, orders],
    evaluate: (c) => c.checkVersionSelection(),
  },
  {
    name: "v04-linked-version-mismatch",
    description: "The document listed under 0.4 declares protocol_version 0.3.",
    suite: "versions",
    company: { version: "0.4", linkedVersionMismatch: true },
    steps: [discover, orders],
    evaluate: (c) => c.checkVersionSelection(),
  },
  {
    name: "v04-conversation-state",
    description: "0.4: the Company Agent keeps working, and a handoff is asked for then withdrawn.",
    suite: "interactions",
    company: { version: "0.4", slowAgent: true },
    steps: [discover, { action: "handoff_then_cancel", text: "I need a person." }],
  },
  {
    name: "v04-version-mismatch",
    description: "0.4: the conversation started in versions the Company no longer continues.",
    suite: "versions",
    company: { version: "0.4", versionMismatch: true },
    steps: [discover, { action: "converse", text: "Still there?" }],
    evaluate: (c) => c.checkVersionMismatch(),
  },
  {
    name: "v04-browser-join",
    description: "0.4: a signed-in browser join, which needs poppy:browser-sign-in.",
    suite: "interactions",
    company: { version: "0.4" },
    steps: [discover, { action: "sign_in", scopes: ["orders:read"] }, { action: "join_browser" }],
  },
  {
    name: "v04-website-pages",
    description: "0.4: a website page fetched with the agent's own HTTP client, signed in.",
    suite: "interactions",
    company: { version: "0.4" },
    steps: [
      discover,
      { action: "sign_in", scopes: ["orders:read"] },
      { action: "fetch_page", url: PAGE },
    ],
  },
  {
    name: "v04-page-refuses-session",
    description: "0.4: a website page refuses the Session header once.",
    suite: "interactions",
    company: { version: "0.4", pageRejectsSession: true },
    steps: [discover, { action: "fetch_page", url: PAGE }],
  },
  {
    name: "skills-and-feedback",
    description: "A skill fetched and checked against its digest, and a feedback report.",
    suite: "interactions",
    company: {},
    steps: [
      discover,
      { action: "read_skill", name: "returns" },
      {
        action: "report_task",
        task: "Pay with a gift card",
        description: "No API or conversation offered a way to use a gift card.",
      },
    ],
  },
  {
    name: "browser-join-0.3",
    description: "0.3: a browser join, which needs no scope of its own.",
    suite: "interactions",
    company: {},
    steps: [discover, { action: "join_browser" }],
  },
  {
    name: "device-sign-in",
    description: "Device Sign-In: the User approves on the Company's own page.",
    suite: "oauth",
    company: {},
    steps: [discover, { action: "sign_in_device", scopes: ["orders:read"] }, orders],
  },
  {
    name: "v04-device-sign-in-offsite-link",
    description:
      "0.4: the Device Sign-In link is on a protected_resources host, which 0.4 no longer allows.",
    suite: "oauth",
    company: { version: "0.4", deviceLinkOffsite: true },
    steps: [discover, { action: "sign_in_device", scopes: ["orders:read"] }],
    evaluate: (c) => c.checkDeviceLink(),
  },
  {
    name: "rate-limited",
    description: "The API answers 429 with Retry-After before it answers the request.",
    suite: "core",
    company: { rateLimitSeconds: 1 },
    steps: [discover, { action: "request_rate_limited", url: `${API}/orders` }],
  },
  {
    name: "v04-task-coverage-per-session",
    description:
      "0.4: a second Session asks for task coverage again rather than reusing the first's.",
    suite: "interactions",
    company: { version: "0.4" },
    steps: [
      discover,
      { action: "task_coverage" },
      { action: "new_session" },
      { action: "task_coverage" },
    ],
  },
  {
    name: "conversation-approval",
    description:
      "The Company Agent asks for approval in a message, and the agent answers with one.",
    suite: "interactions",
    company: { operationInConversation: true },
    steps: [discover, { action: "converse_with_approval", text: "Exchange the jacket, please." }],
  },
  {
    name: "v04-conversation-approval",
    description: "0.4: the same, where the request itself declares the extension it uses.",
    suite: "interactions",
    company: { version: "0.4", operationInConversation: true },
    steps: [discover, { action: "converse_with_approval", text: "Exchange the jacket, please." }],
  },
  {
    name: "v04-version-unsupported",
    description: "Every request with the Session header is refused with version_unsupported.",
    suite: "versions",
    company: { version: "0.4", versionUnsupported: true },
    steps: [discover, orders],
    evaluate: (c) => c.checkVersionErrors(),
  },
];

export function scenarioByName(name: string): ScenarioDefinition {
  const scenario = SCENARIOS.find((candidate) => candidate.name === name);
  if (scenario === undefined) throw new Error(`unknown scenario ${name}`);
  return scenario;
}
