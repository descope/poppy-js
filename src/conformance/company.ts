import { decodeJwt, sha256, thumbprint } from "../jose.ts";

/**
 * A strict Company for testing Personal Agents. It serves discovery at 0.3 or 0.4, an OAuth issuer, an
 * OpenAPI API, an MCP server and conversations, as a `fetch` the agent under test sends everything
 * through. It verifies every request against the rules the spec sets for Personal Agents, and records
 * which checks passed and which failed.
 *
 * A scenario's `version` says which protocol version the Company serves, and the Company then holds the
 * agent to that version's rules: 0.4 wants `Poppy-Version` on every request with the Session header,
 * task coverage from `tasks.endpoint`, and a request id on every conversation POST.
 */
export const ORIGIN = "https://shop.test";
export const ISSUER = ORIGIN;
export const API = `${ORIGIN}/api`;
export const MCP = "https://mcp.shop.test/mcp";
export const CONVERSATIONS = `${ORIGIN}/poppy/conversations`;
/** Where a 0.4 Company serves a Session's excluded tasks, skills and feedback endpoint (spec 9). */
export const TASKS = `${ORIGIN}/poppy/tasks`;
export const FEEDBACK = `${ORIGIN}/poppy/feedback`;
/** Where the agent's own browser joins a Session (spec section 6). */
export const BROWSER_SESSION = `${ORIGIN}/poppy/browser-session`;
/** A page of the Company's website, which 0.4 has an agent fetch with the Session header (5.2). */
export const PAGE = `${ORIGIN}/help/returns`;
/** The one skill the Company publishes, and the bytes its digest covers (spec 9.4). */
export const SKILL_URL = `${ORIGIN}/skills/returns/SKILL.md`;
export const SKILL_BODY = "# Returns\n\nAsk the Company Agent, then call the exchanges API.\n";
/** The scope a signed-in browser join needs, from 0.4 (spec 4.7, section 6). */
const BROWSER_SIGN_IN = "poppy:browser-sign-in";
/** Where this Company serves the document for the version it doesn't prefer (spec 3.4). */
const OTHER_VERSION_DOC = `${ORIGIN}/poppy/other-version.json`;
const TOKEN = `${ORIGIN}/oauth/token`;
const REVOKE = `${ORIGIN}/oauth/revoke`;
const AUTHORIZE = `${ORIGIN}/oauth/authorize`;
const OAUTH_ENDPOINTS = [TOKEN, REVOKE, `${ORIGIN}/oauth/device`];
const ID = /^[A-Za-z0-9_-]{1,256}$/;
/** The device code this Company issues; an agent that shows a bad link must never poll with it. */
const DEVICE_CODE = "dc_conformance";
/** Another domain on the same issuer, which 0.4 no longer accepts a sign-in link on (spec 4.3). */
const SIBLING = "https://shop.example";
/** The tasks this Company says it doesn't offer, in both versions' documents (spec 9.1). */
const EXCLUDED_TASKS = ["Send a wire transfer"];

/** Behaviors a scenario switches on, to see how the agent reacts. */
export interface Scenario {
  /** The protocol version the Company serves and holds the agent to. Defaults to 0.3. */
  version?: "0.3" | "0.4";
  /**
   * poppy.json is the document for the other version, and `supported_versions` links to `version`'s
   * document (spec 3.4). The agent has to follow the link when `version` is the newer of the two.
   */
  linkPreferredVersion?: boolean;
  /** `supported_versions` links 0.4 to a document on another host, which the agent must not use. */
  linkedVersionOffsite?: boolean;
  /** The linked document declares a version other than the one it is listed under, so it's unusable. */
  linkedVersionMismatch?: boolean;
  /** Every request with the Session header is refused with version_unsupported. */
  versionUnsupported?: boolean;
  /** The conversation refuses everything with version_mismatch, as one started elsewhere would. */
  versionMismatch?: boolean;
  /** The Company Agent keeps working over the first read of a conversation, then stops. */
  slowAgent?: boolean;
  /** A website page refuses the Session header once, so the agent asks again without it. */
  pageRejectsSession?: boolean;
  /** www.shop.test redirects poppy.json to an uploaded file. */
  redirectToUpload?: boolean;
  /** organization.domain names another host. */
  wrongDomain?: boolean;
  /** poppy.json declares a protocol version this draft doesn't define. */
  futureVersion?: boolean;
  /** The issuer's protected_resources leaves out the domain. */
  issuerUnlinked?: boolean;
  /** The domain's protected resource metadata fails with HTTP 500. */
  resourceMetadataFails?: boolean;
  /** poppy.json lists an API on a loopback address. */
  privateApi?: boolean;
  /** The API answers session_ended to the first request of each Session, or to every request. */
  sessionEnded?: "once" | "always";
  /** The API answers invalid_session to every request. */
  invalidSession?: boolean;
  /** Every refresh returns a new refresh token. */
  rotate?: boolean;
  /** Sign-in grants a scope the agent didn't ask for. */
  extraScope?: boolean;
  /** The issuer advertises DPoP and binds tokens to the proof's key. */
  dpop?: boolean;
  /** Access tokens are rejected once, with invalid_token, to make the agent refresh. */
  expireTokensOnce?: boolean;
  /** The authorization response names another issuer in iss. */
  wrongIss?: boolean;
  /** Device Sign-In answers with a verification link on a host the Company doesn't control. */
  deviceLinkOffsite?: boolean;
  /** The Company Agent asks for approval in a message, so a reply carries extension content. */
  operationInConversation?: boolean;
  /** The API rate-limits the first request, with Retry-After, before answering. */
  rateLimitSeconds?: number;
}

interface Recorded {
  method: string;
  url: URL;
  headers: Headers;
  body: string;
  /** When the Company saw it, which the rate-limit check measures against (spec 5.6). */
  at: number;
}

interface Issued {
  scope: string[];
  resource: string | undefined;
  revoked: boolean;
  jkt: string | undefined;
}

type Jwk = JsonWebKey & { kid?: string };

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function html(): Response {
  return new Response("<html>ok</html>", {
    status: 200,
    headers: { "content-type": "text/html" },
  });
}

async function verifyJws(jwt: string, jwk: Jwk, alg: unknown): Promise<boolean> {
  const [h, p, s] = jwt.split(".");
  if (h === undefined || p === undefined || s === undefined) return false;
  const data = new TextEncoder().encode(`${h}.${p}`);
  const signature = Buffer.from(s, "base64url");
  try {
    if (alg === "ES256" && jwk.kty === "EC") {
      const key = await crypto.subtle.importKey(
        "jwk",
        { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y } as JsonWebKey,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, data);
    }
    if (alg === "PS384" && jwk.kty === "RSA") {
      const key = await crypto.subtle.importKey(
        "jwk",
        { kty: "RSA", n: jwk.n, e: jwk.e } as JsonWebKey,
        { name: "RSA-PSS", hash: "SHA-384" },
        false,
        ["verify"],
      );
      return crypto.subtle.verify({ name: "RSA-PSS", saltLength: 48 }, key, signature, data);
    }
  } catch {
    return false;
  }
  return false;
}

function safeDecode(jwt: string) {
  try {
    return decodeJwt(jwt);
  } catch {
    return undefined;
  }
}

const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k"];
const DELEGATION_CLAIMS = new Set(["iss", "cnf", "iat", "exp", "jti"]);

export class ConformanceCompany {
  readonly scenario: Scenario;
  readonly requests: Recorded[] = [];
  readonly #passed = new Set<string>();
  readonly #failed = new Map<string, string[]>();
  readonly #agentFetch: typeof fetch;
  #clientId: string | undefined;
  #keys: Promise<Jwk[]> | undefined;
  #redirectUris: string[] = [];
  readonly #assertionJtis = new Set<string>();
  readonly #sessionJtis = new Set<string>();
  readonly #kidToSub = new Map<string, string>();
  readonly #sidIds = new Map<string, string>();
  readonly #endedSids = new Set<string>();
  readonly #sidVersions = new Map<string, string>();
  #browserCode: string | undefined;
  #signInRefused = false;
  #codeIssued = false;
  #codeAuthorized = false;
  #pageRefused = false;
  #handoff: "none" | "pending" = "none";
  #reads = 0;
  #mismatches = 0;
  readonly #rateLimited = new Map<string, number>();
  readonly #taskSids = new Set<string>();
  #sessionErrors = 0;
  #versionErrors = 0;
  readonly #codes = new Map<string, { challenge: string; scope: string[]; redirectUri: string }>();
  readonly #access = new Map<string, Issued>();
  readonly #refresh = new Map<string, Issued>();
  readonly #retiredRefresh = new Set<string>();
  readonly #rejectedTokens = new Set<string>();
  #tokenExpired = false;
  #counter = 0;
  #resourceRequests = 0;
  #authorizeRequests = 0;
  /** The last request refused with approval_required, to compare the retry against. */
  #refusedOperation: { method: string; url: string; body: string } | undefined;
  readonly #conversations = new Map<string, { events: Record<string, unknown>[] }>();
  readonly #messageIds = new Set<string>();

  constructor(scenario: Scenario = {}, options: { agentFetch?: typeof fetch } = {}) {
    this.scenario = scenario;
    this.#agentFetch = options.agentFetch ?? fetch;
  }

  pass(id: string): void {
    this.#passed.add(id);
  }

  fail(id: string, message: string): void {
    const list = this.#failed.get(id) ?? [];
    if (!list.includes(message)) list.push(message);
    this.#failed.set(id, list);
  }

  /** Withdraws a check, such as one that tested something other than the agent. */
  skip(id: string): void {
    this.#passed.delete(id);
    this.#failed.delete(id);
  }

  /** Checks this Company exercised, with the failures found for each. */
  results(): Map<string, string[]> {
    const results = new Map<string, string[]>();
    for (const id of this.#passed) results.set(id, []);
    for (const [id, messages] of this.#failed) results.set(id, messages);
    return results;
  }

  /** Requests whose URL is outside the Company, such as a redirect target or a private address. */
  /** How many requests reached an API, MCP server or conversation endpoint. */
  resourceRequests(): number {
    return this.#resourceRequests;
  }

  /** How many times the agent's "browser" opened the authorization endpoint. */
  authorizeRequests(): number {
    return this.#authorizeRequests;
  }

  offsite(): Recorded[] {
    return this.requests.filter(
      (r) => r.url.hostname !== "shop.test" && r.url.hostname !== "mcp.shop.test",
    );
  }

  readonly fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    const body =
      init.body === undefined || init.body === null
        ? ""
        : init.body instanceof URLSearchParams
          ? init.body.toString()
          : String(init.body);
    const recorded = { method, url, headers, body, at: Date.now() };
    this.requests.push(recorded);
    this.#checkUrl(recorded);
    if (
      url.hostname !== "shop.test" &&
      url.hostname !== "mcp.shop.test" &&
      url.hostname !== "www.shop.test"
    ) {
      if (headers.has("poppy-session") || headers.has("authorization"))
        this.fail("http.redirects", `sent credentials to ${url.origin}`);
      return json(404, { error: "not_found" });
    }
    return this.#route(recorded);
  }) as typeof fetch;

  #checkUrl({ url }: Recorded): void {
    const tokens = [...this.#access.keys(), ...this.#refresh.keys()];
    const text = url.href;
    if (
      url.searchParams.has("access_token") ||
      tokens.some((token) => text.includes(token)) ||
      /eyJ[\w-]+\.eyJ/.test(text)
    )
      this.fail("session.no-secrets-in-url", `a URL carried a credential: ${url.pathname}`);
    else this.pass("session.no-secrets-in-url");
  }

  // ---------- Discovery ----------

  /** The version this Company serves, which its documents and its checks follow (spec 3.4). */
  get version(): "0.3" | "0.4" {
    return this.scenario.version ?? "0.3";
  }

  /** The version it serves at the other document, when the scenario has two (spec 3.4). */
  get #otherVersion(): "0.3" | "0.4" {
    return this.version === "0.3" ? "0.4" : "0.3";
  }

  /** Whether the agent should end up on `version` rather than on the other document's version. */
  get #servesTwoVersions(): boolean {
    return (
      this.scenario.linkPreferredVersion === true ||
      this.scenario.linkedVersionOffsite === true ||
      this.scenario.linkedVersionMismatch === true
    );
  }

  /** A document for one version, without the `supported_versions` that only poppy.json carries. */
  #document(version: "0.3" | "0.4"): Record<string, unknown> {
    const taskCoverage =
      version === "0.3"
        ? {
            feedback: { endpoint: FEEDBACK },
            excluded_tasks: { url: `${ORIGIN}/poppy/excluded-tasks.json` },
            skill_index: this.skillIndex(),
          }
        : { tasks: { endpoint: TASKS } };
    return {
      protocol_version: this.scenario.futureVersion ? "9.9" : version,
      organization: {
        name: "Conformance Shop",
        domain: this.scenario.wrongDomain ? "other.test" : "shop.test",
      },
      auth: {
        scopes: {
          "orders:read": "See your orders",
          "orders:write": "Change your orders",
          ...(version === "0.3"
            ? {}
            : { [BROWSER_SIGN_IN]: "Use the website signed in, with the access you approve" }),
        },
        scope_hints: { "orders:read": { changes: "none", personal_data: true } },
      },
      web: { browser_session_endpoint: BROWSER_SESSION },
      agent: { protocols: [{ type: "poppy", endpoint: CONVERSATIONS }] },
      apis: [
        { type: "openapi", url: `${ORIGIN}/openapi.json`, description: "Orders" },
        { type: "mcp", url: MCP, description: "Search" },
        ...(this.scenario.privateApi
          ? [{ type: "openapi", url: "https://127.0.0.1/openapi.json" }]
          : []),
      ],
      ...taskCoverage,
      // 0.4 lists an entry per major version; 0.3 lists one entry (spec 3.3).
      extensions: {
        operations: version === "0.3" ? { version: "2" } : [{ version: "2" }],
      },
    };
  }

  /** The Agent Skills index this Company publishes, with the digest of the bytes it serves (9.4). */
  skillIndex(): Record<string, unknown> {
    return {
      $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
      skills: [
        {
          name: "returns",
          description: "How to return an item with this Company.",
          type: "skill-md",
          url: SKILL_URL,
          digest: "sha256:f6d76ac5292b338b8a3bb4d4dbd7ca660c3f43068a15ad5e5c2de4d950ed916f",
        },
      ],
    };
  }

  /** What `${ORIGIN}/.well-known/poppy.json` serves. */
  poppyJson(): Record<string, unknown> {
    if (!this.#servesTwoVersions) return this.#document(this.version);
    // poppy.json is the other version's document, and links to the one the agent should choose.
    const link = this.scenario.linkedVersionOffsite
      ? "https://other.test/poppy/0.4.json"
      : OTHER_VERSION_DOC;
    return {
      ...this.#document(this.#otherVersion),
      supported_versions: { [this.version]: link },
    };
  }

  /** The linked document, which carries the version it was listed under and no links of its own. */
  #linkedDocument(): Record<string, unknown> {
    const document = this.#document(this.version);
    if (this.scenario.linkedVersionMismatch) document["protocol_version"] = this.#otherVersion;
    return document;
  }

  #metadata(): Record<string, unknown> {
    return {
      issuer: ISSUER,
      token_endpoint: TOKEN,
      revocation_endpoint: REVOKE,
      authorization_endpoint: AUTHORIZE,
      // Required once grant_types_supported names the device grant (spec 3.2).
      device_authorization_endpoint: `${ORIGIN}/oauth/device`,
      grant_types_supported: [
        "refresh_token",
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:device_code",
      ],
      scopes_supported: ["orders:read", "orders:write", BROWSER_SIGN_IN],
      protected_resources: this.scenario.issuerUnlinked
        ? [MCP]
        : this.scenario.deviceLinkOffsite === true
          ? [ORIGIN, MCP, SIBLING]
          : [ORIGIN, MCP],
      ...(this.scenario.dpop ? { dpop_signing_alg_values_supported: ["ES256"] } : {}),
    };
  }

  async #route(request: Recorded): Promise<Response> {
    const { url, method, headers, body } = request;
    const here = `${url.origin}${url.pathname}`;
    if (OAUTH_ENDPOINTS.includes(here)) {
      if (headers.has("poppy-session"))
        this.fail("session.not-to-oauth", `sent the Session header to ${url.pathname}`);
      else this.pass("session.not-to-oauth");
    }
    switch (here) {
      case "https://www.shop.test/.well-known/poppy.json":
        return new Response(null, {
          status: 301,
          headers: {
            location: this.scenario.redirectToUpload
              ? `${ORIGIN}/uploads/poppy.json`
              : `${ORIGIN}/.well-known/poppy.json`,
          },
        });
      case `${ORIGIN}/.well-known/poppy.json`:
      case `${ORIGIN}/uploads/poppy.json`:
        return json(200, this.poppyJson());
      case OTHER_VERSION_DOC:
        return json(200, this.#linkedDocument());
      case `${ORIGIN}/poppy/excluded-tasks.json`:
        // 0.3 serves excluded tasks as a public document, with no Session header (spec 9.1).
        if (headers.has("poppy-session"))
          this.fail(
            "session.destinations",
            "sent the Session header to the excluded tasks document",
          );
        return json(200, { tasks: EXCLUDED_TASKS.map((task) => ({ task })) });
      case TASKS:
        return this.#resource(request, undefined, undefined, () =>
          this.#tasks(request, this.#sidOf(request)),
        );
      case SKILL_URL:
        // A skill artifact is Company content: it carries no credential, wherever it lives (9.4).
        if (headers.has("poppy-session") || headers.has("authorization"))
          this.fail("tasks.skill-digest", "sent a credential when fetching a skill artifact");
        else this.pass("tasks.skill-digest");
        return new Response(SKILL_BODY, {
          status: 200,
          headers: { "content-type": "text/markdown" },
        });
      case BROWSER_SESSION:
        // Step 1: the agent's own browser loads the page and gets a one-time code (section 6).
        this.#browserCode = `bc_${++this.#counter}`;
        this.#codeIssued = true;
        return new Response(
          `<form method="POST" action="${BROWSER_SESSION}/submit"><input type="hidden" name="code" value="${this.#browserCode}"></form>`,
          { status: 200, headers: { "content-type": "text/html" } },
        );
      case `${BROWSER_SESSION}/authorize`:
        return this.#resource(request, undefined, undefined, () => this.#authorizeBrowser(request));
      case `${BROWSER_SESSION}/submit`:
        if (!this.#codeAuthorized)
          this.fail("browser.join", "submitted the form before authorizing the code");
        else this.pass("browser.join");
        return new Response(null, { status: 303, headers: { location: ORIGIN } });
      case PAGE:
        return this.#page(request);
      case FEEDBACK:
        return this.#resource(request, undefined, undefined, () => {
          if (headers.has("authorization"))
            this.fail("tasks.feedback", "sent an access token with a feedback report");
          else this.pass("tasks.feedback");
          let task: unknown;
          try {
            task = (JSON.parse(body || "{}") as Record<string, unknown>)["task"];
          } catch {
            return json(400, { error: "invalid_request" });
          }
          // The Company already knows it doesn't offer these, so a report is noise (spec 9.3).
          if (EXCLUDED_TASKS.includes(String(task)))
            this.fail("tasks.not-excluded", `reported a task listed as excluded: ${String(task)}`);
          else this.pass("tasks.not-excluded");
          return new Response(null, { status: 202 });
        });
      case `${ORIGIN}/.well-known/oauth-protected-resource`:
        if (this.scenario.resourceMetadataFails) return json(500, { error: "unavailable" });
        return json(200, { resource: ORIGIN, authorization_servers: [ISSUER] });
      case `${ORIGIN}/.well-known/oauth-authorization-server`:
        return json(200, this.#metadata());
      case "https://mcp.shop.test/.well-known/oauth-protected-resource/mcp":
        return json(200, {
          resource: MCP,
          authorization_servers: [ISSUER],
          ...(this.scenario.dpop ? { dpop_signing_alg_values_supported: ["ES256"] } : {}),
        });
      case `${ORIGIN}/oauth/device`: {
        if (method !== "POST") return json(405, {});
        if (!(await this.#clientAuth(new URLSearchParams(body))))
          return json(401, { error: "invalid_client" });
        // 0.4 narrows the link to the issuer's host or organization.domain, or a subdomain of
        // either: a host from protected_resources no longer qualifies (spec 4.3).
        // A host this issuer serves but the Company doesn't control: a subdomain of shop.test
        // would still be legitimate, which is the point 4.3's narrowing turns on.
        const verification =
          this.scenario.deviceLinkOffsite === true ? `${SIBLING}/activate` : `${ORIGIN}/activate`;
        return json(200, {
          device_code: DEVICE_CODE,
          user_code: "WDJB-MJHT",
          verification_uri: verification,
          verification_uri_complete: `${verification}?user_code=WDJB-MJHT`,
          expires_in: 600,
          interval: 0,
        });
      }
      case AUTHORIZE:
        if (method !== "GET") return json(405, {});
        // The User's browser: the issuer approves and sends it back to the agent's redirect_uri.
        return new Response(null, {
          status: 302,
          headers: { location: await this.#authorize(url) },
        });
      case `${ORIGIN}/openapi.json`:
        return json(200, { openapi: "3.1.0", servers: [{ url: API }], paths: {} });
      case TOKEN:
        return method === "POST" ? this.#token(new URLSearchParams(body), headers) : json(405, {});
      case REVOKE:
        return method === "POST" ? this.#revoke(new URLSearchParams(body)) : json(405, {});
      case `${API}/orders`:
        return this.#resource(request, "orders:read", undefined, () => json(200, { orders: [] }));
      case `${API}/redirect`:
        // Redirects whoever asks, so a careless agent's credentials can follow it (spec 3).
        return new Response(null, {
          status: 307,
          headers: { location: "https://elsewhere.test/collect" },
        });
      case `${API}/exchanges`:
        return this.#resource(request, "orders:write", undefined, () => this.#exchange(request));
      case MCP:
        return this.#resource(request, "orders:read", MCP, () =>
          json(200, { jsonrpc: "2.0", id: 1, result: { tools: [] } }),
        );
      default:
        if (here.startsWith(CONVERSATIONS))
          return this.#resource(request, undefined, undefined, () => this.#conversation(request));
        return json(404, { error: "not_found" });
    }
  }

  // ---------- Agent identity ----------

  /** Fetches and checks the agent's client metadata and key set (spec 4.1), once. */
  async #agentKeys(clientId: string): Promise<Jwk[]> {
    if (this.#clientId !== undefined && this.#clientId !== clientId) {
      this.fail("identity.metadata", "the agent used two different client_ids");
    }
    this.#clientId = clientId;
    this.#keys ??= (async () => {
      const response = await this.#agentFetch(clientId, { redirect: "manual" });
      if (!response.ok) {
        this.fail("identity.metadata", `client_id returned HTTP ${response.status}`);
        return [];
      }
      const metadata = (await response.json()) as Record<string, unknown>;
      const host = new URL(clientId).hostname;
      const sameHost = (value: unknown) => {
        try {
          const url = new URL(String(value));
          return url.protocol === "https:" && url.hostname === host;
        } catch {
          return false;
        }
      };
      const redirects = Array.isArray(metadata["redirect_uris"]) ? metadata["redirect_uris"] : [];
      this.#redirectUris = redirects.map(String);
      const loopback = (value: string) => /^http:\/\/(127\.0\.0\.1|\[::1\])(:\d+)?\//.test(value);
      if (metadata["client_id"] !== clientId)
        this.fail("identity.metadata", "client_id doesn't equal the document's URL");
      else if (!sameHost(metadata["jwks_uri"]))
        this.fail("identity.metadata", "jwks_uri isn't HTTPS on the client_id's host");
      else if (!this.#redirectUris.every((uri) => sameHost(uri) || loopback(uri)))
        this.fail("identity.metadata", "a redirect_uri isn't on the client_id's host or loopback");
      else this.pass("identity.metadata");
      const keysResponse = await this.#agentFetch(String(metadata["jwks_uri"]), {
        redirect: "manual",
      });
      const keys = ((await keysResponse.json()) as { keys?: Jwk[] }).keys ?? [];
      if (keys.some((key) => PRIVATE_MEMBERS.some((member) => member in key)))
        this.fail("identity.public-keys", "the key set has private key members");
      else this.pass("identity.public-keys");
      return keys;
    })();
    return this.#keys;
  }

  async #verifyWithAgentKey(jwt: string, clientId: string): Promise<boolean> {
    const decoded = safeDecode(jwt);
    if (decoded === undefined) return false;
    const keys = await this.#agentKeys(clientId);
    const key = keys.find((candidate) => candidate.kid === decoded.header["kid"]);
    return key !== undefined && verifyJws(jwt, key, decoded.header["alg"]);
  }

  // ---------- OAuth ----------

  async #clientAuth(form: URLSearchParams): Promise<boolean> {
    const clientId = form.get("client_id");
    const assertion = form.get("client_assertion");
    const fail = (message: string) => {
      this.fail("oauth.client-assertion", message);
      return false;
    };
    if (clientId === null || assertion === null) return fail("no client_id or client_assertion");
    if (
      form.get("client_assertion_type") !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
      return fail("wrong client_assertion_type");
    if (!(await this.#verifyWithAgentKey(assertion, clientId)))
      return fail("the assertion doesn't verify with a jwks_uri key");
    const { payload } = decodeJwt(assertion);
    if (payload["aud"] !== ISSUER) return fail("aud isn't the issuer as a single string");
    if (payload["iss"] !== clientId || payload["sub"] !== clientId)
      return fail("iss and sub must be the client_id");
    const iat = Number(payload["iat"]);
    const exp = Number(payload["exp"]);
    if (!Number.isFinite(iat)) return fail("no iat");
    if (!Number.isFinite(exp) || exp <= Date.now() / 1000) return fail("exp is missing or past");
    if (exp - iat > 300) return fail("the assertion lives over 5 minutes");
    const jti = payload["jti"];
    if (typeof jti !== "string" || jti.length < 16) return fail("jti is missing or guessable");
    if (this.#assertionJtis.has(jti)) return fail("a jti was reused");
    this.#assertionJtis.add(jti);
    this.pass("oauth.client-assertion");
    return true;
  }

  async #dpopKey(headers: Headers, method: string, url: string, accessToken?: string) {
    const proof = headers.get("dpop");
    if (proof === null) return undefined;
    const decoded = safeDecode(proof);
    const jwk = decoded?.header["jwk"] as Jwk | undefined;
    if (decoded === undefined || jwk === undefined || decoded.header["typ"] !== "dpop+jwt")
      return null;
    if (!(await verifyJws(proof, jwk, decoded.header["alg"]))) return null;
    const target = new URL(url);
    if (
      decoded.payload["htm"] !== method ||
      decoded.payload["htu"] !== `${target.origin}${target.pathname}`
    )
      return null;
    if (accessToken !== undefined && decoded.payload["ath"] !== (await sha256(accessToken)))
      return null;
    return thumbprint(jwk);
  }

  #issue(scope: string[], resource: string | undefined, jkt: string | undefined, refresh: boolean) {
    const n = ++this.#counter;
    const access = `cat_${n}_${crypto.randomUUID()}`;
    this.#access.set(access, { scope, resource, revoked: false, jkt });
    const body: Record<string, unknown> = {
      access_token: access,
      token_type: jkt === undefined ? "Bearer" : "DPoP",
      expires_in: 3600,
      scope: scope.join(" "),
    };
    if (refresh) {
      const token = `crt_${n}_${crypto.randomUUID()}`;
      this.#refresh.set(token, { scope, resource: undefined, revoked: false, jkt });
      body["refresh_token"] = token;
    }
    return body;
  }

  /** Approves a Direct Sign-In as the User would, and returns the redirect back to the agent. */
  async #authorize(url: URL): Promise<string> {
    this.#authorizeRequests++;
    const params = url.searchParams;
    // An issuer reads the client's metadata from its client_id URL before showing the sign-in page.
    const clientId = params.get("client_id");
    if (clientId === null) this.fail("oauth.direct-request", "no client_id");
    else await this.#agentKeys(clientId);
    const redirectUri = params.get("redirect_uri") ?? "";
    if (`${url.origin}${url.pathname}` !== AUTHORIZE)
      this.fail("oauth.direct-request", "the authorization URL isn't the issuer's endpoint");
    else if (
      params.get("response_type") !== "code" ||
      params.get("code_challenge_method") !== "S256"
    )
      this.fail("oauth.direct-request", "no PKCE S256 code challenge");
    else if ((params.get("code_challenge") ?? "").length < 43)
      this.fail("oauth.direct-request", "the code challenge is too short");
    else if ((params.get("state") ?? "").length < 8)
      this.fail("oauth.direct-request", "state is missing or guessable");
    else if ((params.get("scope") ?? "") === "") this.fail("oauth.direct-request", "no scope");
    else if (!this.#redirectUris.includes(redirectUri))
      this.fail("oauth.direct-request", "redirect_uri isn't one of the agent's redirect_uris");
    else this.pass("oauth.direct-request");
    const code = `code_${++this.#counter}`;
    const scope = (params.get("scope") ?? "").split(" ").filter(Boolean);
    this.#codes.set(code, {
      challenge: params.get("code_challenge") ?? "",
      scope: this.scenario.extraScope ? [...scope, "orders:admin"] : scope,
      redirectUri,
    });
    const back = new URL(redirectUri || "https://agent.invalid/callback");
    back.searchParams.set("code", code);
    back.searchParams.set("state", params.get("state") ?? "");
    back.searchParams.set("iss", this.scenario.wrongIss ? "https://evil.test" : ISSUER);
    if (this.scenario.wrongIss) this.#forgedCodes.add(code);
    return back.href;
  }

  /** Codes issued in responses with a wrong iss, which the agent must never exchange. */
  readonly #forgedCodes = new Set<string>();

  async #token(form: URLSearchParams, headers: Headers): Promise<Response> {
    if (!(await this.#clientAuth(form))) return json(401, { error: "invalid_client" });
    let jkt: string | undefined;
    if (this.scenario.dpop) {
      const key = await this.#dpopKey(headers, "POST", TOKEN);
      if (key === undefined || key === null) {
        this.fail("oauth.dpop", "a token request had no valid DPoP proof");
        return json(400, { error: "invalid_dpop_proof" });
      }
      this.pass("oauth.dpop");
      jkt = key;
    }
    const grant = form.get("grant_type");
    if (grant === "authorization_code") {
      const code = form.get("code") ?? "";
      if (this.#forgedCodes.has(code))
        this.fail("oauth.iss-check", "exchanged a code from a response with the wrong iss");
      const issued = this.#codes.get(code);
      if (issued === undefined) return json(400, { error: "invalid_grant" });
      this.#codes.delete(code);
      if ((await sha256(form.get("code_verifier") ?? "")) !== issued.challenge) {
        this.fail("oauth.direct-request", "the code_verifier doesn't match the challenge");
        return json(400, { error: "invalid_grant" });
      }
      if (form.get("redirect_uri") !== issued.redirectUri)
        this.fail("oauth.direct-request", "the token request's redirect_uri differs");
      return json(200, this.#issue(issued.scope, undefined, jkt, true));
    }
    if (grant === "urn:ietf:params:oauth:grant-type:device_code") {
      if (form.get("device_code") !== DEVICE_CODE) return json(400, { error: "invalid_grant" });
      if (this.scenario.deviceLinkOffsite === true && this.version !== "0.3") {
        // 0.4 allows only the issuer's host or organization.domain; this link was neither, and the
        // agent showed it anyway. On 0.3 that host is still legitimate, so nothing is recorded.
        this.fail("oauth.device-link", "polled after a link 0.4 doesn't allow");
        return json(400, { error: "access_denied" });
      }
      this.pass("oauth.device-link");
      return json(200, this.#issue(["orders:read"], undefined, jkt, true));
    }
    if (grant === "refresh_token") {
      const value = form.get("refresh_token") ?? "";
      if (this.#retiredRefresh.has(value)) {
        this.fail("oauth.refresh-rotation", "used a refresh token after it was rotated");
        return json(400, { error: "invalid_grant" });
      }
      const token = this.#refresh.get(value);
      if (token === undefined || token.revoked) return json(400, { error: "invalid_grant" });
      if (this.#retiredRefresh.size > 0) this.pass("oauth.refresh-rotation");
      const resource = form.get("resource") ?? undefined;
      if (resource !== undefined && resource !== MCP) return json(400, { error: "invalid_target" });
      const scope = form.get("scope")?.split(" ") ?? token.scope;
      const body = this.#issue(scope, resource, jkt, this.scenario.rotate === true);
      if (this.scenario.rotate) {
        this.#retiredRefresh.add(value);
        this.#refresh.delete(value);
      }
      return json(200, body);
    }
    return json(400, { error: "unsupported_grant_type" });
  }

  async #revoke(form: URLSearchParams): Promise<Response> {
    if (!(await this.#clientAuth(form))) return json(401, { error: "invalid_client" });
    const token = this.#refresh.get(form.get("token") ?? "");
    if (form.get("token_type_hint") !== "refresh_token")
      this.fail("oauth.revocation", "token_type_hint isn't refresh_token");
    else if (token === undefined)
      this.fail("oauth.revocation", "revoked something other than a current refresh token");
    else {
      token.revoked = true;
      this.pass("oauth.revocation");
    }
    return new Response(null, { status: 200 });
  }

  // ---------- Resources and Sessions ----------

  /** Checks the Session header and any access token as spec 5.3 requires, then runs `handler`. */
  async #resource(
    request: Recorded,
    scope: string | undefined,
    resource: string | undefined,
    handler: () => Response | Promise<Response>,
  ): Promise<Response> {
    const { method, url, headers } = request;
    this.#resourceRequests++;
    const jwt = headers.get("poppy-session");
    if (jwt === null) {
      this.fail("session.header", `no Session header on ${method} ${url.pathname}`);
      return json(400, { error: "invalid_session" });
    }
    this.pass("session.header");
    this.#checkOperator(request);
    const session = await this.#verifySession(jwt, method, url);
    if (session === undefined) return json(400, { error: "invalid_session" });
    const version = this.#checkVersion(headers, String(session.payload["sid"]));
    if (version !== undefined) return version;
    const limited = this.#checkRateLimit(request);
    if (limited !== undefined) return limited;

    const authorization = headers.get("authorization");
    const [scheme, value] = authorization?.split(" ") ?? [];
    const ath = session.payload["ath"];
    if (value === undefined) {
      if (ath !== undefined) this.fail("session.ath", "ath is present without an access token");
      else this.pass("session.ath");
    } else if (ath !== (await sha256(value))) {
      this.fail("session.ath", "ath doesn't match the access token");
    } else this.pass("session.ath");

    const sid = String(session.payload["sid"]);
    if (this.scenario.invalidSession === true) {
      this.#sessionErrors++;
      return json(400, { error: "invalid_session" });
    }
    if (this.scenario.sessionEnded !== undefined) {
      const first = !this.#endedSids.has(sid);
      this.#endedSids.add(sid);
      if (this.scenario.sessionEnded === "always" || first) {
        this.#sessionErrors++;
        return json(400, { error: "session_ended" });
      }
    }

    if (value !== undefined) {
      const token = this.#access.get(value);
      if (token === undefined || token.revoked || this.#rejectedTokens.has(value))
        return challenge(scheme, 'error="invalid_token"', resource);
      if (token.scope.includes("orders:admin")) {
        this.fail("oauth.extra-scopes", "used a token that granted a scope it didn't request");
      }
      if (token.resource !== resource) {
        if (token.resource !== undefined)
          this.fail("oauth.resource-token", `sent a token for ${token.resource} to ${url.origin}`);
        return challenge(scheme, 'error="invalid_token"', resource);
      }
      if (resource !== undefined) this.pass("oauth.resource-token");
      if (token.jkt !== undefined) {
        if (scheme !== "DPoP") this.fail("oauth.dpop", "sent a DPoP-bound token as Bearer");
        else if ((await this.#dpopKey(headers, method, url.href, value)) !== token.jkt)
          this.fail("oauth.dpop", "a DPoP-bound token had no matching proof");
        else this.pass("oauth.dpop");
      }
      if (this.scenario.expireTokensOnce && !this.#tokenExpired) {
        this.#tokenExpired = true;
        this.#rejectedTokens.add(value);
        return challenge(scheme, 'error="invalid_token"', resource);
      }
      if (scope !== undefined && !token.scope.includes(scope))
        return challenge(scheme, `error="insufficient_scope", scope="${scope}"`, resource);
    } else if (scope !== undefined) {
      return challenge("Bearer", `scope="${scope}"`, resource);
    }
    return handler();
  }

  /**
   * Checks `Poppy-Version` and `Poppy-Extensions` on a request with the Session header (spec 3.4).
   * Returns a response when the request can't be handled under a version this Company serves.
   *
   * 0.3 defines neither header, so the Company only records what it sees. From 0.4 it rejects a missing
   * or unserved version with `version_unsupported`, and the agent chooses again.
   */
  #checkVersion(headers: Headers, sid: string): Response | undefined {
    if (this.scenario.versionUnsupported === true) {
      this.#versionErrors++;
      return json(400, { error: "version_unsupported" });
    }
    // Every version this Company has a document for. A scenario that serves two accepts either, since
    // which one the agent may use is what the scenario is testing.
    const served: string[] = this.#servesTwoVersions
      ? [this.version, this.#otherVersion]
      : [this.version];
    const declared = headers.get("poppy-version");
    if (declared === null) {
      // 0.3 defines no Poppy-Version, so a request without one belongs to 0.3 (spec 3.4). This
      // scenario's checks don't cover the header when the agent is working at 0.3.
      if (served.includes("0.3")) return undefined;
      this.fail("versions.header", "no Poppy-Version on a request with the Session header");
      return json(400, { error: "version_unsupported" });
    }
    if (!served.includes(declared) || declared === "0.3") {
      this.fail("versions.header", `Poppy-Version ${declared} isn't a version the Company serves`);
      return json(400, { error: "version_unsupported" });
    }
    const known = this.#sidVersions.get(sid);
    if (known !== undefined && known !== declared)
      this.fail("versions.header", "a Session's Poppy-Version changed");
    else this.pass("versions.header");
    this.#sidVersions.set(sid, declared);

    // Extensions are declared per request from 0.4, not in the client metadata document (spec 3.3).
    const extensions = headers.get("poppy-extensions");
    if (extensions !== null) {
      // Split first, then check each member: one pass over the value, with no nested quantifier for
      // a crafted header to make backtrack (RFC 9651 section 4.2).
      const members = extensions.split(",");
      if (members.every((member) => /^\s*"[^"]+";v="[^"]+"\s*$/.test(member)))
        this.pass("extensions.declared");
      else
        this.fail("extensions.declared", `Poppy-Extensions isn't an RFC 9651 List: ${extensions}`);
    }
    return undefined;
  }

  async #verifySession(jwt: string, method: string, url: URL) {
    const decoded = safeDecode(jwt);
    if (decoded === undefined) {
      this.fail("session.jwt", "the Session header isn't a JWT");
      return undefined;
    }
    const { header, payload } = decoded;
    const clientId = String(payload["iss"]);
    // The delegation (spec 5.2).
    const delegation = typeof header["poppy_dlg"] === "string" ? header["poppy_dlg"] : undefined;
    if (
      header["typ"] !== "poppy-session+jwt" ||
      header["alg"] !== "ES256" ||
      delegation === undefined
    ) {
      this.fail("session.jwt", "typ, alg or poppy_dlg is wrong or missing");
      return undefined;
    }
    const dlg = safeDecode(delegation);
    if (dlg === undefined || !(await this.#verifyWithAgentKey(delegation, clientId))) {
      this.fail("session.delegation", "the delegation doesn't verify with a jwks_uri key");
      return undefined;
    }
    const cnf = (dlg.payload["cnf"] as { jwk?: Jwk } | undefined)?.jwk;
    const now = Math.floor(Date.now() / 1000);
    const dIat = Number(dlg.payload["iat"]);
    const dExp = Number(dlg.payload["exp"]);
    if (
      dlg.header["typ"] !== "poppy-delegation+jwt" ||
      dlg.payload["iss"] !== clientId ||
      !(dExp > now) ||
      dExp - dIat > 24 * 60 * 60 ||
      cnf === undefined
    ) {
      this.fail("session.delegation", "the delegation's typ, iss, lifetime or cnf is wrong");
      return undefined;
    }
    const extra = Object.keys(dlg.payload).filter((claim) => !DELEGATION_CLAIMS.has(claim));
    if (extra.length > 0 || PRIVATE_MEMBERS.some((member) => member in cnf))
      this.fail(
        "session.delegation-privacy",
        extra.length > 0
          ? `the delegation has extra claims: ${extra.join(", ")}`
          : "cnf.jwk has private members",
      );
    else this.pass("session.delegation-privacy");
    if (!(await verifyJws(jwt, cnf, "ES256")) || header["kid"] !== (await thumbprint(cnf))) {
      this.fail(
        "session.jwt",
        "the Session JWT doesn't verify with the delegated key named by kid",
      );
      return undefined;
    }
    this.pass("session.jwt");
    this.pass("session.delegation");

    // The claims.
    const problems: string[] = [];
    if (payload["aud"] !== ISSUER) problems.push("aud isn't the Company identifier");
    if (typeof payload["sid"] !== "string" || !ID.test(payload["sid"]))
      problems.push("sid is invalid");
    if (typeof payload["sub"] !== "string" || payload["sub"] === "") problems.push("no sub");
    if (payload["htm"] !== method) problems.push("htm doesn't match");
    if (payload["htu"] !== `${url.origin}${url.pathname}`) problems.push("htu doesn't match");
    if (Math.abs(Number(payload["iat"]) - now) > 120) problems.push("iat isn't fresh");
    const jti = payload["jti"];
    if (typeof jti !== "string" || jti.length < 16) problems.push("jti is missing or guessable");
    else if (this.#sessionJtis.has(jti)) problems.push("a jti was reused");
    else this.#sessionJtis.add(String(jti));
    if (problems.length > 0) {
      for (const problem of problems) this.fail("session.claims", problem);
      return undefined;
    }
    this.pass("session.claims");

    const sub = String(payload["sub"]);
    const kid = String(header["kid"]);
    const owner = this.#kidToSub.get(kid);
    if (owner !== undefined && owner !== sub)
      this.fail("session.key-per-user", "one delegated key signed for two User IDs");
    else this.pass("session.key-per-user");
    this.#kidToSub.set(kid, sub);

    const ids = `${sub} ${String(payload["agent_id"] ?? "")}`;
    const sid = String(payload["sid"]);
    const known = this.#sidIds.get(sid);
    if (known !== undefined && known !== ids)
      this.fail("session.stable-ids", "a Session's sub or agent_id changed");
    else this.pass("session.stable-ids");
    this.#sidIds.set(sid, ids);
    return decoded;
  }

  /** The distinct `Poppy-Version` values the agent sent with the Session header (spec 3.4). */
  declaredVersions(): string[] {
    return [
      ...new Set(
        this.requests
          .filter((r) => r.headers.has("poppy-session"))
          .map((r) => r.headers.get("poppy-version"))
          .filter((version): version is string => version !== null),
      ),
    ];
  }

  /**
   * Decides the version-selection checks for a scenario that serves two documents (spec 3.4). The
   * Company prefers one version in `poppy.json` and links the other; which one the agent ends up on
   * shows in the document it fetched and the version it names on its requests.
   */
  checkVersionSelection(): void {
    const linked = this.requests.some(
      (r) => `${r.url.origin}${r.url.pathname}` === OTHER_VERSION_DOC,
    );
    const declared = this.declaredVersions();
    if (this.scenario.linkedVersionOffsite === true) {
      // The linked document is on another host, so the agent must not fetch or use it (spec 3.4).
      if (this.requests.some((r) => r.url.hostname === "other.test"))
        this.fail("versions.linked-host", "fetched a supported_versions document on another host");
      else if (declared.includes(this.version))
        this.fail("versions.linked-host", `used the ${this.version} document it must have refused`);
      else this.pass("versions.linked-host");
      return;
    }
    if (this.scenario.linkedVersionMismatch === true) {
      // The linked document declares another version, so nothing in it may be used (spec 3.4).
      if (declared.includes(this.version))
        this.fail(
          "versions.linked-version",
          `used a document listed under ${this.version} that declares ${this.#otherVersion}`,
        );
      else this.pass("versions.linked-version");
      return;
    }
    if (!linked) this.fail("versions.selection", "didn't fetch the newer version's document");
    else if (!declared.includes(this.version))
      this.fail(
        "versions.selection",
        `chose ${declared.join(", ") || "no version"} rather than the newer ${this.version}`,
      );
    else this.pass("versions.selection");
  }

  /** Called by the runner after a Device Sign-In scenario with an off-host link (spec 4.3). */
  checkDeviceLink(): void {
    if (this.scenario.deviceLinkOffsite !== true || this.version === "0.3") return;
    const polled = this.requests.some(
      (r) => `${r.url.origin}${r.url.pathname}` === TOKEN && r.body.includes("device_code"),
    );
    // Refusing to show the link means never getting a token from it.
    if (!polled) this.pass("oauth.device-link");
  }

  /** Called by the runner after a version_mismatch scenario (spec 8.13). */
  checkVersionMismatch(): void {
    if (this.#mismatches === 0) return;
    // The conversation can't continue in these versions, so an agent stops rather than hammering it.
    if (this.#mismatches > 2)
      this.fail("conversation.version-mismatch", "kept sending after version_mismatch");
    else this.pass("conversation.version-mismatch");
  }

  /** Called by the runner after a version_unsupported scenario (spec 3.4). */
  checkVersionErrors(): void {
    // The Company serves no version the agent can use, so it fetches poppy.json again, finds the same
    // answer, and stops. One retry is allowed; more means it kept going.
    const discoveries = this.requests.filter(
      (r) => `${r.url.origin}${r.url.pathname}` === `${ORIGIN}/.well-known/poppy.json`,
    ).length;
    if (this.#versionErrors === 0) return;
    if (this.#versionErrors > 2)
      this.fail("versions.unsupported", "kept sending the request after version_unsupported");
    else if (discoveries < 2)
      this.fail("versions.unsupported", "didn't fetch poppy.json again after version_unsupported");
    else this.pass("versions.unsupported");
  }

  /** Called by the runner after a session_ended or invalid_session scenario (spec 5.3, 5.5). */
  checkSessionErrors(requestsTo: string): void {
    const attempts = this.requests.filter((r) => `${r.url.origin}${r.url.pathname}` === requestsTo);
    const sids = attempts.map(
      (r) => safeDecode(r.headers.get("poppy-session") ?? "")?.payload["sid"],
    );
    if (this.scenario.sessionEnded === "once") {
      if (attempts.length < 2) this.fail("session.ended", "didn't retry after session_ended");
      else if (sids[0] === sids[1]) this.fail("session.ended", "retried with the same sid");
      else this.pass("session.ended");
    } else if (this.scenario.sessionEnded === "always") {
      if (this.#sessionErrors > 2)
        this.fail("session.ended", "kept retrying after a second session_ended");
      else this.pass("session.ended");
    } else if (this.scenario.invalidSession === true) {
      if (this.#sessionErrors > 1)
        this.fail("session.invalid-session", "sent the request again after invalid_session");
      else if (this.#sessionErrors === 1) this.pass("session.invalid-session");
    }
  }

  /**
   * Checks the operator signature on a request that carries the Session header (spec 5.3, RFC 9421
   * in the Web Bot Auth profile). What matters here is what it binds: a signature that leaves out
   * the Session header, or the access token when one is present, doesn't tie the operator to the
   * Session the request claims. The key directory isn't fetched, so the bytes aren't verified.
   */
  #checkOperator({ headers }: Recorded): void {
    const input = headers.get("signature-input");
    // A SHOULD: an agent that doesn't sign at all isn't recorded either way.
    if (input === null) return;
    if (!headers.has("signature")) {
      this.fail("session.operator-signature", "Signature-Input without a Signature");
      return;
    }
    const covered = [...input.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    const problems: string[] = [];
    if (!covered.includes("poppy-session")) problems.push("doesn't cover poppy-session");
    if (headers.has("authorization") && !covered.includes("authorization"))
      problems.push("doesn't cover authorization, which the request carries");
    if (!covered.includes("@authority")) problems.push("doesn't cover @authority");
    for (const parameter of ["keyid", "created", "expires"])
      if (!input.includes(`${parameter}=`)) problems.push(`has no ${parameter}`);
    if (problems.length > 0)
      for (const problem of problems) this.fail("session.operator-signature", problem);
    else this.pass("session.operator-signature");
  }

  /** The extensions this Company lists, by name, whatever shape its version uses (spec 3.3). */
  #listedExtensions(): Record<string, unknown> {
    const listed = this.#document(this.version)["extensions"];
    return typeof listed === "object" && listed !== null ? (listed as Record<string, unknown>) : {};
  }

  /** The `sid` a request's Session header names, or "" when it carries none. */
  #sidOf({ headers }: Recorded): string {
    const decoded = safeDecode(headers.get("poppy-session") ?? "");
    return typeof decoded?.payload["sid"] === "string" ? decoded.payload["sid"] : "";
  }

  /**
   * Rate limits the first request to a path, then measures how long the agent waited before sending
   * it again (spec 5.6): `Retry-After` is a floor, not a suggestion.
   */
  #checkRateLimit({ url, at }: Recorded): Response | undefined {
    const seconds = this.scenario.rateLimitSeconds;
    if (seconds === undefined) return undefined;
    const path = `${url.origin}${url.pathname}`;
    const limited = this.#rateLimited.get(path);
    if (limited === undefined) {
      this.#rateLimited.set(path, at);
      return new Response(JSON.stringify({ error: "rate_limited" }), {
        status: 429,
        headers: { "content-type": "application/json", "retry-after": String(seconds) },
      });
    }
    const waited = (at - limited) / 1000;
    // A small tolerance for the clock, not for an agent that didn't wait.
    if (waited + 0.05 < seconds)
      this.fail(
        "session.rate-limit",
        `sent the request again after ${waited.toFixed(2)}s, with Retry-After ${seconds}`,
      );
    else this.pass("session.rate-limit");
    return undefined;
  }

  // ---------- Browser join and website pages ----------

  /**
   * Step 2 of a browser join (section 6): the agent authorizes the code its own browser was given,
   * with the Session header and, if signed in, its access token.
   *
   * From 0.4 a signed-in join needs `poppy:browser-sign-in`, and a token without it is refused with
   * `insufficient_scope` — the agent then joins signed out, or asks for the scope and starts again.
   */
  #authorizeBrowser({ body, headers }: Recorded): Response {
    let code: unknown;
    try {
      code = (JSON.parse(body || "{}") as Record<string, unknown>)["code"];
    } catch {
      return json(400, { error: "invalid_request" });
    }
    // A code the agent did not read from its own browser's page.
    if (typeof code !== "string" || !this.#codeIssued || code !== this.#browserCode) {
      this.fail(
        "browser.code-source",
        `authorized a code this browser was never given: ${String(code)}`,
      );
      return json(400, { error: "invalid_request" });
    }
    this.pass("browser.code-source");
    const token = headers.get("authorization")?.split(" ")[1];
    if (token !== undefined && this.version !== "0.3") {
      const issued = this.#access.get(token);
      if (issued?.scope.includes(BROWSER_SIGN_IN) !== true) {
        this.#signInRefused = true;
        return challenge(
          "Bearer",
          `error="insufficient_scope", scope="${BROWSER_SIGN_IN}"`,
          undefined,
        );
      }
      this.pass("browser.sign-in-scope");
    } else if (this.version !== "0.3" && this.#signInRefused) {
      // It came back without a token after the refusal, which is one of the two allowed answers.
      this.pass("browser.sign-in-scope");
    }
    this.#codeAuthorized = true;
    return new Response(null, { status: 204 });
  }

  /**
   * A page of the Company's website. From 0.4 an agent that fetches one with its own HTTP client
   * sends the Session header and never a token, so the request is signed out (5.2).
   */
  async #page({ method, url, headers }: Recorded): Promise<Response> {
    const jwt = headers.get("poppy-session");
    if (headers.has("authorization")) {
      this.fail("web.page-signed-out", "sent an access token with a website page request");
      return json(400, { error: "invalid_session" });
    }
    this.pass("web.page-signed-out");
    if (this.version === "0.3") return html();
    if (jwt === null) {
      // Allowed only as the second try, after this Company refused the header once (5.2, 5.6).
      if (this.#pageRefused) this.pass("web.page-session");
      else this.fail("web.page-session", `no Session header on ${method} ${url.pathname}`);
      return html();
    }
    if (this.scenario.pageRejectsSession === true && !this.#pageRefused) {
      this.#pageRefused = true;
      return json(400, { error: "invalid_session" });
    }
    // The same verification a resource gets: signature, delegation, claims, htm and htu. A header
    // that doesn't verify is not a Session header, and an agent sending one isn't conformant.
    const session = await this.#verifySession(jwt, method, url);
    if (session === undefined) {
      this.fail("web.page-session", "a page's Session header didn't verify");
      return json(400, { error: "invalid_session" });
    }
    if (session.payload["ath"] !== undefined)
      this.fail("web.page-signed-out", "a page's Session JWT carried ath");
    else this.pass("web.page-session");
    return html();
  }

  // ---------- Task coverage ----------

  /**
   * The 0.4 tasks response (spec section 9). It describes what the Company offers, not the account, so
   * the request carries the Session header and no access token, even in a signed-in Session.
   */
  #tasks({ method, headers }: Recorded, sid: string): Response {
    this.#taskSids.add(sid);
    // A second Session asking is the point: an answer is never reused in another one (spec 9).
    if (this.#taskSids.size > 1) this.pass("tasks.per-session");
    if (method !== "GET") {
      this.fail("tasks.session", `fetched tasks.endpoint with ${method}, not GET`);
      return json(405, { error: "invalid_request" });
    }
    if (headers.has("authorization"))
      this.fail("tasks.session", "sent an access token to tasks.endpoint");
    else this.pass("tasks.session");
    return json(
      200,
      {
        excluded_tasks: EXCLUDED_TASKS.map((task) => ({ task })),
        feedback: { endpoint: FEEDBACK },
      },
      { "cache-control": "private" },
    );
  }

  // ---------- Operations ----------

  #exchange({ method, url, headers, body }: Recorded): Response {
    const approval = headers.get("poppy-approval");
    if (approval === null) {
      this.#refusedOperation = { method, url: url.href, body };
      return json(403, {
        error: "approval_required",
        operation: {
          operation_id: "exc_1",
          revision: "r1",
          summary: "Exchange the jacket for **$70** more.",
          expires_at: new Date(Date.now() + 600_000).toISOString(),
        },
      });
    }
    const refused = this.#refusedOperation;
    if (!/^operation_id="exc_1",\s*revision="r1"$/.test(approval))
      this.fail("operations.approval", `Poppy-Approval isn't the expected dictionary: ${approval}`);
    else if (
      refused === undefined ||
      refused.method !== method ||
      refused.url !== url.href ||
      refused.body !== body
    )
      this.fail("operations.approval", "the retry isn't the same method, URL and body");
    else this.pass("operations.approval");
    return json(201, { exchanged: true });
  }

  // ---------- Conversations ----------

  #conversation({ method, url, body, headers }: Recorded): Response {
    const rest = url.pathname
      .slice(new URL(CONVERSATIONS).pathname.length)
      .split("/")
      .filter(Boolean);
    let payload: Record<string, unknown> = {};
    try {
      payload = body === "" ? {} : (JSON.parse(body) as Record<string, unknown>);
    } catch {
      return json(400, { error: "invalid_request" });
    }
    const isV4 = this.version !== "0.3";
    if (this.scenario.versionMismatch === true && rest.length > 0) {
      this.#mismatches++;
      return json(409, { error: "version_mismatch", protocol_version: "0.3" });
    }
    const message = payload["message"] as Record<string, unknown> | undefined;
    /**
     * Checks the ID a POST carries (spec 8.2, 8.3). On 0.3 the message carries its own; from 0.4 the
     * request carries a top-level one and the message has none, so a retry of any request is safe.
     */
    const checkRequestId = (): string | undefined => {
      const id = isV4 ? payload["id"] : message?.["id"];
      const check = isV4 ? "conversation.request-id" : "conversation.messages";
      if (typeof id !== "string" || !ID.test(id)) {
        this.fail(check, isV4 ? "a request id is missing or invalid" : "a message id is invalid");
        return undefined;
      }
      if (isV4 && message?.["id"] !== undefined) {
        this.fail(check, "a 0.4 message carried an id of its own, rather than its request's");
        return undefined;
      }
      if (this.#messageIds.has(id)) {
        this.fail(check, "a request id was reused");
        return undefined;
      }
      this.#messageIds.add(id);
      this.pass(check);
      return id;
    };
    const checkMessage = (): boolean => {
      if (checkRequestId() === undefined) return false;
      const author = message?.["author"] as { type?: unknown } | undefined;
      const hasContent = ["text", "data", "context", "extensions"].some(
        (key) => message?.[key] !== undefined,
      );
      if (author?.type !== "agent" && author?.type !== "human") {
        this.fail("conversation.messages", "a message has no author.type");
        return false;
      }
      if (!hasContent) {
        this.fail("conversation.messages", "a message has no content");
        return false;
      }
      // Content an extension defines goes only to a side that uses that extension at that version
      // (spec 8.4). On 0.4 the request declares what it uses; on 0.3 the client document does.
      const content = message?.["extensions"];
      if (typeof content === "object" && content !== null && !Array.isArray(content)) {
        const declared = headers.get("poppy-extensions") ?? "";
        const listed = Object.keys(this.#listedExtensions());
        for (const name of Object.keys(content)) {
          // 0.3 reads the client's document, which this Company can't see here, so listing is the
          // most it can check; 0.4 has the request itself say what it uses.
          const usable = listed.includes(name) && (!isV4 || declared.includes(`"${name}"`));
          if (usable) this.pass("conversation.extension-version");
          else
            this.fail(
              "conversation.extension-version",
              `sent ${name} content to a Company that doesn't use it at that version`,
            );
        }
      }
      this.pass("conversation.messages");
      return true;
    };
    const reply = (id: string) => ({
      id: `evt_${++this.#counter}`,
      type: "message",
      created_at: new Date().toISOString(),
      message: {
        id: `msg_c${this.#counter}`,
        role: "company",
        author: { type: "agent" },
        text: `Reply in ${id}`,
        // Content an extension defines travels in `extensions`, keyed by name (spec 8.4).
        ...(this.scenario.operationInConversation === true
          ? {
              extensions: {
                operations: {
                  operation: {
                    operation_id: "exc_1",
                    revision: "r1",
                    summary: "Exchange the jacket for **$70** more.",
                    terms: { price_difference: 70 },
                    expires_at: new Date(Date.now() + 600_000).toISOString(),
                  },
                },
              },
            }
          : {}),
      },
    });
    // 0.3 reports one status; 0.4 reports four independent fields (spec 8.7).
    const working = this.scenario.slowAgent === true && this.#reads === 0;
    const state = (closed = false) =>
      isV4
        ? { working, handoff: this.#handoff, responder: "agent", closed }
        : { status: closed ? "closed" : working ? "working" : "idle", responder: "agent" };
    if (rest.length === 0 && method === "POST") {
      if (!checkMessage()) return json(400, { error: "invalid_request" });
      const id = `cnv_${++this.#counter}`;
      this.#conversations.set(id, { events: [reply(id)] });
      // A 0.4 POST without wait answers with only the conversation_id (spec 8.3).
      return json(201, isV4 ? { conversation_id: id } : { conversation_id: id, ...state() });
    }
    const conversation = this.#conversations.get(rest[0] ?? "");
    if (conversation === undefined) return json(404, { error: "conversation_not_found" });
    if (rest[1] === "messages" && method === "POST") {
      if (!checkMessage()) return json(400, { error: "invalid_request" });
      conversation.events.push(reply(rest[0] ?? ""));
      return json(
        202,
        isV4 ? { conversation_id: rest[0] } : { conversation_id: rest[0], ...state() },
      );
    }
    if (rest[1] === "events" && method === "GET") {
      if (this.scenario.slowAgent === true) {
        // A second read means the agent didn't stop while the Company still had work (8.7).
        if (this.#reads > 0) this.pass("conversation.working");
        this.#reads++;
      }
      const cursor = url.searchParams.get("cursor");
      const start =
        cursor === null ? 0 : conversation.events.findIndex((e) => e["id"] === cursor) + 1;
      const events = conversation.events.slice(start);
      return json(200, {
        conversation_id: rest[0],
        events,
        cursor: events.at(-1)?.["id"] ?? cursor,
        has_more: false,
        ...state(),
      });
    }
    if (rest[1] === "handoff" && method === "POST") {
      // Withdrawing a handoff is 0.4 only (spec 8.9).
      if (rest[2] === "cancel" && !isV4) return json(404, { error: "not_found" });
      if (rest[2] !== undefined && rest[2] !== "cancel") return json(404, { error: "not_found" });
      if (isV4 && checkRequestId() === undefined) return json(400, { error: "invalid_request" });
      if (rest[2] === "cancel") {
        if (this.#handoff === "pending") this.pass("conversation.handoff-cancel");
        else
          this.fail("conversation.handoff-cancel", "withdrew a handoff that was never asked for");
        this.#handoff = "none";
      } else this.#handoff = "pending";
      return json(
        202,
        isV4 ? { conversation_id: rest[0] } : { status: "queued", responder: "agent" },
      );
    }
    if (rest[1] === "close" && method === "POST") {
      if (isV4 && checkRequestId() === undefined) return json(400, { error: "invalid_request" });
      // A close returns 200 on 0.3 and 202 from 0.4, which acts on it after responding (spec 8.12).
      return isV4
        ? json(202, { conversation_id: rest[0] })
        : json(200, { status: "closed", responder: "agent" });
    }
    return json(404, { error: "not_found" });
  }
}

function challenge(
  scheme: string | undefined,
  params: string,
  resource: string | undefined,
): Response {
  const metadata =
    resource === undefined
      ? ""
      : `, resource_metadata="https://mcp.shop.test/.well-known/oauth-protected-resource/mcp"`;
  return new Response(null, {
    status: params.includes("insufficient_scope") ? 403 : 401,
    headers: { "www-authenticate": `${scheme ?? "Bearer"} ${params}${metadata}` },
  });
}
