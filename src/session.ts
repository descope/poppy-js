import type { Account } from "./account.ts";
import { authChallenge } from "./challenge.ts";
import { Conversations } from "./conversations.ts";
import type { Company } from "./discovery.ts";
import { errorFromBody, errorFromResponse, PoppyError, PoppyProtocolError } from "./errors.ts";
import { checkPublicHost, type Fetch, getJson, httpsUrl, isObject } from "./http.ts";
import { randomId } from "./jose.ts";
import { type Approval, approvalHeader } from "./operations.ts";
import { type OperatorSignatureOptions, signOperator } from "./operator.ts";
import type { ResourceResolver } from "./resources.ts";
import { type DelegatedKeys, signSessionJwt } from "./session-jwt.ts";
import { fetchSkillArtifact, type SkillArtifact } from "./skills.ts";
import {
  type Alternative,
  checkFeedback,
  type ExcludedTask,
  type FeedbackReport,
  parseAlternative,
  parseExcludedTasks,
  parseTaskCoverage,
  type TaskCoverage,
} from "./tasks.ts";

type FetchBody = Exclude<RequestInit["body"], ReadableStream | null | undefined>;

export type SessionFetchInit = Omit<RequestInit, "body" | "redirect"> & {
  body?: FetchBody;
  /** Sends no access token, even when the User is signed in (spec 5). */
  signedOut?: boolean;
  /** Asks for an access token with fewer scopes than the refresh token has (spec 4.4). */
  scope?: string | readonly string[];
  /** The User's approval of an operation, sent in `Poppy-Approval` (Operations extension section 6). */
  approval?: Approval;
};

/** What a re-discovery found, after a Company answered `version_unsupported` (spec 3.4). */
export interface Rediscovered {
  company: Company;
  resolver: ResourceResolver;
}

export interface SessionInit {
  company: Company;
  clientId: string;
  userId: string;
  agentId: string | undefined;
  keys: DelegatedKeys;
  account: Account | undefined;
  resolver: ResourceResolver;
  fetch: Fetch;
  operator: OperatorSignatureOptions | undefined;
  allowPrivateAddresses: boolean;
  /** The extensions the agent supports, by name (spec 3.3), which 0.4 declares per request (3.4). */
  extensions: Readonly<Record<string, { version: string }>>;
  /**
   * Fetches the Company's `poppy.json` again, without a cached copy, and chooses a version again, after
   * a Company answers `version_unsupported` (spec 3.4). Omitted when the agent can't re-discover.
   */
  rediscover?: (() => Promise<Rediscovered>) | undefined;
}

/**
 * Builds the `Poppy-Extensions` value for a Session (spec 3.4): an RFC 9651 List of Strings, each the
 * name of an extension in the chosen document, with the version the agent uses in the `v` parameter.
 * Only extensions both sides list are declared, and the value stays the same for the whole Session.
 */
export function extensionsHeader(
  company: Company,
  extensions: Readonly<Record<string, { version: string }>>,
): string | undefined {
  // RFC 9651 section 3.3.3: a String holds printable ASCII, with `"` and `\` escaped.
  const sfString = (value: string) =>
    /^[\x20-\x7e]*$/.test(value) ? `"${value.replace(/([\\"])/g, "\\$1")}"` : undefined;
  const declared = Object.entries(extensions).flatMap(([name, { version }]) => {
    if (company.extensions[name]?.some((entry) => entry.version === version) !== true) return [];
    const key = sfString(name);
    const value = sfString(version);
    return key === undefined || value === undefined ? [] : [`${key};v=${value}`];
  });
  return declared.length === 0 ? undefined : declared.join(", ");
}

/**
 * Drives the agent's own browser through a browser join (spec 6). Never use the User's own browser.
 */
export interface BrowserJoiner {
  /** Loads the URL in the agent's browser as a top-level navigation. */
  open(url: string): Promise<void>;
  /** Reads the hidden `code` field from the page the browser just loaded, in code the model can't read. */
  readCode(): Promise<string>;
  /** Submits the page's form. */
  submit(): Promise<void>;
}

/**
 * One User's activity at one Company through this agent (spec 5). Get one from {@link PoppyUser.session}.
 * Each request carries a fresh Session JWT, and an access token when the User is signed in.
 */
export class Session {
  readonly userId: string;
  readonly agentId: string | undefined;
  #company: Company;
  #resolver: ResourceResolver;
  #extensionsHeader: string | undefined;
  readonly #init: SessionInit;
  #sid = randomId();
  #ended = false;
  #versionRetried = false;
  #coverage: Promise<TaskCoverage> | undefined;

  constructor(init: SessionInit) {
    this.#company = init.company;
    this.#resolver = init.resolver;
    this.#extensionsHeader = extensionsHeader(init.company, init.extensions);
    this.userId = init.userId;
    this.agentId = init.agentId;
    this.#init = init;
  }

  /**
   * The Company this Session works with. It changes only when the Company answers `version_unsupported`
   * and a fresh discovery chooses another version (spec 3.4); its domain and identifier stay the same.
   */
  get company(): Company {
    return this.#company;
  }

  /** The protocol version this Session uses, sent in `Poppy-Version` from 0.4 (spec 3.4). */
  get protocolVersion(): string {
    return this.#company.protocolVersion;
  }

  /** The Session ID (`sid`). Not a credential, but don't use it for anything else (spec 5.2). */
  get id(): string {
    return this.#sid;
  }

  /** Whether requests carry an access token by default. */
  get signedIn(): boolean {
    return this.#init.account?.signedIn === true;
  }

  get ended(): boolean {
    return this.#ended;
  }

  /** Stops using this Session's `sid` (spec 5.5). The account stays signed in. */
  end(): void {
    this.#ended = true;
  }

  /**
   * Sends a request to the Company with the Session header, plus an access token when signed in (spec 5.2,
   * 4.5). The URL must be a destination for the Session header: a request URL of an API `poppy.json`
   * lists, or a protocol or extension endpoint. Redirects are returned, never followed, so no secret
   * reaches another URL (spec 3).
   *
   * Retries once in a new Session on `session_ended` (spec 5.5), once on a DPoP nonce challenge, and once
   * after refreshing on `invalid_token`. On `version_unsupported` it discovers the Company again and, if
   * that chooses another version, continues in a new Session at that version and sends the request once
   * more (spec 3.4). `invalid_session` is returned, since a new Session doesn't fix it (spec 5.3). Other
   * errors are returned; see {@link authChallenge}.
   */
  async fetch(input: string | URL, init: SessionFetchInit = {}): Promise<Response> {
    if (this.#ended) throw new PoppyProtocolError("this Session has ended");
    const url = httpsUrl(String(input), "request URL");
    checkPublicHost(url, "request URL", this.#init.allowPrivateAddresses);
    if (!(await this.#resolver.isDestination(url)))
      throw new PoppyProtocolError(
        `${url.origin}${url.pathname} is not an API or endpoint ${this.company.domain} lists`,
      );
    if (url.searchParams.has("access_token"))
      throw new PoppyProtocolError("tokens must never go in a URL (spec 5.6)");
    if ((init.body as unknown) instanceof ReadableStream)
      throw new PoppyProtocolError(
        "streaming bodies are not supported, since a retry resends the body",
      );
    const { signedOut, scope, approval, ...requestInit } = init;
    const method = (init.method ?? "GET").toUpperCase();
    const account = signedOut === true ? undefined : this.#init.account;
    let sessionRetried = false;
    let tokenRetried = false;
    let nonceRetried = false;
    for (;;) {
      const choice = account?.signedIn === true ? await this.#resolver.resolve(url) : undefined;
      const token =
        account === undefined || choice === undefined || choice.accountAccess === false
          ? undefined
          : scope === undefined
            ? await account.accessToken(choice)
            : await account.narrowedToken(choice, scope);
      const headers = new Headers(requestInit.headers);
      headers.set(
        "poppy-session",
        await signSessionJwt(this.#init.keys, {
          clientId: this.#init.clientId,
          audience: this.company.identifier,
          sid: this.#sid,
          userId: this.userId,
          agentId: this.agentId,
          method,
          url,
          accessToken: token?.value,
        }),
      );
      let dpopNonces: Map<string, string> | undefined;
      if (token !== undefined) {
        headers.set("authorization", `${token.type} ${token.value}`);
        if (token.type === "DPoP" && account !== undefined) {
          const dpop = await account.dpopForRequest();
          dpopNonces = dpop.nonces;
          headers.set(
            "dpop",
            await dpop.key.proof(method, url.href, {
              accessToken: token.value,
              nonce: dpop.nonces.get(url.origin),
            }),
          );
        }
      } else {
        headers.delete("authorization");
      }
      // From 0.4, a request with the Session header names the version it uses, and the extensions it
      // uses with this Company, the same throughout a Session (spec 3.4).
      if (this.protocolVersion !== "0.3") {
        headers.set("poppy-version", this.protocolVersion);
        if (this.#extensionsHeader !== undefined)
          headers.set("poppy-extensions", this.#extensionsHeader);
      }
      if (approval !== undefined) headers.set("poppy-approval", approvalHeader(approval));
      if (this.#init.operator !== undefined)
        await signOperator(this.#init.operator, url, headers, method);
      const response = await this.#init.fetch(url, {
        ...requestInit,
        method,
        headers,
        redirect: "manual",
      });
      const nonce = response.headers.get("dpop-nonce");
      if (nonce !== null) dpopNonces?.set(url.origin, nonce);

      if (
        response.status === 400 &&
        !sessionRetried &&
        (await sessionError(response, "session_ended"))
      ) {
        // A new Session, once. Its state doesn't carry over, but conversations do (spec 5.5).
        sessionRetried = true;
        this.#sid = randomId();
        await response.body?.cancel();
        continue;
      }
      if (
        response.status === 400 &&
        !this.#versionRetried &&
        (await sessionError(response, "version_unsupported"))
      ) {
        // The Company doesn't serve the version this Session uses. Discover it again, without a cached
        // copy, and choose again; a different version continues in a new Session (spec 3.4).
        this.#versionRetried = true;
        if (await this.#chooseVersionAgain()) {
          await response.body?.cancel();
          // The new version's document is a different document: it may list other endpoints, and a
          // body built for the old version is the wrong shape for this one. Both are checked again
          // here rather than resending what was prepared for the version that just went away.
          if (!(await this.#resolver.isDestination(url)))
            throw new PoppyProtocolError(
              `${url.origin}${url.pathname} is not an API or endpoint ${this.company.domain} lists at ${this.protocolVersion}`,
            );
          if (requestInit.body !== undefined)
            throw new PoppyError("version_unsupported", {
              description: `this Session moved to ${this.protocolVersion}; build the request again and send it`,
              protocolVersion: this.protocolVersion,
            });
          continue;
        }
      }
      if (
        response.status === 401 &&
        token !== undefined &&
        account !== undefined &&
        choice !== undefined
      ) {
        const challenge = authChallenge(response);
        if (challenge?.error === "use_dpop_nonce" && !nonceRetried) {
          nonceRetried = true;
          await response.body?.cancel();
          continue;
        }
        if (challenge?.error === "invalid_token" && !tokenRetried) {
          tokenRetried = true;
          account.invalidate(choice);
          // The resolver this Session is using, which a version switch may have replaced.
          if (challenge.resourceMetadata !== undefined) this.#resolver.forget(choice.service);
          // The retry refreshes. If refresh fails, the account is signed out and the retry goes
          // without a token (spec 5.5).
          await response.body?.cancel();
          continue;
        }
      }
      return response;
    }
  }

  /**
   * Discovers the Company again and chooses a version again (spec 3.4). Resolves true when it chose
   * another one, which this Session then continues in with a new `sid`; the Company's domain and
   * identifier stay the same across versions, so the account and its tokens carry over.
   */
  async #chooseVersionAgain(): Promise<boolean> {
    if (this.#init.rediscover === undefined) return false;
    let found: Rediscovered;
    try {
      found = await this.#init.rediscover();
    } catch {
      // A failed discovery says nothing about which version to use, so this Session stops here.
      return false;
    }
    if (found.company.protocolVersion === this.protocolVersion) return false;
    this.#company = found.company;
    this.#resolver = found.resolver;
    this.#extensionsHeader = extensionsHeader(found.company, this.#init.extensions);
    this.#coverage = undefined;
    this.#sid = randomId();
    return true;
  }

  /**
   * Adds an endpoint an extension defines that `poppy.json` doesn't list, such as a UCP service the
   * Company's profile names (UCP extension 2), so requests under it carry the Session header.
   */
  addExtensionEndpoint(endpoint: string): void {
    this.#resolver.addExtensionEndpoint(httpsUrl(endpoint, "extension endpoint").href);
  }

  /** Talks with the Company Agent (spec section 8), through its `poppy` conversation endpoint. */
  conversations(endpoint?: string): Conversations {
    const protocol =
      endpoint === undefined
        ? this.company.conversationProtocols[0]
        : this.company.conversationProtocols.find((p) => p.endpoint === endpoint);
    if (protocol === undefined)
      throw new PoppyProtocolError(`${this.company.domain} lists no poppy conversation endpoint`);
    return new Conversations(this, protocol.endpoint);
  }

  /**
   * Step 2 of a browser join (spec 6): authorizes a code read from the page the agent's own browser loaded.
   * Signed in unless `signedOut`, so the website acts with the account and the access token's scopes.
   *
   * From 0.4, a signed-in join needs the {@link BROWSER_SIGN_IN_SCOPE} scope. Without it the Company
   * answers `insufficient_scope`, which this throws: authorize the same code again with `signedOut`, so
   * the browser joins signed out, or get the scope and join again from step 1. Check
   * {@link Company.webUnscoped} first, since on an unscoped website the scope gives the account's full
   * access there rather than only the token's other scopes.
   */
  async authorizeBrowserCode(code: string, options: { signedOut?: boolean } = {}): Promise<void> {
    const endpoint = this.company.browserSessionEndpoint;
    if (endpoint === undefined)
      throw new PoppyProtocolError(`${this.company.domain} has no browser_session_endpoint`);
    const response = await this.fetch(`${endpoint.replace(/\/$/, "")}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ code }),
      ...(options.signedOut === undefined ? {} : { signedOut: options.signedOut }),
    });
    if (response.status !== 204 && !response.ok) throw await throwable(response);
    await response.body?.cancel();
  }

  /**
   * Joins the agent's own browser to this Session (spec 6): loads the browser-session page, authorizes its
   * code, and submits the form, right away so the code doesn't expire. Join again after signing in or out.
   */
  async joinBrowser(browser: BrowserJoiner, options: { signedOut?: boolean } = {}): Promise<void> {
    const endpoint = this.company.browserSessionEndpoint;
    if (endpoint === undefined)
      throw new PoppyProtocolError(`${this.company.domain} has no browser_session_endpoint`);
    await browser.open(endpoint);
    await this.authorizeBrowserCode(await browser.readCode(), options);
    await browser.submit();
  }

  /**
   * What the Company offers this Session: its excluded tasks, its skills, and where to send feedback
   * (spec section 9). Read it before starting on a task.
   *
   * On 0.3 these are fields of `poppy.json`, the same for every User. On 0.4 they come from one GET to
   * `tasks.endpoint`, with the Session header and no access token, so a Company can answer different
   * Sessions differently; the answer is kept for this Session only and never reused in another. When the
   * Company answers with nothing usable, this resolves to empty coverage, as the spec asks, so a task
   * carries on rather than failing over a document that only describes what the Company offers.
   */
  taskCoverage(): Promise<TaskCoverage> {
    this.#coverage ??= this.#fetchCoverage().catch(() => EMPTY_COVERAGE);
    return this.#coverage;
  }

  async #fetchCoverage(): Promise<TaskCoverage> {
    const company = this.company;
    if (company.protocolVersion === "0.3") {
      // Only the excluded tasks need a request on 0.3: the skills and the feedback endpoint are
      // already in `poppy.json`, so a document that 404s or times out costs this Session the tasks
      // and nothing else (spec 9.1).
      return {
        excludedTasks: await this.#excludedTasksDocument().catch(() => []),
        skills: company.skills,
        feedbackEndpoint: company.feedbackEndpoint,
      };
    }
    const endpoint = company.tasksEndpoint;
    if (endpoint === undefined) return EMPTY_COVERAGE;
    const response = await this.fetch(endpoint, {
      headers: { accept: "application/json" },
      signedOut: true,
    });
    if (!response.ok) throw await throwable(response);
    const body: unknown = await response.json().catch(() => undefined);
    const coverage = parseTaskCoverage(body, company, endpoint);
    // The feedback endpoint comes from this response rather than poppy.json, so it becomes a Session
    // destination only once the Company has named it (spec 5.2).
    if (coverage.feedbackEndpoint !== undefined)
      this.#resolver.addFeedbackEndpoint(coverage.feedbackEndpoint);
    return coverage;
  }

  /** The 0.3 excluded tasks document: a plain GET with no Session header and no token (spec 9.1). */
  async #excludedTasksDocument(): Promise<ExcludedTask[]> {
    const url = this.company.excludedTasksUrl;
    if (url === undefined) return [];
    const { body } = await getJson(this.#init.fetch, new URL(url), "excluded tasks", {
      allowPrivate: this.#init.allowPrivateAddresses,
    });
    return parseExcludedTasks(body, this.company);
  }

  /**
   * Fetches a skill the Company publishes and checks its digest (spec 9.4), with no Session header or
   * token. The index comes from `poppy.json` on 0.3 and from this Session's task coverage on 0.4.
   */
  async fetchSkill(name: string): Promise<SkillArtifact> {
    const { skills } = await this.taskCoverage();
    const skill = skills.find((entry) => entry.name === name);
    if (skill === undefined)
      throw new PoppyProtocolError(`${this.company.domain} lists no skill ${name}`);
    return fetchSkillArtifact(skill, {
      fetch: this.#init.fetch,
      allowPrivateAddresses: this.#init.allowPrivateAddresses,
    });
  }

  /**
   * Reads the tasks the Company chose not to offer (spec 9.1). Returns an empty list when it publishes
   * none. A shorthand for {@link taskCoverage}, which also carries the skills and feedback endpoint.
   */
  async excludedTasks(): Promise<ExcludedTask[]> {
    return [...(await this.taskCoverage()).excludedTasks];
  }

  /**
   * Reports a task the User couldn't do (spec 9.3), with the Session header and no access token. Resolves
   * with an alternative if the Company says the task can be done after all, else undefined.
   */
  async sendFeedback(report: FeedbackReport): Promise<Alternative | undefined> {
    const endpoint = (await this.taskCoverage()).feedbackEndpoint;
    if (endpoint === undefined)
      throw new PoppyProtocolError(`${this.company.domain} has no feedback endpoint`);
    checkFeedback(report);
    const response = await this.fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ task: report.task, description: report.description }),
      signedOut: true,
    });
    if (response.status === 202) {
      await response.body?.cancel();
      return undefined;
    }
    if (response.status === 200) {
      const body: unknown = await response.json().catch(() => undefined);
      return parseAlternative(body, this.company);
    }
    throw await throwable(response);
  }
}

const EMPTY_COVERAGE: TaskCoverage = {
  excludedTasks: [],
  skills: [],
  feedbackEndpoint: undefined,
};

/** Whether a 400 carries one of the JSON Session errors (spec 5.3, 3.4). */
async function sessionError(response: Response, error: string): Promise<boolean> {
  try {
    const body: unknown = await response.clone().json();
    return isObject(body) && body["error"] === error;
  } catch {
    return false;
  }
}

/**
 * The error for a failed response: from `WWW-Authenticate` for token errors and challenges (spec 7), else
 * from the JSON body (spec 8.13).
 *
 * A 403 is read from its JSON body first, since from 0.4 `extension_required` is a JSON body at APIs
 * too, rather than a challenge, and it isn't an access token error (spec 3.3, section 7). `approval_required`
 * already arrived that way. A 403 with only a challenge, such as 0.3's `extension_required` or
 * `insufficient_scope` on either version, reads from the header.
 *
 * A server may send both, as RFC 6750 servers often do for `insufficient_scope`. The body decides the
 * error code, and the challenge fills in `scope` and `extension` when the body leaves them out, so the
 * caller still learns which scope to request or which extension to declare.
 */
export async function throwable(response: Response): Promise<PoppyError> {
  const challenge = authChallenge(response);
  if (response.status === 403) {
    const body: unknown = await response
      .clone()
      .json()
      .catch(() => undefined);
    if (isObject(body) && typeof body["error"] === "string") {
      await response.body?.cancel();
      return errorFromBody(
        {
          ...body,
          ...(body["scope"] === undefined && challenge?.scope !== undefined
            ? { scope: challenge.scope }
            : {}),
          ...(body["extension"] === undefined && challenge?.extension !== undefined
            ? { extension: challenge.extension }
            : {}),
        },
        response,
      );
    }
  }
  if (challenge !== undefined && (response.status === 401 || response.status === 403)) {
    await response.body?.cancel();
    return new PoppyError(challenge.error ?? "insufficient_scope", {
      status: response.status,
      description: challenge.params["error_description"]?.slice(0, 200),
      scope: challenge.scope,
      extension: challenge.extension,
    });
  }
  return errorFromResponse(response);
}
