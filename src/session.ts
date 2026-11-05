import type { Account } from "./account.ts";
import { authChallenge } from "./challenge.ts";
import { Conversations } from "./conversations.ts";
import type { Company } from "./discovery.ts";
import { errorFromResponse, PoppyError, PoppyProtocolError } from "./errors.ts";
import { checkPublicHost, type Fetch, getJson, httpsUrl, isObject } from "./http.ts";
import { randomId } from "./jose.ts";
import { type Approval, approvalHeader } from "./operations.ts";
import { type OperatorSignatureOptions, signOperator } from "./operator.ts";
import type { ResourceResolver } from "./resources.ts";
import { type DelegatedKeys, signSessionJwt } from "./session-jwt.ts";
import { fetchSkill, type SkillArtifact } from "./skills.ts";
import {
  type Alternative,
  checkFeedback,
  type ExcludedTask,
  type FeedbackReport,
  parseAlternative,
  parseExcludedTasks,
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
  readonly company: Company;
  readonly userId: string;
  readonly agentId: string | undefined;
  readonly #init: SessionInit;
  #sid = randomId();
  #ended = false;

  constructor(init: SessionInit) {
    this.company = init.company;
    this.userId = init.userId;
    this.agentId = init.agentId;
    this.#init = init;
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
   * after refreshing on `invalid_token`. `invalid_session` is returned, since a new Session doesn't fix it
   * (spec 5.3). Other errors are returned; see {@link authChallenge}.
   */
  async fetch(input: string | URL, init: SessionFetchInit = {}): Promise<Response> {
    if (this.#ended) throw new PoppyProtocolError("this Session has ended");
    const url = httpsUrl(String(input), "request URL");
    checkPublicHost(url, "request URL", this.#init.allowPrivateAddresses);
    if (!(await this.#init.resolver.isDestination(url)))
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
      const choice =
        account?.signedIn === true ? await this.#init.resolver.resolve(url) : undefined;
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

      if (response.status === 400 && !sessionRetried && (await isSessionEnded(response))) {
        // A new Session, once. Its state doesn't carry over, but conversations do (spec 5.5).
        sessionRetried = true;
        this.#sid = randomId();
        await response.body?.cancel();
        continue;
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
          if (challenge.resourceMetadata !== undefined) this.#init.resolver.forget(choice.service);
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
   * Adds an endpoint an extension defines that `poppy.json` doesn't list, such as a UCP service the
   * Company's profile names (UCP extension 2), so requests under it carry the Session header.
   */
  addExtensionEndpoint(endpoint: string): void {
    this.#init.resolver.addExtensionEndpoint(httpsUrl(endpoint, "extension endpoint").href);
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
   * Fetches a skill from the Company's `skill_index` and checks its digest (spec 9.4), with no Session
   * header or token. See {@link fetchSkill}.
   */
  fetchSkill(name: string): Promise<SkillArtifact> {
    return fetchSkill(this.company, name, {
      fetch: this.#init.fetch,
      allowPrivateAddresses: this.#init.allowPrivateAddresses,
    });
  }

  /**
   * Reads the tasks the Company chose not to offer (spec 9.1), with a plain GET and no token. Returns an
   * empty list when the Company publishes none.
   */
  async excludedTasks(): Promise<ExcludedTask[]> {
    const url = this.company.excludedTasksUrl;
    if (url === undefined) return [];
    const { body } = await getJson(this.#init.fetch, new URL(url), "excluded tasks", {
      allowPrivate: this.#init.allowPrivateAddresses,
    });
    return parseExcludedTasks(body, this.company);
  }

  /**
   * Reports a task the User couldn't do (spec 9.3), with the Session header and no access token. Resolves
   * with an alternative if the Company says the task can be done after all, else undefined.
   */
  async sendFeedback(report: FeedbackReport): Promise<Alternative | undefined> {
    const endpoint = this.company.feedbackEndpoint;
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

async function isSessionEnded(response: Response): Promise<boolean> {
  try {
    const body: unknown = await response.clone().json();
    return isObject(body) && body["error"] === "session_ended";
  } catch {
    return false;
  }
}

/**
 * The error for a failed response: from `WWW-Authenticate` for token errors and challenges (spec 7), else
 * from the JSON body (spec 8.13).
 */
export async function throwable(response: Response): Promise<PoppyError> {
  const challenge = authChallenge(response);
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
