import { type Company, discover, isAllowedHost } from "./discovery.ts";
import { DpopKey } from "./dpop.ts";
import { errorFromResponse, PoppyError, PoppyProtocolError } from "./errors.ts";
import { type Fetch, httpsUrl, isObject, postForm } from "./http.ts";
import { nowSeconds, randomId, signJwt } from "./jose.ts";
import { MemoryStore, type Store } from "./store.ts";

const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code";
const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ASSERTION_LIFETIME = 60;
/** Renew this many seconds before a Session Token expires, so a request never races the expiry. */
const EXPIRY_MARGIN = 30;
const SESSION_ENDED = new Set(["invalid_session", "account_mismatch"]);
/** Sessions whose state {@link PoppyAgent.forget} deleted. They must not write it back or keep using a token. */
const forgotten = new WeakSet<Session>();

/** The key the agent signs its client and Session assertions with. Its public half is in the agent's `jwks_uri`. */
export interface SigningKey {
  privateKey: CryptoKey;
  /** The `kid` of this key in the published key set. */
  kid: string;
}

/** Options for {@link PoppyAgent}. */
export interface PoppyAgentOptions {
  /** The agent's `client_id`: the HTTPS URL of its client metadata document (spec 4.1). */
  clientId: string;
  signingKey: SigningKey;
  /** Defaults to a {@link MemoryStore}. */
  store?: Store;
  /** Defaults to the global `fetch`. Every request is sent with `redirect: "manual"`. */
  fetch?: Fetch;
}

interface PersistedState {
  dpopKey: JsonWebKey;
  sessionId?: string | undefined;
  accountToken?: string;
  scope?: string;
}

interface TokenResponse {
  accessToken: string;
  expiresIn: number;
  scope: string | undefined;
  sessionId: string | undefined;
  signedIn: boolean | undefined;
  refreshToken: string | undefined;
}

function parseTokenResponse(body: unknown): TokenResponse {
  if (!isObject(body)) throw new PoppyProtocolError("token response must be an object");
  const { access_token, token_type, expires_in, scope, session_id, signed_in, refresh_token } =
    body;
  if (typeof access_token !== "string" || access_token === "")
    throw new PoppyProtocolError("access_token is missing");
  if (typeof token_type !== "string" || token_type.toLowerCase() !== "dpop") {
    throw new PoppyProtocolError("token_type must be DPoP");
  }
  if (typeof expires_in !== "number" || !(expires_in > 0))
    throw new PoppyProtocolError("expires_in must be positive");
  return {
    accessToken: access_token,
    expiresIn: expires_in,
    scope: typeof scope === "string" ? scope : undefined,
    sessionId: typeof session_id === "string" ? session_id : undefined,
    signedIn: typeof signed_in === "boolean" ? signed_in : undefined,
    refreshToken: typeof refresh_token === "string" ? refresh_token : undefined,
  };
}

/** The `error` attribute of a response's `WWW-Authenticate` header, such as `sign_in_required` (spec section 6). */
export function wwwAuthenticateError(response: Response): string | undefined {
  return /\berror="([^"]*)"/.exec(response.headers.get("www-authenticate") ?? "")?.[1];
}

function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    function onAbort() {
      clearTimeout(timer);
      reject(signal?.reason);
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/** A Personal Agent: holds its identity and opens Sessions with Companies for its Users. */
export class PoppyAgent {
  readonly clientId: string;
  readonly #signingKey: SigningKey;
  readonly #store: Store;
  readonly #fetch: Fetch;
  readonly #sessions = new Map<string, Promise<Session>>();
  /**
   * In-flight {@link forget} calls per store key. Opening that User waits for them, so it cannot be erased, and
   * fails when they fail, so it cannot pick up state that was not deleted.
   */
  readonly #forgetting = new Map<string, Promise<void>>();

  constructor(options: PoppyAgentOptions) {
    if (httpsUrl(options.clientId, "clientId").href !== options.clientId) {
      throw new PoppyProtocolError("clientId must be a normalized URL, exactly as published");
    }
    this.clientId = options.clientId;
    this.#signingKey = options.signingKey;
    this.#store = options.store ?? new MemoryStore();
    this.#fetch = options.fetch ?? fetch;
  }

  /** Discovers a Company from its website, using this agent's `fetch`. */
  discover(website: string): Promise<Company> {
    return discover(website, { fetch: this.#fetch });
  }

  /**
   * Opens the Session for `userId` at `company`, resuming a stored one when there is one.
   *
   * `userId` is the opaque ID this agent gives the User for this Company (spec 4.2). It must be stable, differ per
   * Company, and must not contain or be derived from personal data such as an email, even with a keyed hash.
   */
  session(company: Company, userId: string): Promise<Session> {
    if (userId === "") return Promise.reject(new PoppyProtocolError("userId is required"));
    const storeKey = this.#storeKey(company, userId);
    // One live Session per stored state, so two Sessions never overwrite each other's Account Token.
    let session = this.#sessions.get(storeKey);
    if (session === undefined) {
      const forgetting = this.#forgetting.get(storeKey);
      session =
        forgetting === undefined
          ? this.#openSession(company, userId, storeKey)
          : forgetting.then(() => this.#openSession(company, userId, storeKey));
      session.catch(() => this.#sessions.delete(storeKey));
      this.#sessions.set(storeKey, session);
    }
    return session;
  }

  /**
   * Forgets `userId` at `company`: signs the Session out when it is signed in, then deletes its stored state.
   * Sessions opened before stop working; the next {@link session} call starts a new, signed-out one.
   * A failed revocation does not stop the state from being deleted.
   */
  forget(company: Company, userId: string): Promise<void> {
    const storeKey = this.#storeKey(company, userId);
    const open = this.#sessions.get(storeKey);
    this.#sessions.delete(storeKey);
    const previous = this.#forgetting.get(storeKey)?.catch(() => undefined) ?? Promise.resolve();
    const forgetting = previous.then(() => this.#erase(company, userId, storeKey, open));
    this.#forgetting.set(storeKey, forgetting);
    void forgetting
      .catch(() => undefined)
      .then(() => {
        if (this.#forgetting.get(storeKey) === forgetting) this.#forgetting.delete(storeKey);
      });
    return forgetting;
  }

  async #erase(
    company: Company,
    userId: string,
    storeKey: string,
    open: Promise<Session> | undefined,
  ): Promise<void> {
    let session = await open?.catch(() => undefined);
    if (open === undefined && (await this.#hasAccountToken(storeKey))) {
      // Only then: opening a Session without an Account Token would start a new one at the Company.
      session = await this.#openSession(company, userId, storeKey).catch(() => undefined);
    }
    await session?.signOut().catch(() => undefined);
    if (session !== undefined) forgotten.add(session);
    await this.#store.delete(storeKey);
  }

  #storeKey(company: Company, userId: string): string {
    return `poppy:${this.clientId}:${company.issuer}:${userId}`;
  }

  async #hasAccountToken(storeKey: string): Promise<boolean> {
    const stored = await this.#store.get(storeKey);
    if (stored === undefined) return false;
    try {
      return (JSON.parse(stored) as PersistedState).accountToken !== undefined;
    } catch {
      return false;
    }
  }

  async #openSession(company: Company, userId: string, storeKey: string): Promise<Session> {
    const stored = await this.#store.get(storeKey);
    let state: PersistedState;
    let dpopKey: DpopKey;
    if (stored === undefined) {
      const generated = await DpopKey.generate();
      dpopKey = generated.key;
      state = { dpopKey: generated.exported };
      await this.#store.set(storeKey, JSON.stringify(state));
    } else {
      state = JSON.parse(stored) as PersistedState;
      dpopKey = await DpopKey.fromJwk(state.dpopKey);
    }
    const session = new Session({
      company,
      userId,
      clientId: this.clientId,
      signingKey: this.#signingKey,
      fetch: this.#fetch,
      dpopKey,
      state,
      persist: (next) => this.#store.set(storeKey, JSON.stringify(next)),
    });
    await session.renew();
    return session;
  }
}

interface SessionInit {
  company: Company;
  userId: string;
  clientId: string;
  signingKey: SigningKey;
  fetch: Fetch;
  dpopKey: DpopKey;
  state: PersistedState;
  persist: (state: PersistedState) => Promise<void>;
}

type FetchBody = Exclude<RequestInit["body"], ReadableStream | null | undefined>;

/** A Session with one Company for one User (spec 4.2). Get one from {@link PoppyAgent.session}. */
export class Session {
  readonly company: Company;
  readonly #init: SessionInit;
  #state: PersistedState;
  #accessToken: string | undefined;
  #expiresAt = 0;
  #signedIn = false;
  #renewing: Promise<void> | undefined;
  #queue: Promise<unknown> = Promise.resolve();
  readonly #nonces = new Map<string, string>();

  constructor(init: SessionInit) {
    this.company = init.company;
    this.#init = init;
    this.#state = init.state;
  }

  /** The Session ID. Not a credential. Undefined if the Company did not return one. */
  get sessionId(): string | undefined {
    return this.#state.sessionId;
  }

  get signedIn(): boolean {
    return this.#signedIn;
  }

  /** The account scopes the current Session Token carries, space-separated. Empty when signed out. */
  get scope(): string {
    return this.#state.scope ?? "";
  }

  /**
   * Gets a new Session Token now: with the Account Token when there is one (spec 4.8), else with a fresh Session
   * assertion (4.2). Concurrent calls share one request.
   */
  renew(): Promise<void> {
    this.#renewing ??= this.#serial(() => this.#renew()).finally(() => {
      this.#renewing = undefined;
    });
    return this.#renewing;
  }

  async #renew(): Promise<void> {
    this.#ensureNotForgotten();
    if (this.#state.accountToken !== undefined) {
      try {
        await this.#renewWith(() => this.#refreshParams(), this.#state.scope ?? "");
        return;
      } catch (error) {
        if (!(error instanceof PoppyError) || error.error !== "invalid_grant") throw error;
        // Spec 4.8: the Account Token expired or was revoked; the Session continues signed out.
        await this.#forgetAccount();
      }
    }
    await this.#renewWith(() => this.#assertionParams(), "");
  }

  /** Runs `task` after every earlier one settles, so token, sign-out and Session ID writes never interleave. */
  #serial<T>(task: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(task, task);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  /** `fallbackScope` is the scope to keep when the Company's response omits `scope` (RFC 6749 section 5.1). */
  async #renewWith(
    params: () => Promise<Record<string, string>>,
    fallbackScope: string,
  ): Promise<void> {
    try {
      await this.#applyToken(await this.#tokenRequest(params), fallbackScope);
    } catch (error) {
      const ended = error instanceof PoppyError && SESSION_ENDED.has(error.error);
      if (!ended || this.#state.sessionId === undefined) throw error;
      await this.#persist({ ...this.#state, sessionId: undefined });
      await this.#applyToken(await this.#tokenRequest(params), fallbackScope);
    }
  }

  async #assertionParams(): Promise<Record<string, string>> {
    const { clientId, userId, company, signingKey } = this.#init;
    const iat = nowSeconds();
    const assertion = await signJwt(
      { typ: "JWT", kid: signingKey.kid },
      {
        iss: clientId,
        sub: userId,
        aud: company.issuer,
        iat,
        exp: iat + ASSERTION_LIFETIME,
        jti: randomId(),
      },
      signingKey.privateKey,
    );
    return { grant_type: JWT_BEARER, assertion, ...this.#sessionParam() };
  }

  async #refreshParams(): Promise<Record<string, string>> {
    return {
      grant_type: "refresh_token",
      refresh_token: this.#state.accountToken ?? "",
      ...this.#sessionParam(),
    };
  }

  #sessionParam(): Record<string, string> {
    return this.#state.sessionId === undefined ? {} : { session_id: this.#state.sessionId };
  }

  async #clientAuth(): Promise<Record<string, string>> {
    const { clientId, company, signingKey } = this.#init;
    const iat = nowSeconds();
    const assertion = await signJwt(
      { typ: "JWT", kid: signingKey.kid },
      {
        iss: clientId,
        sub: clientId,
        aud: company.issuer,
        iat,
        exp: iat + ASSERTION_LIFETIME,
        jti: randomId(),
      },
      signingKey.privateKey,
    );
    return {
      client_id: clientId,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion,
    };
  }

  #rememberNonce(url: string, response: Response): void {
    const nonce = response.headers.get("dpop-nonce");
    if (nonce !== null) this.#nonces.set(new URL(url).origin, nonce);
  }

  async #tokenRequest(params: () => Promise<Record<string, string>>): Promise<TokenResponse> {
    const url = this.company.tokenEndpoint;
    for (let attempt = 0; ; attempt++) {
      const nonce = this.#nonces.get(new URL(url).origin);
      const proof = await this.#init.dpopKey.proof(
        "POST",
        url,
        nonce === undefined ? {} : { nonce },
      );
      const body = new URLSearchParams({ ...(await params()), ...(await this.#clientAuth()) });
      const response = await postForm(this.#init.fetch, url, body, { dpop: proof });
      this.#rememberNonce(url, response);
      if (response.ok) {
        try {
          return parseTokenResponse(await response.json());
        } catch (error) {
          throw error instanceof PoppyError
            ? error
            : new PoppyProtocolError("token response is not JSON");
        }
      }
      const error = await errorFromResponse(response);
      if (error.error !== "use_dpop_nonce" || attempt > 0) throw error;
    }
  }

  async #applyToken(token: TokenResponse, fallbackScope: string): Promise<string> {
    const next: PersistedState = {
      ...this.#state,
      sessionId: token.sessionId ?? this.#state.sessionId,
      scope: token.scope ?? fallbackScope,
      ...(token.refreshToken === undefined ? {} : { accountToken: token.refreshToken }),
    };
    await this.#persist(next);
    this.#accessToken = token.accessToken;
    this.#expiresAt = Date.now() + token.expiresIn * 1000;
    this.#signedIn = token.signedIn ?? next.accountToken !== undefined;
    return next.scope ?? "";
  }

  #ensureNotForgotten(): void {
    if (forgotten.has(this)) throw new PoppyProtocolError("this Session was forgotten");
  }

  async #persist(state: PersistedState): Promise<void> {
    this.#ensureNotForgotten();
    await this.#init.persist(state);
    this.#state = state;
  }

  async #forgetAccount(): Promise<void> {
    const { accountToken: _, ...rest } = this.#state;
    await this.#persist({ ...rest, scope: "" });
    this.#accessToken = undefined;
    this.#expiresAt = 0;
    this.#signedIn = false;
  }

  async #currentToken(): Promise<string> {
    this.#ensureNotForgotten();
    if (this.#accessToken === undefined || Date.now() >= this.#expiresAt - EXPIRY_MARGIN * 1000)
      await this.renew();
    if (this.#accessToken === undefined) throw new PoppyProtocolError("no Session Token");
    return this.#accessToken;
  }

  /**
   * Calls a Company API with the Session Token and a DPoP Proof (spec 4.3, section 6).
   *
   * The URL must be https and on the Company's domain, a subdomain of it, or an API or Company Agent host from
   * poppy.json. Redirects are returned, not followed. Retries once on a DPoP nonce challenge and once on
   * `invalid_token`. Other 401 and 403 responses are returned for the caller to handle; see
   * {@link wwwAuthenticateError}.
   */
  async fetch(
    input: string | URL,
    init: Omit<RequestInit, "body" | "redirect"> & { body?: FetchBody } = {},
  ): Promise<Response> {
    const url = httpsUrl(String(input), "API URL");
    if (!isAllowedHost(this.company, url.hostname)) {
      throw new PoppyProtocolError(`${url.hostname} is not a host of ${this.company.domain}`);
    }
    if (url.username !== "" || url.password !== "")
      throw new PoppyProtocolError("API URL must not carry credentials");
    if (init.body instanceof ReadableStream) {
      throw new PoppyProtocolError(
        "streaming bodies are not supported, since a retry resends the body",
      );
    }
    const method = (init.method ?? "GET").toUpperCase();
    let nonceRetried = false;
    let renewed = false;
    for (;;) {
      const token = await this.#currentToken();
      const nonce = this.#nonces.get(url.origin);
      const proof = await this.#init.dpopKey.proof(
        method,
        url.href,
        nonce === undefined ? { accessToken: token } : { accessToken: token, nonce },
      );
      const headers = new Headers(init.headers);
      headers.set("authorization", `DPoP ${token}`);
      headers.set("dpop", proof);
      const response = await this.#init.fetch(url, {
        ...init,
        method,
        headers,
        redirect: "manual",
      });
      this.#rememberNonce(url.href, response);
      if (response.status !== 401) return response;
      const error = wwwAuthenticateError(response);
      if (error === "use_dpop_nonce" && !nonceRetried) {
        nonceRetried = true;
      } else if (error === "invalid_token" && !renewed) {
        renewed = true;
        await this.renew();
      } else {
        return response;
      }
      await response.body?.cancel();
    }
  }

  /**
   * Starts Device Sign-In (spec 4.6). Show the User `verificationUri` and `userCode`, then call
   * {@link DeviceSignIn.wait}.
   *
   * @param scope Space-separated scopes the task needs, each from `company.deviceScopes`.
   */
  async startDeviceSignIn(scope: string): Promise<DeviceSignIn> {
    const { deviceAuthorizationEndpoint, deviceScopes } = this.company;
    if (deviceAuthorizationEndpoint === undefined || deviceScopes === undefined) {
      throw new PoppyProtocolError(`${this.company.domain} does not offer Device Sign-In`);
    }
    const requested = scope.split(" ").filter(Boolean);
    const unavailable = requested.filter((item) => !deviceScopes.includes(item));
    if (requested.length === 0 || unavailable.length > 0) {
      throw new PoppyError("invalid_scope", {
        description: `request scopes from: ${deviceScopes.join(" ")}`,
      });
    }
    const body = new URLSearchParams({ scope: requested.join(" "), ...(await this.#clientAuth()) });
    const response = await postForm(this.#init.fetch, deviceAuthorizationEndpoint, body);
    if (!response.ok) throw await errorFromResponse(response);
    const data: unknown = await response.json().catch(() => undefined);
    if (!isObject(data))
      throw new PoppyProtocolError("device authorization response must be an object");
    const {
      device_code,
      user_code,
      verification_uri,
      verification_uri_complete,
      expires_in,
      interval,
    } = data;
    if (
      typeof device_code !== "string" ||
      typeof user_code !== "string" ||
      typeof expires_in !== "number"
    ) {
      throw new PoppyProtocolError("device authorization response is missing fields");
    }
    return new DeviceSignIn(
      {
        userCode: user_code,
        verificationUri: httpsUrl(verification_uri, "verification_uri").href,
        verificationUriComplete:
          verification_uri_complete === undefined
            ? undefined
            : httpsUrl(verification_uri_complete, "verification_uri_complete").href,
        expiresIn: expires_in,
        interval: typeof interval === "number" && interval > 0 ? interval : 5,
      },
      device_code,
      async (deviceCode) => {
        try {
          return await this.#tokenRequest(async () => ({
            grant_type: DEVICE_CODE,
            device_code: deviceCode,
            ...this.#sessionParam(),
          }));
        } catch (error) {
          // Spec 4.4: this Session cannot be signed in; the User signs in again in a new Session.
          if (error instanceof PoppyError && SESSION_ENDED.has(error.error)) {
            await this.#serial(() => this.#persist({ ...this.#state, sessionId: undefined }));
          }
          throw error;
        }
      },
      (token) => this.#serial(() => this.#applyToken(token, requested.join(" "))),
    );
  }

  /**
   * Signs out: revokes the Account Token (spec 4.9). The Session continues signed out.
   * Does nothing when not signed in.
   */
  signOut(): Promise<void> {
    return this.#serial(() => this.#signOut());
  }

  async #signOut(): Promise<void> {
    const token = this.#state.accountToken;
    if (token === undefined) return;
    const body = new URLSearchParams({
      token,
      token_type_hint: "refresh_token",
      ...(await this.#clientAuth()),
    });
    const response = await postForm(this.#init.fetch, this.company.revocationEndpoint, body);
    if (!response.ok) throw await errorFromResponse(response);
    await this.#forgetAccount();
  }
}

/** What to show the User for a pending {@link DeviceSignIn} (RFC 8628 section 3.2). */
export interface DeviceSignInDetails {
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string | undefined;
  /** Seconds until the request expires. */
  expiresIn: number;
  /** Seconds between polls. */
  interval: number;
}

/** A pending Device Sign-In. The device code stays private to this object. */
export class DeviceSignIn {
  readonly userCode: string;
  readonly verificationUri: string;
  readonly verificationUriComplete: string | undefined;
  readonly expiresIn: number;
  #interval: number;
  readonly #deviceCode: string;
  readonly #poll: (deviceCode: string) => Promise<TokenResponse>;
  readonly #complete: (token: TokenResponse) => Promise<string>;
  readonly #deadline: number;

  constructor(
    details: DeviceSignInDetails,
    deviceCode: string,
    poll: (deviceCode: string) => Promise<TokenResponse>,
    complete: (token: TokenResponse) => Promise<string>,
  ) {
    this.userCode = details.userCode;
    this.verificationUri = details.verificationUri;
    this.verificationUriComplete = details.verificationUriComplete;
    this.expiresIn = details.expiresIn;
    this.#interval = details.interval;
    this.#deviceCode = deviceCode;
    this.#poll = poll;
    this.#complete = complete;
    this.#deadline = Date.now() + details.expiresIn * 1000;
  }

  /**
   * Polls until the User finishes, then signs the Session in. Resolves with the granted scopes, which may be
   * fewer than requested (spec 4.4). Rejects with `access_denied` or `expired_token`, or the signal's reason.
   */
  async wait(options: { signal?: AbortSignal } = {}): Promise<{ scope: string }> {
    for (;;) {
      if (Date.now() + this.#interval * 1000 > this.#deadline)
        throw new PoppyError("expired_token");
      await sleep(this.#interval * 1000, options.signal);
      try {
        const token = await this.#poll(this.#deviceCode);
        return { scope: await this.#complete(token) };
      } catch (error) {
        if (!(error instanceof PoppyError)) throw error;
        if (error.error === "slow_down") this.#interval += 5;
        else if (error.error !== "authorization_pending") throw error;
      }
    }
  }
}
