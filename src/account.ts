import { type Company, DEVICE_CODE_GRANT, MEDIATED_SIGN_IN_GRANT } from "./discovery.ts";
import { DpopKey } from "./dpop.ts";
import { errorBodies, errorFromResponse, PoppyError, PoppyProtocolError } from "./errors.ts";
import { type Fetch, isObject, postForm, sleep } from "./http.ts";
import { randomId, type Signer } from "./jose.ts";
import {
  checkSignInUrl,
  clientAuth,
  issuerUsesDpop,
  type OAuthContext,
  oauthError,
  parseTokenResponse,
  pkce,
  requireOAuth,
  revokeRefreshToken,
  splitScope,
  tokenRequest,
  type TokenResponse,
} from "./oauth.ts";
import type { ResourceChoice } from "./resources.ts";
import type { Store } from "./store.ts";

/** Refresh access tokens this long before they expire. */
const EXPIRY_MARGIN = 30_000;
/** Assumed lifetime of an access token whose response has no `expires_in`. */
const DEFAULT_LIFETIME = 300;

interface AccountState {
  refreshToken?: string;
  /** Space-separated scopes of the refresh token. */
  scope?: string;
  dpopKey?: JsonWebKey;
}

/** An access token, held in memory only (spec 10.2). */
export interface AccessToken {
  value: string;
  type: "Bearer" | "DPoP";
  expiresAt: number;
  scope: readonly string[];
}

export interface PendingDirectSignIn {
  identifier: string;
  issuer: string;
  localUserId: string;
  account: string;
  agent: string | undefined;
  verifier: string;
  redirectUri: string;
  scope: string[];
  expiresAt: number;
}

export interface AccountInit {
  clientId: string;
  signer: Signer;
  fetch: Fetch;
  store: Store;
  storeKey: string;
  company: Company;
}

export const PENDING_PREFIX = "poppy:0.3:direct:";
export const PENDING_LIFETIME = 10 * 60_000;

/**
 * One account at one Company (spec 4): its refresh token, persisted in the store, and its access tokens,
 * kept in memory per `resource`. Token writes run one at a time, so a rotated refresh token is never lost.
 */
export class Account {
  readonly #init: AccountInit;
  #state: AccountState = {};
  #dpop: DpopKey | undefined;
  readonly #nonces = new Map<string, string>();
  readonly #tokens = new Map<string, Promise<AccessToken | undefined>>();
  #queue: Promise<unknown> = Promise.resolve();
  #generation = 0;
  #forgotten = false;

  constructor(init: AccountInit) {
    this.#init = init;
  }

  async load(): Promise<void> {
    const stored = await this.#init.store.get(this.#init.storeKey);
    if (stored === undefined) return;
    try {
      this.#state = JSON.parse(stored) as AccountState;
    } catch {
      // V8's SyntaxError quotes the input, which holds the refresh token.
      throw new PoppyProtocolError("stored account state is not valid JSON");
    }
  }

  get signedIn(): boolean {
    return this.#state.refreshToken !== undefined;
  }

  /** Scopes of the refresh token. Empty when signed out. */
  get scope(): string[] {
    return this.signedIn ? splitScope(this.#state.scope ?? "") : [];
  }

  /** Refuses to start sign-in when the Company sets `auth.disabled` (spec 3.2). */
  #checkSignInAllowed(): void {
    const company = this.#init.company;
    if (company.signIn.disabled)
      throw new PoppyProtocolError(`${company.domain} offers Personal Agents no sign-in`);
  }

  #context(): OAuthContext {
    const { clientId, signer, fetch, company } = this.#init;
    return { clientId, signer, fetch, company, oauth: requireOAuth(company) };
  }

  #serial<T>(task: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(task, task);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async #persist(state: AccountState): Promise<void> {
    if (this.#forgotten) throw new PoppyProtocolError("this account was forgotten");
    // A rotated refresh token is already the only valid one, even if the write fails.
    this.#state = state;
    await this.#init.store.set(this.#init.storeKey, JSON.stringify(state));
  }

  /**
   * The account's DPoP key (spec 4.5), generated once and kept in the store. Each Account belongs to one
   * of the agent's Users at one Company identifier, and so to one User ID, so a key never signs for two
   * Users and Companies can't match a User by its thumbprint, as 0.4 requires of delegated keys too.
   */
  async #dpopKey(): Promise<DpopKey> {
    if (this.#dpop !== undefined) return this.#dpop;
    if (this.#state.dpopKey !== undefined) {
      this.#dpop = await DpopKey.fromJwk(this.#state.dpopKey);
    } else {
      const generated = await DpopKey.generate();
      this.#dpop = generated.key;
      await this.#persist({ ...this.#state, dpopKey: generated.exported });
    }
    return this.#dpop;
  }

  /**
   * The DPoP key for a token request, when the issuer supports DPoP. The issuer then decides, for each
   * token, whether to bind it, and the token's `token_type` says which it did (spec 4.5).
   */
  async #dpopFor(): Promise<{ key: DpopKey; nonces: Map<string, string> } | undefined> {
    if (!issuerUsesDpop(this.#context().oauth)) return undefined;
    return { key: await this.#dpopKey(), nonces: this.#nonces };
  }

  /** The DPoP key and nonces for a resource request with a DPoP-bound token. */
  async dpopForRequest(): Promise<{ key: DpopKey; nonces: Map<string, string> }> {
    return { key: await this.#dpopKey(), nonces: this.#nonces };
  }

  /**
   * An access token for a request, or undefined when signed out (spec 4.5). Gets one with the refresh token
   * when needed, for the service's own `resource` if it has one.
   */
  accessToken(choice: ResourceChoice): Promise<AccessToken | undefined> {
    if (!this.signedIn) return Promise.resolve(undefined);
    const key = choice.resource ?? "";
    const cached = this.#tokens.get(key);
    if (cached !== undefined) {
      return cached.then((token) =>
        token !== undefined && Date.now() < token.expiresAt - EXPIRY_MARGIN
          ? token
          : this.#tokens.get(key) !== cached
            ? this.accessToken(choice)
            : this.#refreshInto(key, choice),
      );
    }
    return this.#refreshInto(key, choice);
  }

  /** Drops a token a resource rejected with `invalid_token`, so the next request gets a new one. */
  invalidate(choice: ResourceChoice): void {
    this.#tokens.delete(choice.resource ?? "");
  }

  #refreshInto(key: string, choice: ResourceChoice): Promise<AccessToken | undefined> {
    const pending = this.#serial(() => this.#refresh(choice)).catch((error: unknown) => {
      if (this.#tokens.get(key) === pending) this.#tokens.delete(key);
      throw error;
    });
    this.#tokens.set(key, pending);
    return pending;
  }

  /**
   * Refreshes (spec 4.4). On `invalid_grant` the User or Company ended access, so the account continues
   * signed out and this resolves undefined (spec 5.5).
   */
  async #refresh(
    choice: ResourceChoice,
    scope?: readonly string[],
  ): Promise<AccessToken | undefined> {
    const refreshToken = this.#state.refreshToken;
    if (refreshToken === undefined) return undefined;
    const requested = scope ?? splitScope(this.#state.scope ?? "");
    let body: unknown;
    try {
      body = await tokenRequest(
        this.#context(),
        {
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          ...(scope === undefined ? {} : { scope: requested.join(" ") }),
          ...(choice.resource === undefined ? {} : { resource: choice.resource }),
        },
        await this.#dpopFor(),
      );
    } catch (error) {
      if (oauthError(error, "invalid_grant") && this.#state.refreshToken === refreshToken) {
        await this.#dropAccount();
        return undefined;
      }
      throw error;
    }
    const token = parseTokenResponse(body, requested);
    if (token.refreshToken !== undefined && token.refreshToken !== refreshToken)
      await this.#persist({ ...this.#state, refreshToken: token.refreshToken });
    return toAccessToken(token);
  }

  /** Gets an access token with fewer scopes than the refresh token, such as read-only for a lookup. */
  async narrowedToken(
    choice: ResourceChoice,
    scope: string | readonly string[],
  ): Promise<AccessToken | undefined> {
    return this.#serial(() => this.#refresh(choice, splitScope(scope)));
  }

  async #dropAccount(): Promise<void> {
    this.#tokens.clear();
    this.#generation++;
    const { refreshToken: _, scope: __, ...rest } = this.#state;
    await this.#persist(rest);
  }

  /**
   * Stores a sign-in's tokens (spec 4.7). The new refresh token replaces the old, which is revoked; that
   * isn't sign-out. A sign-in that started before a sign-out is revoked instead.
   */
  #complete(token: TokenResponse, generation: number): Promise<string[]> {
    return this.#serial(async () => {
      if (token.refreshToken === undefined)
        throw new PoppyProtocolError("sign-in returned no refresh token");
      if (generation !== this.#generation) {
        await revokeRefreshToken(this.#context(), token.refreshToken).catch(() => undefined);
        throw new PoppyProtocolError("the account signed out while sign-in was pending");
      }
      const previous = this.#state.refreshToken;
      await this.#persist({
        ...this.#state,
        refreshToken: token.refreshToken,
        scope: token.scope.join(" "),
      });
      this.#tokens.clear();
      this.#tokens.set("", Promise.resolve(toAccessToken(token)));
      if (previous !== undefined && previous !== token.refreshToken)
        await revokeRefreshToken(this.#context(), previous).catch(() => undefined);
      return token.scope;
    });
  }

  /** The scopes a new sign-in requests: those asked for, plus those already held unless replacing. */
  #requestedScopes(scope: string | readonly string[], replace: boolean | undefined): string[] {
    const requested = splitScope(scope);
    if (requested.length === 0)
      throw new PoppyError("invalid_scope", { description: "scope is required" });
    return replace === true ? requested : splitScope([...this.scope, ...requested]);
  }

  /** Starts Direct Sign-In (spec 4.2): returns the URL to open in the User's browser. */
  async startDirect(
    options: { scope: string | readonly string[]; redirectUri: string; replaceScopes?: boolean },
    pending: Omit<
      PendingDirectSignIn,
      "verifier" | "redirectUri" | "scope" | "expiresAt" | "issuer" | "identifier"
    >,
  ): Promise<{ url: string; state: string }> {
    this.#checkSignInAllowed();
    const { oauth } = this.#context();
    if (oauth.authorizationEndpoint === undefined)
      throw new PoppyProtocolError(`${this.#init.company.domain} does not offer Direct Sign-In`);
    const scope = this.#requestedScopes(options.scope, options.replaceScopes);
    const { verifier, challenge } = await pkce();
    const state = randomId();
    const record: PendingDirectSignIn = {
      ...pending,
      identifier: this.#init.company.identifier,
      issuer: oauth.issuer,
      verifier,
      redirectUri: options.redirectUri,
      scope,
      expiresAt: Date.now() + PENDING_LIFETIME,
    };
    await this.#init.store.set(`${PENDING_PREFIX}${state}`, JSON.stringify(record));
    const url = new URL(oauth.authorizationEndpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.#init.clientId);
    url.searchParams.set("redirect_uri", options.redirectUri);
    url.searchParams.set("scope", scope.join(" "));
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    return { url: url.href, state };
  }

  /**
   * Finishes Direct Sign-In from the redirect back (spec 4.2). Checks `iss` against the issuer sign-in
   * started with (RFC 9207), including on errors, then exchanges the code.
   */
  async completeDirect(record: PendingDirectSignIn, params: URLSearchParams): Promise<string[]> {
    const generation = this.#generation;
    const { oauth } = this.#context();
    if (params.get("iss") !== record.issuer || oauth.issuer !== record.issuer)
      throw new PoppyProtocolError("the sign-in response is not from this Company's issuer");
    const error = params.get("error");
    if (error !== null)
      throw new PoppyError(error, { description: params.get("error_description")?.slice(0, 200) });
    const code = params.get("code");
    if (code === null) throw new PoppyProtocolError("the sign-in response has no code");
    const body = await tokenRequest(
      this.#context(),
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: record.redirectUri,
        code_verifier: record.verifier,
      },
      await this.#dpopFor(),
    );
    return this.#complete(parseTokenResponse(body, record.scope), generation);
  }

  /** Starts Device Sign-In (spec 4.3). */
  async startDevice(options: {
    scope: string | readonly string[];
    replaceScopes?: boolean;
  }): Promise<DeviceSignIn> {
    this.#checkSignInAllowed();
    const generation = this.#generation;
    const context = this.#context();
    const { oauth, company } = context;
    if (oauth.deviceAuthorizationEndpoint === undefined)
      throw new PoppyProtocolError(`${company.domain} does not offer Device Sign-In`);
    const scope = this.#requestedScopes(options.scope, options.replaceScopes);
    const response = await postForm(
      context.fetch,
      oauth.deviceAuthorizationEndpoint,
      new URLSearchParams({ scope: scope.join(" "), ...(await this.#clientAuth()) }),
    );
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
    )
      throw new PoppyProtocolError("device authorization response is missing fields");
    return new DeviceSignIn(
      {
        organizationName: company.name,
        domain: company.domain,
        userCode: user_code,
        verificationUri: checkSignInUrl(company, verification_uri, "verification_uri"),
        verificationUriComplete:
          verification_uri_complete === undefined
            ? undefined
            : checkSignInUrl(company, verification_uri_complete, "verification_uri_complete"),
        expiresIn: expires_in,
        interval: typeof interval === "number" && interval > 0 ? interval : 5,
      },
      device_code,
      async (deviceCode) =>
        parseTokenResponse(
          await tokenRequest(
            this.#context(),
            { grant_type: DEVICE_CODE_GRANT, device_code: deviceCode },
            await this.#dpopFor(),
          ),
          scope,
        ),
      (token) => this.#complete(token, generation),
    );
  }

  #clientAuth(): Promise<Record<string, string>> {
    return clientAuth(this.#context());
  }

  /**
   * Mediated Sign-In (extension, transitional). Sends the credentials only to the issuer's token endpoint
   * with the extension's grant, and never keeps them.
   */
  async mediated(options: {
    scope: string | readonly string[];
    credentials: Readonly<Record<string, string>>;
  }): Promise<MediatedSignInResult> {
    this.#checkSignInAllowed();
    const generation = this.#generation;
    const { company } = this.#init;
    const config = company.signIn.mediated;
    if (config === undefined)
      throw new PoppyProtocolError(`${company.domain} does not offer Mediated Sign-In`);
    const scope = splitScope(options.scope);
    const unavailable = scope.filter((item) => !config.scopes.includes(item));
    if (scope.length === 0 || unavailable.length > 0)
      throw new PoppyError("invalid_scope", {
        description: `request scopes from: ${config.scopes.join(" ")}`,
      });
    const names = config.fields.map((field) => field.name);
    const given = Object.keys(options.credentials);
    if (names.some((name) => !given.includes(name)) || given.some((name) => !names.includes(name)))
      throw new PoppyProtocolError(`credentials must be exactly: ${names.join(", ")}`);
    return this.#mediatedStep(
      { grant_type: MEDIATED_SIGN_IN_GRANT, scope: scope.join(" "), ...options.credentials },
      scope,
      generation,
    );
  }

  async #mediatedStep(
    params: Record<string, string>,
    scope: string[],
    generation: number,
  ): Promise<MediatedSignInResult> {
    const { company } = this.#init;
    try {
      const body = await tokenRequest(this.#context(), params, await this.#dpopFor());
      return {
        status: "signed_in",
        scope: await this.#complete(parseTokenResponse(body, scope), generation),
      };
    } catch (error) {
      if (!(error instanceof PoppyError) || error.error !== "code_required") throw error;
      const body = errorBodies.get(error);
      const signInId = body?.["sign_in_id"];
      if (typeof signInId !== "string")
        throw new PoppyProtocolError("code_required has no sign_in_id");
      const sentTo = body?.["sent_to"];
      const expiresIn = body?.["expires_in"];
      return {
        status: "code_required",
        organizationName: company.name,
        domain: company.domain,
        sentTo: typeof sentTo === "string" ? sentTo : undefined,
        expiresIn: typeof expiresIn === "number" ? expiresIn : undefined,
        submitCode: (code: string) =>
          this.#mediatedStep(
            { grant_type: MEDIATED_SIGN_IN_GRANT, sign_in_id: signInId, one_time_code: code },
            scope,
            generation,
          ),
      };
    }
  }

  /** Signs out (spec 5.5): revokes the refresh token. Sessions continue signed out. */
  signOut(): Promise<void> {
    return this.#serial(async () => {
      this.#generation++;
      const token = this.#state.refreshToken;
      if (token === undefined) return;
      await revokeRefreshToken(this.#context(), token);
      await this.#dropAccount();
    });
  }

  /** Signs out, then deletes the stored state. Further use of this account fails. */
  forget(): Promise<void> {
    return this.#serial(async () => {
      this.#generation++;
      const token = this.#state.refreshToken;
      if (token !== undefined) await revokeRefreshToken(this.#context(), token);
      this.#tokens.clear();
      this.#forgotten = true;
      await this.#init.store.delete(this.#init.storeKey);
    });
  }
}

function toAccessToken(token: TokenResponse): AccessToken {
  return {
    value: token.accessToken,
    type: token.tokenType,
    expiresAt: Date.now() + (token.expiresIn ?? DEFAULT_LIFETIME) * 1000,
    scope: token.scope,
  };
}

/** The result of a Mediated Sign-In step. */
export type MediatedSignInResult =
  | { status: "signed_in"; scope: string[] }
  | {
      status: "code_required";
      /** Show the Company's name and domain whenever you ask the User for a code. */
      organizationName: string;
      domain: string;
      /** Where the Company sent the code, such as "Text to the phone number ending in 71". */
      sentTo: string | undefined;
      expiresIn: number | undefined;
      /** Sends the one-time code the User gives you. */
      submitCode(code: string): Promise<MediatedSignInResult>;
    };

/** What to show the User for a pending {@link DeviceSignIn} (RFC 8628 section 3.2, spec 4.3). */
export interface DeviceSignInDetails {
  /** Show the Company's name and domain with the link (spec 4.3). */
  organizationName: string;
  domain: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string | undefined;
  /** Seconds until the request expires. */
  expiresIn: number;
  /** Seconds between polls. */
  interval: number;
}

/** A pending Device Sign-In. The device code stays private to this object (spec 10.2). */
export class DeviceSignIn implements Readonly<DeviceSignInDetails> {
  readonly organizationName: string;
  readonly domain: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly verificationUriComplete: string | undefined;
  readonly expiresIn: number;
  #interval: number;
  readonly #deviceCode: string;
  readonly #poll: (deviceCode: string) => Promise<TokenResponse>;
  readonly #complete: (token: TokenResponse) => Promise<string[]>;
  readonly #deadline: number;

  constructor(
    details: DeviceSignInDetails,
    deviceCode: string,
    poll: (deviceCode: string) => Promise<TokenResponse>,
    complete: (token: TokenResponse) => Promise<string[]>,
  ) {
    this.organizationName = details.organizationName;
    this.domain = details.domain;
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

  get interval(): number {
    return this.#interval;
  }

  /**
   * Polls until the User finishes, then stores the tokens. Resolves with the granted scopes, which may be
   * fewer than requested (spec 4.7). Rejects with `access_denied` or `expired_token`, or the signal's reason.
   */
  async wait(options: { signal?: AbortSignal } = {}): Promise<{ scope: string[] }> {
    for (;;) {
      if (Date.now() + this.#interval * 1000 > this.#deadline)
        throw new PoppyError("expired_token");
      await sleep(this.#interval * 1000, options.signal);
      try {
        return { scope: await this.#complete(await this.#poll(this.#deviceCode)) };
      } catch (error) {
        if (!(error instanceof PoppyError)) throw error;
        if (error.error === "slow_down") this.#interval += 5;
        else if (error.error !== "authorization_pending") throw error;
      }
    }
  }
}
