import { companySupports, type Company } from "./discovery.ts";
import { PoppyError, PoppyProtocolError, parseRetryAfter } from "./errors.ts";
import { isObject, sleep } from "./http.ts";
import { randomId } from "./jose.ts";
import { type Approval, approvalField, type Operation, parseOperation } from "./operations.ts";
import { type Session, throwable } from "./session.ts";

const ID = /^[A-Za-z0-9_-]{1,256}$/;
/** How long a long-poll read asks the Company to hold the request, in seconds (spec 8.5). */
const POLL_WAIT = 30;
const RECONNECT_DELAY = 1000;

/**
 * The 0.3 `status`: `idle`, `queued` and `closed`, or `working`, which unknown values also read as
 * (0.3 spec 8.7).
 *
 * 0.4 replaced it with {@link ConversationState}'s four independent fields, because a conversation can be
 * in several of these at once. {@link Conversation.status} still reports one of these values on both
 * versions, derived from the state, so code written for 0.3 keeps working.
 */
export type ConversationStatus = "working" | "idle" | "queued" | "closed";
/** `none`, or `pending` while the Company looks for a person (spec 8.7, 8.9). */
export type Handoff = "none" | "pending";
/** `agent`, or `human`, which unknown values also read as (spec 8.7). */
export type Responder = "agent" | "human";

/**
 * A conversation's state (spec 8.7). From 0.4 the Company reports these four independent fields, so the
 * Company Agent can keep answering while the Company looks for a person. On 0.3 they are derived from
 * `status`, which carries one value at a time.
 */
export interface ConversationState {
  /** The Company has work in progress, including a request it accepted but hasn't acted on. */
  working: boolean;
  /** `pending` while the Company is looking for a person to join. */
  handoff: Handoff;
  /** Who is handling the Company side. */
  responder: Responder;
  /** The conversation takes no more messages, handoff requests or handoff cancels. */
  closed: boolean;
}

/** Who wrote a message (spec 8.4, 8.8). */
export interface Author {
  /** `human` only for the User's own words; summaries and translations are `agent` (spec 8.8). */
  type: "agent" | "human";
  /** Company messages only: a stable ID, a display name and a picture URL. Content from the Company. */
  id?: string;
  name?: string;
  image?: string;
}

/** Facts about the User's situation (spec 8.4). Fields left out keep their previous values. */
export interface MessageContext {
  /** RFC 5646 language tag, such as `en-US`. */
  locale?: string;
  /** IANA time zone name, such as `America/Los_Angeles`. */
  time_zone?: string;
  /** Whether the User can answer questions right now. */
  user_available?: boolean;
  [field: string]: unknown;
}

/** A web page a Company message refers to (Links extension section 3). Content from the Company. */
export interface MessageLink {
  /** HTTPS. A title can name a page other than the one at its URL, so show the URL's domain too. */
  url: string;
  title: string | undefined;
}

/** A notice the Company marked apart from the rest of a message (Disclosures extension section 3). */
export interface Disclosure {
  text: string;
}

/** A message the agent sends. Needs at least one of `text`, `data`, `context` or `approval`. */
export interface OutgoingMessage {
  /**
   * Unique for the User; reuse it to retry the same request (spec 8.3). Generated when left out. On 0.3
   * it is the message's ID; from 0.4 it is the request's ID, which the message takes as its own.
   */
  id?: string;
  /** Defaults to `{ type: "agent" }`. */
  author?: { type: "agent" | "human" };
  text?: string;
  data?: Record<string, unknown>;
  context?: MessageContext;
  /**
   * The last cursor the agent had read when it wrote this message (spec 8.4), from 0.4, so the Company
   * can tell which of its messages the agent had seen. A hint only, and only on a message the agent
   * wrote: a message with `author.type` `human` must not carry it. Ignored on 0.3.
   */
  asOfCursor?: string;
  /**
   * The User's approval of an operation, sent in `extensions.operations` (Operations extension section 6).
   * Only to a Company that lists the Operations extension, version 2.
   */
  approval?: Approval;
}

/** A message from either side, as the Company recorded it (spec 8.4). */
export interface ConversationMessage {
  /** The Company sets it when it records the message: the request's ID for the agent's own messages. */
  id: string;
  /** `user` or `company`, the side it came from. */
  role: string;
  author: Author;
  text: string | undefined;
  data: Readonly<Record<string, unknown>> | undefined;
  context: Readonly<Record<string, unknown>> | undefined;
  /**
   * On a message from the Company Agent, the ID of the latest request it took into account (spec 8.4),
   * from 0.4. A hint for matching a short reply to what it answers, never something to depend on.
   */
  asOfRequest: string | undefined;
  /** On a message the agent wrote, the last cursor it had read when it wrote it (spec 8.4), from 0.4. */
  asOfCursor: string | undefined;
  /** Content defined by extensions, keyed by extension name, as sent (spec 8.4). */
  extensions: Readonly<Record<string, unknown>> | undefined;
  /** An operation awaiting the User's approval, from `extensions.operations` (Operations section 4). */
  operation: Operation | undefined;
  /** Links from `extensions.links` (Links extension). Empty when there are none. */
  links: readonly MessageLink[];
  /** Disclosures from `extensions.disclosures` (Disclosures extension). Empty when there are none. */
  disclosures: readonly Disclosure[];
}

interface EventBase {
  id: string;
  /** RFC 3339. */
  createdAt: string;
}

/**
 * An event in a conversation (spec 8.5). Events of unknown types are skipped.
 *
 * A `state` event carries `handoff`, `responder` and `closed` from 0.4, and `status` and `responder` on
 * 0.3; both are read into the same fields, with the ones the version doesn't send derived from the ones
 * it does. `working` is not an event on either version (spec 8.7).
 */
export type ConversationEvent =
  | (EventBase & { type: "message"; message: ConversationMessage })
  | (EventBase & {
      type: "state";
      status: ConversationStatus;
      handoff: Handoff;
      responder: Responder;
      closed: boolean;
      /** Undefined on 0.4, where a state event says nothing about `working` (spec 8.7). */
      working: boolean | undefined;
    })
  | (EventBase & { type: "authorization"; error: string; scope: string })
  | (EventBase & { type: "user_requested"; reason: string })
  | (EventBase & { type: "direct_opened" | "direct_closed"; conversationId: string });

/** What a request returned: new events, deduplicated, and the conversation's state after them. */
export interface ConversationUpdate extends ConversationState {
  events: ConversationEvent[];
  /** The 0.3 `status`, derived from the state on 0.4 (spec 8.7). */
  status: ConversationStatus;
  /** When true, read again right away (spec 8.5). */
  hasMore: boolean;
}

/** An item from {@link Conversation.stream}. */
export type StreamItem =
  | { type: "event"; event: ConversationEvent }
  /** A piece of a message the Company Agent is still writing (spec 8.6). Replace with the `message` event. */
  | { type: "text-delta"; messageId: string; text: string }
  /** `working` changed (spec 8.6, 8.7), which is state rather than an event, so it has no cursor. */
  | { type: "working"; working: boolean }
  /** The stream reconnected: drop pieces of messages not yet received in full (spec 8.6). */
  | { type: "reconnected" };

function normalizeStatus(value: unknown): ConversationStatus {
  return value === "idle" || value === "queued" || value === "closed" ? value : "working";
}

function normalizeHandoff(value: unknown): Handoff {
  // An unrecognized value reads as pending, the more cautious answer (spec 8.7).
  return value === "none" ? "none" : "pending";
}

function normalizeResponder(value: unknown): Responder {
  return value === "agent" ? "agent" : "human";
}

/** The 0.3 `status` a 0.4 state corresponds to, so one API reports both versions (spec 8.7). */
function statusFor(state: ConversationState): ConversationStatus {
  if (state.closed) return "closed";
  if (state.handoff === "pending") return "queued";
  return state.working ? "working" : "idle";
}

/** The 0.4 state a 0.3 `status` corresponds to. `queued` meant waiting for a person, with no work shown. */
function stateFor(status: ConversationStatus, responder: Responder): ConversationState {
  return {
    working: status === "working",
    handoff: status === "queued" ? "pending" : "none",
    responder,
    closed: status === "closed",
  };
}

function parseAuthor(value: unknown): Author {
  if (!isObject(value)) return { type: "agent" };
  const author: Author = { type: value["type"] === "human" ? "human" : "agent" };
  if (typeof value["id"] === "string") author.id = value["id"];
  if (typeof value["name"] === "string") author.name = value["name"];
  if (typeof value["image"] === "string") author.image = value["image"];
  return author;
}

function items(content: unknown): Record<string, unknown>[] {
  return isObject(content) && Array.isArray(content["items"])
    ? content["items"].filter(isObject)
    : [];
}

function parseLinks(content: unknown): MessageLink[] {
  return items(content).flatMap((item) => {
    const url = item["url"];
    if (typeof url !== "string" || !url.startsWith("https://") || !URL.canParse(url)) return [];
    return [{ url, title: typeof item["title"] === "string" ? item["title"] : undefined }];
  });
}

function parseDisclosures(content: unknown): Disclosure[] {
  return items(content).flatMap((item) =>
    typeof item["text"] === "string" && item["text"] !== "" ? [{ text: item["text"] }] : [],
  );
}

function parseMessage(value: unknown, eventId: string): ConversationMessage | undefined {
  if (!isObject(value)) return undefined;
  // The Company sets the message's id when it records it (spec 8.4); fall back to the event's own.
  const id = typeof value["id"] === "string" ? value["id"] : eventId;
  const extensions = isObject(value["extensions"]) ? value["extensions"] : undefined;
  const operations = extensions?.["operations"];
  let operation: Operation | undefined;
  if (isObject(operations) && operations["operation"] !== undefined) {
    try {
      operation = parseOperation(operations["operation"]);
    } catch {
      operation = undefined;
    }
  }
  return {
    id,
    role: typeof value["role"] === "string" ? value["role"] : "company",
    author: parseAuthor(value["author"]),
    text: typeof value["text"] === "string" ? value["text"] : undefined,
    data: isObject(value["data"]) ? value["data"] : undefined,
    context: isObject(value["context"]) ? value["context"] : undefined,
    asOfRequest: typeof value["as_of_request"] === "string" ? value["as_of_request"] : undefined,
    asOfCursor: typeof value["as_of_cursor"] === "string" ? value["as_of_cursor"] : undefined,
    extensions,
    operation,
    links: parseLinks(extensions?.["links"]),
    disclosures: parseDisclosures(extensions?.["disclosures"]),
  };
}

/** Parses one event, or undefined for an unknown or malformed type, which the agent skips (spec 8.5). */
export function parseEvent(value: unknown): ConversationEvent | undefined {
  if (!isObject(value) || typeof value["id"] !== "string") return undefined;
  const base = {
    id: value["id"],
    createdAt: typeof value["created_at"] === "string" ? value["created_at"] : "",
  };
  switch (value["type"]) {
    case "message": {
      const message = parseMessage(value["message"], base.id);
      return message === undefined ? undefined : { ...base, type: "message", message };
    }
    case "state": {
      const responder = normalizeResponder(value["responder"]);
      // 0.3 sends status, which carries all four; 0.4 sends handoff, responder and closed, and says
      // nothing about working, which isn't recorded as an event (spec 8.7).
      if (value["status"] !== undefined) {
        const state = stateFor(normalizeStatus(value["status"]), responder);
        return { ...base, type: "state", ...state, status: statusFor(state) };
      }
      const handoff = normalizeHandoff(value["handoff"]);
      const closed = value["closed"] === true;
      return {
        ...base,
        type: "state",
        working: undefined,
        handoff,
        responder,
        closed,
        status: statusFor({ working: false, handoff, responder, closed }),
      };
    }
    case "authorization":
      return {
        ...base,
        type: "authorization",
        error: typeof value["error"] === "string" ? value["error"] : "insufficient_scope",
        scope: typeof value["scope"] === "string" ? value["scope"] : "",
      };
    case "user_requested":
      return {
        ...base,
        type: "user_requested",
        reason: typeof value["reason"] === "string" ? value["reason"] : "",
      };
    case "direct_opened":
    case "direct_closed":
      return typeof value["conversation_id"] === "string"
        ? { ...base, type: value["type"], conversationId: value["conversation_id"] }
        : undefined;
    default:
      return undefined;
  }
}

function requestId(id: string | undefined, prefix = "msg_"): string {
  const value = id ?? randomId(prefix);
  if (!ID.test(value))
    throw new PoppyProtocolError("a request id must be 1 to 256 URL-safe base64 characters");
  return value;
}

/**
 * Builds a conversation POST body (spec 8.3). On 0.3 the message carries its own `id`; from 0.4 the
 * request carries a top-level `id` and the message takes it as its own, so a retried request can't act
 * twice whatever its path.
 */
function messageBody(
  message: OutgoingMessage,
  defaultAuthor: "agent" | "human",
  company: Company,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  const id = requestId(message.id);
  if (
    message.text === undefined &&
    message.data === undefined &&
    message.context === undefined &&
    message.approval === undefined
  )
    throw new PoppyProtocolError("a message needs text, data, context or an approval");
  // A side sends an extension's content only to one that uses the same version (spec 8.4).
  if (message.approval !== undefined && !companySupports(company, "operations", "2"))
    throw new PoppyProtocolError(
      `${company.domain} doesn't list the Operations extension, version 2`,
    );
  const author = message.author?.type ?? defaultAuthor;
  // Only a message an AI wrote says what it had read; a person's doesn't (spec 8.4).
  const asOfCursor =
    company.protocolVersion === "0.3" || author === "human" ? undefined : message.asOfCursor;
  const body = {
    author: { type: author },
    ...(message.text === undefined ? {} : { text: message.text }),
    ...(message.data === undefined ? {} : { data: message.data }),
    ...(message.context === undefined ? {} : { context: message.context }),
    ...(asOfCursor === undefined ? {} : { as_of_cursor: asOfCursor }),
    ...(message.approval === undefined
      ? {}
      : { extensions: { operations: { approval: approvalField(message.approval) } } }),
  };
  return company.protocolVersion === "0.3"
    ? { ...extra, message: { id, ...body } }
    : { id, ...extra, message: body };
}

function withQuery(url: string, query: Record<string, string | number | undefined>): string {
  const target = new URL(url);
  for (const [key, value] of Object.entries(query))
    if (value !== undefined) target.searchParams.set(key, String(value));
  return target.href;
}

/** The conversations at one `poppy` endpoint, in one Session (spec 8). */
export class Conversations {
  readonly session: Session;
  readonly endpoint: string;

  constructor(session: Session, endpoint: string) {
    this.session = session;
    this.endpoint = endpoint.replace(/\/$/, "");
  }

  /**
   * Starts a conversation with its first message (spec 8.3). With `wait`, the response also carries the
   * Company's first events, held for up to that many seconds.
   */
  async start(
    message: OutgoingMessage,
    options: { wait?: number } = {},
  ): Promise<{ conversation: Conversation; update: ConversationUpdate }> {
    return this.#create(messageBody(message, "agent", this.session.company), options.wait, false);
  }

  /**
   * Opens a Direct Conversation (spec 8.10), linked to an open conversation, for the User to talk with the
   * Company themselves. Messages default to `author.type` `human`. Start one only when the User agrees.
   *
   * To accept a `user_requested` event, pass its ID as `userRequestedEventId`. The message is then
   * optional: without one, the Company speaks first. Retrying the acceptance returns the same conversation.
   */
  async openDirect(
    parentConversationId: string,
    message: OutgoingMessage | undefined,
    options: { wait?: number; userRequestedEventId?: string; id?: string } = {},
  ): Promise<{ conversation: Conversation; update: ConversationUpdate }> {
    const { userRequestedEventId } = options;
    if (message === undefined && userRequestedEventId === undefined)
      throw new PoppyProtocolError("a Direct Conversation starts with a message or an acceptance");
    if (userRequestedEventId !== undefined && !ID.test(userRequestedEventId))
      throw new PoppyProtocolError("malformed event ID");
    const company = this.session.company;
    const links = {
      parent_conversation_id: parentConversationId,
      ...(userRequestedEventId === undefined
        ? {}
        : { user_requested_event_id: userRequestedEventId }),
    };
    // From 0.4 every POST carries a request id, including one that opens a Direct Conversation with no
    // message of its own (spec 8.3, 8.10).
    const body =
      message === undefined
        ? company.protocolVersion === "0.3"
          ? links
          : { id: requestId(options.id, "dir_"), ...links }
        : messageBody(
            { ...message, ...(options.id === undefined ? {} : { id: options.id }) },
            "human",
            company,
            links,
          );
    return this.#create(body, options.wait, true);
  }

  /**
   * Resumes a conversation in this Session. Pass the `cursor` and `handledEventIds` you saved, so a read
   * from the start after `cursor_expired` skips events already handled (spec 8.5).
   */
  resume(
    conversationId: string,
    options: { cursor?: string; direct?: boolean; handledEventIds?: Iterable<string> } = {},
  ): Conversation {
    if (!ID.test(conversationId)) throw new PoppyProtocolError("malformed Conversation ID");
    const conversation = new Conversation(
      this,
      conversationId,
      options.cursor,
      options.direct ?? false,
    );
    for (const id of options.handledEventIds ?? []) conversation.markHandled(id);
    return conversation;
  }

  async #create(
    body: Record<string, unknown>,
    wait: number | undefined,
    direct: boolean,
  ): Promise<{ conversation: Conversation; update: ConversationUpdate }> {
    const response = await this.request("POST", withQuery(this.endpoint, { wait }), body);
    const id = response["conversation_id"];
    if (typeof id !== "string" || !ID.test(id))
      throw new PoppyProtocolError("the Company returned no valid conversation_id");
    const conversation = new Conversation(this, id, undefined, direct);
    return { conversation, update: conversation.apply(response) };
  }

  /** Sends a JSON request and returns the JSON body, throwing {@link PoppyError} on an error status. */
  async request(
    method: string,
    url: string,
    body: Record<string, unknown> | undefined,
    headers: Record<string, string> = {},
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>> {
    const response = await this.session.fetch(url, {
      method,
      ...(signal === undefined ? {} : { signal }),
      headers: {
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...headers,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) throw await throwable(response);
    const json: unknown = await response.json().catch(() => undefined);
    if (!isObject(json))
      throw new PoppyProtocolError("conversation response must be a JSON object");
    return json;
  }
}

/** One conversation with the Company Agent (spec 8). Keeps its cursor and skips events already handled. */
export class Conversation {
  readonly id: string;
  /** Whether this is a Direct Conversation (spec 8.10). */
  readonly direct: boolean;
  readonly #conversations: Conversations;
  #cursor: string | undefined;
  // A new conversation starts working, with no handoff and no person (spec 8.7).
  #state: ConversationState = {
    working: true,
    handoff: "none",
    responder: "agent",
    closed: false,
  };
  readonly #seen = new Set<string>();

  constructor(
    conversations: Conversations,
    id: string,
    cursor: string | undefined,
    direct: boolean,
  ) {
    this.#conversations = conversations;
    this.id = id;
    this.#cursor = cursor;
    this.direct = direct;
  }

  /**
   * The conversation's state after the last response (spec 8.7): `working`, `handoff`, `responder` and
   * `closed`. On 0.3 these are derived from `status`.
   */
  get state(): ConversationState {
    return { ...this.#state };
  }

  /** The Company has work in progress. Read until it's false to get its whole reply (spec 8.7). */
  get working(): boolean {
    return this.#state.working;
  }

  /** The conversation takes no more messages (spec 8.12). */
  get closed(): boolean {
    return this.#state.closed;
  }

  /** The 0.3 `status` for the current state, derived from it on 0.4 (spec 8.7). */
  get status(): ConversationStatus {
    return statusFor(this.#state);
  }

  get responder(): Responder {
    return this.#state.responder;
  }

  /** The cursor after the last event handled. Save it to resume later (spec 8.5). */
  get cursor(): string | undefined {
    return this.#cursor;
  }

  /** The IDs of events already handled. Save them with the cursor to resume without repeats. */
  get handledEventIds(): string[] {
    return [...this.#seen];
  }

  /** Marks an event as handled, so reads skip it. */
  markHandled(eventId: string): void {
    this.#seen.add(eventId);
  }

  get #url(): string {
    return `${this.#conversations.endpoint}/${this.id}`;
  }

  /** Applies a response: handles new events in order and saves the cursor after them (spec 8.5). */
  apply(response: Record<string, unknown>): ConversationUpdate {
    const events: ConversationEvent[] = [];
    if (Array.isArray(response["events"])) {
      for (const raw of response["events"]) {
        const id = isObject(raw) ? raw["id"] : undefined;
        if (typeof id !== "string") continue;
        if (this.#seen.has(id)) continue;
        this.#seen.add(id);
        this.#cursor = id;
        const event = parseEvent(raw);
        if (event === undefined) continue;
        if (event.type === "state") {
          this.#state = {
            // A 0.4 state event says nothing about working, so it keeps its value (spec 8.7).
            working: event.working ?? this.#state.working,
            handoff: event.handoff,
            responder: event.responder,
            closed: event.closed,
          };
          // `status` is only knowable once the event is merged with the `working` its version
          // doesn't report, or a 0.4 event on a working conversation would read as `idle`.
          events.push({ ...event, status: statusFor(this.#state) });
          continue;
        }
        events.push(event);
      }
      if (typeof response["cursor"] === "string") this.#cursor = response["cursor"];
    }
    // The state fields of a read are the state when the Company responded, so they can be newer than
    // the events returned (spec 8.5). 0.3 reports status and responder; 0.4 reports all four.
    if (response["status"] !== undefined) {
      this.#state = stateFor(
        normalizeStatus(response["status"]),
        normalizeResponder(response["responder"] ?? this.#state.responder),
      );
    } else {
      if (typeof response["working"] === "boolean") this.#state.working = response["working"];
      if (response["handoff"] !== undefined)
        this.#state.handoff = normalizeHandoff(response["handoff"]);
      if (typeof response["closed"] === "boolean") this.#state.closed = response["closed"];
      if (response["responder"] !== undefined)
        this.#state.responder = normalizeResponder(response["responder"]);
    }
    return {
      events,
      ...this.#state,
      status: statusFor(this.#state),
      hasMore: response["has_more"] === true,
    };
  }

  /**
   * Sends a message (spec 8.3). With `wait`, the response carries the Company's events after the cursor.
   * To retry after a failure, send the same message again with the same `id`.
   */
  async send(
    message: OutgoingMessage,
    options: { wait?: number } = {},
  ): Promise<ConversationUpdate> {
    // In a Direct Conversation the User writes, so messages default to `human` (spec 8.10).
    const body = messageBody(
      message,
      this.direct ? "human" : "agent",
      this.#conversations.session.company,
    );
    const url = withQuery(`${this.#url}/messages`, {
      wait: options.wait,
      cursor: options.wait === undefined ? undefined : this.#cursor,
    });
    return this.apply(await this.#conversations.request("POST", url, body));
  }

  /**
   * Reads one page of events after the cursor (spec 8.5), holding up to `wait` seconds for one. On
   * `cursor_expired`, reads from the beginning and skips events already handled.
   */
  async read(options: { wait?: number; signal?: AbortSignal } = {}): Promise<ConversationUpdate> {
    try {
      return this.apply(
        await this.#conversations.request(
          "GET",
          withQuery(`${this.#url}/events`, { cursor: this.#cursor, wait: options.wait }),
          undefined,
          {},
          options.signal,
        ),
      );
    } catch (error) {
      if (
        !(error instanceof PoppyError) ||
        error.error !== "cursor_expired" ||
        this.#cursor === undefined
      )
        throw error;
      this.#cursor = undefined;
      return this.read(options);
    }
  }

  /** Reads until `has_more` is false. */
  async readAll(options: { wait?: number } = {}): Promise<ConversationUpdate> {
    const events: ConversationEvent[] = [];
    for (;;) {
      const update = await this.read(events.length === 0 ? options : {});
      events.push(...update.events);
      if (!update.hasMore) return { ...update, events };
    }
  }

  /** A POST with only a request id, which 0.4 requires on every conversation request (spec 8.3). */
  #idBody(id: string | undefined, prefix: string): Record<string, unknown> {
    return this.#conversations.session.company.protocolVersion === "0.3"
      ? {}
      : { id: requestId(id, prefix) };
  }

  /**
   * Asks for a person at the Company (spec 8.9). The Company accepts the request and acts on it after
   * responding, so read until `working` is false to see `handoff` and `responder` settle.
   */
  async handoff(options: { id?: string } = {}): Promise<ConversationState> {
    this.apply(
      await this.#conversations.request(
        "POST",
        `${this.#url}/handoff`,
        this.#idBody(options.id, "hnd_"),
      ),
    );
    return this.state;
  }

  /**
   * Withdraws a request for a person (spec 8.9), from 0.4. The Company MAY stop looking or keep looking,
   * and a person may join before it acts on the cancel, so read `handoff` and `responder` for the
   * outcome rather than depending on the cancel taking effect.
   */
  async cancelHandoff(options: { id?: string } = {}): Promise<ConversationState> {
    if (this.#conversations.session.company.protocolVersion === "0.3")
      throw new PoppyProtocolError("withdrawing a handoff needs protocol version 0.4 or later");
    this.apply(
      await this.#conversations.request(
        "POST",
        `${this.#url}/handoff/cancel`,
        this.#idBody(options.id, "hnc_"),
      ),
    );
    return this.state;
  }

  /**
   * Closes the conversation (spec 8.12). Doesn't cancel anything it started.
   *
   * From 0.4 a close doesn't wait its turn: the Company MAY act on requests it hasn't acted on yet, or
   * drop them, so read until `working` is false before closing to be sure it acted on everything sent.
   */
  async close(options: { id?: string } = {}): Promise<ConversationState> {
    this.apply(
      await this.#conversations.request(
        "POST",
        `${this.#url}/close`,
        this.#idBody(options.id, "cls_"),
      ),
    );
    return this.state;
  }

  /**
   * Opens a Direct Conversation linked to this one (spec 8.10). Pass `userRequestedEventId` to accept a
   * `user_requested` event, with or without a first message.
   */
  openDirect(
    message: OutgoingMessage | undefined,
    options: { wait?: number; userRequestedEventId?: string } = {},
  ): Promise<{ conversation: Conversation; update: ConversationUpdate }> {
    return this.#conversations.openDirect(this.id, message, options);
  }

  /**
   * Streams events (spec 8.6), reconnecting with `Last-Event-ID` when the Company closes the stream, until
   * the conversation is closed or `signal` aborts. Falls back to long-polling a Company that doesn't stream.
   */
  async *stream(options: { signal?: AbortSignal } = {}): AsyncGenerator<StreamItem> {
    const { signal } = options;
    let first = true;
    while (!signal?.aborted) {
      if (!first) yield { type: "reconnected" };
      first = false;
      const response = await this.#conversations.session.fetch(
        withQuery(
          `${this.#url}/events`,
          this.#cursor === undefined ? {} : { cursor: this.#cursor },
        ),
        {
          headers: {
            accept: "text/event-stream",
            ...(this.#cursor === undefined ? {} : { "last-event-id": this.#cursor }),
          },
          ...(signal === undefined ? {} : { signal }),
        },
      );
      if (response.status === 429) {
        await response.body?.cancel();
        await sleep((parseRetryAfter(response.headers.get("retry-after")) ?? 1) * 1000, signal);
        continue;
      }
      if (!response.ok) {
        const error = await throwable(response);
        if (error.error === "cursor_expired" && this.#cursor !== undefined) {
          this.#cursor = undefined;
          continue;
        }
        throw error;
      }
      let progressed = false;
      if (response.headers.get("content-type")?.includes("text/event-stream") === true) {
        for await (const item of this.#readStream(response, signal)) {
          progressed = true;
          yield item;
        }
      } else {
        const json: unknown = await response.json().catch(() => undefined);
        if (!isObject(json)) throw new PoppyProtocolError("events response must be a JSON object");
        // A Company that doesn't stream reports `working` in each read's body rather than as an
        // event, so changes to it are turned back into `working` items here (spec 8.6, 8.7).
        let working = this.#state.working;
        let update = this.apply(json);
        if (update.working !== working) yield { type: "working", working: update.working };
        working = update.working;
        for (const event of update.events) yield { type: "event", event };
        while ((update.hasMore || !update.closed) && !signal?.aborted) {
          update = await this.read({
            wait: update.hasMore ? 0 : POLL_WAIT,
            ...(signal === undefined ? {} : { signal }),
          });
          if (update.working !== working) yield { type: "working", working: update.working };
          working = update.working;
          for (const event of update.events) yield { type: "event", event };
        }
        return;
      }
      if (this.#state.closed) return;
      if (!progressed) await sleep(RECONNECT_DELAY, signal).catch(() => undefined);
    }
  }

  async *#readStream(
    response: Response,
    signal: AbortSignal | undefined,
  ): AsyncGenerator<StreamItem> {
    if (response.body === null) return;
    const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = "";
    let eventName = "";
    let data: string[] = [];
    try {
      for (;;) {
        if (signal?.aborted) return;
        const { value, done } = await reader.read();
        if (done) return;
        buffer += value;
        let newline: RegExpExecArray | null;
        while ((newline = /\r\n|\r|\n/.exec(buffer)) !== null) {
          const line = buffer.slice(0, newline.index);
          buffer = buffer.slice(newline.index + newline[0].length);
          if (line === "") {
            const item = this.#dispatch(eventName, data.join("\n"));
            eventName = "";
            data = [];
            if (item !== undefined) yield item;
            continue;
          }
          if (line.startsWith(":")) continue;
          const colon = line.indexOf(":");
          const field = colon === -1 ? line : line.slice(0, colon);
          const fieldValue = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
          if (field === "event") eventName = fieldValue;
          else if (field === "data") data.push(fieldValue);
        }
      }
    } finally {
      await reader.cancel().catch(() => undefined);
    }
  }

  #dispatch(eventName: string, data: string): StreamItem | undefined {
    if (data === "") return undefined;
    let json: unknown;
    try {
      json = JSON.parse(data);
    } catch {
      return undefined;
    }
    if (eventName === "text-delta") {
      if (
        !isObject(json) ||
        typeof json["message_id"] !== "string" ||
        typeof json["text"] !== "string"
      )
        return undefined;
      return { type: "text-delta", messageId: json["message_id"], text: json["text"] };
    }
    // From 0.4, working arrives as its own event with no SSE id, since it isn't recorded (spec 8.6).
    if (eventName === "working") {
      if (!isObject(json) || typeof json["working"] !== "boolean") return undefined;
      this.#state.working = json["working"];
      return { type: "working", working: json["working"] };
    }
    if (eventName !== "" && eventName !== "message") return undefined;
    const before = this.#seen.size;
    const update = this.apply({ events: [json] });
    const event = update.events[0];
    return event === undefined || this.#seen.size === before ? undefined : { type: "event", event };
  }
}
