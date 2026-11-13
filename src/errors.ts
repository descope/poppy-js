/** Codes a Company may return (spec 4, 5.3, 7, 8.13, extensions). Other strings can occur. */
export type PoppyErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "invalid_scope"
  | "invalid_target"
  | "unsupported_grant_type"
  | "invalid_session"
  | "session_ended"
  | "version_unsupported"
  | "unauthorized_client"
  | "invalid_token"
  | "insufficient_scope"
  | "invalid_dpop_proof"
  | "use_dpop_nonce"
  | "extension_required"
  | "rate_limited"
  | "authorization_pending"
  | "slow_down"
  | "access_denied"
  | "expired_token"
  | "code_required"
  | "approval_required"
  | "conversation_not_found"
  | "conversation_closed"
  | "direct_conversation_open"
  | "message_id_conflict"
  | "request_id_conflict"
  | "version_mismatch"
  | "invalid_cursor"
  | "cursor_expired"
  | "protocol_error"
  | (string & {});

export interface PoppyErrorOptions {
  status?: number | undefined;
  description?: string | undefined;
  retryAfter?: number | undefined;
  extension?: string | undefined;
  conversationId?: string | undefined;
  scope?: string | undefined;
  protocolVersion?: string | undefined;
}

/**
 * An error returned by a Company, or a failed protocol check.
 * Holds only the HTTP status, `error`, `error_description` and a few named fields, never tokens,
 * assertions, Session JWTs, device codes, credentials or response bodies, so it is safe to log (spec 10.2).
 */
export class PoppyError extends Error {
  override readonly name: string = "PoppyError";
  readonly error: PoppyErrorCode;
  readonly status: number | undefined;
  readonly errorDescription: string | undefined;
  /** Seconds to wait before retrying, from `Retry-After` on HTTP 429 or 503 (spec 5.6). */
  readonly retryAfter: number | undefined;
  /** The extension a Company requires, on `extension_required` (spec 3.3). */
  readonly extension: string | undefined;
  /** The open Direct Conversation, on `direct_conversation_open` (spec 8.10). */
  readonly conversationId: string | undefined;
  /** The scopes a request needs, on `insufficient_scope` (spec 7). */
  readonly scope: string | undefined;
  /** The version a conversation started in, on `version_mismatch` (spec 8.2, 8.13). */
  readonly protocolVersion: string | undefined;

  constructor(error: PoppyErrorCode, options: PoppyErrorOptions = {}) {
    super(options.description ? `${error}: ${options.description}` : error);
    this.error = error;
    this.status = options.status;
    this.errorDescription = options.description;
    this.retryAfter = options.retryAfter;
    this.extension = options.extension;
    this.conversationId = options.conversationId;
    this.scope = options.scope;
    this.protocolVersion = options.protocolVersion;
  }
}

/** Raised when a document or response breaks the protocol. Has no `status`. */
export class PoppyProtocolError extends PoppyError {
  override readonly name = "PoppyProtocolError";

  constructor(description: string) {
    super("protocol_error", { description });
  }
}

const MAX_FIELD = 200;

export function parseRetryAfter(value: string | null): number | undefined {
  if (value === null) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds;
  const date = Date.parse(value);
  return Number.isNaN(date) ? undefined : Math.max(0, Math.ceil((date - Date.now()) / 1000));
}

function stringField(body: unknown, key: string): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const value = (body as Record<string, unknown>)[key];
  return typeof value === "string" ? value.slice(0, MAX_FIELD) : undefined;
}

/**
 * The JSON body of each error, for this package's own use, such as reading `sign_in_id` on
 * `code_required`. Kept off the error object so logging an error never logs a body.
 */
export const errorBodies = new WeakMap<PoppyError, Record<string, unknown>>();

/** Builds an error from a JSON error body (RFC 6749 section 5.2), keeping only safe fields. */
export function errorFromBody(body: unknown, response: Response): PoppyError {
  const code =
    stringField(body, "error") ??
    (response.status === 429 ? "rate_limited" : `http_${response.status}`);
  const error = new PoppyError(code, {
    status: response.status,
    description: stringField(body, "error_description"),
    retryAfter: parseRetryAfter(response.headers.get("retry-after")),
    extension: stringField(body, "extension"),
    conversationId: stringField(body, "conversation_id"),
    scope: stringField(body, "scope"),
    protocolVersion: stringField(body, "protocol_version"),
  });
  if (typeof body === "object" && body !== null && !Array.isArray(body))
    errorBodies.set(error, body as Record<string, unknown>);
  return error;
}

export async function errorFromResponse(response: Response): Promise<PoppyError> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  return errorFromBody(body, response);
}
