/** OAuth and Poppy error codes a Company may return (spec 4.2, 4.4, 4.6, 4.8, section 6). */
export type PoppyErrorCode =
  | "invalid_client"
  | "invalid_grant"
  | "invalid_session"
  | "account_mismatch"
  | "invalid_scope"
  | "invalid_dpop_proof"
  | "use_dpop_nonce"
  | "extension_required"
  | "rate_limited"
  | "authorization_pending"
  | "slow_down"
  | "access_denied"
  | "expired_token"
  | "invalid_token"
  | "sign_in_required"
  | (string & {});

/**
 * An error returned by a Company, or a protocol check that failed on the agent side.
 *
 * Carries only the HTTP status, the OAuth `error` code and `error_description`. It never holds tokens,
 * assertions, device codes or response bodies, so it is safe to log.
 */
export class PoppyError extends Error {
  override readonly name = "PoppyError";
  readonly error: PoppyErrorCode;
  readonly status: number | undefined;
  readonly errorDescription: string | undefined;
  /** Seconds to wait before retrying, from `Retry-After` on HTTP 429 (spec 4.3). */
  readonly retryAfter: number | undefined;
  /** The extension a Company requires, on `extension_required` (spec 3.3). */
  readonly extension: string | undefined;

  constructor(
    error: PoppyErrorCode,
    options: {
      status?: number | undefined;
      description?: string | undefined;
      retryAfter?: number | undefined;
      extension?: string | undefined;
    } = {},
  ) {
    super(options.description ? `${error}: ${options.description}` : error);
    this.error = error;
    this.status = options.status;
    this.errorDescription = options.description;
    this.retryAfter = options.retryAfter;
    this.extension = options.extension;
  }
}

/** Raised when a document or response breaks the protocol, before any token is sent. */
export class PoppyProtocolError extends PoppyError {
  constructor(description: string) {
    super("protocol_error", { description });
  }
}

const MAX_DESCRIPTION = 200;

function parseRetryAfter(value: string | null): number | undefined {
  if (value === null) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds;
  const date = Date.parse(value);
  return Number.isNaN(date) ? undefined : Math.max(0, Math.ceil((date - Date.now()) / 1000));
}

function stringField(body: unknown, key: string): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const value = (body as Record<string, unknown>)[key];
  return typeof value === "string" ? value.slice(0, MAX_DESCRIPTION) : undefined;
}

/** Builds a PoppyError from an OAuth JSON error response, keeping only safe fields. */
export async function errorFromResponse(response: Response): Promise<PoppyError> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  const code =
    stringField(body, "error") ??
    (response.status === 429 ? "rate_limited" : `http_${response.status}`);
  return new PoppyError(code, {
    status: response.status,
    description: stringField(body, "error_description"),
    retryAfter: parseRetryAfter(response.headers.get("retry-after")),
    extension: stringField(body, "extension"),
  });
}
