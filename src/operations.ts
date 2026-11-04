import { PoppyProtocolError } from "./errors.ts";
import { isObject } from "./http.ts";

/** The extension name and version this client implements (Operations extension section 2). */
export const OPERATIONS_EXTENSION = { name: "operations", version: "2" } as const;

const ID = /^[A-Za-z0-9_-]{1,256}$/;

/** One action the Company performs once the User approves its exact terms (Operations section 3). */
export interface Operation {
  operationId: string;
  /** Identifies these terms. A new revision needs a new approval. */
  revision: string;
  /** The terms in plain language. Show it to the User with {@link renderSummary} or as text. */
  summary: string;
  /** The same terms as JSON, for checking against the `summary` and what you asked for. */
  terms: Readonly<Record<string, unknown>> | undefined;
  /** RFC 3339. The last time an approval of this revision is accepted. */
  expiresAt: string;
}

/** The User's approval of one revision (Operations section 6). */
export interface Approval {
  operationId: string;
  revision: string;
}

export function parseOperation(value: unknown): Operation {
  if (!isObject(value)) throw new PoppyProtocolError("operation must be an object");
  const { operation_id, revision, summary, terms, expires_at } = value;
  if (typeof operation_id !== "string" || !ID.test(operation_id))
    throw new PoppyProtocolError("operation_id is missing or malformed");
  if (typeof revision !== "string" || !ID.test(revision))
    throw new PoppyProtocolError("revision is missing or malformed");
  if (typeof summary !== "string" || summary === "")
    throw new PoppyProtocolError("operation summary is missing");
  if (typeof expires_at !== "string" || Number.isNaN(Date.parse(expires_at)))
    throw new PoppyProtocolError("operation expires_at is missing or malformed");
  if (terms !== undefined && !isObject(terms))
    throw new PoppyProtocolError("operation terms must be an object");
  return { operationId: operation_id, revision, summary, terms, expiresAt: expires_at };
}

/** The approval for an operation's current revision. Send it only after the User approves it (section 5). */
export function approvalFor(operation: Operation): Approval {
  return { operationId: operation.operationId, revision: operation.revision };
}

export function isOperationExpired(operation: Operation, now = Date.now()): boolean {
  return Date.parse(operation.expiresAt) < now;
}

/**
 * Reads the operation from an API response that refuses with `approval_required` (Operations section 4).
 * Reads a clone, so the response body stays readable. Returns undefined for any other response.
 */
export async function operationFromResponse(response: Response): Promise<Operation | undefined> {
  if (response.status !== 403) return undefined;
  let body: unknown;
  try {
    body = await response.clone().json();
  } catch {
    return undefined;
  }
  if (!isObject(body) || body["error"] !== "approval_required") return undefined;
  return parseOperation(body["operation"]);
}

/** Reads the operation from an MCP tool error result (Operations section 4). */
export function operationFromToolResult(result: unknown): Operation | undefined {
  if (!isObject(result) || result["isError"] !== true) return undefined;
  const structured = result["structuredContent"];
  if (!isObject(structured) || structured["operation"] === undefined) return undefined;
  return parseOperation(structured["operation"]);
}

function sfString(value: string, what: string): string {
  if (!ID.test(value))
    throw new PoppyProtocolError(`${what} has characters an approval can't carry`);
  return `"${value}"`;
}

/** The `Poppy-Approval` header value, an RFC 9651 Dictionary (Operations section 6). */
export function approvalHeader(approval: Approval): string {
  return `operation_id=${sfString(approval.operationId, "operation_id")}, revision=${sfString(approval.revision, "revision")}`;
}

/** The `_meta` member to add to the same `tools/call` to approve an MCP operation. */
export function approvalMeta(approval: Approval): Record<string, unknown> {
  return {
    "personalagentprotocol.org/approval": {
      operation_id: approval.operationId,
      revision: approval.revision,
    },
  };
}

/** The `approval` field of a conversation message. */
export function approvalField(approval: Approval): Record<string, string> {
  return { operation_id: approval.operationId, revision: approval.revision };
}

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function inline(text: string): string {
  return escapeHtml(text)
    .replace(/\*\*(?=\S)(.+?)(?<=\S)\*\*/g, "<strong>$1</strong>")
    .replace(/__(?=\S)(.+?)(?<=\S)__/g, "<strong>$1</strong>")
    .replace(/\*(?=\S)(.+?)(?<=\S)\*/g, "<em>$1</em>")
    .replace(/(?<![\w])_(?=\S)(.+?)(?<=\S)_(?![\w])/g, "<em>$1</em>");
}

/**
 * Renders an operation `summary` as HTML with only what Operations section 3 allows: emphasis, strong
 * emphasis, paragraphs and lists. Links, images and HTML stay visible as text, so a summary can't send the
 * User elsewhere or load content while they decide.
 */
export function renderSummary(summary: string): string {
  return summary
    .replaceAll("\r\n", "\n")
    .split(/\n\s*\n/)
    .map((block) => block.trim())
    .filter((block) => block !== "")
    .map((block) => {
      const lines = block.split("\n").map((line) => line.trim());
      if (lines.every((line) => /^[-*+]\s+/.test(line)))
        return `<ul>${lines.map((line) => `<li>${inline(line.replace(/^[-*+]\s+/, ""))}</li>`).join("")}</ul>`;
      if (lines.every((line) => /^\d{1,9}[.)]\s+/.test(line)))
        return `<ol>${lines.map((line) => `<li>${inline(line.replace(/^\d{1,9}[.)]\s+/, ""))}</li>`).join("")}</ol>`;
      return `<p>${inline(lines.join(" "))}</p>`;
    })
    .join("");
}
