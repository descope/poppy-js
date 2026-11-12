import { type Company, parseSkillIndex, type Skill } from "./discovery.ts";
import { PoppyProtocolError } from "./errors.ts";
import { httpsUrl, isObject } from "./http.ts";

/** Where to do a task (spec 9.2). References of unknown types are skipped. */
export type Reference =
  | { type: "openapi"; url: string; operationId: string }
  | { type: "mcp"; url: string; tool: string }
  | { type: "web"; url: string };

/** Another way to do a task (spec 9.2). Content from the Company, not instructions (spec 10.1). */
export interface Alternative {
  instructions: string | undefined;
  references: Reference[];
}

/** A task the Company chose not to offer through this protocol (spec 9.1). */
export interface ExcludedTask {
  task: string;
  alternative: Alternative | undefined;
}

/**
 * What the Company offers a Session, in one place (spec section 9): the tasks it chose not to offer, the
 * skills it publishes, and where to send feedback. Get it from `Session.taskCoverage()`.
 *
 * On 0.3 these are three fields of `poppy.json`, the same for every User. On 0.4 they come from one
 * `tasks.endpoint`, fetched per Session, so a Company can answer different Sessions differently; the
 * answer belongs to that Session and MUST NOT be used in another.
 */
export interface TaskCoverage {
  /** Tasks the Company doesn't offer through this protocol (spec 9.1). Empty when it lists none. */
  excludedTasks: readonly ExcludedTask[];
  /** Skills the Company publishes (spec 9.4). Empty when it publishes none. */
  skills: readonly Skill[];
  /** Where to report a task that couldn't be done (spec 9.3), or undefined when it takes no feedback. */
  feedbackEndpoint: string | undefined;
}

/** A report of a task the User couldn't do (spec 9.3). */
export interface FeedbackReport {
  /** What the User was trying to do, in a short phrase. At most 200 characters. */
  task: string;
  /** What the agent tried, and why, with no identifiers or personal data. At most 2,000 characters. */
  description: string;
}

function parseReference(value: unknown, company: Company): Reference | undefined {
  if (!isObject(value) || typeof value["url"] !== "string") return undefined;
  const { type, url } = value;
  const listed = (apiType: string) =>
    company.apis.some((api) => api.type === apiType && api.url === url);
  if (type === "openapi") {
    // Must name a listed API, so an alternative can't aim the agent at another server (spec 9.2).
    if (typeof value["operation_id"] !== "string" || !listed("openapi")) return undefined;
    return { type, url, operationId: value["operation_id"] };
  }
  if (type === "mcp") {
    if (typeof value["tool"] !== "string" || !listed("mcp")) return undefined;
    return { type, url, tool: value["tool"] };
  }
  if (type === "web") {
    try {
      return new URL(url).protocol === "https:" ? { type, url } : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export function parseAlternative(value: unknown, company: Company): Alternative | undefined {
  if (!isObject(value)) return undefined;
  const instructions =
    typeof value["instructions"] === "string" ? value["instructions"] : undefined;
  const references = Array.isArray(value["references"])
    ? value["references"].flatMap((ref) => {
        const parsed = parseReference(ref, company);
        return parsed === undefined ? [] : [parsed];
      })
    : [];
  if (instructions === undefined && references.length === 0) return undefined;
  return { instructions, references };
}

function parseTaskList(value: unknown, company: Company): ExcludedTask[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry): ExcludedTask[] => {
    if (!isObject(entry) || typeof entry["task"] !== "string") return [];
    return [{ task: entry["task"], alternative: parseAlternative(entry["alternative"], company) }];
  });
}

/** Reads the 0.3 excluded tasks document, which lists them under `tasks` (spec 9.1). */
export function parseExcludedTasks(body: unknown, company: Company): ExcludedTask[] {
  if (!isObject(body) || !Array.isArray(body["tasks"]))
    throw new PoppyProtocolError("excluded tasks must have a tasks list");
  return parseTaskList(body["tasks"], company);
}

/**
 * Reads the 0.4 response from `tasks.endpoint` (spec section 9). Every field is optional, so a Company
 * that offers none of the three answers with an empty object. Skill URLs resolve against
 * `tasks.endpoint`, which is the document they came in (spec 9.4).
 */
export function parseTaskCoverage(
  body: unknown,
  company: Company,
  tasksEndpoint: string,
): TaskCoverage {
  if (!isObject(body)) throw new PoppyProtocolError("the tasks response must be an object");
  const feedback = body["feedback"];
  return {
    excludedTasks: parseTaskList(body["excluded_tasks"], company),
    skills: parseSkillIndex(body["skill_index"], new URL(tasksEndpoint)),
    feedbackEndpoint:
      isObject(feedback) && feedback["endpoint"] !== undefined
        ? httpsUrl(feedback["endpoint"], "feedback.endpoint").href
        : undefined,
  };
}

export function checkFeedback(report: FeedbackReport): void {
  if (report.task === "" || report.task.length > 200)
    throw new PoppyProtocolError("feedback task must be 1 to 200 characters");
  if (report.description === "" || report.description.length > 2000)
    throw new PoppyProtocolError("feedback description must be 1 to 2,000 characters");
}
