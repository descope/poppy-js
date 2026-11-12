import { SUPPORTED_PROTOCOL_VERSIONS } from "../discovery.ts";
import { CHECKS, type Check } from "./checks.ts";
import { ConformanceCompany } from "./company.ts";
import { SCENARIOS, type ScenarioDefinition, type Step } from "./scenarios.ts";

/**
 * A TypeScript agent under test, called in this process. Every method other than `discover` and
 * `request` is optional: steps that need a missing method are skipped, and so are the checks they decide.
 * Agents in other languages run as a process instead; see the `@descope/poppy-conformance` CLI.
 */
export interface AgentDriver {
  /** Discovers the Company at `website`. Rejects if the agent refuses it. */
  discover(website: string): Promise<void>;
  /** Sends a request through the agent, signed in if it is. Resolves with the response status. */
  request(url: string, init?: { method?: string; body?: string }): Promise<number>;
  /**
   * Signs in with Direct Sign-In for `scope`. Call `browser` with the authorization URL; it returns the
   * URL the User's browser comes back to.
   */
  signInDirect?(
    scope: string[],
    browser: (authorizationUrl: string) => Promise<string>,
  ): Promise<void>;
  signOut?(): Promise<void>;
  /** Starts a conversation with the Company Agent, and sends one more message. */
  converse?(text: string): Promise<void>;
  /** Sends a request the Company refuses with `approval_required`, approves it, and retries. */
  requestWithApproval?(url: string, init: { method: string; body: string }): Promise<number>;
  /** Reads the Company's task coverage for this Session: excluded tasks, skills and feedback. */
  taskCoverage?(): Promise<void>;
  /** Reports a task the User couldn't do, to the feedback endpoint the Company names. */
  reportTask?(report: { task: string; description: string }): Promise<void>;
}

/** Makes a fresh agent, with no state, that sends all of its HTTP through `fetch`. */
export type AgentFactory = (env: { fetch: typeof fetch }) => Promise<AgentDriver>;

export interface ConformanceOptions {
  /**
   * Fetches the agent's client metadata and key set, as a Company would. Defaults to the global `fetch`,
   * so they must be published, unless you serve them yourself.
   */
  agentFetch?: typeof fetch;
  /** Run only these scenarios, by name. Defaults to all. */
  scenarios?: readonly string[];
}

export type CheckStatus = "pass" | "fail" | "skip";

/** One check's verdict in one scenario. */
export interface ScenarioCheck {
  id: string;
  status: "pass" | "fail";
  details: string[];
}

export interface ScenarioResult {
  scenario: string;
  description: string;
  checks: ScenarioCheck[];
  /** Steps the agent couldn't carry out, with why. Expected in scenarios it should refuse. */
  stepErrors: string[];
}

export interface CheckResult extends Check {
  status: CheckStatus;
  /** Why it failed, with the scenario, or why it was skipped. */
  details: string[];
}

export interface ConformanceReport {
  /** The spec versions the suite checks, newest first. */
  protocolVersions: readonly string[];
  scenarios: ScenarioResult[];
  /** Every check, across all scenarios: failed if any scenario failed it. */
  results: CheckResult[];
  passed: number;
  failed: number;
  skipped: number;
}

/** Reads what a scenario's Company recorded, after the agent is done. */
export function scenarioResult(
  definition: ScenarioDefinition,
  company: ConformanceCompany,
  stepErrors: string[],
): ScenarioResult {
  definition.evaluate?.(company);
  const order = (id: string) => CHECKS.findIndex((check) => check.id === id);
  const checks = [...company.results()]
    .map(([id, details]) => ({
      id,
      status: details.length === 0 ? ("pass" as const) : ("fail" as const),
      details,
    }))
    .sort((a, b) => order(a.id) - order(b.id));
  return { scenario: definition.name, description: definition.description, checks, stepErrors };
}

/** Rolls scenario results up into one verdict per check. */
export function summarize(scenarios: ScenarioResult[]): ConformanceReport {
  const results: CheckResult[] = CHECKS.map((check) => {
    const seen = scenarios.flatMap((s) =>
      s.checks.filter((c) => c.id === check.id).map((c) => ({ ...c, scenario: s.scenario })),
    );
    if (seen.length === 0) return { ...check, status: "skip", details: ["not exercised"] };
    const failures = seen.filter((c) => c.status === "fail");
    return {
      ...check,
      status: failures.length > 0 ? "fail" : "pass",
      details: failures.flatMap((c) => c.details.map((d) => `${c.scenario}: ${d}`)),
    };
  });
  return {
    protocolVersions: SUPPORTED_PROTOCOL_VERSIONS,
    scenarios,
    results,
    passed: results.filter((r) => r.status === "pass").length,
    failed: results.filter((r) => r.status === "fail").length,
    skipped: results.filter((r) => r.status === "skip").length,
  };
}

async function runStep(
  step: Step,
  driver: AgentDriver,
  company: ConformanceCompany,
): Promise<void> {
  switch (step.action) {
    case "discover":
      return driver.discover(step.website);
    case "request": {
      await driver.request(step.url, {
        ...(step.method === undefined ? {} : { method: step.method }),
        ...(step.body === undefined ? {} : { body: step.body }),
      });
      return;
    }
    case "sign_in":
      if (driver.signInDirect === undefined) throw new Error("the driver has no signInDirect()");
      // The User's browser: open the authorization URL and come back with its redirect.
      return driver.signInDirect(step.scopes, async (url) => {
        const response = await company.fetch(url, { redirect: "manual" });
        return response.headers.get("location") ?? "";
      });
    case "sign_out":
      if (driver.signOut === undefined) throw new Error("the driver has no signOut()");
      return driver.signOut();
    case "converse":
      if (driver.converse === undefined) throw new Error("the driver has no converse()");
      return driver.converse(step.text);
    case "request_with_approval":
      if (driver.requestWithApproval === undefined)
        throw new Error("the driver has no requestWithApproval()");
      await driver.requestWithApproval(step.url, { method: step.method, body: step.body });
      return;
    case "task_coverage":
      if (driver.taskCoverage === undefined) throw new Error("the driver has no taskCoverage()");
      return driver.taskCoverage();
    case "report_task":
      if (driver.reportTask === undefined) throw new Error("the driver has no reportTask()");
      return driver.reportTask({ task: step.task, description: step.description });
  }
}

/**
 * Runs scenarios against fresh agents from `factory`, in this process, and reports each check as passed,
 * failed or skipped.
 */
export async function runConformance(
  factory: AgentFactory,
  options: ConformanceOptions = {},
): Promise<ConformanceReport> {
  const selected = SCENARIOS.filter(
    (s) => options.scenarios === undefined || options.scenarios.includes(s.name),
  );
  const results: ScenarioResult[] = [];
  for (const definition of selected) {
    const company = new ConformanceCompany(
      definition.company,
      options.agentFetch === undefined ? {} : { agentFetch: options.agentFetch },
    );
    const driver = await factory({ fetch: company.fetch });
    const stepErrors: string[] = [];
    for (const step of definition.steps) {
      try {
        await runStep(step, driver, company);
      } catch (error) {
        stepErrors.push(
          `${step.action}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    results.push(scenarioResult(definition, company, stepErrors));
  }
  return summarize(results);
}

/** A plain-text report, one line per check. */
export function formatReport(report: ConformanceReport): string {
  const mark = { pass: "PASS", fail: "FAIL", skip: "SKIP" } as const;
  const lines = report.results.map((r) => {
    const line = `${mark[r.status]}  ${r.level.padEnd(6)} ${r.section.padEnd(13)} ${r.id}`;
    return r.status === "pass" ? line : `${line}\n        ${r.details.join("\n        ")}`;
  });
  return [
    `Personal Agent Protocol ${report.protocolVersions.join(" and ")} conformance: ${report.passed} passed, ${report.failed} failed, ${report.skipped} skipped`,
    ...lines,
  ].join("\n");
}
