#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  applyBaseline,
  CHECKS,
  formatReport,
  parseBaseline,
  SCENARIOS,
  type ScenarioResult,
  summarize,
} from "@descope/poppy/conformance";
import { Harness } from "./harness.ts";

const USAGE = `Usage:
  poppy-conformance list
  poppy-conformance agent --command "<command>" [options]

Runs your Personal Agent once per scenario, with the website URL appended to <command>. The agent reads
POPPY_CONFORMANCE_SCENARIO and POPPY_CONFORMANCE_CONTEXT, reaches the test Company through HTTPS_PROXY,
and trusts the CA in NODE_EXTRA_CA_CERTS, SSL_CERT_FILE and REQUESTS_CA_BUNDLE.

Options:
  --scenario <name>           Run one scenario. Repeat for several.
  --suite <suite>             all (default), core, oauth or interactions.
  --expected-failures <file>  YAML baseline of known failures.
  --client-id <url>           Your agent's published client_id. Without it the harness gives the agent a
                              test identity, and the identity checks are skipped.
  --redirect-uri <url>        Your agent's redirect URI, with --client-id.
  --timeout <ms>              Per scenario. Default 30000.
  --results <dir>             Where to write results. Default ./results.
  --verbose                   Print each scenario's output.`;

function parseArgs(argv: string[]): { command: string | undefined; flags: Map<string, string[]> } {
  const [command, ...rest] = argv;
  const flags = new Map<string, string[]>();
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i] ?? "";
    if (!arg.startsWith("--")) throw new Error(`unexpected argument ${arg}`);
    const name = arg.slice(2);
    const value = name === "verbose" ? "true" : rest[++i];
    if (value === undefined) throw new Error(`--${name} needs a value`);
    flags.set(name, [...(flags.get(name) ?? []), value]);
  }
  return { command, flags };
}

function list(): void {
  console.log("Scenarios:");
  for (const s of SCENARIOS)
    console.log(`  ${s.name.padEnd(28)} ${s.suite.padEnd(13)} ${s.description}`);
  console.log("\nChecks:");
  for (const c of CHECKS)
    console.log(`  ${c.id.padEnd(28)} ${c.level.padEnd(7)} ${c.section.padEnd(13)} ${c.title}`);
}

async function agent(flags: Map<string, string[]>): Promise<number> {
  const command = flags.get("command")?.[0];
  if (command === undefined) throw new Error("--command is required");
  const suite = flags.get("suite")?.[0] ?? "all";
  const names = flags.get("scenario");
  const scenarios = SCENARIOS.filter((s) =>
    names === undefined ? suite === "all" || s.suite === suite : names.includes(s.name),
  );
  if (scenarios.length === 0) throw new Error("no scenarios match");
  const clientId = flags.get("client-id")?.[0];
  const redirectUri = flags.get("redirect-uri")?.[0];
  const timeoutMs = Number(flags.get("timeout")?.[0] ?? 30_000);
  const resultsDir = flags.get("results")?.[0] ?? "results";
  const verbose = flags.has("verbose");

  const harness = new Harness({
    ...(clientId === undefined ? {} : { clientId }),
    ...(redirectUri === undefined ? {} : { redirectUri }),
  });
  await harness.start();
  const results: ScenarioResult[] = [];
  const crashed: string[] = [];
  try {
    for (const scenario of scenarios) {
      const run = await harness.run(scenario, command, { timeoutMs });
      results.push(run.result);
      const dir = join(
        resultsDir,
        `${scenario.name}-${new Date().toISOString().replace(/[:.]/g, "-")}`,
      );
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "checks.json"), `${JSON.stringify(run.result, null, 2)}\n`);
      writeFileSync(join(dir, "stdout.txt"), run.stdout);
      writeFileSync(join(dir, "stderr.txt"), run.stderr);
      const failed = run.result.checks.filter((c) => c.status === "fail").length;
      if (run.timedOut || run.exitCode !== 0) crashed.push(scenario.name);
      console.log(
        `${failed === 0 ? "ok  " : "FAIL"}  ${scenario.name} (${run.result.checks.length} checks${failed === 0 ? "" : `, ${failed} failed`})`,
      );
      if (verbose) {
        if (run.stdout !== "") console.log(run.stdout.trimEnd().replace(/^/gm, "      "));
        if (run.stderr !== "") console.log(run.stderr.trimEnd().replace(/^/gm, "      "));
      }
    }
  } finally {
    await harness.stop();
  }

  const report = summarize(results);
  if (crashed.length > 0) console.log(`\nAgent crashed or timed out in: ${crashed.join(", ")}`);
  console.log(`\n${formatReport(report)}`);
  const baselineFile = flags.get("expected-failures")?.[0];
  if (baselineFile !== undefined) {
    const outcome = applyBaseline(report, parseBaseline(readFileSync(baselineFile, "utf8")));
    if (outcome.expected.length > 0)
      console.log(`\nExpected failures: ${outcome.expected.join(", ")}`);
    if (outcome.unexpected.length > 0)
      console.log(`Unexpected failures: ${outcome.unexpected.join(", ")}`);
    if (outcome.stale.length > 0)
      console.log(`Stale baseline entries, which pass now: ${outcome.stale.join(", ")}`);
    return crashed.length > 0 ? 1 : outcome.exitCode;
  }
  // A failed MUST fails the run. A failed SHOULD is reported, and doesn't.
  return crashed.length > 0 || report.results.some((r) => r.status === "fail" && r.level === "MUST")
    ? 1
    : 0;
}

async function main(): Promise<number> {
  const { command, flags } = parseArgs(process.argv.slice(2));
  if (command === "list") {
    list();
    return 0;
  }
  if (command === "agent") return agent(flags);
  console.log(USAGE);
  return command === undefined || command === "help" || command === "--help" ? 0 : 2;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    console.error(`\n${USAGE}`);
    process.exitCode = 2;
  },
);
