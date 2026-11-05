import type { ConformanceReport } from "./run.ts";

/**
 * Known failures an agent's own repository records, so conformance can run in CI without failing while
 * still catching regressions. An entry is a whole scenario, `sign-in`, or one check in it,
 * `sign-in:oauth.dpop`.
 */
export type Baseline = readonly string[];

/**
 * Reads a baseline file:
 *
 * ```yaml
 * agent:
 *   - sign-in-dpop
 *   - sign-in:oauth.dpop
 * ```
 */
export function parseBaseline(text: string): Baseline {
  const entries: string[] = [];
  let inAgent = false;
  for (const raw of text.split(/\r?\n/)) {
    const comment = raw.search(/\s#/);
    const line = (comment === -1 ? raw : raw.slice(0, comment)).trimEnd();
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    if (/^\S/.test(line)) {
      if (!/^agent:\s*$/.test(line)) throw new Error(`unexpected key in baseline: ${line}`);
      inAgent = true;
      continue;
    }
    if (/^\s+-\s+\S+:\s+\S/.test(line))
      throw new Error(`write "scenario:check" with no space after the colon: ${line.trim()}`);
    const item = /^\s+-\s+(\S+)\s*$/.exec(line);
    if (!inAgent || item === null) throw new Error(`unexpected line in baseline: ${line.trim()}`);
    const entry = item[1] ?? "";
    entries.push(entry);
  }
  const whole = new Set(entries.filter((e) => !e.includes(":")));
  for (const entry of entries)
    if (entry.includes(":") && whole.has(entry.split(":")[0] ?? ""))
      throw new Error(`${entry} is redundant: its scenario is baselined whole`);
  return entries;
}

export interface BaselineOutcome {
  /** Failures not in the baseline: regressions. */
  unexpected: string[];
  /** Failures the baseline expects. */
  expected: string[];
  /** Baseline entries that pass now, which should be removed. */
  stale: string[];
  /** Exit 1 on regressions or stale entries, as in MCP's conformance suite. */
  exitCode: 0 | 1;
}

/** Judges a report against a baseline, per check. */
export function applyBaseline(report: ConformanceReport, baseline: Baseline): BaselineOutcome {
  const failures = report.scenarios.flatMap((s) =>
    s.checks.filter((c) => c.status === "fail").map((c) => `${s.scenario}:${c.id}`),
  );
  const ran = new Set(report.scenarios.map((s) => s.scenario));
  const excused = (failure: string) =>
    baseline.includes(failure) || baseline.includes(failure.split(":")[0] ?? "");
  const unexpected = failures.filter((f) => !excused(f));
  const expected = failures.filter(excused);
  const stale = baseline.filter((entry) => {
    const scenario = entry.split(":")[0] ?? "";
    // An entry for a scenario that didn't run, or a check it never reached, can't be judged.
    if (!ran.has(scenario)) return false;
    if (!entry.includes(":")) return !failures.some((f) => f.startsWith(`${scenario}:`));
    const reached = report.scenarios
      .find((s) => s.scenario === scenario)
      ?.checks.some((c) => `${scenario}:${c.id}` === entry);
    return reached === true && !failures.includes(entry);
  });
  return {
    unexpected,
    expected,
    stale,
    exitCode: unexpected.length > 0 || stale.length > 0 ? 1 : 0,
  };
}
