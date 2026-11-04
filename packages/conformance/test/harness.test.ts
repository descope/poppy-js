import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  applyBaseline,
  parseBaseline,
  SCENARIOS,
  type ScenarioResult,
  summarize,
} from "@descope/poppy/conformance";
import { Harness } from "../src/harness.ts";

const SDK_AGENT = `node ${fileURLToPath(new URL("../../../examples/conformance-agent.ts", import.meta.url))}`;
const PYTHON_AGENT = `python3 ${fileURLToPath(new URL("./fixtures/careless_agent.py", import.meta.url))}`;

function hasPython(): boolean {
  try {
    execFileSync("python3", ["--version"]);
    return true;
  } catch {
    return false;
  }
}

/** Node's fetch honors HTTPS_PROXY with NODE_USE_ENV_PROXY from 22.21 and 24.5. */
function nodeUsesEnvProxy(): boolean {
  const [major = 0, minor = 0] = process.versions.node.split(".").map(Number);
  return major > 24 || (major === 24 && minor >= 5) || (major === 22 && minor >= 21);
}

describe.runIf(nodeUsesEnvProxy())("the harness", () => {
  const harness = new Harness();
  beforeAll(() => harness.start());
  afterAll(() => harness.stop());

  it("passes this SDK's everything-agent, run as a separate process through the proxy", async () => {
    const results: ScenarioResult[] = [];
    for (const scenario of SCENARIOS) results.push((await harness.run(scenario, SDK_AGENT)).result);
    const report = summarize(results);
    const failed = report.results.filter((r) => r.status === "fail");
    expect(failed).toEqual([]);
    // The identity checks test the harness's own identity here, so they're skipped.
    expect(report.results.filter((r) => r.status === "skip").map((r) => r.id)).toEqual([
      "identity.metadata",
      "identity.public-keys",
    ]);
  }, 120_000);

  it.runIf(hasPython())(
    "fails a careless agent written in Python",
    async () => {
      const names = ["discovery-domain", "signed-out", "session-ended-once"];
      const results: ScenarioResult[] = [];
      for (const name of names) {
        const scenario = SCENARIOS.find((s) => s.name === name);
        if (scenario !== undefined)
          results.push((await harness.run(scenario, PYTHON_AGENT)).result);
      }
      const status = Object.fromEntries(summarize(results).results.map((r) => [r.id, r.status]));
      expect(status).toMatchObject({
        "discovery.domain": "fail",
        "session.header": "fail",
        "http.redirects": "fail",
      });
    },
    60_000,
  );
});

describe("expected-failures baselines", () => {
  const report = summarize([
    {
      scenario: "sign-in-dpop",
      description: "",
      stepErrors: [],
      checks: [
        { id: "oauth.dpop", status: "fail", details: ["no proof"] },
        { id: "session.jwt", status: "pass", details: [] },
      ],
    },
    {
      scenario: "signed-out",
      description: "",
      stepErrors: [],
      checks: [{ id: "session.header", status: "pass", details: [] }],
    },
  ]);

  it("excuses listed failures, and flags regressions and stale entries", () => {
    expect(
      applyBaseline(report, parseBaseline("agent:\n  - sign-in-dpop:oauth.dpop\n")),
    ).toMatchObject({
      expected: ["sign-in-dpop:oauth.dpop"],
      unexpected: [],
      stale: [],
      exitCode: 0,
    });
    expect(applyBaseline(report, [])).toMatchObject({
      unexpected: ["sign-in-dpop:oauth.dpop"],
      exitCode: 1,
    });
    expect(applyBaseline(report, ["sign-in-dpop", "signed-out:session.header"])).toMatchObject({
      stale: ["signed-out:session.header"],
      exitCode: 1,
    });
    // A baseline for a scenario that didn't run can't be judged, so it isn't stale.
    expect(applyBaseline(report, ["sign-in-dpop", "sign-in"]).stale).toEqual([]);
  });

  it("rejects malformed baselines", () => {
    expect(() => parseBaseline("server:\n  - x\n")).toThrow("unexpected key");
    expect(() => parseBaseline("agent:\n  - sign-in: oauth.dpop\n")).toThrow("no space");
    expect(() => parseBaseline("agent:\n  - sign-in\n  - sign-in:oauth.dpop\n")).toThrow(
      "redundant",
    );
    expect(parseBaseline("# known failures\nagent:\n  - sign-in # flaky\n")).toEqual(["sign-in"]);
  });
});
