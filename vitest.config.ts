import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      // Workspace packages import the SDK by name; test against the source, not a build.
      "@descope/poppy/conformance": new URL("./src/conformance/index.ts", import.meta.url).pathname,
      "@descope/poppy": new URL("./src/index.ts", import.meta.url).pathname,
    },
  },
  test: {
    coverage: {
      enabled: true,
      provider: "v8",
      include: ["src/**"],
      // ponytail: floors just under the coverage of the 0.3 rewrite; raise them as tests grow.
      thresholds: { statements: 82, branches: 72, functions: 90, lines: 87 },
    },
  },
});
