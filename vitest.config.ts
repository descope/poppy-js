import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      enabled: true,
      provider: "v8",
      include: ["src/**"],
      // ponytail: floors just under the coverage at 0.1.0; raise them as tests grow.
      thresholds: { statements: 89, branches: 80, functions: 90, lines: 93 },
    },
  },
});
