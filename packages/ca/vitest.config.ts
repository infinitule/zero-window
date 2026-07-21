import { defineConfig, mergeConfig } from "vitest/config";
import shared from "../../vitest.shared.js";

export default mergeConfig(
  shared,
  defineConfig({
    test: {
      coverage: {
        provider: "v8",
        include: ["src/**/*.ts"],
        // The CLI is exercised as a binary in the M7 deployment drills, not
        // by unit tests; measuring it here would misreport library coverage.
        exclude: ["src/cli.ts"],
        thresholds: { lines: 90, functions: 90, statements: 90 },
      },
    },
  }),
);
