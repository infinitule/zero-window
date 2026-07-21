import { defineConfig, mergeConfig } from "vitest/config";
import shared from "../../vitest.shared.js";

export default mergeConfig(
  shared,
  defineConfig({
    test: {
      coverage: {
        provider: "v8",
        include: ["src/**/*.ts"],
        // The CLI is exercised end-to-end in the M7/M8 drills; index.ts is a
        // re-export barrel with no logic.
        // CLI and daemon are process entrypoints exercised in the M7 deployment
        // drills and the pilot, not by unit tests; index.ts is a re-export barrel.
        exclude: ["src/cli.ts", "src/daemon.ts", "src/index.ts"],
        thresholds: { lines: 90, functions: 90, statements: 90 },
      },
    },
  }),
);
