import { defineConfig, mergeConfig } from "vitest/config";
import shared from "../../vitest.shared.js";

export default mergeConfig(
  shared,
  defineConfig({
    test: {
      coverage: {
        provider: "v8",
        include: ["src/**/*.ts"],
        exclude: ["src/cli.ts", "src/daemon.ts", "src/index.ts", "src/ipp-types.d.ts"],
        thresholds: { lines: 90, functions: 90, statements: 90 },
      },
    },
  }),
);
