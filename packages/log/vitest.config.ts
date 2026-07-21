import { defineConfig, mergeConfig } from "vitest/config";
import shared from "../../vitest.shared.js";

/**
 * @zw/log is a critical path (>=90% line coverage required).
 * asn1/rfc3161/cms are exercised against real recorded TSA tokens.
 */
export default mergeConfig(
  shared,
  defineConfig({
    test: {
      coverage: {
        provider: "v8",
        include: ["src/**/*.ts"],
        thresholds: { lines: 90, functions: 90, statements: 90 },
      },
    },
  }),
);
