import { defineConfig, mergeConfig } from "vitest/config";
import shared from "../../vitest.shared.js";

/**
 * @zw/crypto is a critical path: the engineering bar requires >=90% line
 * coverage here. Thresholds are enforced in CI by `pnpm coverage`.
 */
export default mergeConfig(
  shared,
  defineConfig({
    test: {
      coverage: {
        provider: "v8",
        include: ["src/**/*.ts"],
        // Ambient typings and the sodium import shim carry no logic.
        exclude: ["src/sodium.ts", "src/sodium-native.d.ts", "src/conformance.ts"],
        thresholds: {
          lines: 90,
          functions: 90,
          statements: 90,
        },
      },
    },
  }),
);
