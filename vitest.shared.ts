import { defineConfig } from "vitest/config";

/**
 * Shared vitest configuration.
 *
 * `sodium-native` and `pkcs11js` are native (N-API) modules. Vite must not
 * try to transform or bundle them — they are externalized so Node's own
 * resolver loads the .node binary from the package that declares the
 * dependency. Under pnpm's strict node_modules layout this is also what makes
 * a transitive native dep resolvable from a dependent package's tests.
 */
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 30_000,
    server: {
      deps: {
        external: [/sodium-native/, /pkcs11js/],
      },
    },
  },
});
