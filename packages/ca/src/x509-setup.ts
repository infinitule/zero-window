// @peculiar/x509 v2 uses tsyringe for dependency injection, which requires a
// Reflect.metadata polyfill to be loaded BEFORE the library. Importing it
// here — the single module every other file in this package imports x509
// through — guarantees the ordering regardless of which entry point is used
// (library, CLI, or tests).
import "reflect-metadata";
import { webcrypto } from "node:crypto";
import * as x509 from "@peculiar/x509";

// Node's WebCrypto implements the interface the library expects.
x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export { x509 };
