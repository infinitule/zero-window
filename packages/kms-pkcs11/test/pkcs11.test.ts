import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runKeyProviderConformance } from "@zw/crypto";
import { Pkcs11KeyProvider } from "../src/index.js";
import { findSoftHsmModule, provisionSoftHsmToken, type SoftHsmToken } from "./softhsm.js";

/**
 * These tests run against SoftHSM2, a real PKCS#11 provider. In CI the
 * SoftHSM2 job requires them to run (ZW_REQUIRE_PKCS11=1 turns a missing
 * SoftHSM2 into a failure instead of a skip).
 */

const required = process.env["ZW_REQUIRE_PKCS11"] === "1";
const available = findSoftHsmModule() !== null;

if (required && !available) {
  throw new Error(
    "ZW_REQUIRE_PKCS11=1 but no SoftHSM2 module found; install softhsm2 or set ZW_PKCS11_MODULE",
  );
}

describe.skipIf(!available)("Pkcs11KeyProvider against SoftHSM2", () => {
  let token: SoftHsmToken;
  // A pristine token with no master wrapping key, and one reserved for the
  // wrong-PIN check. SoftHSM enumerates its token store once, at
  // C_Initialize, so every token this suite needs must exist BEFORE the
  // first provider opens the module.
  let bareToken: SoftHsmToken;
  let pinToken: SoftHsmToken;
  let counter = 0;

  beforeAll(async () => {
    const t = await provisionSoftHsmToken("zw-conformance");
    if (!t) throw new Error("SoftHSM2 provisioning failed");
    token = t;
    const bare = await provisionSoftHsmToken("zw-nomaster", t);
    const pinT = await provisionSoftHsmToken("zw-badpin", t);
    if (!bare || !pinT) throw new Error("SoftHSM2 secondary token provisioning failed");
    bareToken = bare;
    pinToken = pinT;
  });

  afterAll(async () => {
    if (token) await rm(token.dir, { recursive: true, force: true });
  });

  runKeyProviderConformance(
    {
      it: (name, fn) => it(name, fn),
      expectTrue: (cond, message) => expect(cond, message).toBe(true),
    },
    async () =>
      Pkcs11KeyProvider.open({
        modulePath: token.modulePath,
        tokenLabel: token.tokenLabel,
        pin: token.pin,
        // Each provider instance in the conformance suite gets its own seed
        // store but shares the token's master wrapping key — mirroring a real
        // deployment where authority and centre are separate hosts with
        // separate HSMs.
        seedStorePath: join(token.dir, `seeds-${counter++}.json`),
        createIfMissing: true,
      }),
  );

  it("reports token capabilities including native EdDSA support", async () => {
    const p = await Pkcs11KeyProvider.open({
      modulePath: token.modulePath,
      tokenLabel: token.tokenLabel,
      pin: token.pin,
      seedStorePath: join(token.dir, "seeds-caps.json"),
      createIfMissing: true,
    });
    try {
      const caps = p.capabilities();
      expect(caps.tokenLabel).toBe("zw-conformance");
      expect(caps.manufacturer.length).toBeGreaterThan(0);
      expect(caps.aesGcm).toBe(true); // required: seeds are wrapped with AES-GCM
      expect(typeof caps.nativeEdDSA).toBe("boolean");
    } finally {
      await p.close();
    }
  });

  it("persists keys across provider restarts on the same token", async () => {
    const seedStorePath = join(token.dir, "seeds-persist.json");
    const open = () =>
      Pkcs11KeyProvider.open({
        modulePath: token.modulePath,
        tokenLabel: token.tokenLabel,
        pin: token.pin,
        seedStorePath,
        createIfMissing: true,
      });

    const p1 = await open();
    const signPub = await p1.ensureSigningKey("authority-log");
    const boxPub = await p1.ensureBoxKey("authority-box");
    await p1.close();

    const p2 = await open();
    try {
      expect((await p2.getSigningPublicKey("authority-log")).equals(signPub)).toBe(true);
      expect((await p2.getBoxPublicKey("authority-box")).equals(boxPub)).toBe(true);
    } finally {
      await p2.close();
    }
  });

  it("seed store on disk holds only ciphertext bound to the token (T1)", async () => {
    const seedStorePath = join(token.dir, "seeds-atrest.json");
    const p = await Pkcs11KeyProvider.open({
      modulePath: token.modulePath,
      tokenLabel: token.tokenLabel,
      pin: token.pin,
      seedStorePath,
      createIfMissing: true,
    });
    const signPub = await p.ensureSigningKey("k1");
    const boxPub = await p.ensureBoxKey("k2");
    await p.close();

    const raw = await readFile(seedStorePath);
    const parsed = JSON.parse(raw.toString("utf8")) as { entries: Record<string, string> };
    expect(Object.keys(parsed.entries).sort()).toEqual(["box:k2", "sign:k1"]);
    // No derivable public key material appears in the file — everything is
    // AES-GCM ciphertext under the non-extractable token master key.
    expect(raw.includes(signPub)).toBe(false);
    expect(raw.includes(boxPub)).toBe(false);
    for (const b64 of Object.values(parsed.entries)) {
      const blob = Buffer.from(b64, "base64");
      // 12-byte IV + 32-byte seed + 16-byte tag
      expect(blob.length).toBe(12 + 32 + 16);
    }
  });

  it("fails closed when the master wrapping key is absent and creation not requested", async () => {
    // A pristine token with no master wrapping key: opening without
    // createIfMissing must refuse rather than silently minting one.
    await expect(
      Pkcs11KeyProvider.open({
        modulePath: bareToken.modulePath,
        tokenLabel: bareToken.tokenLabel,
        pin: bareToken.pin,
        seedStorePath: join(bareToken.dir, "seeds-nomaster.json"),
      }),
    ).rejects.toThrow(/no master wrapping key/);
  });

  it("rejects a wrong PIN and an unknown token label with precise diagnostics", async () => {
    // Uses a token this process has never logged into, so the PIN is
    // actually checked (login state is per-token, not per-session).
    await expect(
      Pkcs11KeyProvider.open({
        modulePath: pinToken.modulePath,
        tokenLabel: pinToken.tokenLabel,
        pin: "9999",
        seedStorePath: join(pinToken.dir, "seeds-badpin.json"),
        createIfMissing: true,
      }),
    ).rejects.toThrow(/CKR_PIN_INCORRECT/);

    await expect(
      Pkcs11KeyProvider.open({
        modulePath: token.modulePath,
        tokenLabel: "no-such-token",
        pin: token.pin,
        seedStorePath: join(token.dir, "seeds-badlabel.json"),
        createIfMissing: true,
      }),
    ).rejects.toThrow(/no token labelled "no-such-token"/);
  });
});
