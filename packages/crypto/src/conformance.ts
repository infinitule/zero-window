import { generateBoxKeyPair, sealOpen } from "./box.js";
import { verifyDomain } from "./sign.js";
import { KekEngine } from "./kek-engine.js";
import type { KeyProvider } from "./provider.js";

/**
 * Provider conformance suite. Every KeyProvider implementation must pass
 * these behaviours identically — this is what makes the abstraction real
 * rather than aspirational. Exported from @zw/crypto so each provider package
 * runs it against its own backend (SoftHSM2, file vault) in its own tests.
 *
 * Written framework-agnostically: the caller supplies `it` and `expectTrue`
 * so it can be driven by vitest without @zw/crypto depending on vitest.
 */

export interface ConformanceHarness {
  it(name: string, fn: () => Promise<void>): void;
  expectTrue(cond: boolean, message: string): void;
}

export function runKeyProviderConformance(
  harness: ConformanceHarness,
  makeProvider: () => Promise<KeyProvider>,
): void {
  const { it, expectTrue } = harness;

  it("conformance: signing keys are stable, sign/verify with domain separation", async () => {
    const p = await makeProvider();
    try {
      const pub = await p.ensureSigningKey("authority-log");
      expectTrue(pub.length === 32, "Ed25519 public key must be 32 bytes");
      const again = await p.getSigningPublicKey("authority-log");
      expectTrue(again.equals(pub), "signing public key must be stable across calls");
      // ensureSigningKey is idempotent — must not rotate the key
      expectTrue(
        (await p.ensureSigningKey("authority-log")).equals(pub),
        "ensureSigningKey must be idempotent",
      );

      const msg = Buffer.from("BUNDLE_CREATED|exam-1");
      const sig = await p.sign("authority-log", "log-entry", msg);
      expectTrue(verifyDomain("log-entry", msg, sig, pub), "signature must verify in its domain");
      expectTrue(
        !verifyDomain("other-domain", msg, sig, pub),
        "signature must NOT verify under a different domain (I-SIG-1)",
      );
      expectTrue(
        !verifyDomain("log-entry", Buffer.from("tampered"), sig, pub),
        "signature must not verify for a different message",
      );
    } finally {
      await p.close();
    }
  });

  it("conformance: box keys are stable and open their own sealed envelopes", async () => {
    const p = await makeProvider();
    try {
      const pub = await p.ensureBoxKey("centre-A");
      expectTrue(pub.length === 32, "X25519 public key must be 32 bytes");
      expectTrue(
        (await p.getBoxPublicKey("centre-A")).equals(pub),
        "box public key must be stable",
      );

      const { seal } = await import("./box.js");
      const payload = Buffer.from("share-material-abcdef");
      const opened = await p.openSealedShare("centre-A", seal(payload, pub));
      expectTrue(opened.equals(payload), "provider must open a box sealed to its own public key");
    } finally {
      await p.close();
    }
  });

  it("conformance: unknown key ids fail closed with KEY_NOT_FOUND", async () => {
    const p = await makeProvider();
    try {
      let code = "";
      try {
        await p.getSigningPublicKey("no-such-key");
      } catch (err) {
        code = (err as { code?: string }).code ?? "";
      }
      expectTrue(code === "KEY_NOT_FOUND", `expected KEY_NOT_FOUND, got "${code}"`);
    } finally {
      await p.close();
    }
  });

  it("conformance: full KEK lifecycle — generate, encrypt, split, release, unwrap, decrypt", async () => {
    const authority = await makeProvider();
    const centre = await makeProvider();
    try {
      const ad = Buffer.from("bundle:EXAM-2026-CONF");
      const plaintext = Buffer.from("question bank payload");

      const fp = await authority.generateKek("kek-conf");
      const ct = await authority.aeadEncryptWithKek("kek-conf", plaintext, ad);

      // custodian personal keys (held by humans, not by the provider)
      const custodians = Array.from({ length: 5 }, (_, i) => ({
        custodianId: `cust-${i + 1}`,
        kp: generateBoxKeyPair(),
      }));
      const shares = await authority.splitAndDestroyKek("kek-conf", {
        threshold: 3,
        custodians: custodians.map((c) => ({
          custodianId: c.custodianId,
          boxPublicKey: c.kp.publicKey,
        })),
      });
      expectTrue(shares.length === 5, "expected 5 sealed shares");

      // KEK must be gone from the provider after the split (I-KP-2)
      let destroyed = false;
      try {
        await authority.aeadEncryptWithKek("kek-conf", plaintext, ad);
      } catch {
        destroyed = true;
      }
      expectTrue(destroyed, "KEK must not survive splitAndDestroyKek");

      // three custodians recover their share material
      const blobs = shares
        .slice(0, 3)
        .map((s, i) => sealOpen(s.sealed, custodians[i]!.kp.publicKey, custodians[i]!.kp.secretKey));

      const centrePub = await centre.ensureBoxKey("centre-kek-recv");
      const released = await authority.reconstructWrapRelease(
        blobs,
        [{ recipientId: "centre-1", boxPublicKey: centrePub }],
        fp,
      );
      expectTrue(released.kekFingerprint.equals(fp), "released KEK fingerprint must match");
      expectTrue(
        released.plaintextKekLifetimeUs > 0 && released.plaintextKekLifetimeUs < 500_000,
        `plaintext KEK lifetime ${released.plaintextKekLifetimeUs}us must be within the 500ms budget`,
      );

      const gotFp = await centre.unwrapKek(
        "kek-recv",
        released.wrapped[0]!.sealed,
        "centre-kek-recv",
      );
      expectTrue(gotFp.equals(fp), "unwrapped KEK fingerprint must match the authority's");
      const back = await centre.aeadDecryptWithKek("kek-recv", ct, ad);
      expectTrue(back.equals(plaintext), "centre must decrypt the bundle after release");

      // wrong associated data must fail closed
      let adRejected = false;
      try {
        await centre.aeadDecryptWithKek("kek-recv", ct, Buffer.from("wrong-ad"));
      } catch {
        adRejected = true;
      }
      expectTrue(adRejected, "AEAD must reject mismatched associated data");

      await centre.discardKek("kek-recv");
      let discarded = false;
      try {
        await centre.aeadDecryptWithKek("kek-recv", ct, ad);
      } catch {
        discarded = true;
      }
      expectTrue(discarded, "discardKek must remove the KEK");
    } finally {
      await authority.close();
      await centre.close();
    }
  });

  it("conformance: release rejects below-threshold and wrong-fingerprint share sets", async () => {
    const p = await makeProvider();
    try {
      const fp = await p.generateKek("kek-neg");
      const custodians = Array.from({ length: 5 }, (_, i) => ({
        custodianId: `c${i}`,
        kp: generateBoxKeyPair(),
      }));
      const shares = await p.splitAndDestroyKek("kek-neg", {
        threshold: 3,
        custodians: custodians.map((c) => ({
          custodianId: c.custodianId,
          boxPublicKey: c.kp.publicKey,
        })),
      });
      const blobs = shares.map((s, i) =>
        sealOpen(s.sealed, custodians[i]!.kp.publicKey, custodians[i]!.kp.secretKey),
      );

      // T9: two custodians must not be able to release a 3-of-5 KEK
      let belowThresholdRejected = false;
      try {
        await p.reconstructWrapRelease(blobs.slice(0, 2), [], fp);
      } catch {
        belowThresholdRejected = true;
      }
      expectTrue(belowThresholdRejected, "release must fail below threshold (T9)");

      let wrongFpRejected = false;
      try {
        await p.reconstructWrapRelease(blobs.slice(0, 3), [], Buffer.alloc(32, 0xab));
      } catch (err) {
        wrongFpRejected = (err as { code?: string }).code === "FINGERPRINT_MISMATCH";
      }
      expectTrue(wrongFpRejected, "release must reject a fingerprint mismatch");

      // corrupted share blob must be detected, not silently produce a wrong KEK
      const corrupted = blobs.slice(0, 3).map((b) => Buffer.from(b));
      const victim = corrupted[0];
      if (!victim) throw new Error("conformance: expected 3 share blobs");
      victim[20] = (victim[20] ?? 0) ^ 0xff;
      let corruptionRejected = false;
      try {
        await p.reconstructWrapRelease(corrupted, [], fp);
      } catch (err) {
        corruptionRejected = (err as { code?: string }).code === "SHARE_INVALID";
      }
      expectTrue(corruptionRejected, "corrupted share must be rejected with SHARE_INVALID");
    } finally {
      await p.close();
    }
  });

  it("conformance: KEK fingerprints are domain-separated hashes, never key bytes", async () => {
    const p = await makeProvider();
    try {
      const fp = await p.generateKek("kek-fp");
      expectTrue(fp.length === 32, "fingerprint must be a 32-byte hash");
      // A fingerprint must not equal the hash of an all-zero key, and must
      // differ between two independently generated KEKs.
      const fp2 = await p.generateKek("kek-fp-2");
      expectTrue(!fp.equals(fp2), "distinct KEKs must have distinct fingerprints");
      expectTrue(
        !fp.equals(KekEngine.fingerprintOf(Buffer.alloc(32))),
        "fingerprint must not be that of a zero key",
      );
    } finally {
      await p.close();
    }
  });
}
