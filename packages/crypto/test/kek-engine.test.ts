import { describe, expect, it } from "vitest";
import {
  KekEngine,
  KeyProviderError,
  generateBoxKeyPair,
  randomFill,
  sealOpen,
} from "../src/index.js";

function newEngine(): KekEngine {
  return new KekEngine(randomFill);
}

describe("KekEngine", () => {
  it("generates, encrypts, decrypts under a held KEK", () => {
    const eng = newEngine();
    const fp = eng.generate("kek-1");
    expect(fp).toHaveLength(32);
    const ad = Buffer.from("bundle:EXAM-1");
    const ct = eng.encrypt("kek-1", Buffer.from("paper content"), ad);
    expect(eng.decrypt("kek-1", ct, ad).toString()).toBe("paper content");
    expect(() => eng.decrypt("kek-1", ct, Buffer.from("other-ad"))).toThrow();
    eng.close();
  });

  it("full ceremony round-trip: split → custodians open → reconstruct → wrap → unwrap", () => {
    const eng = newEngine();
    const fp = eng.generate("kek-exam");
    const ad = Buffer.from("bundle:EXAM-2026-01");
    const ct = eng.encrypt("kek-exam", Buffer.from("the question bank"), ad);

    const custodians = Array.from({ length: 5 }, (_, i) => ({
      id: `cust-${i + 1}`,
      kp: generateBoxKeyPair(),
    }));
    const encShares = eng.splitAndDestroy("kek-exam", {
      threshold: 3,
      custodians: custodians.map((c) => ({ custodianId: c.id, boxPublicKey: c.kp.publicKey })),
    });
    expect(encShares).toHaveLength(5);

    // KEK is gone after split (I-KP-2)
    expect(() => eng.encrypt("kek-exam", Buffer.alloc(1), ad)).toThrowError(KeyProviderError);

    // three custodians decrypt their sealed shares
    const blobs = encShares.slice(0, 3).map((es, i) => {
      const c = custodians[i]!;
      return sealOpen(es.sealed, c.kp.publicKey, c.kp.secretKey);
    });

    const centre = generateBoxKeyPair();
    const result = eng.reconstructWrapRelease(
      blobs,
      [{ recipientId: "centre-A", boxPublicKey: centre.publicKey }],
      fp,
    );
    expect(result.kekFingerprint.equals(fp)).toBe(true);
    expect(result.plaintextKekLifetimeUs).toBeGreaterThan(0);
    expect(result.plaintextKekLifetimeUs).toBeLessThan(500_000); // < 500ms budget

    // centre engine imports the wrapped KEK and can decrypt the bundle
    const centreEng = newEngine();
    const raw = sealOpen(result.wrapped[0]!.sealed, centre.publicKey, centre.secretKey);
    const fp2 = centreEng.import("kek-recv", raw);
    expect(fp2.equals(fp)).toBe(true);
    expect(centreEng.decrypt("kek-recv", ct, ad).toString()).toBe("the question bank");
    centreEng.close();
    eng.close();
  });

  it("rejects reconstruction against a wrong fingerprint", () => {
    const eng = newEngine();
    const fp = eng.generate("k1");
    const custodians = Array.from({ length: 3 }, (_, i) => ({
      id: `c${i}`,
      kp: generateBoxKeyPair(),
    }));
    const shares = eng.splitAndDestroy("k1", {
      threshold: 2,
      custodians: custodians.map((c) => ({ custodianId: c.id, boxPublicKey: c.kp.publicKey })),
    });
    const blobs = shares.slice(0, 2).map((es, i) =>
      sealOpen(es.sealed, custodians[i]!.kp.publicKey, custodians[i]!.kp.secretKey),
    );
    const wrongFp = Buffer.alloc(32, 9);
    expect(() =>
      eng.reconstructWrapRelease(blobs, [], wrongFp),
    ).toThrowError(/fingerprint/);
    // correct fingerprint still works afterwards (no state poisoning)
    const ok = eng.reconstructWrapRelease(blobs, [], fp);
    expect(ok.kekFingerprint.equals(fp)).toBe(true);
    eng.close();
  });

  it("refuses duplicate KEK ids and operations after close", () => {
    const eng = newEngine();
    eng.generate("dup");
    expect(() => eng.generate("dup")).toThrowError(/already held/);
    eng.close();
    expect(() => eng.generate("post-close")).toThrowError(/closed/);
  });
});
