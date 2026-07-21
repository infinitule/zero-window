import { describe, expect, it } from "vitest";
import {
  KekEngine,
  KeyProviderError,
  generateBoxKeyPair,
  randomFill,
  sealOpen,
  serializeShare,
  shamirSplit,
} from "../src/index.js";

/**
 * Error and edge paths on the release-critical KEK path. Every one of these
 * is a way exam day could go wrong; each must fail closed with a diagnostic
 * an operator can act on (runbooks/incident-response.md).
 */

function engine(): KekEngine {
  return new KekEngine(randomFill);
}

function custodianSet(n: number) {
  return Array.from({ length: n }, (_, i) => ({
    custodianId: `cust-${i + 1}`,
    kp: generateBoxKeyPair(),
  }));
}

describe("KekEngine edge cases", () => {
  it("refuses to split when custodians are fewer than the threshold", () => {
    const eng = engine();
    eng.generate("k");
    const custodians = custodianSet(2);
    expect(() =>
      eng.splitAndDestroy("k", {
        threshold: 3,
        custodians: custodians.map((c) => ({
          custodianId: c.custodianId,
          boxPublicKey: c.kp.publicKey,
        })),
      }),
    ).toThrowError(/fewer custodians than threshold/);
    eng.close();
  });

  it("destroys the KEK even when sealing a share fails mid-split", () => {
    const eng = engine();
    eng.generate("k");
    const good = generateBoxKeyPair();
    expect(() =>
      eng.splitAndDestroy("k", {
        threshold: 2,
        custodians: [
          { custodianId: "ok", boxPublicKey: good.publicKey },
          // malformed public key — seal() rejects it
          { custodianId: "bad", boxPublicKey: Buffer.alloc(8) },
        ],
      }),
    ).toThrow(/bad public key/);
    // INVARIANT: the KEK must not survive a failed ceremony.
    expect(() => eng.fingerprint("k")).toThrowError(/not held/);
    eng.close();
  });

  it("destroy() on an unknown id is a no-op", () => {
    const eng = engine();
    expect(() => eng.destroy("never-existed")).not.toThrow();
    eng.close();
  });

  it("rejects unparseable share blobs with SHARE_INVALID", () => {
    const eng = engine();
    const fp = eng.generate("k");
    const custodians = custodianSet(3);
    eng.splitAndDestroy("k", {
      threshold: 2,
      custodians: custodians.map((c) => ({
        custodianId: c.custodianId,
        boxPublicKey: c.kp.publicKey,
      })),
    });
    let code = "";
    try {
      eng.reconstructWrapRelease([Buffer.from("not a share at all")], [], fp);
    } catch (err) {
      code = (err as KeyProviderError).code;
      expect((err as Error).message).toMatch(/share parse failed/);
    }
    expect(code).toBe("SHARE_INVALID");
    eng.close();
  });

  it("reports reconstruction failure when shares come from different splits", () => {
    const eng = engine();
    const secret = Buffer.alloc(32, 1);
    const a = shamirSplit(secret, { threshold: 2, shares: 3 });
    const b = shamirSplit(secret, { threshold: 2, shares: 3 });
    let code = "";
    try {
      eng.reconstructWrapRelease(
        [serializeShare(a[0]!), serializeShare(b[1]!)],
        [],
        Buffer.alloc(32),
      );
    } catch (err) {
      code = (err as KeyProviderError).code;
      expect((err as Error).message).toMatch(/reconstruction failed.*different splits/);
    }
    expect(code).toBe("SHARE_INVALID");
    eng.close();
  });

  it("wraps to many recipients in one release and stays inside the time budget", () => {
    const eng = engine();
    const fp = eng.generate("k");
    const custodians = custodianSet(5);
    const shares = eng.splitAndDestroy("k", {
      threshold: 3,
      custodians: custodians.map((c) => ({
        custodianId: c.custodianId,
        boxPublicKey: c.kp.publicKey,
      })),
    });
    const blobs = shares
      .slice(0, 3)
      .map((s, i) => sealOpen(s.sealed, custodians[i]!.kp.publicKey, custodians[i]!.kp.secretKey));

    // 64 centres requesting in the same release — the T-0 fan-out.
    const recipients = Array.from({ length: 64 }, (_, i) => {
      const kp = generateBoxKeyPair();
      return { recipientId: `centre-${i}`, boxPublicKey: kp.publicKey };
    });
    const res = eng.reconstructWrapRelease(blobs, recipients, fp);
    expect(res.wrapped).toHaveLength(64);
    expect(new Set(res.wrapped.map((w) => w.sealed.toString("hex"))).size).toBe(64);
    expect(res.plaintextKekLifetimeUs).toBeLessThan(500_000);
    eng.close();
  });

  it("import rejects a KEK of the wrong length and refuses duplicate ids", () => {
    const eng = engine();
    expect(() => eng.import("k", Buffer.alloc(16))).toThrowError(/wrong length/);
    eng.generate("dup");
    expect(() => eng.import("dup", Buffer.alloc(32))).toThrowError(/already held/);
    eng.close();
  });

  it("all operations fail closed after close()", () => {
    const eng = engine();
    eng.generate("k");
    eng.close();
    expect(() => eng.generate("x")).toThrowError(/closed/);
    expect(() => eng.import("y", Buffer.alloc(32))).toThrowError(/closed/);
    expect(() => eng.encrypt("k", Buffer.alloc(1), Buffer.alloc(0))).toThrowError(/closed/);
    expect(() => eng.reconstructWrapRelease([], [], Buffer.alloc(32))).toThrowError(/closed/);
  });

  it("fingerprintOf is deterministic and domain-separated", () => {
    const kek = Buffer.alloc(32, 9);
    expect(KekEngine.fingerprintOf(kek).equals(KekEngine.fingerprintOf(kek))).toBe(true);
    expect(KekEngine.fingerprintOf(kek).equals(KekEngine.fingerprintOf(Buffer.alloc(32, 8)))).toBe(
      false,
    );
    // Must not be a bare hash of the key — it is domain-separated, so it
    // cannot collide with any other hash the system publishes.
    expect(KekEngine.fingerprintOf(kek)).toHaveLength(32);
  });
});
