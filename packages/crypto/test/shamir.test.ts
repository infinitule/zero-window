import { describe, expect, it } from "vitest";
import { blake2b } from "../src/hash.js";
import { gfMul, gfPolyEval } from "../src/gf256.js";
import {
  parseShare,
  serializeShare,
  shamirCombine,
  shamirSplit,
  type ShamirShare,
} from "../src/shamir.js";

/** Table-free reference GF(2^8) multiply (Russian peasant), used to
 * cross-check the table-based implementation — an independent code path. */
function refMul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

/** Deterministic entropy stream for KATs: BLAKE2b counter mode. */
function deterministicEntropy(seed: string): (buf: Buffer) => void {
  let counter = 0;
  let pool = Buffer.alloc(0);
  return (buf: Buffer) => {
    while (pool.length < buf.length) {
      pool = Buffer.concat([
        pool,
        blake2b(Buffer.from(`${seed}/${counter++}`, "utf8"), { outLen: 64 }),
      ]);
    }
    pool.copy(buf, 0, 0, buf.length);
    pool = pool.subarray(buf.length);
  };
}

describe("GF(256) arithmetic", () => {
  it("table-based multiply matches the table-free reference for all 65536 pairs", () => {
    for (let a = 0; a < 256; a++) {
      for (let b = 0; b < 256; b++) {
        expect(gfMul(a, b)).toBe(refMul(a, b));
      }
    }
  });

  it("polynomial evaluation matches direct reference computation", () => {
    const coeffs = new Uint8Array([0x53, 0xca, 0x01, 0xff]);
    for (let x = 0; x < 256; x++) {
      let want = 0;
      let xp = 1;
      for (const c of coeffs) {
        want ^= refMul(c, xp);
        xp = refMul(xp, x);
      }
      expect(gfPolyEval(coeffs, x)).toBe(want);
    }
  });
});

describe("Shamir split/combine", () => {
  it("KAT: deterministic entropy produces a stable, reconstructable share set", () => {
    const secret = Buffer.from("0123456789abcdef0123456789abcdef", "hex");
    const shares = shamirSplit(secret, {
      threshold: 3,
      shares: 5,
      entropy: deterministicEntropy("zw-shamir-kat-1"),
    });
    expect(shares).toHaveLength(5);
    // Every 3-subset reconstructs the secret
    for (let a = 0; a < 5; a++) {
      for (let b = a + 1; b < 5; b++) {
        for (let c = b + 1; c < 5; c++) {
          const got = shamirCombine([shares[a]!, shares[b]!, shares[c]!]);
          expect(got.equals(secret)).toBe(true);
        }
      }
    }
    // Regression pin: share bytes are a pure function of the entropy stream.
    const digest = blake2b(Buffer.concat(shares.map((s) => Buffer.concat([s.setId, Buffer.from([s.x, s.threshold]), s.y]))));
    expect(digest.toString("hex")).toMatchSnapshot();
  });

  it("reconstructs with random entropy for varied (t, n)", () => {
    for (const [t, n] of [
      [2, 2],
      [2, 5],
      [3, 5],
      [5, 7],
      [10, 12],
    ] as const) {
      const secret = Buffer.alloc(32);
      deterministicEntropy(`secret-${t}-${n}`)(secret);
      const shares = shamirSplit(secret, { threshold: t, shares: n });
      expect(shamirCombine(shares.slice(0, t)).equals(secret)).toBe(true);
      expect(shamirCombine(shares.slice(n - t)).equals(secret)).toBe(true);
      expect(shamirCombine(shares).equals(secret)).toBe(true);
    }
  });

  it("fails closed below threshold", () => {
    const secret = Buffer.from("very-secret-key-material-32bytes");
    const shares = shamirSplit(secret, { threshold: 3, shares: 5 });
    expect(() => shamirCombine(shares.slice(0, 2))).toThrow(/threshold is 3/);
  });

  it("rejects mixed share sets, duplicates and inconsistent shapes", () => {
    const s1 = shamirSplit(Buffer.alloc(16, 1), { threshold: 2, shares: 3 });
    const s2 = shamirSplit(Buffer.alloc(16, 2), { threshold: 2, shares: 3 });
    expect(() => shamirCombine([s1[0]!, s2[1]!])).toThrow(/different splits/);
    expect(() => shamirCombine([s1[0]!, s1[0]!])).toThrow(/at least|duplicate/i);
  });

  it("t-1 shares are statistically independent of the secret (chi-square)", () => {
    // For two maximally different secrets, the marginal distribution of any
    // single share byte must be uniform. 4096 trials, 256 bins; chi-square
    // 99.9% critical value for 255 dof ≈ 340.5. We assert < 400 to keep the
    // false-failure rate negligible while still catching any biased splitter
    // (a leaky implementation, e.g. a_1=secret, would produce a constant bin).
    for (const secretByte of [0x00, 0xff]) {
      const secret = Buffer.alloc(1, secretByte);
      const counts = new Array<number>(256).fill(0);
      const entropy = deterministicEntropy(`independence-${secretByte}`);
      const N = 4096;
      for (let i = 0; i < N; i++) {
        const shares = shamirSplit(secret, { threshold: 2, shares: 2, entropy });
        counts[shares[0]!.y[0]!]!++;
      }
      const expected = N / 256;
      const chi2 = counts.reduce((acc, c) => acc + ((c - expected) ** 2) / expected, 0);
      expect(chi2).toBeLessThan(400);
    }
  });

  it("share serialization round-trips and detects corruption", () => {
    const shares = shamirSplit(Buffer.alloc(32, 7), { threshold: 3, shares: 5 });
    for (const s of shares) {
      const blob = serializeShare(s);
      const back = parseShare(blob);
      expect(back.x).toBe(s.x);
      expect(back.threshold).toBe(s.threshold);
      expect(back.setId.equals(s.setId)).toBe(true);
      expect(back.y.equals(s.y)).toBe(true);
      const corrupted = Buffer.from(blob);
      corrupted[20]! ^= 0x40;
      expect(() => parseShare(corrupted)).toThrow(/checksum|magic|length/);
    }
  });

  it("a forged share at threshold yields a wrong secret, not the real one", () => {
    const secret = Buffer.alloc(32, 0x42);
    const shares = shamirSplit(secret, { threshold: 3, shares: 5 });
    const forged: ShamirShare = {
      setId: Buffer.from(shares[0]!.setId),
      x: 5,
      threshold: 3,
      y: Buffer.alloc(32, 0xaa),
    };
    const got = shamirCombine([shares[0]!, shares[1]!, forged]);
    expect(got.equals(secret)).toBe(false);
  });
});
