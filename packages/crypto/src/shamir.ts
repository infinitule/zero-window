import { gfDiv, gfMul, gfPolyEval } from "./gf256.js";
import { blake2b, domainHash } from "./hash.js";
import { randomFill, secureAlloc, zeroFree } from "./secure.js";

/**
 * Shamir secret sharing over GF(2^8), byte-parallel: each secret byte is the
 * constant term of an independent random polynomial of degree t-1; share j
 * carries the evaluations at x = j (1-based, x=0 is the secret and never a
 * share index).
 *
 * INVARIANT I-SSS-1: coefficients a_1..a_{t-1} are fresh CSPRNG output per
 * byte per split; any t-1 shares are therefore statistically independent of
 * the secret (verified by property test).
 *
 * Share wire format (version 1):
 *   magic "ZWS1" | setId(8) | x(1) | t(1) | secretLen(2 BE) | y(secretLen) | check(16)
 * where check = BLAKE2b-16 over the preceding bytes, domain-separated.
 * The checksum detects corruption/mix-ups; it is not a MAC. Authenticity of
 * shares comes from the sealed+signed ceremony envelope that carries them.
 */

export interface ShamirShare {
  /** identifies the split this share belongs to (random, public) */
  setId: Buffer;
  /** evaluation point, 1..255 */
  x: number;
  threshold: number;
  /** evaluations, same length as the secret */
  y: Buffer;
}

export interface SplitOptions {
  threshold: number;
  shares: number;
  /**
   * Test-only injection point for deterministic KATs. Production callers must
   * omit it (CSPRNG is used).
   */
  entropy?: (buf: Buffer) => void;
}

export function shamirSplit(secret: Buffer, opts: SplitOptions): ShamirShare[] {
  const { threshold: t, shares: n } = opts;
  if (!Number.isInteger(t) || !Number.isInteger(n)) throw new Error("shamirSplit: t,n must be integers");
  if (t < 2) throw new Error("shamirSplit: threshold must be >= 2");
  if (n < t) throw new Error("shamirSplit: shares must be >= threshold");
  if (n > 255) throw new Error("shamirSplit: at most 255 shares");
  if (secret.length === 0) throw new Error("shamirSplit: empty secret");

  const fill = opts.entropy ?? randomFill;
  const setId = Buffer.alloc(8);
  fill(setId);

  const ys: Buffer[] = [];
  for (let j = 0; j < n; j++) ys.push(Buffer.alloc(secret.length));

  // coefficient buffer is key-equivalent material → secure alloc + zeroize
  const coeffs = secureAlloc(t);
  try {
    for (let i = 0; i < secret.length; i++) {
      fill(coeffs);
      coeffs[0] = secret[i]!;
      for (let j = 0; j < n; j++) {
        ys[j]![i] = gfPolyEval(coeffs, j + 1);
      }
    }
  } finally {
    zeroFree(coeffs);
  }

  return ys.map((y, j) => ({ setId: Buffer.from(setId), x: j + 1, threshold: t, y }));
}

/**
 * Reconstruct the secret from >= t shares via Lagrange interpolation at x=0.
 * `out` should be a secure buffer when the secret is key material.
 * Throws with precise diagnostics on malformed/mismatched share sets.
 */
export function shamirCombine(shares: ShamirShare[], out?: Buffer): Buffer {
  if (shares.length === 0) throw new Error("shamirCombine: no shares");
  const t = shares[0]!.threshold;
  const len = shares[0]!.y.length;
  const setId = shares[0]!.setId;
  if (shares.length < t) {
    throw new Error(`shamirCombine: ${shares.length} share(s) provided, threshold is ${t}`);
  }
  const seen = new Set<number>();
  for (const s of shares) {
    if (!s.setId.equals(setId)) throw new Error("shamirCombine: shares from different splits");
    if (s.threshold !== t) throw new Error("shamirCombine: inconsistent thresholds");
    if (s.y.length !== len) throw new Error("shamirCombine: inconsistent share lengths");
    if (s.x < 1 || s.x > 255) throw new Error(`shamirCombine: invalid share index ${s.x}`);
    if (seen.has(s.x)) throw new Error(`shamirCombine: duplicate share index ${s.x}`);
    seen.add(s.x);
  }

  const use = shares.slice(0, t);
  // Lagrange basis at x=0: L_j(0) = Π_{m≠j} x_m / (x_m ⊕ x_j)
  const lagrange: number[] = use.map((sj, j) => {
    let num = 1;
    let den = 1;
    for (let m = 0; m < use.length; m++) {
      if (m === j) continue;
      num = gfMul(num, use[m]!.x);
      den = gfMul(den, use[m]!.x ^ sj.x);
    }
    return gfDiv(num, den);
  });

  const secret = out ?? Buffer.alloc(len);
  if (secret.length !== len) throw new Error("shamirCombine: output buffer length mismatch");
  secret.fill(0);
  for (let i = 0; i < len; i++) {
    let b = 0;
    for (let j = 0; j < use.length; j++) {
      b ^= gfMul(use[j]!.y[i]!, lagrange[j]!);
    }
    secret[i] = b;
  }
  return secret;
}

const SHARE_MAGIC = Buffer.from("ZWS1", "ascii");
const CHECK_LEN = 16;

export function serializeShare(s: ShamirShare): Buffer {
  if (s.setId.length !== 8) throw new Error("serializeShare: setId must be 8 bytes");
  const head = Buffer.alloc(SHARE_MAGIC.length + 8 + 1 + 1 + 2);
  SHARE_MAGIC.copy(head, 0);
  s.setId.copy(head, 4);
  head[12] = s.x;
  head[13] = s.threshold;
  head.writeUInt16BE(s.y.length, 14);
  const body = Buffer.concat([head, s.y]);
  const check = blake2b(domainHash("shamir-share", body), { outLen: CHECK_LEN });
  return Buffer.concat([body, check]);
}

export function parseShare(buf: Buffer): ShamirShare {
  if (buf.length < 16 + 1 + CHECK_LEN) throw new Error("parseShare: too short");
  if (!buf.subarray(0, 4).equals(SHARE_MAGIC)) throw new Error("parseShare: bad magic");
  const yLen = buf.readUInt16BE(14);
  const expected = 16 + yLen + CHECK_LEN;
  if (buf.length !== expected) {
    throw new Error(`parseShare: length ${buf.length}, expected ${expected}`);
  }
  const body = buf.subarray(0, 16 + yLen);
  const check = buf.subarray(16 + yLen);
  const want = blake2b(domainHash("shamir-share", Buffer.from(body)), { outLen: CHECK_LEN });
  if (!want.equals(check)) throw new Error("parseShare: checksum mismatch (corrupted share)");
  return {
    setId: Buffer.from(buf.subarray(4, 12)),
    x: buf[12]!,
    threshold: buf[13]!,
    y: Buffer.from(buf.subarray(16, 16 + yLen)),
  };
}
