import { blake2b } from "@zw/crypto";

/**
 * Deterministic PRNG for paper assembly.
 *
 * BLAKE2b in counter mode, keyed by the per-candidate seed. This is NOT a
 * source of secrecy — the seed is derivable from public log data plus the
 * (post-release) bundle plaintext, which is exactly the point: any auditor
 * holding the evidence can re-derive every paper byte-for-byte (F4).
 *
 * INVARIANT I-GEN-1: every draw depends only on (seed, draw sequence). No
 * wall clock, no Math.random, no platform-dependent iteration order anywhere
 * in the assembly path.
 */
export class DeterministicStream {
  private counter = 0;
  private pool: Buffer = Buffer.alloc(0);
  private offset = 0;

  constructor(private readonly seed: Buffer) {
    if (seed.length !== 32) throw new Error("DeterministicStream: seed must be 32 bytes");
  }

  private refill(): void {
    const block = Buffer.alloc(8);
    block.writeBigUInt64BE(BigInt(this.counter++));
    this.pool = blake2b(block, { key: this.seed, outLen: 64 });
    this.offset = 0;
  }

  nextByte(): number {
    if (this.offset >= this.pool.length) this.refill();
    return this.pool[this.offset++]!;
  }

  nextUint32(): number {
    let v = 0;
    for (let i = 0; i < 4; i++) v = (v << 8) | this.nextByte();
    return v >>> 0;
  }

  /**
   * Uniform integer in [0, n) via rejection sampling — modulo bias would make
   * some papers statistically more likely than others, which an adversary
   * predicting paper composition could exploit, and which would also make the
   * uniformity property test fail.
   */
  nextBelow(n: number): number {
    if (!Number.isInteger(n) || n <= 0) throw new Error(`nextBelow: n must be a positive integer`);
    if (n === 1) return 0;
    const limit = Math.floor(0x1_0000_0000 / n) * n;
    for (;;) {
      const v = this.nextUint32();
      if (v < limit) return v % n;
    }
  }

  /** Fisher–Yates. Returns a new array; input order is never mutated. */
  shuffle<T>(items: readonly T[]): T[] {
    const out = [...items];
    for (let i = out.length - 1; i > 0; i--) {
      const j = this.nextBelow(i + 1);
      [out[i], out[j]] = [out[j]!, out[i]!];
    }
    return out;
  }

  /** Sample k items without replacement, preserving deterministic order of draws. */
  sample<T>(items: readonly T[], k: number): T[] {
    if (k > items.length) {
      throw new Error(`sample: requested ${k} from pool of ${items.length}`);
    }
    const pool = [...items];
    const out: T[] = [];
    for (let i = 0; i < k; i++) {
      const j = this.nextBelow(pool.length);
      out.push(pool[j]!);
      pool.splice(j, 1);
    }
    return out;
  }
}
