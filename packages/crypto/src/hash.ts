import sodium from "./sodium.js";

/** BLAKE2b hashing (libsodium crypto_generichash). */

export const HASH_BYTES = 32;
export const HASH_BYTES_LONG = 64;

export function blake2b(
  data: Buffer | Buffer[],
  opts: { key?: Buffer; outLen?: number } = {},
): Buffer {
  const outLen = opts.outLen ?? HASH_BYTES;
  const out = Buffer.alloc(outLen);
  const parts = Array.isArray(data) ? data : [data];
  const state = Buffer.alloc(sodium.crypto_generichash_STATEBYTES);
  sodium.crypto_generichash_init(state, opts.key ?? null, outLen);
  for (const p of parts) sodium.crypto_generichash_update(state, p);
  sodium.crypto_generichash_final(state, out);
  return out;
}

/** Incremental BLAKE2b hasher. */
export class Blake2bHasher {
  private readonly state: Buffer;
  private readonly outLen: number;
  private finished = false;

  constructor(opts: { key?: Buffer; outLen?: number } = {}) {
    this.outLen = opts.outLen ?? HASH_BYTES;
    this.state = Buffer.alloc(sodium.crypto_generichash_STATEBYTES);
    sodium.crypto_generichash_init(this.state, opts.key ?? null, this.outLen);
  }

  update(data: Buffer): this {
    if (this.finished) throw new Error("hasher already finalized");
    sodium.crypto_generichash_update(this.state, data);
    return this;
  }

  digest(): Buffer {
    if (this.finished) throw new Error("hasher already finalized");
    this.finished = true;
    const out = Buffer.alloc(this.outLen);
    sodium.crypto_generichash_final(this.state, out);
    return out;
  }
}

/**
 * Domain-separated hash: blake2b(personal-prefix || data). Used everywhere a
 * hash is bound into a protocol message so hashes from different contexts can
 * never be confused (INVARIANT I-HASH-1).
 */
export function domainHash(domain: string, data: Buffer | Buffer[]): Buffer {
  const prefix = Buffer.from(`zero-window/v1/${domain}\n`, "utf8");
  const parts = Array.isArray(data) ? data : [data];
  return blake2b([prefix, ...parts]);
}

export function hex(buf: Buffer): string {
  return buf.toString("hex");
}

export function fromHex(s: string): Buffer {
  if (!/^([0-9a-fA-F]{2})*$/.test(s)) throw new Error("invalid hex string");
  return Buffer.from(s, "hex");
}
