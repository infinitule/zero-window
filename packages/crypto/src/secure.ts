import sodium from "./sodium.js";

/**
 * Secure memory helpers. INVARIANT (I-SEC-1): every buffer that ever holds
 * raw key material is allocated with secureAlloc (guarded, mlocked pages)
 * and released with zeroFree. Ordinary Buffers may hold ciphertext, hashes,
 * signatures and public keys only.
 */

/** Allocate an mlocked, guarded buffer for key material. */
export function secureAlloc(size: number): Buffer {
  return sodium.sodium_malloc(size);
}

/** Zero a buffer in a way the compiler cannot elide. */
export function zeroize(buf: Buffer): void {
  sodium.sodium_memzero(buf);
}

/**
 * Zeroize and (for sodium_malloc'd buffers) make the pages inaccessible.
 * Safe to call on ordinary Buffers as well — they are just zeroized.
 */
export function zeroFree(buf: Buffer): void {
  sodium.sodium_memzero(buf);
  // sodium_free is only valid for sodium_malloc'd memory; sodium-native
  // exposes secure buffers with the `secure` own-property set to true.
  if ((buf as Buffer & { secure?: boolean }).secure === true) {
    try {
      sodium.sodium_free(buf);
    } catch {
      // Already freed — zeroization above still happened.
    }
  }
}

/** Constant-time equality for secrets/MACs. */
export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return sodium.sodium_memcmp(a, b);
}

/** Fill a buffer with CSPRNG bytes. */
export function randomFill(buf: Buffer): void {
  sodium.randombytes_buf(buf);
}

/** Fresh random bytes in an ordinary buffer (for non-secret material: nonces, ids). */
export function randomBytes(n: number): Buffer {
  const b = Buffer.alloc(n);
  sodium.randombytes_buf(b);
  return b;
}
