import sodium from "./sodium.js";
import { secureAlloc } from "./secure.js";

/**
 * Password-based key derivation (Argon2id v1.3). Used by @zw/kms-vault to
 * derive the keystore file key from the vault passphrase. Exposed here so
 * libsodium stays behind a single import point (see sodium.ts).
 */

export const PWHASH_SALT_BYTES = sodium.crypto_pwhash_SALTBYTES;
export const PWHASH_OPSLIMIT_MODERATE = sodium.crypto_pwhash_OPSLIMIT_MODERATE;
export const PWHASH_MEMLIMIT_MODERATE = sodium.crypto_pwhash_MEMLIMIT_MODERATE;

export interface KdfParams {
  alg: "argon2id13";
  salt: Buffer;
  opslimit: number;
  memlimit: number;
}

/**
 * Derive `outLen` bytes from a passphrase into a secure buffer.
 * Caller owns zeroization of the result.
 */
export function deriveKeyFromPassphrase(
  passphrase: Buffer,
  params: KdfParams,
  outLen: number,
): Buffer {
  if (params.alg !== "argon2id13") {
    throw new Error(`unsupported KDF algorithm: ${params.alg}`);
  }
  if (params.salt.length !== PWHASH_SALT_BYTES) {
    throw new Error(`KDF salt must be ${PWHASH_SALT_BYTES} bytes`);
  }
  const out = secureAlloc(outLen);
  sodium.crypto_pwhash(
    out,
    passphrase,
    params.salt,
    params.opslimit,
    params.memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  return out;
}
