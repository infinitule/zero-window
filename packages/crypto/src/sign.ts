import sodium from "./sodium.js";
import { secureAlloc } from "./secure.js";

/** Ed25519 signatures (libsodium crypto_sign, detached). */

export const SIGN_PUBLICKEY_BYTES = sodium.crypto_sign_PUBLICKEYBYTES; // 32
export const SIGN_SECRETKEY_BYTES = sodium.crypto_sign_SECRETKEYBYTES; // 64
export const SIGN_BYTES = sodium.crypto_sign_BYTES; // 64

export interface SigningKeyPair {
  publicKey: Buffer;
  /** secure buffer — caller owns zeroization */
  secretKey: Buffer;
}

export function generateSigningKeyPair(): SigningKeyPair {
  const publicKey = Buffer.alloc(SIGN_PUBLICKEY_BYTES);
  const secretKey = secureAlloc(SIGN_SECRETKEY_BYTES);
  sodium.crypto_sign_keypair(publicKey, secretKey);
  return { publicKey, secretKey };
}

export function signingKeyPairFromSeed(seed: Buffer): SigningKeyPair {
  if (seed.length !== sodium.crypto_sign_SEEDBYTES) throw new Error("bad seed length");
  const publicKey = Buffer.alloc(SIGN_PUBLICKEY_BYTES);
  const secretKey = secureAlloc(SIGN_SECRETKEY_BYTES);
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed);
  return { publicKey, secretKey };
}

export function sign(message: Buffer, secretKey: Buffer): Buffer {
  const sig = Buffer.alloc(SIGN_BYTES);
  sodium.crypto_sign_detached(sig, message, secretKey);
  return sig;
}

export function verify(message: Buffer, signature: Buffer, publicKey: Buffer): boolean {
  if (signature.length !== SIGN_BYTES || publicKey.length !== SIGN_PUBLICKEY_BYTES) return false;
  return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}

/**
 * Domain-separated signing: the domain string is prepended so a signature
 * from one protocol context can never be replayed into another
 * (INVARIANT I-SIG-1).
 */
export function signDomain(domain: string, message: Buffer, secretKey: Buffer): Buffer {
  return sign(Buffer.concat([Buffer.from(`zero-window/v1/${domain}\n`, "utf8"), message]), secretKey);
}

export function verifyDomain(
  domain: string,
  message: Buffer,
  signature: Buffer,
  publicKey: Buffer,
): boolean {
  return verify(
    Buffer.concat([Buffer.from(`zero-window/v1/${domain}\n`, "utf8"), message]),
    signature,
    publicKey,
  );
}
