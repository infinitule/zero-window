import sodium from "./sodium.js";
import { secureAlloc } from "./secure.js";

/**
 * X25519 sealed boxes (libsodium crypto_box_seal): anonymous public-key
 * encryption used to deliver custodian shares and wrapped KEKs. The sender
 * needs only the recipient's public key; the recipient decrypts with their
 * keypair. Forward-authenticity comes from signing the containing protocol
 * message, not from the box.
 */

export const BOX_PUBLICKEY_BYTES = sodium.crypto_box_PUBLICKEYBYTES; // 32
export const BOX_SECRETKEY_BYTES = sodium.crypto_box_SECRETKEYBYTES; // 32
export const BOX_SEAL_OVERHEAD = sodium.crypto_box_SEALBYTES; // 48

export interface BoxKeyPair {
  publicKey: Buffer;
  /** secure buffer — caller owns zeroization */
  secretKey: Buffer;
}

export function generateBoxKeyPair(): BoxKeyPair {
  const publicKey = Buffer.alloc(BOX_PUBLICKEY_BYTES);
  const secretKey = secureAlloc(BOX_SECRETKEY_BYTES);
  sodium.crypto_box_keypair(publicKey, secretKey);
  return { publicKey, secretKey };
}

export function boxKeyPairFromSeed(seed: Buffer): BoxKeyPair {
  if (seed.length !== sodium.crypto_box_SEEDBYTES) throw new Error("bad seed length");
  const publicKey = Buffer.alloc(BOX_PUBLICKEY_BYTES);
  const secretKey = secureAlloc(BOX_SECRETKEY_BYTES);
  sodium.crypto_box_seed_keypair(publicKey, secretKey, seed);
  return { publicKey, secretKey };
}

export function seal(plaintext: Buffer, recipientPublicKey: Buffer): Buffer {
  if (recipientPublicKey.length !== BOX_PUBLICKEY_BYTES) throw new Error("seal: bad public key");
  const out = Buffer.alloc(plaintext.length + BOX_SEAL_OVERHEAD);
  sodium.crypto_box_seal(out, plaintext, recipientPublicKey);
  return out;
}

/**
 * Open a sealed box. Throws on failure. `out` may be a secure buffer when the
 * plaintext is key material.
 */
export function sealOpen(
  sealed: Buffer,
  publicKey: Buffer,
  secretKey: Buffer,
  out?: Buffer,
): Buffer {
  if (sealed.length < BOX_SEAL_OVERHEAD) throw new Error("sealOpen: too short");
  const plain = out ?? Buffer.alloc(sealed.length - BOX_SEAL_OVERHEAD);
  if (plain.length !== sealed.length - BOX_SEAL_OVERHEAD) {
    throw new Error("sealOpen: output buffer length mismatch");
  }
  const ok = sodium.crypto_box_seal_open(plain, sealed, publicKey, secretKey);
  if (!ok) throw new Error("sealOpen: decryption failed");
  return plain;
}
