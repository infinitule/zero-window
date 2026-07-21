import sodium from "./sodium.js";
import { randomBytes } from "./secure.js";

/**
 * AEAD: XChaCha20-Poly1305 (IETF). The 24-byte nonce is random per message —
 * safe for random nonces at any realistic message volume.
 */

export const AEAD_KEY_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES; // 32
export const AEAD_NONCE_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
export const AEAD_TAG_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16

export interface AeadCiphertext {
  /** AEAD suite identifier, recorded so ciphertext is self-describing. */
  suite: "xchacha20poly1305-ietf";
  nonce: Buffer;
  /** ciphertext || tag as produced by the _encrypt "combined" API */
  ciphertext: Buffer;
}

export function aeadEncrypt(
  key: Buffer,
  plaintext: Buffer,
  associatedData: Buffer,
  nonce?: Buffer,
): AeadCiphertext {
  if (key.length !== AEAD_KEY_BYTES) throw new Error("aeadEncrypt: bad key length");
  const n = nonce ?? randomBytes(AEAD_NONCE_BYTES);
  if (n.length !== AEAD_NONCE_BYTES) throw new Error("aeadEncrypt: bad nonce length");
  const out = Buffer.alloc(plaintext.length + AEAD_TAG_BYTES);
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(out, plaintext, associatedData, null, n, key);
  return { suite: "xchacha20poly1305-ietf", nonce: n, ciphertext: out };
}

/**
 * Decrypt; throws on any authentication failure. `out` may be a secure buffer
 * supplied by the caller when the plaintext is itself key material.
 */
export function aeadDecrypt(
  key: Buffer,
  ct: AeadCiphertext,
  associatedData: Buffer,
  out?: Buffer,
): Buffer {
  if (key.length !== AEAD_KEY_BYTES) throw new Error("aeadDecrypt: bad key length");
  if (ct.suite !== "xchacha20poly1305-ietf") throw new Error(`aeadDecrypt: unsupported suite ${ct.suite}`);
  if (ct.ciphertext.length < AEAD_TAG_BYTES) throw new Error("aeadDecrypt: ciphertext too short");
  const plain = out ?? Buffer.alloc(ct.ciphertext.length - AEAD_TAG_BYTES);
  if (plain.length !== ct.ciphertext.length - AEAD_TAG_BYTES) {
    throw new Error("aeadDecrypt: output buffer length mismatch");
  }
  sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    plain,
    null,
    ct.ciphertext,
    associatedData,
    ct.nonce,
    key,
  );
  return plain;
}

/** Serialize an AeadCiphertext to a portable binary envelope. */
const AEAD_MAGIC = Buffer.from("ZWAE1", "ascii");

export function serializeAead(ct: AeadCiphertext): Buffer {
  return Buffer.concat([AEAD_MAGIC, ct.nonce, ct.ciphertext]);
}

export function parseAead(buf: Buffer): AeadCiphertext {
  if (buf.length < AEAD_MAGIC.length + AEAD_NONCE_BYTES + AEAD_TAG_BYTES) {
    throw new Error("parseAead: envelope too short");
  }
  if (!buf.subarray(0, AEAD_MAGIC.length).equals(AEAD_MAGIC)) {
    throw new Error("parseAead: bad magic");
  }
  const nonce = Buffer.from(buf.subarray(AEAD_MAGIC.length, AEAD_MAGIC.length + AEAD_NONCE_BYTES));
  const ciphertext = Buffer.from(buf.subarray(AEAD_MAGIC.length + AEAD_NONCE_BYTES));
  return { suite: "xchacha20poly1305-ietf", nonce, ciphertext };
}
