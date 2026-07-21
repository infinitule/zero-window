/**
 * Minimal, strict ambient typings for the subset of sodium-native v4 used by
 * ZERO-WINDOW. Hand-written so the boundary stays auditable; anything not
 * declared here is intentionally unavailable.
 */
declare module "sodium-native" {
  interface SodiumNative {
    // memory
    sodium_malloc(size: number): Buffer;
    sodium_free(buf: Buffer): void;
    sodium_memzero(buf: Buffer): void;
    sodium_mlock(buf: Buffer): void;
    sodium_munlock(buf: Buffer): void;
    sodium_memcmp(a: Buffer, b: Buffer): boolean;
    randombytes_buf(buf: Buffer): void;

    // generichash / BLAKE2b
    crypto_generichash_STATEBYTES: number;
    crypto_generichash_BYTES: number;
    crypto_generichash_BYTES_MIN: number;
    crypto_generichash_BYTES_MAX: number;
    crypto_generichash(out: Buffer, input: Buffer, key?: Buffer | null): void;
    crypto_generichash_init(state: Buffer, key: Buffer | null, outLen: number): void;
    crypto_generichash_update(state: Buffer, input: Buffer): void;
    crypto_generichash_final(state: Buffer, out: Buffer): void;

    // AEAD XChaCha20-Poly1305 (IETF)
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number;
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number;
    crypto_aead_xchacha20poly1305_ietf_ABYTES: number;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext: Buffer,
      message: Buffer,
      additionalData: Buffer | null,
      secretNonce: null,
      publicNonce: Buffer,
      key: Buffer,
    ): number;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      message: Buffer,
      secretNonce: null,
      ciphertext: Buffer,
      additionalData: Buffer | null,
      publicNonce: Buffer,
      key: Buffer,
    ): number;

    // Ed25519 signatures
    crypto_sign_PUBLICKEYBYTES: number;
    crypto_sign_SECRETKEYBYTES: number;
    crypto_sign_SEEDBYTES: number;
    crypto_sign_BYTES: number;
    crypto_sign_keypair(publicKey: Buffer, secretKey: Buffer): void;
    crypto_sign_seed_keypair(publicKey: Buffer, secretKey: Buffer, seed: Buffer): void;
    crypto_sign_detached(signature: Buffer, message: Buffer, secretKey: Buffer): void;
    crypto_sign_verify_detached(signature: Buffer, message: Buffer, publicKey: Buffer): boolean;

    // X25519 boxes / sealed boxes
    crypto_box_PUBLICKEYBYTES: number;
    crypto_box_SECRETKEYBYTES: number;
    crypto_box_SEEDBYTES: number;
    crypto_box_SEALBYTES: number;
    crypto_box_keypair(publicKey: Buffer, secretKey: Buffer): void;
    crypto_box_seed_keypair(publicKey: Buffer, secretKey: Buffer, seed: Buffer): void;
    crypto_box_seal(ciphertext: Buffer, message: Buffer, publicKey: Buffer): void;
    crypto_box_seal_open(
      message: Buffer,
      ciphertext: Buffer,
      publicKey: Buffer,
      secretKey: Buffer,
    ): boolean;

    // password hashing (keystore key derivation in @zw/kms-vault)
    crypto_pwhash_SALTBYTES: number;
    crypto_pwhash_OPSLIMIT_MODERATE: number;
    crypto_pwhash_MEMLIMIT_MODERATE: number;
    crypto_pwhash_ALG_ARGON2ID13: number;
    crypto_pwhash(
      out: Buffer,
      password: Buffer,
      salt: Buffer,
      opslimit: number,
      memlimit: number,
      algorithm: number,
    ): void;
  }

  const sodium: SodiumNative;
  export default sodium;
}
