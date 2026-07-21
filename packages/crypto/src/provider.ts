import type { AeadCiphertext } from "./aead.js";

/**
 * Key-provider abstraction. INVARIANT I-KP-1: raw private/secret key bytes
 * never cross this interface. Callers see only: public keys, ciphertexts,
 * signatures, fingerprints, and sealed envelopes. The single deliberate
 * exception is Shamir SHARE material (`openSealedShare`, and the share blobs
 * passed into `reconstructWrapRelease`): a share is not a key — any t-1
 * shares are information-theoretically independent of the KEK — and shares
 * must travel from custodians to the release service by design.
 *
 * Two production implementations:
 *   @zw/kms-pkcs11  — PKCS#11 (SoftHSM2 in CI; YubiHSM 2 / Thales Luna /
 *                     AWS CloudHSM validated per INTEGRATIONS.md)
 *   @zw/kms-vault   — encrypted file keystore + OS keyring
 */

export interface CustodianRecipient {
  custodianId: string;
  /** X25519 public key (32 bytes) of the custodian's personal key */
  boxPublicKey: Buffer;
}

export interface KekRecipient {
  recipientId: string;
  /** X25519 public key (32 bytes) of the receiving centre's provider */
  boxPublicKey: Buffer;
}

export interface EncryptedShare {
  custodianId: string;
  /** Shamir evaluation point */
  x: number;
  /** serialized ShamirShare sealed to the custodian's box public key */
  sealed: Buffer;
}

export interface WrappedKek {
  recipientId: string;
  /** raw KEK sealed to the recipient's box public key */
  sealed: Buffer;
  /** fingerprint of the wrapped KEK — lets the recipient verify before use */
  kekFingerprint: Buffer;
}

export interface ReleaseResult {
  wrapped: WrappedKek[];
  /**
   * Wall-clock microseconds during which the reconstructed plaintext KEK
   * existed in provider memory. Budget: < 500ms (enforced by @zw/authority
   * metric + test).
   */
  plaintextKekLifetimeUs: number;
  kekFingerprint: Buffer;
}

export interface KeyProvider {
  readonly kind: "pkcs11" | "file-vault";

  // ------------------------------------------------------------------
  // KEK lifecycle — authority ceremony side.
  // A KEK lives ONLY in provider memory between generateKek and
  // splitAndDestroyKek; it is never persisted in any form (I-KP-2).
  // ------------------------------------------------------------------

  /** Generate a fresh 32-byte KEK inside the provider. Returns its fingerprint. */
  generateKek(kekId: string): Promise<Buffer>;

  /** AEAD-encrypt data under a held KEK (bundle encryption). */
  aeadEncryptWithKek(kekId: string, plaintext: Buffer, associatedData: Buffer): Promise<AeadCiphertext>;

  /**
   * Shamir-split the KEK, seal each share to its custodian, then zeroize and
   * forget the KEK. After this resolves the plaintext KEK no longer exists
   * anywhere.
   */
  splitAndDestroyKek(
    kekId: string,
    opts: { threshold: number; custodians: CustodianRecipient[] },
  ): Promise<EncryptedShare[]>;

  // ------------------------------------------------------------------
  // Threshold release — authority release-service side.
  // ------------------------------------------------------------------

  /**
   * Reconstruct the KEK from serialized share blobs, verify it against the
   * expected fingerprint, seal it to every recipient, zeroize. The plaintext
   * KEK lifetime is measured inside and returned.
   */
  reconstructWrapRelease(
    shareBlobs: Buffer[],
    recipients: KekRecipient[],
    expectedKekFingerprint: Buffer,
  ): Promise<ReleaseResult>;

  // ------------------------------------------------------------------
  // KEK receipt — centre side. Unwrapped KEKs are memory-only (I-KP-2).
  // ------------------------------------------------------------------

  /** Open a WrappedKek sealed to this provider's box key; hold KEK in memory. */
  unwrapKek(kekId: string, sealed: Buffer, boxKeyId: string): Promise<Buffer>;

  /** AEAD-decrypt under a held KEK. Plaintext is exam content, not key material. */
  aeadDecryptWithKek(kekId: string, ciphertext: AeadCiphertext, associatedData: Buffer): Promise<Buffer>;

  /** Zeroize and forget a held KEK. */
  discardKek(kekId: string): Promise<void>;

  // ------------------------------------------------------------------
  // Long-lived keys, protected at rest by the provider.
  // ------------------------------------------------------------------

  /** Create-if-absent an Ed25519 signing key. Returns the public key. */
  ensureSigningKey(keyId: string): Promise<Buffer>;

  getSigningPublicKey(keyId: string): Promise<Buffer>;

  /** Domain-separated Ed25519 signature. */
  sign(keyId: string, domain: string, message: Buffer): Promise<Buffer>;

  /** Create-if-absent an X25519 box key. Returns the public key. */
  ensureBoxKey(keyId: string): Promise<Buffer>;

  getBoxPublicKey(keyId: string): Promise<Buffer>;

  /**
   * Custodian client operation: open the sealed share envelope addressed to
   * this provider's box key. Returns the serialized ShamirShare (share
   * material, not key material — see I-KP-1).
   */
  openSealedShare(boxKeyId: string, sealed: Buffer): Promise<Buffer>;

  /** Zeroize all in-memory secrets and release resources. */
  close(): Promise<void>;
}

/** Thrown by providers on fingerprint mismatch, missing keys, etc. */
export class KeyProviderError extends Error {
  constructor(
    message: string,
    readonly code:
      | "KEK_NOT_HELD"
      | "KEK_ALREADY_EXISTS"
      | "KEY_NOT_FOUND"
      | "FINGERPRINT_MISMATCH"
      | "SHARE_INVALID"
      | "PROVIDER_CLOSED"
      | "BACKEND_FAILURE",
  ) {
    super(message);
    this.name = "KeyProviderError";
  }
}
