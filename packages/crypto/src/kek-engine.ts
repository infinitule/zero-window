import { aeadEncrypt, aeadDecrypt, AEAD_KEY_BYTES, type AeadCiphertext } from "./aead.js";
import { seal } from "./box.js";
import { domainHash } from "./hash.js";
import { secureAlloc, zeroFree } from "./secure.js";
import {
  parseShare,
  serializeShare,
  shamirCombine,
  shamirSplit,
  type ShamirShare,
} from "./shamir.js";
import {
  KeyProviderError,
  type CustodianRecipient,
  type EncryptedShare,
  type KekRecipient,
  type ReleaseResult,
} from "./provider.js";

/**
 * In-memory KEK engine shared by both key providers. All raw KEK bytes live
 * in sodium secure buffers owned by this class; both providers delegate the
 * hot path here and differ only in how long-lived keys are protected at rest
 * and where randomness comes from.
 */
export class KekEngine {
  private readonly keks = new Map<string, Buffer>();
  private closed = false;

  constructor(private readonly randomFill: (buf: Buffer) => void) {}

  static fingerprintOf(kek: Buffer): Buffer {
    return domainHash("kek-fingerprint", kek);
  }

  private assertOpen(): void {
    if (this.closed) throw new KeyProviderError("provider closed", "PROVIDER_CLOSED");
  }

  generate(kekId: string): Buffer {
    this.assertOpen();
    if (this.keks.has(kekId)) {
      throw new KeyProviderError(`KEK ${kekId} already held`, "KEK_ALREADY_EXISTS");
    }
    const kek = secureAlloc(AEAD_KEY_BYTES);
    this.randomFill(kek);
    this.keks.set(kekId, kek);
    return KekEngine.fingerprintOf(kek);
  }

  /** Import raw KEK bytes (from unwrap); takes ownership, zeroizes source. */
  import(kekId: string, raw: Buffer): Buffer {
    this.assertOpen();
    if (this.keks.has(kekId)) {
      throw new KeyProviderError(`KEK ${kekId} already held`, "KEK_ALREADY_EXISTS");
    }
    if (raw.length !== AEAD_KEY_BYTES) {
      zeroFree(raw);
      throw new KeyProviderError("unwrapped KEK has wrong length", "SHARE_INVALID");
    }
    const kek = secureAlloc(AEAD_KEY_BYTES);
    raw.copy(kek);
    zeroFree(raw);
    this.keks.set(kekId, kek);
    return KekEngine.fingerprintOf(kek);
  }

  private held(kekId: string): Buffer {
    this.assertOpen();
    const kek = this.keks.get(kekId);
    if (!kek) throw new KeyProviderError(`KEK ${kekId} not held`, "KEK_NOT_HELD");
    return kek;
  }

  encrypt(kekId: string, plaintext: Buffer, ad: Buffer): AeadCiphertext {
    return aeadEncrypt(this.held(kekId), plaintext, ad);
  }

  decrypt(kekId: string, ct: AeadCiphertext, ad: Buffer): Buffer {
    return aeadDecrypt(this.held(kekId), ct, ad);
  }

  fingerprint(kekId: string): Buffer {
    return KekEngine.fingerprintOf(this.held(kekId));
  }

  splitAndDestroy(
    kekId: string,
    opts: { threshold: number; custodians: CustodianRecipient[] },
  ): EncryptedShare[] {
    const kek = this.held(kekId);
    const { threshold, custodians } = opts;
    if (custodians.length < threshold) {
      throw new KeyProviderError("fewer custodians than threshold", "SHARE_INVALID");
    }
    try {
      const shares = shamirSplit(kek, { threshold, shares: custodians.length });
      return shares.map((s, i) => {
        const custodian = custodians[i]!;
        const blob = serializeShare(s);
        const sealed = seal(blob, custodian.boxPublicKey);
        blob.fill(0);
        zeroFree(s.y as Buffer);
        return { custodianId: custodian.custodianId, x: s.x, sealed };
      });
    } finally {
      this.destroy(kekId);
    }
  }

  destroy(kekId: string): void {
    const kek = this.keks.get(kekId);
    if (kek) {
      zeroFree(kek);
      this.keks.delete(kekId);
    }
  }

  /**
   * Reconstruct → verify fingerprint → wrap to recipients → zeroize.
   * Plaintext-KEK lifetime is measured from the first byte of reconstructed
   * KEK existing to its zeroization.
   */
  reconstructWrapRelease(
    shareBlobs: Buffer[],
    recipients: KekRecipient[],
    expectedFingerprint: Buffer,
  ): ReleaseResult {
    this.assertOpen();
    let shares: ShamirShare[];
    try {
      shares = shareBlobs.map((b) => parseShare(b));
    } catch (err) {
      throw new KeyProviderError(
        `share parse failed: ${(err as Error).message}`,
        "SHARE_INVALID",
      );
    }
    const kek = secureAlloc(AEAD_KEY_BYTES);
    const t0 = process.hrtime.bigint();
    let fp: Buffer;
    let wrapped: ReleaseResult["wrapped"];
    try {
      try {
        shamirCombine(shares, kek);
      } catch (err) {
        throw new KeyProviderError(
          `reconstruction failed: ${(err as Error).message}`,
          "SHARE_INVALID",
        );
      }
      fp = KekEngine.fingerprintOf(kek);
      if (!fp.equals(expectedFingerprint)) {
        throw new KeyProviderError(
          "reconstructed KEK fingerprint does not match expected value — wrong or corrupted shares",
          "FINGERPRINT_MISMATCH",
        );
      }
      wrapped = recipients.map((r) => ({
        recipientId: r.recipientId,
        sealed: seal(kek, r.boxPublicKey),
        kekFingerprint: fp,
      }));
    } finally {
      // Zeroization happens on every path, success or failure, and the
      // plaintext-KEK lifetime clock stops here.
      zeroFree(kek);
      for (const s of shares) (s.y as Buffer).fill(0);
    }
    const plaintextKekLifetimeUs = Number((process.hrtime.bigint() - t0) / 1000n);
    return { wrapped, kekFingerprint: fp, plaintextKekLifetimeUs };
  }

  close(): void {
    for (const id of [...this.keks.keys()]) this.destroy(id);
    this.closed = true;
  }
}
