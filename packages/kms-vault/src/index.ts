import {
  AEAD_KEY_BYTES,
  KekEngine,
  KeyProviderError,
  boxKeyPairFromSeed,
  randomBytes,
  randomFill,
  sealOpen,
  secureAlloc,
  signDomain,
  signingKeyPairFromSeed,
  zeroFree,
  type AeadCiphertext,
  type CustodianRecipient,
  type EncryptedShare,
  type KekRecipient,
  type KeyProvider,
  type ReleaseResult,
} from "@zw/crypto";
import { Keystore } from "./keystore.js";
import { detectKeyring } from "./keyring.js";

export { Keystore } from "./keystore.js";
export { detectKeyring, type Keyring } from "./keyring.js";

const SEED_BYTES = 32;

export interface VaultProviderOptions {
  /** Path to the encrypted keystore file. */
  keystorePath: string;
  /**
   * Passphrase source, in precedence order:
   *   1. `passphrase` (explicit — tests, or an operator prompt)
   *   2. OS keyring entry (service "zero-window", account = `keyringAccount`)
   *   3. ZW_VAULT_PASSPHRASE environment variable (systemd LoadCredential)
   * If none yields a passphrase and `createIfMissing` is set, a 32-byte random
   * passphrase is generated and stored in the OS keyring.
   */
  passphrase?: Buffer;
  keyringAccount?: string;
  createIfMissing?: boolean;
}

/**
 * `file-vault` key provider: software keystore encrypted at rest under an
 * Argon2id-derived key, with the passphrase held in the OS keyring.
 *
 * Long-lived keys (Ed25519 signing, X25519 box) are stored as 32-byte SEEDS
 * so key bytes exist in plaintext only inside secure buffers for the duration
 * of one operation. KEKs are never persisted at all (I-KP-2).
 *
 * Security posture vs. PKCS#11: a root-level compromise of the host while the
 * service is running can read derived keys from process memory. That is the
 * documented tradeoff of the no-HSM pilot tier — see SECURITY.md §"Provider
 * tiers" and DECISIONS.md D-3.
 */
export class VaultKeyProvider implements KeyProvider {
  readonly kind = "file-vault" as const;

  private constructor(
    private readonly keystore: Keystore,
    private readonly engine: KekEngine,
  ) {}

  static async open(opts: VaultProviderOptions): Promise<VaultKeyProvider> {
    const account = opts.keyringAccount ?? "vault-passphrase";
    let passphrase: Buffer | null = opts.passphrase ?? null;
    let ownsPassphrase = false;

    if (!passphrase) {
      const keyring = await detectKeyring();
      passphrase = await keyring.get("zero-window", account);
      ownsPassphrase = passphrase !== null;
      if (!passphrase) {
        const env = process.env["ZW_VAULT_PASSPHRASE"];
        if (env !== undefined && env.length > 0) {
          passphrase = Buffer.from(env, "utf8");
          ownsPassphrase = true;
        }
      }
      if (!passphrase && opts.createIfMissing === true) {
        passphrase = randomBytes(32);
        ownsPassphrase = true;
        await keyring.set("zero-window", account, passphrase);
      }
      if (!passphrase) {
        throw new KeyProviderError(
          `no vault passphrase: not in OS keyring (account "${account}"), ` +
            "ZW_VAULT_PASSPHRASE unset, and createIfMissing not requested",
          "BACKEND_FAILURE",
        );
      }
    }

    try {
      const keystore = await Keystore.open(opts.keystorePath, passphrase);
      return new VaultKeyProvider(keystore, new KekEngine(randomFill));
    } finally {
      if (ownsPassphrase) zeroFree(passphrase);
    }
  }

  // ---------------- KEK lifecycle ----------------

  async generateKek(kekId: string): Promise<Buffer> {
    return this.engine.generate(kekId);
  }

  async aeadEncryptWithKek(
    kekId: string,
    plaintext: Buffer,
    associatedData: Buffer,
  ): Promise<AeadCiphertext> {
    return this.engine.encrypt(kekId, plaintext, associatedData);
  }

  async splitAndDestroyKek(
    kekId: string,
    opts: { threshold: number; custodians: CustodianRecipient[] },
  ): Promise<EncryptedShare[]> {
    return this.engine.splitAndDestroy(kekId, opts);
  }

  async reconstructWrapRelease(
    shareBlobs: Buffer[],
    recipients: KekRecipient[],
    expectedKekFingerprint: Buffer,
  ): Promise<ReleaseResult> {
    return this.engine.reconstructWrapRelease(shareBlobs, recipients, expectedKekFingerprint);
  }

  async unwrapKek(kekId: string, sealed: Buffer, boxKeyId: string): Promise<Buffer> {
    const seed = this.seedFor("box", boxKeyId);
    const kp = boxKeyPairFromSeed(seed);
    zeroFree(seed);
    const raw = secureAlloc(AEAD_KEY_BYTES);
    try {
      sealOpen(sealed, kp.publicKey, kp.secretKey, raw);
    } catch (err) {
      zeroFree(raw);
      throw new KeyProviderError(
        `unwrapKek: sealed KEK did not open for box key ${boxKeyId}: ${(err as Error).message}`,
        "SHARE_INVALID",
      );
    } finally {
      zeroFree(kp.secretKey);
    }
    return this.engine.import(kekId, raw);
  }

  async aeadDecryptWithKek(
    kekId: string,
    ciphertext: AeadCiphertext,
    associatedData: Buffer,
  ): Promise<Buffer> {
    return this.engine.decrypt(kekId, ciphertext, associatedData);
  }

  async discardKek(kekId: string): Promise<void> {
    this.engine.destroy(kekId);
  }

  // ---------------- long-lived keys ----------------

  private seedFor(kind: "sign" | "box", keyId: string): Buffer {
    const entry = `${kind}:${keyId}`;
    if (!this.keystore.has(entry)) {
      throw new KeyProviderError(`key ${entry} not found in keystore`, "KEY_NOT_FOUND");
    }
    return this.keystore.get(entry);
  }

  private async ensureSeed(kind: "sign" | "box", keyId: string): Promise<Buffer> {
    const entry = `${kind}:${keyId}`;
    if (!this.keystore.has(entry)) {
      const seed = secureAlloc(SEED_BYTES);
      randomFill(seed);
      try {
        await this.keystore.put(entry, seed);
      } finally {
        zeroFree(seed);
      }
    }
    return this.keystore.get(entry);
  }

  async ensureSigningKey(keyId: string): Promise<Buffer> {
    const seed = await this.ensureSeed("sign", keyId);
    const kp = signingKeyPairFromSeed(seed);
    zeroFree(seed);
    zeroFree(kp.secretKey);
    return kp.publicKey;
  }

  async getSigningPublicKey(keyId: string): Promise<Buffer> {
    const seed = this.seedFor("sign", keyId);
    const kp = signingKeyPairFromSeed(seed);
    zeroFree(seed);
    zeroFree(kp.secretKey);
    return kp.publicKey;
  }

  async sign(keyId: string, domain: string, message: Buffer): Promise<Buffer> {
    const seed = this.seedFor("sign", keyId);
    const kp = signingKeyPairFromSeed(seed);
    zeroFree(seed);
    try {
      return signDomain(domain, message, kp.secretKey);
    } finally {
      zeroFree(kp.secretKey);
    }
  }

  async ensureBoxKey(keyId: string): Promise<Buffer> {
    const seed = await this.ensureSeed("box", keyId);
    const kp = boxKeyPairFromSeed(seed);
    zeroFree(seed);
    zeroFree(kp.secretKey);
    return kp.publicKey;
  }

  async getBoxPublicKey(keyId: string): Promise<Buffer> {
    const seed = this.seedFor("box", keyId);
    const kp = boxKeyPairFromSeed(seed);
    zeroFree(seed);
    zeroFree(kp.secretKey);
    return kp.publicKey;
  }

  async openSealedShare(boxKeyId: string, sealed: Buffer): Promise<Buffer> {
    const seed = this.seedFor("box", boxKeyId);
    const kp = boxKeyPairFromSeed(seed);
    zeroFree(seed);
    try {
      return sealOpen(sealed, kp.publicKey, kp.secretKey);
    } catch (err) {
      throw new KeyProviderError(
        `openSealedShare: envelope did not open for box key ${boxKeyId}: ${(err as Error).message}`,
        "SHARE_INVALID",
      );
    } finally {
      zeroFree(kp.secretKey);
    }
  }

  async close(): Promise<void> {
    this.engine.close();
    this.keystore.close();
  }
}
