import pkcs11js from "pkcs11js";
import {
  AEAD_KEY_BYTES,
  KekEngine,
  KeyProviderError,
  boxKeyPairFromSeed,
  randomBytes,
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
import { Pkcs11Session, wrapP11, type Pkcs11Config } from "./session.js";

export { Pkcs11Session, type Pkcs11Config } from "./session.js";

const SEED_BYTES = 32;
const GCM_IV_BYTES = 12;
const GCM_TAG_BITS = 128;
const MASTER_KEY_LABEL = "zw-master-wrapping-key";

/**
 * CKM_EDDSA from PKCS#11 v3.0 (§2.3.6). pkcs11js 2.1.x does not export this
 * constant, so it is declared here from the specification and used only to
 * probe whether the attached token advertises native Ed25519 — never to
 * invoke a mechanism this provider depends on.
 */
const CKM_EDDSA = 0x00001057;

function aesGcmMechanism(iv: Buffer): pkcs11js.Mechanism {
  const params: pkcs11js.AesGCM = {
    type: pkcs11js.CK_PARAMS_AES_GCM,
    iv,
    ivBits: GCM_IV_BYTES * 8,
    tagBits: GCM_TAG_BITS,
  };
  return { mechanism: pkcs11js.CKM_AES_GCM, parameter: params };
}

export interface Pkcs11ProviderOptions extends Pkcs11Config {
  /**
   * Where wrapped seed blobs are persisted. The blobs are ciphertext under a
   * non-extractable token key; the file is useless without the HSM.
   */
  seedStorePath: string;
  /** Create the master wrapping key if the token does not have one yet. */
  createIfMissing?: boolean;
}

interface SeedStoreFile {
  version: number;
  /** entry id -> base64(iv || ciphertext||tag) */
  entries: Record<string, string>;
}

/**
 * Reported capabilities of the attached token. `nativeEdDSA` tells a
 * deployment whether Ed25519 private keys can live entirely inside the HSM
 * (YubiHSM 2, Thales Luna) or whether this provider must operate in
 * wrapped-seed mode (SoftHSM2 built without --with-eddsa).
 */
export interface TokenCapabilities {
  tokenLabel: string;
  manufacturer: string;
  model: string;
  serial: string;
  nativeEdDSA: boolean;
  aesGcm: boolean;
}

/**
 * `pkcs11` key provider.
 *
 * SECURITY BOUNDARY (documented in SECURITY.md §"Provider tiers", DECISIONS.md D-4):
 *
 *   - A single AES-256 master wrapping key is generated INSIDE the token with
 *     CKA_SENSITIVE=true, CKA_EXTRACTABLE=false, CKA_TOKEN=true. It cannot be
 *     read out of the HSM by any means, including by this code.
 *   - All ZERO-WINDOW long-lived key material is stored as 32-byte seeds
 *     encrypted under that master key (CKM_AES_GCM). At rest, seeds are
 *     cryptographically bound to the token: stealing the seed store file
 *     yields nothing without the HSM and its PIN.
 *   - To perform an Ed25519 signature or open a sealed box, the seed is
 *     decrypted by the HSM into an mlocked secure buffer, used for exactly
 *     one operation, and zeroized. libsodium performs the curve arithmetic.
 *   - KEKs are never persisted in any form.
 *
 * What this does NOT give you: protection against an attacker with live root
 * on the host during an operation, who could read a seed from process memory.
 * Eliminating that requires the curve operations themselves to run inside the
 * HSM. PKCS#11 defines no mechanism matching libsodium's crypto_box_seal, and
 * the ZERO-WINDOW evidence format is libsodium-based end-to-end so that any
 * third party can verify it with stock libsodium. `capabilities()` reports
 * whether the attached token supports native EdDSA; INTEGRATIONS.md records
 * the validated-hardware matrix and this tradeoff.
 */
export class Pkcs11KeyProvider implements KeyProvider {
  readonly kind = "pkcs11" as const;

  private constructor(
    private readonly session: Pkcs11Session,
    private readonly masterKey: Buffer,
    private readonly seedStorePath: string,
    private store: SeedStoreFile,
    private readonly engine: KekEngine,
  ) {}

  static async open(opts: Pkcs11ProviderOptions): Promise<Pkcs11KeyProvider> {
    const session = Pkcs11Session.open(opts);
    try {
      const p11 = session.p11;
      let masterKey = session.findOne([
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
        { type: pkcs11js.CKA_LABEL, value: MASTER_KEY_LABEL },
      ]);

      if (!masterKey) {
        if (opts.createIfMissing !== true) {
          throw new KeyProviderError(
            `token has no master wrapping key labelled "${MASTER_KEY_LABEL}"; ` +
              "run `zw-authority provider init` (see runbooks/key-ceremony.md) " +
              "or pass createIfMissing",
            "KEY_NOT_FOUND",
          );
        }
        masterKey = wrapP11("C_GenerateKey(AES-256)", () =>
          p11.C_GenerateKey(session.session, { mechanism: pkcs11js.CKM_AES_KEY_GEN }, [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
            { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_AES },
            { type: pkcs11js.CKA_LABEL, value: MASTER_KEY_LABEL },
            { type: pkcs11js.CKA_VALUE_LEN, value: 32 },
            { type: pkcs11js.CKA_TOKEN, value: true },
            { type: pkcs11js.CKA_PRIVATE, value: true },
            // INVARIANT I-P11-1: the master key is non-extractable and
            // sensitive — it never leaves the token, by policy set at birth.
            { type: pkcs11js.CKA_SENSITIVE, value: true },
            { type: pkcs11js.CKA_EXTRACTABLE, value: false },
            { type: pkcs11js.CKA_ENCRYPT, value: true },
            { type: pkcs11js.CKA_DECRYPT, value: true },
          ]),
        );
      }

      const { readFile } = await import("node:fs/promises");
      let store: SeedStoreFile;
      try {
        store = JSON.parse(await readFile(opts.seedStorePath, "utf8")) as SeedStoreFile;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        store = { version: 1, entries: {} };
      }

      // All randomness comes from the HSM RNG.
      const engine = new KekEngine((buf) => session.randomFill(buf));
      return new Pkcs11KeyProvider(session, masterKey, opts.seedStorePath, store, engine);
    } catch (err) {
      session.close();
      throw err;
    }
  }

  capabilities(): TokenCapabilities {
    const info = this.session.tokenInfo();
    const mechs = wrapP11("C_GetMechanismList", () =>
      this.session.p11.C_GetMechanismList(this.session.slot),
    ).map((m) => Number(m));
    return {
      tokenLabel: info.label.trim(),
      manufacturer: info.manufacturerID.trim(),
      model: info.model.trim(),
      serial: info.serialNumber.trim(),
      nativeEdDSA: mechs.includes(CKM_EDDSA),
      aesGcm: mechs.includes(Number(pkcs11js.CKM_AES_GCM)),
    };
  }

  // ---------------- seed wrapping via the token ----------------

  private encryptSeed(seed: Buffer): Buffer {
    const iv = randomBytes(GCM_IV_BYTES);
    this.session.randomFill(iv);
    const mech = aesGcmMechanism(iv);
    const out = Buffer.alloc(seed.length + GCM_TAG_BITS / 8 + 16);
    const ct = wrapP11("C_Encrypt(AES-GCM)", () => {
      this.session.p11.C_EncryptInit(this.session.session, mech, this.masterKey);
      return this.session.p11.C_Encrypt(this.session.session, seed, out);
    });
    return Buffer.concat([iv, Buffer.from(ct)]);
  }

  /** Decrypt a wrapped seed into a caller-owned secure buffer. */
  private decryptSeed(blob: Buffer, out: Buffer): void {
    const iv = blob.subarray(0, GCM_IV_BYTES);
    const ct = blob.subarray(GCM_IV_BYTES);
    const mech = aesGcmMechanism(Buffer.from(iv));
    const scratch = Buffer.alloc(ct.length);
    const plain = wrapP11("C_Decrypt(AES-GCM)", () => {
      this.session.p11.C_DecryptInit(this.session.session, mech, this.masterKey);
      return this.session.p11.C_Decrypt(this.session.session, Buffer.from(ct), scratch);
    });
    if (plain.length !== out.length) {
      scratch.fill(0);
      throw new KeyProviderError(
        `unwrapped seed length ${plain.length}, expected ${out.length}`,
        "BACKEND_FAILURE",
      );
    }
    Buffer.from(plain).copy(out);
    scratch.fill(0);
  }

  private async persist(): Promise<void> {
    const { mkdir, writeFile, rename } = await import("node:fs/promises");
    const { dirname, join } = await import("node:path");
    await mkdir(dirname(this.seedStorePath), { recursive: true });
    const tmp = join(dirname(this.seedStorePath), `.${Date.now()}-${process.pid}.tmp`);
    await writeFile(tmp, JSON.stringify(this.store, null, 2), { mode: 0o600 });
    await rename(tmp, this.seedStorePath);
  }

  private async ensureSeed(kind: "sign" | "box", keyId: string): Promise<void> {
    const entry = `${kind}:${keyId}`;
    if (this.store.entries[entry] !== undefined) return;
    const seed = secureAlloc(SEED_BYTES);
    try {
      this.session.randomFill(seed);
      this.store.entries[entry] = this.encryptSeed(seed).toString("base64");
      await this.persist();
    } finally {
      zeroFree(seed);
    }
  }

  /** Load a seed into a secure buffer. Caller MUST zeroFree it. */
  private loadSeed(kind: "sign" | "box", keyId: string): Buffer {
    const entry = `${kind}:${keyId}`;
    const b64 = this.store.entries[entry];
    if (b64 === undefined) {
      throw new KeyProviderError(`key ${entry} not found on this token`, "KEY_NOT_FOUND");
    }
    const seed = secureAlloc(SEED_BYTES);
    try {
      this.decryptSeed(Buffer.from(b64, "base64"), seed);
    } catch (err) {
      zeroFree(seed);
      throw err;
    }
    return seed;
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
    const seed = this.loadSeed("box", boxKeyId);
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

  async ensureSigningKey(keyId: string): Promise<Buffer> {
    await this.ensureSeed("sign", keyId);
    return this.getSigningPublicKey(keyId);
  }

  async getSigningPublicKey(keyId: string): Promise<Buffer> {
    const seed = this.loadSeed("sign", keyId);
    const kp = signingKeyPairFromSeed(seed);
    zeroFree(seed);
    zeroFree(kp.secretKey);
    return kp.publicKey;
  }

  async sign(keyId: string, domain: string, message: Buffer): Promise<Buffer> {
    const seed = this.loadSeed("sign", keyId);
    const kp = signingKeyPairFromSeed(seed);
    zeroFree(seed);
    try {
      return signDomain(domain, message, kp.secretKey);
    } finally {
      zeroFree(kp.secretKey);
    }
  }

  async ensureBoxKey(keyId: string): Promise<Buffer> {
    await this.ensureSeed("box", keyId);
    return this.getBoxPublicKey(keyId);
  }

  async getBoxPublicKey(keyId: string): Promise<Buffer> {
    const seed = this.loadSeed("box", keyId);
    const kp = boxKeyPairFromSeed(seed);
    zeroFree(seed);
    zeroFree(kp.secretKey);
    return kp.publicKey;
  }

  async openSealedShare(boxKeyId: string, sealed: Buffer): Promise<Buffer> {
    const seed = this.loadSeed("box", boxKeyId);
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
    this.session.close();
  }
}
