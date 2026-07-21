import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  AEAD_KEY_BYTES,
  PWHASH_MEMLIMIT_MODERATE,
  PWHASH_OPSLIMIT_MODERATE,
  PWHASH_SALT_BYTES,
  aeadDecrypt,
  aeadEncrypt,
  deriveKeyFromPassphrase,
  domainHash,
  parseAead,
  randomBytes,
  secureAlloc,
  serializeAead,
  zeroFree,
} from "@zw/crypto";

/**
 * Encrypted-at-rest keystore file.
 *
 * Layout (JSON, atomic-replaced):
 *   { version, kdf: {alg, salt, opslimit, memlimit}, entries: {id: <b64 AEAD>} }
 *
 * The file key is derived from the vault passphrase with Argon2id (moderate
 * limits). Every entry is independently AEAD-sealed under the file key with
 * the entry id as associated data, so entries cannot be swapped between ids
 * (INVARIANT I-KS-1).
 */

const KEYSTORE_VERSION = 1;

interface KeystoreFile {
  version: number;
  kdf: {
    alg: "argon2id13";
    salt: string;
    opslimit: number;
    memlimit: number;
  };
  entries: Record<string, string>;
}

export class Keystore {
  private constructor(
    private readonly path: string,
    private readonly fileKey: Buffer,
    private file: KeystoreFile,
  ) {}

  /** Derive the file key; creates the keystore if absent. */
  static async open(path: string, passphrase: Buffer): Promise<Keystore> {
    let file: KeystoreFile;
    try {
      file = JSON.parse(await readFile(path, "utf8")) as KeystoreFile;
      if (file.version !== KEYSTORE_VERSION) {
        throw new Error(`keystore ${path}: unsupported version ${file.version}`);
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      file = {
        version: KEYSTORE_VERSION,
        kdf: {
          alg: "argon2id13",
          salt: randomBytes(PWHASH_SALT_BYTES).toString("base64"),
          opslimit: PWHASH_OPSLIMIT_MODERATE,
          memlimit: PWHASH_MEMLIMIT_MODERATE,
        },
        entries: {},
      };
    }
    const fileKey = deriveKeyFromPassphrase(
      passphrase,
      {
        alg: file.kdf.alg,
        salt: Buffer.from(file.kdf.salt, "base64"),
        opslimit: file.kdf.opslimit,
        memlimit: file.kdf.memlimit,
      },
      AEAD_KEY_BYTES,
    );
    const ks = new Keystore(path, fileKey, file);
    // Verify the passphrase eagerly against any existing entry so a wrong
    // passphrase fails at open, not at first use.
    const firstId = Object.keys(file.entries)[0];
    if (firstId !== undefined) {
      try {
        zeroFree(ks.get(firstId));
      } catch {
        zeroFree(fileKey);
        throw new Error(`keystore ${path}: wrong passphrase or corrupted keystore`);
      }
    }
    return ks;
  }

  has(id: string): boolean {
    return this.file.entries[id] !== undefined;
  }

  ids(): string[] {
    return Object.keys(this.file.entries);
  }

  /** Decrypt an entry into a fresh secure buffer. Caller owns zeroization. */
  get(id: string): Buffer {
    const b64 = this.file.entries[id];
    if (b64 === undefined) throw new Error(`keystore: no entry ${id}`);
    const ct = parseAead(Buffer.from(b64, "base64"));
    const out = secureAlloc(ct.ciphertext.length - 16);
    try {
      aeadDecrypt(this.fileKey, ct, Buffer.from(`zw-keystore-entry/${id}`, "utf8"), out);
    } catch (err) {
      zeroFree(out);
      throw err;
    }
    return out;
  }

  /** Seal and persist an entry. Does not take ownership of `secret`. */
  async put(id: string, secret: Buffer): Promise<void> {
    const ct = aeadEncrypt(this.fileKey, secret, Buffer.from(`zw-keystore-entry/${id}`, "utf8"));
    this.file.entries[id] = serializeAead(ct).toString("base64");
    await this.flush();
  }

  async delete(id: string): Promise<void> {
    delete this.file.entries[id];
    await this.flush();
  }

  /** Stable fingerprint of the keystore contents — used in health output. */
  fingerprint(): Buffer {
    return domainHash(
      "keystore-state",
      Buffer.from(JSON.stringify(Object.keys(this.file.entries).sort()), "utf8"),
    );
  }

  private async flush(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    // Atomic replace: write to a sibling temp file, fsync via rename.
    const tmp = join(dirname(this.path), `.${Date.now()}-${process.pid}.tmp`);
    await writeFile(tmp, JSON.stringify(this.file, null, 2), { mode: 0o600 });
    await rename(tmp, this.path);
  }

  close(): void {
    zeroFree(this.fileKey);
  }
}
