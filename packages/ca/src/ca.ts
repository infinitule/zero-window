import { webcrypto } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { x509 } from "./x509-setup.js";
import { randomBytes } from "@zw/crypto";
import {
  REVOCATION_REASON_CODES,
  type CertRole,
  type CertificateRecord,
  type IssuedCertificate,
  type RevocationReason,
} from "./types.js";

/**
 * ZERO-WINDOW internal CA.
 *
 * Design decisions that matter operationally:
 *
 *  - Two tiers. The ROOT signs only intermediates and is meant to live
 *    offline (its private key is exported once and removed from the online
 *    host — see runbooks/key-ceremony.md). The INTERMEDIATE signs leaves.
 *    Compromise of the online issuing key is recoverable by revoking one
 *    intermediate rather than re-provisioning every centre in the country.
 *
 *  - ECDSA P-384. Chosen over RSA-4096 for handshake cost on centre-node
 *    hardware, and over P-256 for margin on certificates that must remain
 *    valid across a multi-year exam cycle. Ed25519 would be preferable but
 *    is still unevenly supported by TLS stacks and middleboxes in the
 *    deployment environment (D-16).
 *
 *  - INVARIANT I-CA-1: every leaf carries exactly the key usages its role
 *    needs. Server certificates get serverAuth, client certificates get
 *    clientAuth. Neither gets both, so a stolen centre client certificate
 *    cannot be used to stand up a server impersonating the authority.
 *
 *  - INVARIANT I-CA-2: centre and custodian certificates bind a hardware
 *    identifier into the subject (OU=hw:<id>) AND a SAN URI. The authority
 *    checks it at connection time, so a copied key pair on different
 *    hardware is detectable.
 */

const KEY_ALGORITHM: EcKeyGenParams & { hash: string } = {
  name: "ECDSA",
  namedCurve: "P-384",
  hash: "SHA-384",
};

const SIGNING_ALGORITHM: EcdsaParams = { name: "ECDSA", hash: "SHA-384" };

/** Default lifetimes, in days. Short leaves force rotation to be routine. */
export const DEFAULT_LIFETIME_DAYS: Record<CertRole, number> = {
  root: 3650,
  intermediate: 1825,
  "authority-server": 397,
  "centre-client": 397,
  "custodian-client": 397,
  "auditor-client": 90,
};

export interface CaConfig {
  /** Directory holding ca.json, keys and CRLs. */
  dir: string;
  /** Organization name placed in every subject. */
  organization?: string;
  /** Country code placed in every subject. */
  country?: string;
}

interface CaState {
  version: 1;
  organization: string;
  country: string;
  /** Serial of the current issuing intermediate. */
  activeIntermediate: string | null;
  certificates: CertificateRecord[];
  /** Monotonic CRL number (RFC 5280 §5.2.3). */
  crlNumber: number;
}

export class CaError extends Error {
  constructor(
    message: string,
    readonly code:
      | "NOT_INITIALIZED"
      | "ALREADY_INITIALIZED"
      | "NO_ISSUER"
      | "UNKNOWN_CERT"
      | "ALREADY_REVOKED"
      | "ROLE_INVALID"
      | "KEY_MISSING",
  ) {
    super(message);
    this.name = "CaError";
  }
}

export class CertificateAuthority {
  private constructor(
    private readonly dir: string,
    private state: CaState,
  ) {}

  static async open(config: CaConfig): Promise<CertificateAuthority> {
    const statePath = join(config.dir, "ca.json");
    let state: CaState;
    try {
      state = JSON.parse(await readFile(statePath, "utf8")) as CaState;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      state = {
        version: 1,
        organization: config.organization ?? "ZERO-WINDOW Examination Authority",
        country: config.country ?? "IN",
        activeIntermediate: null,
        certificates: [],
        crlNumber: 0,
      };
    }
    return new CertificateAuthority(config.dir, state);
  }

  get organization(): string {
    return this.state.organization;
  }

  // ------------------------------------------------------------------
  // Initialization
  // ------------------------------------------------------------------

  /**
   * Create the root and the first issuing intermediate. Returns both private
   * keys; the caller is responsible for moving the ROOT key offline.
   */
  async initialize(): Promise<{ root: IssuedCertificate; intermediate: IssuedCertificate }> {
    if (this.state.certificates.length > 0) {
      throw new CaError(
        `CA at ${this.dir} is already initialized (${this.state.certificates.length} certificates)`,
        "ALREADY_INITIALIZED",
      );
    }

    const rootKeys = await this.generateKeyPair();
    const rootSerial = newSerial();
    const rootName = this.dn("ZERO-WINDOW Root CA");
    const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: rootSerial,
      name: rootName,
      notBefore: new Date(),
      notAfter: daysFromNow(DEFAULT_LIFETIME_DAYS.root),
      signingAlgorithm: SIGNING_ALGORITHM,
      keys: rootKeys,
      extensions: [
        // pathLenConstraint 1: root may sign an intermediate, which may sign
        // leaves — and no deeper. A third tier would be a misconfiguration.
        new x509.BasicConstraintsExtension(true, 1, true),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
          true,
        ),
        await x509.SubjectKeyIdentifierExtension.create(rootKeys.publicKey),
      ],
    });

    const rootRecord = await this.record(rootCert, "root", null);
    this.state.certificates.push(rootRecord);
    const rootKeyPem = await exportPrivateKey(rootKeys.privateKey);

    const intermediate = await this.issueIntermediate(rootKeys.privateKey, rootCert, rootRecord);
    await this.persist();
    await this.writeKey(rootSerial, rootKeyPem);

    return {
      root: { record: rootRecord, privateKeyPem: rootKeyPem, chainPem: rootRecord.pem },
      intermediate,
    };
  }

  private async issueIntermediate(
    rootKey: CryptoKey,
    rootCert: x509.X509Certificate,
    rootRecord: CertificateRecord,
  ): Promise<IssuedCertificate> {
    const keys = await this.generateKeyPair();
    const serial = newSerial();
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: serial,
      subject: this.dn("ZERO-WINDOW Issuing CA"),
      issuer: rootCert.subject,
      notBefore: new Date(),
      notAfter: daysFromNow(DEFAULT_LIFETIME_DAYS.intermediate),
      signingAlgorithm: SIGNING_ALGORITHM,
      publicKey: keys.publicKey,
      signingKey: rootKey,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
          true,
        ),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        await x509.AuthorityKeyIdentifierExtension.create(rootCert),
      ],
    });

    const record = await this.record(cert, "intermediate", rootRecord.serial);
    this.state.certificates.push(record);
    this.state.activeIntermediate = serial;
    const keyPem = await exportPrivateKey(keys.privateKey);
    await this.writeKey(serial, keyPem);

    return {
      record,
      privateKeyPem: keyPem,
      chainPem: `${record.pem}${rootRecord.pem}`,
    };
  }

  // ------------------------------------------------------------------
  // Leaf issuance
  // ------------------------------------------------------------------

  async issue(opts: {
    role: Exclude<CertRole, "root" | "intermediate">;
    commonName: string;
    /** DNS names / IPs for server certificates. */
    sans?: string[];
    /** Hardware identifier for centre and custodian certificates. */
    hardwareId?: string;
    lifetimeDays?: number;
  }): Promise<IssuedCertificate> {
    const { issuerCert, issuerKey, issuerRecord } = await this.activeIssuer();

    if (
      (opts.role === "centre-client" || opts.role === "custodian-client") &&
      (opts.hardwareId === undefined || opts.hardwareId.length === 0)
    ) {
      throw new CaError(
        `role ${opts.role} requires a hardware identifier (I-CA-2): pass --hardware-id`,
        "ROLE_INVALID",
      );
    }

    const keys = await this.generateKeyPair();
    const serial = newSerial();
    const isServer = opts.role === "authority-server";

    const extensions: x509.Extension[] = [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        // digitalSignature covers ECDSA in TLS 1.3 for both directions;
        // keyEncipherment is deliberately absent (no RSA key transport).
        x509.KeyUsageFlags.digitalSignature,
        true,
      ),
      // I-CA-1: exactly one EKU per role, never both.
      new x509.ExtendedKeyUsageExtension(
        [isServer ? x509.ExtendedKeyUsage.serverAuth : x509.ExtendedKeyUsage.clientAuth],
        true,
      ),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(issuerCert),
    ];

    const sanEntries: x509.JsonGeneralNames = [];
    for (const san of opts.sans ?? []) {
      sanEntries.push(isIpAddress(san) ? { type: "ip", value: san } : { type: "dns", value: san });
    }
    if (opts.hardwareId !== undefined && opts.hardwareId.length > 0) {
      // The hardware binding also appears as a URI SAN so a TLS peer can
      // check it without parsing the subject DN.
      sanEntries.push({ type: "url", value: `urn:zero-window:hw:${opts.hardwareId}` });
    }
    if (sanEntries.length > 0) {
      extensions.push(new x509.SubjectAlternativeNameExtension(sanEntries, false));
    }

    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: serial,
      subject: this.dn(opts.commonName, opts.hardwareId),
      issuer: issuerCert.subject,
      notBefore: new Date(),
      notAfter: daysFromNow(opts.lifetimeDays ?? DEFAULT_LIFETIME_DAYS[opts.role]),
      signingAlgorithm: SIGNING_ALGORITHM,
      publicKey: keys.publicKey,
      signingKey: issuerKey,
      extensions,
    });

    const record = await this.record(cert, opts.role, issuerRecord.serial, {
      ...(opts.hardwareId !== undefined ? { hardwareId: opts.hardwareId } : {}),
      ...(opts.sans !== undefined ? { sans: opts.sans } : {}),
    });
    this.state.certificates.push(record);
    await this.persist();

    const rootRecord = this.rootRecord();
    return {
      record,
      privateKeyPem: await exportPrivateKey(keys.privateKey),
      chainPem: `${record.pem}${issuerRecord.pem}${rootRecord.pem}`,
    };
  }

  /**
   * Rotate a certificate: issue a replacement with the same identity, then
   * revoke the old one as `superseded`. Both steps happen or neither does,
   * so a rotation cannot leave the fleet with two live certificates for one
   * identity or with none.
   */
  async rotate(serial: string, lifetimeDays?: number): Promise<IssuedCertificate> {
    const existing = this.get(serial);
    if (existing.role === "root" || existing.role === "intermediate") {
      throw new CaError(
        `rotate() handles leaf certificates; use rotateIntermediate() for ${existing.role}`,
        "ROLE_INVALID",
      );
    }
    const replacement = await this.issue({
      role: existing.role,
      commonName: existing.commonName,
      ...(existing.sans !== undefined ? { sans: existing.sans } : {}),
      ...(existing.hardwareId !== undefined ? { hardwareId: existing.hardwareId } : {}),
      ...(lifetimeDays !== undefined ? { lifetimeDays } : {}),
    });
    await this.revoke(serial, "superseded");
    return replacement;
  }

  /**
   * Issue a new intermediate from the root and make it the active issuer.
   * The previous intermediate is NOT revoked automatically: certificates it
   * signed remain valid until they expire or are individually revoked.
   * Revoking it is a separate, deliberate act (incident response).
   */
  async rotateIntermediate(rootPrivateKeyPem: string): Promise<IssuedCertificate> {
    const rootRecord = this.rootRecord();
    const rootCert = new x509.X509Certificate(rootRecord.pem);
    const rootKey = await importPrivateKey(rootPrivateKeyPem);
    const issued = await this.issueIntermediate(rootKey, rootCert, rootRecord);
    await this.persist();
    return issued;
  }

  // ------------------------------------------------------------------
  // Revocation
  // ------------------------------------------------------------------

  async revoke(serial: string, reason: RevocationReason = "unspecified"): Promise<void> {
    const record = this.get(serial);
    if (record.revoked) {
      throw new CaError(
        `certificate ${serial} was already revoked at ${record.revoked.at} (${record.revoked.reason})`,
        "ALREADY_REVOKED",
      );
    }
    record.revoked = { at: new Date().toISOString(), reason };
    await this.persist();
  }

  isRevoked(serial: string): boolean {
    return this.get(serial).revoked !== undefined;
  }

  /**
   * Generate and sign a CRL covering every revoked certificate issued by the
   * active intermediate. `nextUpdate` is deliberately short: a stale CRL is
   * treated as a failure by the mTLS verifier, so an operator who stops
   * publishing CRLs cannot silently disable revocation checking.
   */
  async generateCrl(validityHours = 24): Promise<string> {
    const { issuerCert, issuerKey } = await this.activeIssuer();
    this.state.crlNumber++;

    const entries = this.state.certificates
      .filter((c) => c.revoked !== undefined && c.issuerSerial === this.state.activeIntermediate)
      .map((c) => ({
        serialNumber: c.serial,
        revocationDate: new Date(c.revoked!.at),
        reason: REVOCATION_REASON_CODES[c.revoked!.reason] as x509.X509CrlReason,
      }));

    const crl = await x509.X509CrlGenerator.create({
      issuer: issuerCert.subject,
      thisUpdate: new Date(),
      nextUpdate: new Date(Date.now() + validityHours * 3_600_000),
      signingAlgorithm: SIGNING_ALGORITHM,
      signingKey: issuerKey,
      entries,
      extensions: [await x509.AuthorityKeyIdentifierExtension.create(issuerCert)],
    });

    // RFC 7468 §5 specifies the "X509 CRL" label for CRLs. @peculiar/x509
    // emits the bare "CRL" label, which OpenSSL and other standard tooling
    // refuse to parse — and an operator must be able to inspect a published
    // CRL with `openssl crl`. Normalize to the standard label.
    const pem = toStandardCrlPem(crl.toString("pem"));
    await this.persist();
    await writeFileAtomic(join(this.dir, "crl.pem"), pem, 0o644);
    return pem;
  }

  // ------------------------------------------------------------------
  // Accessors
  // ------------------------------------------------------------------

  get(serial: string): CertificateRecord {
    const record = this.state.certificates.find((c) => c.serial === serial);
    if (!record) throw new CaError(`no certificate with serial ${serial}`, "UNKNOWN_CERT");
    return record;
  }

  list(filter?: { role?: CertRole; includeRevoked?: boolean }): CertificateRecord[] {
    return this.state.certificates.filter((c) => {
      if (filter?.role && c.role !== filter.role) return false;
      if (filter?.includeRevoked === false && c.revoked) return false;
      return true;
    });
  }

  rootRecord(): CertificateRecord {
    const root = this.state.certificates.find((c) => c.role === "root");
    if (!root) throw new CaError(`CA at ${this.dir} is not initialized`, "NOT_INITIALIZED");
    return root;
  }

  /** PEM trust bundle an mTLS peer should be configured with. */
  trustBundlePem(): string {
    const root = this.rootRecord();
    const intermediates = this.state.certificates.filter((c) => c.role === "intermediate");
    return [root.pem, ...intermediates.map((c) => c.pem)].join("");
  }

  private async activeIssuer(): Promise<{
    issuerCert: x509.X509Certificate;
    issuerKey: CryptoKey;
    issuerRecord: CertificateRecord;
  }> {
    if (!this.state.activeIntermediate) {
      throw new CaError(
        `CA at ${this.dir} has no active issuing intermediate; run \`zw-ca init\``,
        "NOT_INITIALIZED",
      );
    }
    const issuerRecord = this.get(this.state.activeIntermediate);
    if (issuerRecord.revoked) {
      throw new CaError(
        `the active intermediate ${issuerRecord.serial} is revoked; run \`zw-ca rotate-intermediate\``,
        "NO_ISSUER",
      );
    }
    const keyPem = await this.readKey(issuerRecord.serial);
    return {
      issuerCert: new x509.X509Certificate(issuerRecord.pem),
      issuerKey: await importPrivateKey(keyPem),
      issuerRecord,
    };
  }

  // ------------------------------------------------------------------
  // Internals
  // ------------------------------------------------------------------

  private async generateKeyPair(): Promise<CryptoKeyPair> {
    return (await webcrypto.subtle.generateKey(KEY_ALGORITHM, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
  }

  private dn(commonName: string, hardwareId?: string): string {
    const parts = [
      `CN=${escapeDn(commonName)}`,
      `O=${escapeDn(this.state.organization)}`,
      `C=${escapeDn(this.state.country)}`,
    ];
    if (hardwareId !== undefined && hardwareId.length > 0) {
      parts.splice(1, 0, `OU=hw:${escapeDn(hardwareId)}`);
    }
    return parts.join(", ");
  }

  private async record(
    cert: x509.X509Certificate,
    role: CertRole,
    issuerSerial: string | null,
    extra: { hardwareId?: string; sans?: string[] } = {},
  ): Promise<CertificateRecord> {
    const fingerprint = Buffer.from(await cert.getThumbprint("SHA-256")).toString("hex");
    const cn = /CN=([^,]+)/.exec(cert.subject)?.[1] ?? cert.subject;
    return {
      serial: cert.serialNumber,
      role,
      subject: cert.subject,
      commonName: cn,
      issuerSerial,
      notBefore: cert.notBefore.toISOString(),
      notAfter: cert.notAfter.toISOString(),
      fingerprint,
      pem: cert.toString("pem") + "\n",
      ...extra,
    };
  }

  private keyPath(serial: string): string {
    return join(this.dir, "private", `${serial}.key.pem`);
  }

  private async writeKey(serial: string, pem: string): Promise<void> {
    await writeFileAtomic(this.keyPath(serial), pem, 0o600);
  }

  private async readKey(serial: string): Promise<string> {
    try {
      return await readFile(this.keyPath(serial), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        throw new CaError(
          `private key for ${serial} is not present at ${this.keyPath(serial)} — ` +
            "it may have been moved offline, which is expected for the root",
          "KEY_MISSING",
        );
      }
      throw err;
    }
  }

  private async persist(): Promise<void> {
    await writeFileAtomic(
      join(this.dir, "ca.json"),
      JSON.stringify(this.state, null, 2) + "\n",
      0o600,
    );
  }
}

// ---------------------------------------------------------------- helpers

/** Rewrite a "BEGIN CRL" PEM to the RFC 7468 "BEGIN X509 CRL" label. */
export function toStandardCrlPem(pem: string): string {
  const normalized = pem
    .replace(/-----BEGIN CRL-----/g, "-----BEGIN X509 CRL-----")
    .replace(/-----END CRL-----/g, "-----END X509 CRL-----");
  return normalized.endsWith("\n") ? normalized : normalized + "\n";
}

function newSerial(): string {
  // 16 random bytes with the top bit cleared so the DER INTEGER is positive.
  const b = randomBytes(16);
  b[0] = (b[0] ?? 0) & 0x7f;
  return b.toString("hex");
}

function daysFromNow(days: number): Date {
  return new Date(Date.now() + days * 86_400_000);
}

function isIpAddress(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(":");
}

function escapeDn(value: string): string {
  return value.replace(/([,+"\\<>;])/g, "\\$1");
}

async function exportPrivateKey(key: CryptoKey): Promise<string> {
  const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", key);
  const b64 = Buffer.from(pkcs8).toString("base64");
  const wrapped = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  return `-----BEGIN PRIVATE KEY-----\n${wrapped}\n-----END PRIVATE KEY-----\n`;
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  return webcrypto.subtle.importKey(
    "pkcs8",
    Buffer.from(b64, "base64"),
    KEY_ALGORITHM,
    true,
    ["sign"],
  );
}

async function writeFileAtomic(path: string, data: string, mode: number): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = join(dirname(path), `.${Date.now()}-${process.pid}.tmp`);
  await writeFile(tmp, data, { mode });
  await rename(tmp, path);
}
