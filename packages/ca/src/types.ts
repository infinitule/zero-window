/**
 * Certificate roles in the ZERO-WINDOW PKI.
 *
 * The role determines key usage, extended key usage, and lifetime. Roles are
 * not interchangeable: a centre node's client certificate cannot be used to
 * stand up a server impersonating the authority, because it carries only
 * clientAuth EKU (INVARIANT I-CA-2).
 */
export type CertRole =
  /** The offline root. Signs intermediates only. */
  | "root"
  /** Online issuing CA. Signs leaf certificates. */
  | "intermediate"
  /** Authority service TLS server certificate. */
  | "authority-server"
  /** Centre node client certificate, bound to a hardware identifier. */
  | "centre-client"
  /** Custodian client certificate used to authenticate at the ceremony. */
  | "custodian-client"
  /** Auditor read-only client certificate. */
  | "auditor-client";

export interface CertificateRecord {
  /** Hex serial number. */
  serial: string;
  role: CertRole;
  subject: string;
  /** Common name, extracted for convenience. */
  commonName: string;
  issuerSerial: string | null;
  notBefore: string;
  notAfter: string;
  /** SHA-256 fingerprint, hex, lowercase. */
  fingerprint: string;
  pem: string;
  /** Hardware identifier bound into the certificate, when the role has one. */
  hardwareId?: string;
  /** Subject alternative names (DNS/IP) for server certificates. */
  sans?: string[];
  revoked?: {
    at: string;
    reason: RevocationReason;
  };
}

/** RFC 5280 §5.3.1 CRLReason values used by the ZERO-WINDOW PKI. */
export type RevocationReason =
  | "unspecified"
  | "keyCompromise"
  | "caCompromise"
  | "affiliationChanged"
  | "superseded"
  | "cessationOfOperation";

export const REVOCATION_REASON_CODES: Record<RevocationReason, number> = {
  unspecified: 0,
  keyCompromise: 1,
  caCompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
};

export interface IssuedCertificate {
  record: CertificateRecord;
  /** PEM-encoded PKCS#8 private key. Written with mode 0600 by the CLI. */
  privateKeyPem: string;
  /** Leaf → intermediate → root, in that order. */
  chainPem: string;
}
