import { X509Certificate } from "node:crypto";
import { readFile } from "node:fs/promises";
import { x509 } from "./x509-setup.js";

/**
 * mTLS material and peer verification for ZERO-WINDOW services.
 *
 * Node's TLS stack verifies the chain and expiry for us when
 * `requestCert: true, rejectUnauthorized: true` are set. What it does NOT do
 * is check our CRL or our hardware binding, so those are enforced here and
 * called from every service's connection handler.
 */

export interface MtlsMaterial {
  /** PEM certificate chain: leaf first. */
  cert: string;
  /** PEM PKCS#8 private key. */
  key: string;
  /** PEM trust bundle (root + intermediates). */
  ca: string;
}

export interface MtlsFilePaths {
  certPath: string;
  keyPath: string;
  caPath: string;
  /** Optional CRL. When configured, a missing or stale CRL fails closed. */
  crlPath?: string;
}

export async function loadMtlsMaterial(paths: MtlsFilePaths): Promise<MtlsMaterial> {
  const [cert, key, ca] = await Promise.all([
    readFile(paths.certPath, "utf8"),
    readFile(paths.keyPath, "utf8"),
    readFile(paths.caPath, "utf8"),
  ]);
  return { cert, key, ca };
}

/**
 * Node TLS server options for an mTLS listener.
 * TLS 1.3 only: the deployment is entirely first-party, so there is no
 * legacy peer to accommodate and no reason to keep 1.2 cipher negotiation
 * in the attack surface.
 */
export function tlsServerOptions(material: MtlsMaterial): {
  cert: string;
  key: string;
  ca: string;
  requestCert: true;
  rejectUnauthorized: true;
  minVersion: "TLSv1.3";
} {
  return {
    cert: material.cert,
    key: material.key,
    ca: material.ca,
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: "TLSv1.3",
  };
}

export function tlsClientOptions(
  material: MtlsMaterial,
  servername: string,
): {
  cert: string;
  key: string;
  ca: string;
  servername: string;
  rejectUnauthorized: true;
  minVersion: "TLSv1.3";
} {
  return {
    cert: material.cert,
    key: material.key,
    ca: material.ca,
    servername,
    rejectUnauthorized: true,
    minVersion: "TLSv1.3",
  };
}

export type PeerCheckFailure =
  | "NO_PEER_CERTIFICATE"
  | "REVOKED"
  | "CRL_STALE"
  | "CRL_UNAVAILABLE"
  | "HARDWARE_MISMATCH"
  | "EKU_INVALID"
  | "EXPIRED";

export class PeerRejected extends Error {
  constructor(
    message: string,
    readonly reason: PeerCheckFailure,
  ) {
    super(message);
    this.name = "PeerRejected";
  }
}

/**
 * A parsed CRL with the freshness policy applied.
 *
 * INVARIANT I-CA-3: an absent or expired CRL is a hard failure, never a
 * silent pass. Revocation that can be disabled by deleting a file is not
 * revocation.
 */
export class RevocationList {
  private constructor(
    private readonly crl: x509.X509Crl,
    private readonly serials: Set<string>,
  ) {}

  static parse(pem: string): RevocationList {
    // Accept both the RFC 7468 "X509 CRL" label we publish and the bare
    // "CRL" label @peculiar/x509 produces, so a CRL from either source or
    // from external tooling loads.
    const crl = new x509.X509Crl(
      pem
        .replace(/-----BEGIN X509 CRL-----/g, "-----BEGIN CRL-----")
        .replace(/-----END X509 CRL-----/g, "-----END CRL-----"),
    );
    const serials = new Set(crl.entries.map((e) => normalizeSerial(e.serialNumber)));
    return new RevocationList(crl, serials);
  }

  static async load(path: string): Promise<RevocationList> {
    try {
      return RevocationList.parse(await readFile(path, "utf8"));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        throw new PeerRejected(
          `CRL not found at ${path}: refusing to accept peers without revocation data (I-CA-3)`,
          "CRL_UNAVAILABLE",
        );
      }
      throw err;
    }
  }

  get thisUpdate(): Date {
    return this.crl.thisUpdate;
  }

  get nextUpdate(): Date | undefined {
    return this.crl.nextUpdate;
  }

  /** Throws if the CRL is past its nextUpdate. */
  assertFresh(now = new Date()): void {
    const next = this.crl.nextUpdate;
    if (!next) {
      throw new PeerRejected(
        "CRL has no nextUpdate: cannot establish freshness",
        "CRL_STALE",
      );
    }
    if (now > next) {
      throw new PeerRejected(
        `CRL expired at ${next.toISOString()} (now ${now.toISOString()}): publish a fresh CRL with \`zw-ca crl\``,
        "CRL_STALE",
      );
    }
  }

  isRevoked(serial: string): boolean {
    return this.serials.has(normalizeSerial(serial));
  }
}

export interface PeerRequirements {
  /** Required extended key usage for this direction. */
  requireEku: "clientAuth" | "serverAuth";
  /** When set, the peer's certificate must carry this hardware id (I-CA-2). */
  expectHardwareId?: string;
  crl?: RevocationList;
  now?: Date;
}

const EKU_OID = {
  clientAuth: "1.3.6.1.5.5.7.3.2",
  serverAuth: "1.3.6.1.5.5.7.3.1",
} as const;

/**
 * Application-level checks on an already TLS-verified peer certificate.
 * Call from the service's connection or request hook.
 */
export function checkPeerCertificate(
  peer: X509Certificate | undefined,
  requirements: PeerRequirements,
): { serial: string; subject: string; hardwareId: string | undefined } {
  if (!peer) {
    throw new PeerRejected(
      "no client certificate presented: mTLS is mandatory on this endpoint",
      "NO_PEER_CERTIFICATE",
    );
  }

  const now = requirements.now ?? new Date();
  if (now < new Date(peer.validFrom) || now > new Date(peer.validTo)) {
    throw new PeerRejected(
      `peer certificate ${peer.serialNumber} is outside its validity window (${peer.validFrom} .. ${peer.validTo})`,
      "EXPIRED",
    );
  }

  // Re-parse with the x509 library to read extensions Node does not expose.
  const parsed = new x509.X509Certificate(peer.raw);
  const eku = parsed.getExtension(x509.ExtendedKeyUsageExtension);
  const wanted = EKU_OID[requirements.requireEku];
  if (!eku || !eku.usages.includes(wanted)) {
    throw new PeerRejected(
      `peer certificate ${peer.serialNumber} does not carry ${requirements.requireEku} EKU (I-CA-1)`,
      "EKU_INVALID",
    );
  }

  const hardwareId = extractHardwareId(parsed);
  if (requirements.expectHardwareId !== undefined) {
    if (hardwareId !== requirements.expectHardwareId) {
      throw new PeerRejected(
        `peer certificate ${peer.serialNumber} is bound to hardware "${hardwareId ?? "(none)"}" but this enrolment expects "${requirements.expectHardwareId}": the key pair may have been copied to another machine (I-CA-2)`,
        "HARDWARE_MISMATCH",
      );
    }
  }

  if (requirements.crl) {
    requirements.crl.assertFresh(now);
    if (requirements.crl.isRevoked(peer.serialNumber)) {
      throw new PeerRejected(
        `peer certificate ${peer.serialNumber} (${peer.subject.replace(/\n/g, ", ")}) is revoked`,
        "REVOKED",
      );
    }
  }

  // Node reports serials as uppercase hex; the CA records them lowercase.
  // Normalizing here means a caller can compare this against a
  // CertificateRecord.serial directly, which is exactly what enrolment checks
  // do — an unnormalized value would silently never match.
  return { serial: normalizeSerial(peer.serialNumber), subject: peer.subject, hardwareId };
}

/** Read the hardware id from the URI SAN, falling back to the subject OU. */
export function extractHardwareId(cert: x509.X509Certificate): string | undefined {
  const san = cert.getExtension(x509.SubjectAlternativeNameExtension);
  const uri = san?.names.toJSON().find((n) => n.type === "url" && n.value.startsWith("urn:zero-window:hw:"));
  if (uri) return uri.value.slice("urn:zero-window:hw:".length);
  const ou = /OU=hw:([^,]+)/.exec(cert.subject);
  return ou?.[1];
}

/**
 * Serial numbers appear in three representations across this stack: the x509
 * library's lowercase hex, Node's uppercase hex, and DER integers that may
 * carry a leading zero pad. Every comparison goes through this.
 */
function normalizeSerial(serial: string): string {
  return serial.replace(/^0+/, "").toLowerCase();
}
