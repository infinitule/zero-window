import { X509Certificate } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { x509 } from "../src/x509-setup.js";
import {
  CaError,
  CertificateAuthority,
  PeerRejected,
  RevocationList,
  checkPeerCertificate,
  extractHardwareId,
} from "../src/index.js";

const dirs: string[] = [];

async function newCa(): Promise<CertificateAuthority> {
  const dir = await mkdtemp(join(tmpdir(), "zw-ca-"));
  dirs.push(dir);
  const ca = await CertificateAuthority.open({ dir, organization: "Test Authority" });
  await ca.initialize();
  return ca;
}

afterAll(async () => {
  await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
});

describe("CA initialization", () => {
  it("creates a root and an issuing intermediate with correct constraints", async () => {
    const dir = await mkdtemp(join(tmpdir(), "zw-ca-"));
    dirs.push(dir);
    const ca = await CertificateAuthority.open({ dir, organization: "Test Authority" });
    const { root, intermediate } = await ca.initialize();

    const rootCert = new x509.X509Certificate(root.record.pem);
    const bc = rootCert.getExtension(x509.BasicConstraintsExtension)!;
    expect(bc.ca).toBe(true);
    // Root may sign an intermediate which signs leaves — and no deeper.
    expect(bc.pathLength).toBe(1);

    const intCert = new x509.X509Certificate(intermediate.record.pem);
    const intBc = intCert.getExtension(x509.BasicConstraintsExtension)!;
    expect(intBc.ca).toBe(true);
    expect(intBc.pathLength).toBe(0);

    // The intermediate must actually be signed by the root.
    expect(await intCert.verify({ publicKey: rootCert.publicKey })).toBe(true);
    expect(root.record.role).toBe("root");
    expect(intermediate.record.issuerSerial).toBe(root.record.serial);
  });

  it("refuses to re-initialize an existing CA", async () => {
    const ca = await newCa();
    await expect(ca.initialize()).rejects.toThrowError(CaError);
    await expect(ca.initialize()).rejects.toThrow(/already initialized/);
  });

  it("reports NOT_INITIALIZED before init", async () => {
    const dir = await mkdtemp(join(tmpdir(), "zw-ca-"));
    dirs.push(dir);
    const ca = await CertificateAuthority.open({ dir });
    expect(() => ca.rootRecord()).toThrowError(/not initialized/);
    await expect(
      ca.issue({ role: "auditor-client", commonName: "a" }),
    ).rejects.toThrow(/no active issuing intermediate/);
  });

  it("persists state across reopen", async () => {
    const dir = await mkdtemp(join(tmpdir(), "zw-ca-"));
    dirs.push(dir);
    const ca1 = await CertificateAuthority.open({ dir });
    await ca1.initialize();
    const issued = await ca1.issue({ role: "auditor-client", commonName: "auditor-1" });

    const ca2 = await CertificateAuthority.open({ dir });
    expect(ca2.get(issued.record.serial).commonName).toBe("auditor-1");
    expect(ca2.list()).toHaveLength(3); // root + intermediate + leaf
  });
});

describe("leaf issuance", () => {
  it("issues a server certificate with serverAuth EKU and SANs", async () => {
    const ca = await newCa();
    const issued = await ca.issue({
      role: "authority-server",
      commonName: "authority.zero-window.internal",
      sans: ["authority.zero-window.internal", "10.0.0.5"],
    });

    const cert = new x509.X509Certificate(issued.record.pem);
    const eku = cert.getExtension(x509.ExtendedKeyUsageExtension)!;
    // I-CA-1: exactly serverAuth, never both.
    expect(eku.usages).toEqual(["1.3.6.1.5.5.7.3.1"]);

    const san = cert.getExtension(x509.SubjectAlternativeNameExtension)!;
    const names = san.names.toJSON();
    expect(names.some((n) => n.type === "dns" && n.value === "authority.zero-window.internal")).toBe(
      true,
    );
    expect(names.some((n) => n.type === "ip" && n.value === "10.0.0.5")).toBe(true);

    // Chain is leaf -> intermediate -> root
    expect(issued.chainPem.match(/BEGIN CERTIFICATE/g)).toHaveLength(3);
  });

  it("issues a client certificate with clientAuth EKU only", async () => {
    const ca = await newCa();
    const issued = await ca.issue({
      role: "centre-client",
      commonName: "CENTRE-A",
      hardwareId: "tpm-abc123",
    });
    const cert = new x509.X509Certificate(issued.record.pem);
    expect(cert.getExtension(x509.ExtendedKeyUsageExtension)!.usages).toEqual([
      "1.3.6.1.5.5.7.3.2",
    ]);
    // I-CA-2: hardware binding in both subject OU and URI SAN.
    expect(issued.record.subject).toContain("OU=hw:tpm-abc123");
    expect(extractHardwareId(cert)).toBe("tpm-abc123");
  });

  it("requires a hardware id for centre and custodian roles (I-CA-2)", async () => {
    const ca = await newCa();
    await expect(
      ca.issue({ role: "centre-client", commonName: "CENTRE-B" }),
    ).rejects.toThrow(/requires a hardware identifier/);
    await expect(
      ca.issue({ role: "custodian-client", commonName: "custodian-1" }),
    ).rejects.toThrow(/requires a hardware identifier/);
    // Auditor certificates carry no hardware binding by design.
    await expect(
      ca.issue({ role: "auditor-client", commonName: "auditor-1" }),
    ).resolves.toBeDefined();
  });

  it("leaf certificates are not CAs and verify against the intermediate", async () => {
    const ca = await newCa();
    const issued = await ca.issue({ role: "auditor-client", commonName: "auditor" });
    const cert = new x509.X509Certificate(issued.record.pem);
    expect(cert.getExtension(x509.BasicConstraintsExtension)!.ca).toBe(false);

    const intermediate = ca.list({ role: "intermediate" })[0]!;
    const intCert = new x509.X509Certificate(intermediate.pem);
    expect(await cert.verify({ publicKey: intCert.publicKey })).toBe(true);
  });

  it("honours a lifetime override", async () => {
    const ca = await newCa();
    const issued = await ca.issue({
      role: "auditor-client",
      commonName: "short-lived",
      lifetimeDays: 1,
    });
    const lifetimeMs =
      new Date(issued.record.notAfter).getTime() - new Date(issued.record.notBefore).getTime();
    expect(lifetimeMs).toBeLessThanOrEqual(86_400_000 + 60_000);
  });

  it("issues unique serials", async () => {
    const ca = await newCa();
    const serials = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const issued = await ca.issue({ role: "auditor-client", commonName: `a-${i}` });
      serials.add(issued.record.serial);
    }
    expect(serials.size).toBe(20);
  });
});

describe("rotation", () => {
  it("rotate() issues a replacement and supersedes the original", async () => {
    const ca = await newCa();
    const original = await ca.issue({
      role: "centre-client",
      commonName: "CENTRE-A",
      hardwareId: "tpm-1",
    });

    const replacement = await ca.rotate(original.record.serial);
    expect(replacement.record.serial).not.toBe(original.record.serial);
    // Identity is preserved across rotation.
    expect(replacement.record.commonName).toBe("CENTRE-A");
    expect(replacement.record.hardwareId).toBe("tpm-1");
    // The old one is revoked as superseded, so a fleet never has two live
    // certificates for one identity.
    expect(ca.isRevoked(original.record.serial)).toBe(true);
    expect(ca.get(original.record.serial).revoked!.reason).toBe("superseded");
    expect(ca.isRevoked(replacement.record.serial)).toBe(false);
  });

  it("rotate() preserves SANs for server certificates", async () => {
    const ca = await newCa();
    const original = await ca.issue({
      role: "authority-server",
      commonName: "authority.internal",
      sans: ["authority.internal", "10.1.2.3"],
    });
    const replacement = await ca.rotate(original.record.serial);
    expect(replacement.record.sans).toEqual(["authority.internal", "10.1.2.3"]);
    const cert = new x509.X509Certificate(replacement.record.pem);
    const names = cert.getExtension(x509.SubjectAlternativeNameExtension)!.names.toJSON();
    expect(names.some((n) => n.value === "10.1.2.3")).toBe(true);
  });

  it("rotate() refuses CA certificates", async () => {
    const ca = await newCa();
    const intermediate = ca.list({ role: "intermediate" })[0]!;
    await expect(ca.rotate(intermediate.serial)).rejects.toThrow(/rotateIntermediate/);
  });

  it("rotate-intermediate issues a new issuer without invalidating existing leaves", async () => {
    const dir = await mkdtemp(join(tmpdir(), "zw-ca-"));
    dirs.push(dir);
    const ca = await CertificateAuthority.open({ dir });
    const { root } = await ca.initialize();
    const oldIntermediate = ca.list({ role: "intermediate" })[0]!;

    const leafUnderOld = await ca.issue({ role: "auditor-client", commonName: "before" });

    const newIntermediate = await ca.rotateIntermediate(root.privateKeyPem);
    expect(newIntermediate.record.serial).not.toBe(oldIntermediate.serial);
    // The previous intermediate stays valid: leaves under it are unaffected.
    expect(ca.isRevoked(oldIntermediate.serial)).toBe(false);
    expect(ca.isRevoked(leafUnderOld.record.serial)).toBe(false);

    // New leaves are signed by the new intermediate.
    const leafUnderNew = await ca.issue({ role: "auditor-client", commonName: "after" });
    expect(leafUnderNew.record.issuerSerial).toBe(newIntermediate.record.serial);

    const newIntCert = new x509.X509Certificate(newIntermediate.record.pem);
    const newLeafCert = new x509.X509Certificate(leafUnderNew.record.pem);
    expect(await newLeafCert.verify({ publicKey: newIntCert.publicKey })).toBe(true);

    // The trust bundle carries both intermediates so old leaves still chain.
    expect(ca.trustBundlePem().match(/BEGIN CERTIFICATE/g)).toHaveLength(3);
  });

  it("issuance fails closed when the active intermediate is revoked", async () => {
    const ca = await newCa();
    const intermediate = ca.list({ role: "intermediate" })[0]!;
    await ca.revoke(intermediate.serial, "caCompromise");
    await expect(
      ca.issue({ role: "auditor-client", commonName: "x" }),
    ).rejects.toThrow(/is revoked; run `zw-ca rotate-intermediate`/);
  });
});

describe("revocation and CRLs", () => {
  it("revokes a certificate and lists it in a signed CRL", async () => {
    const ca = await newCa();
    const a = await ca.issue({ role: "auditor-client", commonName: "a" });
    const b = await ca.issue({ role: "auditor-client", commonName: "b" });

    await ca.revoke(a.record.serial, "keyCompromise");
    const crlPem = await ca.generateCrl();

    const crl = RevocationList.parse(crlPem);
    expect(crl.isRevoked(a.record.serial)).toBe(true);
    expect(crl.isRevoked(b.record.serial)).toBe(false);

    // The CRL must be signed by the issuing intermediate.
    const parsed = new x509.X509Crl(crlPem);
    const intCert = new x509.X509Certificate(ca.list({ role: "intermediate" })[0]!.pem);
    expect(await parsed.verify({ publicKey: intCert.publicKey })).toBe(true);
    expect(parsed.entries[0]!.reason).toBe(1); // keyCompromise
  });

  it("publishes CRLs with the RFC 7468 label so external tooling can read them", async () => {
    const ca = await newCa();
    const issued = await ca.issue({ role: "auditor-client", commonName: "a" });
    await ca.revoke(issued.record.serial);
    const pem = await ca.generateCrl();

    // @peculiar/x509 emits a bare "BEGIN CRL" label, which OpenSSL refuses.
    // An operator must be able to run `openssl crl -in crl.pem -text`.
    expect(pem).toMatch(/^-----BEGIN X509 CRL-----/);
    expect(pem).toContain("-----END X509 CRL-----");
    expect(pem).not.toMatch(/-----BEGIN CRL-----/);

    // Round-trips through our own parser regardless of label.
    expect(RevocationList.parse(pem).isRevoked(issued.record.serial)).toBe(true);
    expect(
      RevocationList.parse(pem.replace(/X509 CRL/g, "CRL")).isRevoked(issued.record.serial),
    ).toBe(true);
  });

  it("the published CRL parses with openssl", async () => {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const exec = promisify(execFile);
    const { writeFile } = await import("node:fs/promises");

    const ca = await newCa();
    const issued = await ca.issue({ role: "auditor-client", commonName: "revoked-one" });
    await ca.revoke(issued.record.serial, "keyCompromise");
    const dir = await mkdtemp(join(tmpdir(), "zw-crl-"));
    dirs.push(dir);
    const path = join(dir, "crl.pem");
    await writeFile(path, await ca.generateCrl());

    const { stdout } = await exec("openssl", ["crl", "-in", path, "-noout", "-text"]);
    expect(stdout).toContain("Certificate Revocation List");
    expect(stdout).toContain("ecdsa-with-SHA384");
    expect(stdout.toUpperCase()).toContain(issued.record.serial.toUpperCase());
  });

  it("refuses to revoke twice and reports the original revocation", async () => {
    const ca = await newCa();
    const issued = await ca.issue({ role: "auditor-client", commonName: "a" });
    await ca.revoke(issued.record.serial, "keyCompromise");
    await expect(ca.revoke(issued.record.serial)).rejects.toThrow(
      /already revoked at .* \(keyCompromise\)/,
    );
  });

  it("rejects an unknown serial", async () => {
    const ca = await newCa();
    expect(() => ca.get("deadbeef")).toThrowError(CaError);
    await expect(ca.revoke("deadbeef")).rejects.toThrow(/no certificate with serial/);
  });

  it("CRL numbers increase monotonically", async () => {
    const ca = await newCa();
    const first = new x509.X509Crl(await ca.generateCrl());
    const second = new x509.X509Crl(await ca.generateCrl());
    expect(second.thisUpdate.getTime()).toBeGreaterThanOrEqual(first.thisUpdate.getTime());
  });

  it("a stale CRL fails closed rather than silently passing (I-CA-3)", async () => {
    const ca = await newCa();
    const crlPem = await ca.generateCrl(1);
    const crl = RevocationList.parse(crlPem);

    expect(() => crl.assertFresh(new Date())).not.toThrow();
    const later = new Date(Date.now() + 2 * 3_600_000);
    expect(() => crl.assertFresh(later)).toThrowError(PeerRejected);
    expect(() => crl.assertFresh(later)).toThrow(/CRL expired at .*publish a fresh CRL/s);
  });

  it("a missing CRL file is a hard failure, not an absent-means-allow", async () => {
    await expect(RevocationList.load("/nonexistent/crl.pem")).rejects.toThrow(
      /refusing to accept peers without revocation data/,
    );
  });
});

describe("peer verification", () => {
  async function peerOf(pem: string): Promise<X509Certificate> {
    return new X509Certificate(pem);
  }

  it("accepts a valid client certificate with the right EKU", async () => {
    const ca = await newCa();
    const issued = await ca.issue({
      role: "centre-client",
      commonName: "CENTRE-A",
      hardwareId: "tpm-9",
    });
    const result = checkPeerCertificate(await peerOf(issued.record.pem), {
      requireEku: "clientAuth",
      expectHardwareId: "tpm-9",
    });
    expect(result.serial).toBe(issued.record.serial);
    expect(result.hardwareId).toBe("tpm-9");
  });

  it("rejects a missing peer certificate", () => {
    expect(() => checkPeerCertificate(undefined, { requireEku: "clientAuth" })).toThrow(
      /mTLS is mandatory/,
    );
  });

  it("rejects a server certificate presented as a client (I-CA-1)", async () => {
    const ca = await newCa();
    const server = await ca.issue({
      role: "authority-server",
      commonName: "authority.internal",
      sans: ["authority.internal"],
    });
    // A stolen server certificate must not authenticate as a centre.
    expect(() =>
      checkPeerCertificate(new X509Certificate(server.record.pem), {
        requireEku: "clientAuth",
      }),
    ).toThrow(/does not carry clientAuth EKU/);
  });

  it("rejects a client certificate used to impersonate the server (I-CA-1)", async () => {
    const ca = await newCa();
    const client = await ca.issue({
      role: "centre-client",
      commonName: "CENTRE-A",
      hardwareId: "tpm-1",
    });
    expect(() =>
      checkPeerCertificate(new X509Certificate(client.record.pem), {
        requireEku: "serverAuth",
      }),
    ).toThrow(/does not carry serverAuth EKU/);
  });

  it("rejects a certificate whose hardware binding does not match the enrolment (I-CA-2)", async () => {
    const ca = await newCa();
    const issued = await ca.issue({
      role: "centre-client",
      commonName: "CENTRE-A",
      hardwareId: "tpm-original",
    });
    expect(() =>
      checkPeerCertificate(new X509Certificate(issued.record.pem), {
        requireEku: "clientAuth",
        expectHardwareId: "tpm-different",
      }),
    ).toThrow(/key pair may have been copied to another machine/);
  });

  it("rejects a revoked peer against a fresh CRL", async () => {
    const ca = await newCa();
    const issued = await ca.issue({
      role: "centre-client",
      commonName: "CENTRE-A",
      hardwareId: "tpm-1",
    });
    await ca.revoke(issued.record.serial, "keyCompromise");
    const crl = RevocationList.parse(await ca.generateCrl());

    expect(() =>
      checkPeerCertificate(new X509Certificate(issued.record.pem), {
        requireEku: "clientAuth",
        crl,
      }),
    ).toThrow(/is revoked/);
  });

  it("accepts a non-revoked peer against the same CRL", async () => {
    const ca = await newCa();
    const revokedCert = await ca.issue({
      role: "centre-client",
      commonName: "CENTRE-GONE",
      hardwareId: "tpm-x",
    });
    const liveCert = await ca.issue({
      role: "centre-client",
      commonName: "CENTRE-LIVE",
      hardwareId: "tpm-y",
    });
    await ca.revoke(revokedCert.record.serial, "cessationOfOperation");
    const crl = RevocationList.parse(await ca.generateCrl());

    expect(() =>
      checkPeerCertificate(new X509Certificate(liveCert.record.pem), {
        requireEku: "clientAuth",
        crl,
      }),
    ).not.toThrow();
  });

  it("rejects an expired peer certificate", async () => {
    const ca = await newCa();
    const issued = await ca.issue({
      role: "auditor-client",
      commonName: "auditor",
      lifetimeDays: 1,
    });
    const future = new Date(Date.now() + 3 * 86_400_000);
    expect(() =>
      checkPeerCertificate(new X509Certificate(issued.record.pem), {
        requireEku: "clientAuth",
        now: future,
      }),
    ).toThrow(/outside its validity window/);
  });

  it("rotation plus CRL actually stops the old certificate being accepted", async () => {
    // The end-to-end property operators care about: after rotating a centre's
    // certificate and publishing the CRL, the old one is refused.
    const ca = await newCa();
    const original = await ca.issue({
      role: "centre-client",
      commonName: "CENTRE-A",
      hardwareId: "tpm-1",
    });
    const replacement = await ca.rotate(original.record.serial);
    const crl = RevocationList.parse(await ca.generateCrl());

    expect(() =>
      checkPeerCertificate(new X509Certificate(original.record.pem), {
        requireEku: "clientAuth",
        expectHardwareId: "tpm-1",
        crl,
      }),
    ).toThrow(/is revoked/);

    expect(() =>
      checkPeerCertificate(new X509Certificate(replacement.record.pem), {
        requireEku: "clientAuth",
        expectHardwareId: "tpm-1",
        crl,
      }),
    ).not.toThrow();
  });
});
