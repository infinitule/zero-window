import { mkdtemp, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { Authority, buildAuthorityServer, encodeAdmitToken } from "@zw/authority";
import { CertificateAuthority } from "@zw/ca";
import { generateBoxKeyPair, sealOpen } from "@zw/crypto";
import { VaultKeyProvider } from "@zw/kms-vault";
import { CentreNode } from "../src/centre.js";
import { AuthoritySyncClient, SyncError } from "../src/sync.js";
import { sampleBank, sampleBlueprint } from "./fixtures.js";

/**
 * M5 acceptance: autonomy mode (T10).
 *
 * Everything here crosses a real TLS 1.3 socket with certificates from the
 * real internal CA. At T-0 the wrapped KEK arrives over mTLS — then the
 * authority process is killed, and the exam must proceed to completion:
 * check-in, generation, printing, close, checkpoint. No mocks anywhere.
 */

const EXAM = "EXAM-2026-AUT";
const CENTRE = "CENTRE-AUT";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function tempDir(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "zw-autonomy-"));
  dirs.push(d);
  return d;
}

it("the exam completes after authority connectivity is killed post-release", async () => {
  // ---- PKI ----------------------------------------------------------
  const caDir = await tempDir();
  const ca = await CertificateAuthority.open({ dir: caDir });
  await ca.initialize();
  const serverCert = await ca.issue({
    role: "authority-server",
    commonName: "authority",
    sans: ["localhost", "127.0.0.1"],
  });
  const centreCert = await ca.issue({
    role: "centre-client",
    commonName: CENTRE,
    hardwareId: "tpm-autonomy-1",
  });

  // ---- authority ----------------------------------------------------
  const aDir = await tempDir();
  const authority = await Authority.open({
    statePath: join(aDir, "authority.db"),
    logPath: join(aDir, "log.db"),
    provider: await VaultKeyProvider.open({
      keystorePath: join(aDir, "keystore.json"),
      passphrase: Buffer.from("a", "utf8"),
    }),
  });
  const custodians = Array.from({ length: 5 }, (_, i) => ({
    custodianId: `cust-${i + 1}`,
    keys: generateBoxKeyPair(),
  }));
  for (const c of custodians) {
    authority.enrolCustodian({
      custodianId: c.custodianId,
      name: c.custodianId,
      boxPublicKey: c.keys.publicKey,
      certFingerprint: "",
    });
  }

  // ---- centre -------------------------------------------------------
  const cDir = await tempDir();
  const spoolDir = join(cDir, "spool");
  const centre = await CentreNode.open({
    centreId: CENTRE,
    examId: EXAM,
    statePath: join(cDir, "centre.db"),
    logPath: join(cDir, "log.db"),
    provider: await VaultKeyProvider.open({
      keystorePath: join(cDir, "keystore.json"),
      passphrase: Buffer.from("c", "utf8"),
    }),
    authorityPublicKey: authority.publicKey,
    spoolDir,
  });
  await authority.enrolCentre({
    centreId: CENTRE,
    boxPublicKey: centre.boxPublicKey,
    certFingerprint: centreCert.record.fingerprint,
    hardwareId: "tpm-autonomy-1",
  });

  // ---- provision, distribute, admit ---------------------------------
  const provisioned = await authority.provision({
    bank: sampleBank(EXAM),
    blueprint: sampleBlueprint(EXAM),
    threshold: 3,
  });
  await authority.distribute(provisioned.paper.bundleId, CENTRE);
  const tokens = await authority.issueAdmitTokens({
    examId: EXAM,
    centreId: CENTRE,
    salt: Authority.newRegistrationSalt(),
    expiresAt: Date.now() + 86_400_000,
    candidates: [
      { registrationId: "REG-1", seat: "A-01" },
      { registrationId: "REG-2", seat: "A-02" },
    ],
  });

  // ---- serve over mTLS ----------------------------------------------
  const server = await buildAuthorityServer({
    authority,
    tls: {
      cert: serverCert.chainPem,
      key: serverCert.privateKeyPem,
      ca: ca.trustBundlePem(),
    },
  });
  const port = (server.server.address() as AddressInfo).port;

  const sync = new AuthoritySyncClient({
    authorityHost: "127.0.0.1",
    authorityPort: port,
    servername: "localhost",
    tls: {
      cert: centreCert.chainPem,
      key: centreCert.privateKeyPem,
      ca: ca.trustBundlePem(),
    },
  });

  // The key the wire reports must match the key pinned at enrolment.
  expect((await sync.authorityKey()).equals(authority.publicKey)).toBe(true);

  // Custody transfer over the wire, hash-verified on receipt (T3).
  await sync.fetchBundle(centre, EXAM, "paper");

  // Before release: 425, not a KEK (T2).
  expect(await sync.tryFetchKek(centre, EXAM, "paper")).toBe(false);

  // ---- threshold release at T-0 --------------------------------------
  await authority.scheduleRelease({
    examId: EXAM,
    bundleId: provisioned.paper.bundleId,
    releaseAt: Date.now() - 1000,
  });
  const shareOf = (id: string) => {
    const rec = authority.store
      .shares(provisioned.paper.bundleId)
      .find((s) => s.custodianId === id)!;
    const c = custodians.find((x) => x.custodianId === id)!;
    return { custodianId: id, shareBlob: sealOpen(rec.sealed, c.keys.publicKey, c.keys.secretKey) };
  };
  await authority.release({
    bundleId: provisioned.paper.bundleId,
    shares: [shareOf("cust-1"), shareOf("cust-2"), shareOf("cust-3")],
  });

  // KEK pickup over the wire.
  expect(await sync.tryFetchKek(centre, EXAM, "paper")).toBe(true);

  // ---- KILL AUTHORITY CONNECTIVITY -----------------------------------
  await server.close();
  await authority.close();

  // Sync is now impossible — and irrelevant.
  await expect(sync.tryFetchKek(centre, EXAM, "paper")).rejects.toBeInstanceOf(SyncError);

  // ---- the exam proceeds to completion, fully offline ----------------
  for (const t of tokens) await centre.checkIn(encodeAdmitToken(t));
  const { printed, failures } = await centre.runT0();
  expect(failures).toEqual([]);
  expect(printed).toBe(2);
  expect(await readdir(spoolDir)).toHaveLength(2);

  await centre.closeExam();
  await centre.checkpoint();

  // Liveness stayed green throughout; the missing authority is not a fault.
  expect((await centre.health.live()).status).toBe("pass");

  const types = centre.log.entries().map((e) => e.type);
  for (const expected of [
    "BUNDLE_RECEIVED",
    "KEK_RECEIVED",
    "CANDIDATE_CHECKED_IN",
    "PAPER_GENERATED",
    "PAPER_PRINTED",
    "EXAM_CLOSED",
  ]) {
    expect(types, `missing ${expected}`).toContain(expected);
  }
  await centre.close();
}, 180_000);

it("mTLS: a client certificate from a foreign CA cannot reach the API", async () => {
  const caDir = await tempDir();
  const ca = await CertificateAuthority.open({ dir: caDir });
  await ca.initialize();
  const serverCert = await ca.issue({
    role: "authority-server",
    commonName: "authority",
    sans: ["localhost", "127.0.0.1"],
  });

  const foreignDir = await tempDir();
  const foreignCa = await CertificateAuthority.open({ dir: foreignDir });
  await foreignCa.initialize();
  const impostorCert = await foreignCa.issue({
    role: "centre-client",
    commonName: CENTRE,
    hardwareId: "tpm-autonomy-1",
  });

  const aDir = await tempDir();
  const authority = await Authority.open({
    statePath: join(aDir, "authority.db"),
    logPath: join(aDir, "log.db"),
    provider: await VaultKeyProvider.open({
      keystorePath: join(aDir, "keystore.json"),
      passphrase: Buffer.from("a", "utf8"),
    }),
  });
  const server = await buildAuthorityServer({
    authority,
    tls: { cert: serverCert.chainPem, key: serverCert.privateKeyPem, ca: ca.trustBundlePem() },
  });
  const port = (server.server.address() as AddressInfo).port;

  const impostorSync = new AuthoritySyncClient({
    authorityHost: "127.0.0.1",
    authorityPort: port,
    servername: "localhost",
    tls: {
      cert: impostorCert.chainPem,
      key: impostorCert.privateKeyPem,
      ca: ca.trustBundlePem(),
    },
    timeoutMs: 3000,
  });
  await expect(impostorSync.authorityKey()).rejects.toBeInstanceOf(SyncError);

  await server.close();
  await authority.close();
}, 60_000);
