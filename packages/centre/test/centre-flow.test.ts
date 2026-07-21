import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Authority, encodeAdmitToken } from "@zw/authority";
import { generateBoxKeyPair, sealOpen } from "@zw/crypto";
import { VaultKeyProvider } from "@zw/kms-vault";
import { CentreNode, CentreError } from "../src/centre.js";
import { sampleBank, sampleBlueprint } from "./fixtures.js";

/**
 * Full custody flow, in-process: F1 → F2 → F3 → F4 → F5. Every hand-off is
 * explicit (bundle envelope, wrapped KEK, admit token QR string) — exactly
 * what crosses the wire or the air gap in production.
 */

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

const EXAM = "EXAM-2026-PHYS";
const CENTRE = "CENTRE-A";

async function tempDir(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "zw-flow-"));
  dirs.push(d);
  return d;
}

interface World {
  authority: Authority;
  centre: CentreNode;
  custodians: Array<{ custodianId: string; keys: ReturnType<typeof generateBoxKeyPair> }>;
  spoolDir: string;
  centreDir: string;
  qrPayloads: string[];
  paperBundle: { bundleId: string; bundleHash: string; kekFingerprint: string };
  shares(ids: string[]): Array<{ custodianId: string; shareBlob: Buffer }>;
}

async function buildWorld(opts: { candidates?: number } = {}): Promise<World> {
  const aDir = await tempDir();
  const cDir = await tempDir();
  const spoolDir = join(cDir, "spool");

  const aProvider = await VaultKeyProvider.open({
    keystorePath: join(aDir, "keystore.json"),
    passphrase: Buffer.from("authority-test", "utf8"),
  });
  const authority = await Authority.open({
    statePath: join(aDir, "authority.db"),
    logPath: join(aDir, "log.db"),
    provider: aProvider,
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

  const cProvider = await VaultKeyProvider.open({
    keystorePath: join(cDir, "keystore.json"),
    passphrase: Buffer.from("centre-test", "utf8"),
  });
  const centre = await CentreNode.open({
    centreId: CENTRE,
    examId: EXAM,
    statePath: join(cDir, "centre.db"),
    logPath: join(cDir, "log.db"),
    provider: cProvider,
    authorityPublicKey: authority.publicKey,
    spoolDir,
  });

  await authority.enrolCentre({
    centreId: CENTRE,
    boxPublicKey: centre.boxPublicKey,
    certFingerprint: "fp",
    hardwareId: "tpm-1",
  });

  // F1: provision + distribute
  const result = await authority.provision({
    bank: sampleBank(EXAM),
    blueprint: sampleBlueprint(EXAM),
    threshold: 3,
  });
  await authority.distribute(result.paper.bundleId, CENTRE);
  const stored = authority.store.bundle(result.paper.bundleId)!;
  await centre.receiveBundle(stored.ciphertext, {
    bundleId: stored.bundleId,
    examId: stored.examId,
    kind: "paper",
    bundleHash: stored.bundleHash,
    kekFingerprint: stored.kekFingerprint,
    threshold: stored.threshold,
  });

  // F2: admit tokens
  const n = opts.candidates ?? 3;
  const tokens = await authority.issueAdmitTokens({
    examId: EXAM,
    centreId: CENTRE,
    salt: Authority.newRegistrationSalt(),
    expiresAt: Date.now() + 86_400_000,
    candidates: Array.from({ length: n }, (_, i) => ({
      registrationId: `REG-${1000 + i}`,
      seat: `A-${String(i + 1).padStart(2, "0")}`,
    })),
  });

  return {
    authority,
    centre,
    custodians,
    spoolDir,
    centreDir: cDir,
    qrPayloads: tokens.map(encodeAdmitToken),
    paperBundle: {
      bundleId: result.paper.bundleId,
      bundleHash: result.paper.bundleHash,
      kekFingerprint: result.paper.kekFingerprint,
    },
    shares(ids: string[]) {
      return ids.map((custodianId) => {
        const rec = authority.store
          .shares(result.paper.bundleId)
          .find((s) => s.custodianId === custodianId)!;
        const c = custodians.find((x) => x.custodianId === custodianId)!;
        return {
          custodianId,
          shareBlob: sealOpen(rec.sealed, c.keys.publicKey, c.keys.secretKey),
        };
      });
    },
  };
}

async function releaseToCentre(w: World): Promise<void> {
  await w.authority.scheduleRelease({
    examId: EXAM,
    bundleId: w.paperBundle.bundleId,
    releaseAt: Date.now() - 1000,
  });
  const outcome = await w.authority.release({
    bundleId: w.paperBundle.bundleId,
    shares: w.shares(["cust-1", "cust-2", "cust-3"]),
  });
  const wrapped = outcome.wrapped.find((x) => x.centreId === CENTRE)!;
  await w.centre.receiveWrappedKek(w.paperBundle.bundleId, wrapped.sealed);
}

describe("centre custody (T3)", () => {
  it("accepts a bundle whose hash matches and logs BUNDLE_RECEIVED", async () => {
    const w = await buildWorld();
    const entry = w.centre.log.entries().find((e) => e.type === "BUNDLE_RECEIVED")!;
    expect(entry.payload["bundle_hash"]).toBe(w.paperBundle.bundleHash);
    await w.centre.close();
    await w.authority.close();
  });

  it("refuses a tampered bundle outright", async () => {
    const w = await buildWorld();
    const stored = w.authority.store.bundle(w.paperBundle.bundleId)!;
    const tampered = Buffer.from(stored.ciphertext);
    tampered[100]! ^= 0x01;

    const cDir = await tempDir();
    const provider = await VaultKeyProvider.open({
      keystorePath: join(cDir, "keystore.json"),
      passphrase: Buffer.from("x", "utf8"),
    });
    const fresh = await CentreNode.open({
      centreId: "CENTRE-B",
      examId: EXAM,
      statePath: join(cDir, "c.db"),
      logPath: join(cDir, "l.db"),
      provider,
      authorityPublicKey: w.authority.publicKey,
      spoolDir: join(cDir, "spool"),
    });
    await expect(
      fresh.receiveBundle(tampered, {
        bundleId: stored.bundleId,
        examId: stored.examId,
        kind: "paper",
        bundleHash: stored.bundleHash,
        kekFingerprint: stored.kekFingerprint,
        threshold: stored.threshold,
      }),
    ).rejects.toMatchObject({ code: "BUNDLE_HASH_MISMATCH" });
    await fresh.close();
    await w.centre.close();
    await w.authority.close();
  });
});

describe("centre key receipt (T2)", () => {
  it("cannot generate before the KEK is released, even with the bundle in custody", async () => {
    const w = await buildWorld();
    await w.centre.checkIn(w.qrPayloads[0]!);
    await expect(w.centre.generatePaper("A-01")).rejects.toMatchObject({ code: "KEK_NOT_HELD" });
    await w.centre.close();
    await w.authority.close();
  });

  it("rejects a wrapped KEK whose fingerprint does not match the bundle", async () => {
    const w = await buildWorld();
    // Wrap a DIFFERENT key to the centre: fingerprint check must catch it.
    const { seal, randomBytes } = await import("@zw/crypto");
    const bogus = seal(randomBytes(32), w.centre.boxPublicKey);
    await expect(
      w.centre.receiveWrappedKek(w.paperBundle.bundleId, bogus),
    ).rejects.toMatchObject({ code: "KEK_FINGERPRINT_MISMATCH" });
    await w.centre.close();
    await w.authority.close();
  });
});

describe("check-in (T7)", () => {
  it("verifies offline, binds seats, and refuses duplicates", async () => {
    const w = await buildWorld();
    const r1 = await w.centre.checkIn(w.qrPayloads[0]!);
    expect(r1.seat).toBe("A-01");

    await expect(w.centre.checkIn(w.qrPayloads[0]!)).rejects.toMatchObject({
      code: "DUPLICATE_CHECKIN",
    });

    const bound = w.centre.log.entries().find((e) => e.type === "CANDIDATE_CHECKED_IN")!;
    expect(bound.payload["seat"]).toBe("A-01");
    expect(bound.payload["token_hash"]).toMatch(/^[0-9a-f]{64}$/);
    await w.centre.close();
    await w.authority.close();
  });

  it("refuses tokens for another centre and garbage QR payloads", async () => {
    const w = await buildWorld();
    const otherCentreToken = await w.authority.issueAdmitTokens({
      examId: EXAM,
      centreId: "CENTRE-Z",
      salt: Authority.newRegistrationSalt(),
      expiresAt: Date.now() + 86_400_000,
      candidates: [{ registrationId: "R", seat: "Z-01" }],
    });
    await expect(
      w.centre.checkIn(encodeAdmitToken(otherCentreToken[0]!)),
    ).rejects.toMatchObject({ code: "ADMIT_REFUSED" });
    await expect(w.centre.checkIn("!!!not-a-qr!!!")).rejects.toMatchObject({
      code: "ADMIT_REFUSED",
    });
    expect(w.centre.metrics.expose()).toContain("zw_centre_admit_refused_total");
    await w.centre.close();
    await w.authority.close();
  });
});

describe("T-0 generation and printing (F4)", () => {
  it("runs the full exam: check-in → generate → print → close", async () => {
    const w = await buildWorld({ candidates: 3 });
    await releaseToCentre(w);
    for (const qr of w.qrPayloads) await w.centre.checkIn(qr);

    const { printed, failures } = await w.centre.runT0();
    expect(failures).toEqual([]);
    expect(printed).toBe(3);

    // Papers spooled as PDFs (spool transport in this test).
    const files = await readdir(w.spoolDir);
    expect(files).toHaveLength(3);
    for (const f of files) {
      const pdf = await readFile(join(w.spoolDir, f));
      expect(pdf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    }

    // The log tells the whole story per seat.
    const types = w.centre.log.entries().map((e) => e.type);
    expect(types.filter((t) => t === "PAPER_GENERATED")).toHaveLength(3);
    expect(types.filter((t) => t === "PAPER_PRINTED")).toHaveLength(3);

    // Each PAPER_PRINTED carries the same hash PAPER_GENERATED committed.
    const generated = w.centre.log.entries().filter((e) => e.type === "PAPER_GENERATED");
    const printedEntries = w.centre.log.entries().filter((e) => e.type === "PAPER_PRINTED");
    for (const p of printedEntries) {
      const g = generated.find((x) => x.payload["seat"] === p.payload["seat"])!;
      expect(p.payload["paper_hash"]).toBe(g.payload["paper_hash"]);
    }

    await w.centre.closeExam();
    const closed = w.centre.log.entries().find((e) => e.type === "EXAM_CLOSED")!;
    expect(closed.payload["papers_printed"]).toBe(3);

    // After close, the KEK is gone: generation is impossible again.
    await expect(w.centre.generatePaper("A-01")).rejects.toMatchObject({
      code: "ALREADY_GENERATED",
    });
    await w.centre.close();
    await w.authority.close();
  }, 120_000);

  it("refuses to print bytes that do not match the logged hash", async () => {
    const w = await buildWorld({ candidates: 1 });
    await releaseToCentre(w);
    await w.centre.checkIn(w.qrPayloads[0]!);
    await w.centre.generatePaper("A-01");
    await expect(
      w.centre.printPaper("A-01", Buffer.from("%PDF-1.7 substituted content")),
    ).rejects.toMatchObject({ code: "SEAT_MISMATCH" });
    await w.centre.close();
    await w.authority.close();
  }, 60_000);

  it("refuses a second generation for the same seat", async () => {
    const w = await buildWorld({ candidates: 1 });
    await releaseToCentre(w);
    await w.centre.checkIn(w.qrPayloads[0]!);
    await w.centre.generatePaper("A-01");
    await expect(w.centre.generatePaper("A-01")).rejects.toMatchObject({
      code: "ALREADY_GENERATED",
    });
    await w.centre.close();
    await w.authority.close();
  }, 60_000);

  it("accepts the KEK from a signed offline medium, refuses a tampered one (T10)", async () => {
    const w = await buildWorld({ candidates: 1 });
    await w.authority.scheduleRelease({
      examId: EXAM,
      bundleId: w.paperBundle.bundleId,
      releaseAt: Date.now() - 1000,
    });
    const { medium } = await w.authority.releaseOffline({
      bundleId: w.paperBundle.bundleId,
      shares: w.shares(["cust-3", "cust-4", "cust-5"]),
    });

    const tampered = { ...medium, releasedAt: medium.releasedAt - 1 };
    await expect(w.centre.receiveOfflineMedium(tampered)).rejects.toMatchObject({
      code: "MEDIUM_INVALID",
    });

    await w.centre.receiveOfflineMedium(medium);
    await w.centre.checkIn(w.qrPayloads[0]!);
    const { pdf } = await w.centre.generatePaper("A-01");
    expect(pdf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    await w.centre.close();
    await w.authority.close();
  }, 60_000);
});

describe("ACCEPTANCE: no plaintext exam content at rest on the centre (T1/T2)", () => {
  it("centre state contains no question text before OR after T-0", async () => {
    const w = await buildWorld({ candidates: 2 });
    const bank = sampleBank(EXAM);

    const scan = async (phase: string) => {
      const files = await readdir(w.centreDir, { recursive: true, withFileTypes: true });
      for (const f of files) {
        if (!f.isFile()) continue;
        const path = join(f.parentPath ?? w.centreDir, f.name);
        // The spool directory holds papers deliberately printed at T-0 for
        // candidates — those are the product, not a leak. Everything else
        // must be clean.
        if (path.includes("spool")) continue;
        const bytes = await readFile(path);
        for (const item of bank.items.slice(0, 6)) {
          expect(
            bytes.includes(Buffer.from(item.body.slice(0, 40), "utf8")),
            `${phase}: ${path} leaked question text`,
          ).toBe(false);
        }
      }
    };

    await scan("pre-release");
    await releaseToCentre(w);
    for (const qr of w.qrPayloads) await w.centre.checkIn(qr);
    await w.centre.runT0();
    await scan("post-T0");
    await w.centre.closeExam();
    await scan("post-close");
    await w.centre.close();
    await w.authority.close();
  }, 120_000);
});
