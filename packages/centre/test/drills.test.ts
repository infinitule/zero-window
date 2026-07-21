import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readdir, rm, cp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ipp from "ipp";
import { afterEach, describe, expect, it } from "vitest";
import { Authority, encodeAdmitToken } from "@zw/authority";
import { generateBoxKeyPair, sealOpen } from "@zw/crypto";
import { VaultKeyProvider } from "@zw/kms-vault";
import { verifyEvidence } from "@zw/log";
import { CentreNode } from "../src/centre.js";
import { sampleBank, sampleBlueprint } from "./fixtures.js";

/**
 * M7 failure drills, as executable tests.
 *
 * Exam day cannot be re-run, so each fallback in runbooks/exam-day.md and
 * runbooks/restore.md is rehearsed here against real components. If a drill
 * fails, the corresponding runbook section is wrong.
 *
 *   Drill 1  printer failure → failover to secondary mid-exam
 *   Drill 2  centre node destroyed → cold-spare restore from signed state
 *   Drill 3  network down at T-0 → offline release on signed media
 */

const EXAM = "EXAM-2026-DRILL";
const CENTRE = "CENTRE-D";

const dirs: string[] = [];
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))),
  );
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function tempDir(prefix: string): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

/** An IPP printer that completes jobs until `failAfter`, then refuses. */
async function printer(opts: { failAfter?: number } = {}): Promise<{
  url: string;
  jobs: number;
  kill(): void;
}> {
  let jobs = 0;
  let killed = false;
  const state = { jobs: 0 };

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      if (killed) {
        res.destroy();
        return;
      }
      const parsed = ipp.parse(Buffer.concat(chunks));
      const op = String(parsed.operation);
      const id = parsed.id ?? 1;
      let response: ipp.IppRequest;

      if (op === "Print-Job") {
        state.jobs++;
        jobs = state.jobs;
        const failing = opts.failAfter !== undefined && state.jobs > opts.failAfter;
        response = failing
          ? { version: "2.0", statusCode: "server-error-device-error", id }
          : {
              version: "2.0",
              statusCode: "successful-ok",
              id,
              "job-attributes-tag": { "job-id": 500 + state.jobs, "job-state": "pending" },
            };
      } else if (op === "Get-Job-Attributes") {
        response = {
          version: "2.0",
          statusCode: "successful-ok",
          id,
          "job-attributes-tag": { "job-id": 500, "job-state": "completed" },
        };
      } else {
        response = { version: "2.0", statusCode: "server-error-operation-not-supported", id };
      }
      res.setHeader("content-type", "application/ipp");
      res.end(ipp.serialize(response));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/printers/p`,
    get jobs() {
      return state.jobs;
    },
    kill() {
      killed = true;
    },
  };
}

interface Rig {
  authority: Authority;
  centre: CentreNode;
  centreDir: string;
  bundleId: string;
  qrs: string[];
  custodians: Array<{ custodianId: string; keys: ReturnType<typeof generateBoxKeyPair> }>;
  shares(ids: string[]): Array<{ custodianId: string; shareBlob: Buffer }>;
}

async function rig(opts: {
  candidates?: number;
  printers?: Array<{ printerId: string; url: string }>;
  spoolDir?: string;
  centreDir?: string;
}): Promise<Rig> {
  const aDir = await tempDir("zw-drill-a-");
  const cDir = opts.centreDir ?? (await tempDir("zw-drill-c-"));

  const authority = await Authority.open({
    statePath: join(aDir, "a.db"),
    logPath: join(aDir, "log.db"),
    provider: await VaultKeyProvider.open({
      keystorePath: join(aDir, "ks.json"),
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
    ...(opts.printers ? { printers: opts.printers } : {}),
    ...(opts.spoolDir ? { spoolDir: opts.spoolDir } : {}),
  });
  await authority.enrolCentre({
    centreId: CENTRE,
    boxPublicKey: centre.boxPublicKey,
    certFingerprint: "fp",
    hardwareId: "hw-drill",
  });

  const provisioned = await authority.provision({
    bank: sampleBank(EXAM),
    blueprint: sampleBlueprint(EXAM),
    threshold: 3,
  });
  await authority.distribute(provisioned.paper.bundleId, CENTRE);
  const stored = authority.store.bundle(provisioned.paper.bundleId)!;
  await centre.receiveBundle(stored.ciphertext, {
    bundleId: stored.bundleId,
    examId: stored.examId,
    kind: "paper",
    bundleHash: stored.bundleHash,
    kekFingerprint: stored.kekFingerprint,
    threshold: stored.threshold,
  });

  const n = opts.candidates ?? 4;
  const tokens = await authority.issueAdmitTokens({
    examId: EXAM,
    centreId: CENTRE,
    salt: Authority.newRegistrationSalt(),
    expiresAt: Date.now() + 86_400_000,
    candidates: Array.from({ length: n }, (_, i) => ({
      registrationId: `REG-${i}`,
      seat: `D-${String(i + 1).padStart(2, "0")}`,
    })),
  });

  return {
    authority,
    centre,
    centreDir: cDir,
    bundleId: provisioned.paper.bundleId,
    qrs: tokens.map(encodeAdmitToken),
    custodians,
    shares(ids) {
      return ids.map((custodianId) => {
        const rec = authority.store
          .shares(provisioned.paper.bundleId)
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

describe("DRILL 1 — printer fails mid-exam (runbooks/exam-day.md §printer-failure)", () => {
  it("fails over to the secondary printer and the exam completes", async () => {
    const primary = await printer({ failAfter: 2 });
    const secondary = await printer();
    const r = await rig({
      candidates: 4,
      printers: [
        { printerId: "hall-primary", url: primary.url },
        { printerId: "hall-backup", url: secondary.url },
      ],
    });

    await r.authority.scheduleRelease({
      examId: EXAM,
      bundleId: r.bundleId,
      releaseAt: Date.now() - 1000,
    });
    const out = await r.authority.release({
      bundleId: r.bundleId,
      shares: r.shares(["cust-1", "cust-2", "cust-3"]),
    });
    await r.centre.receiveWrappedKek(
      r.bundleId,
      out.wrapped.find((w) => w.centreId === CENTRE)!.sealed,
    );
    for (const qr of r.qrs) await r.centre.checkIn(qr);

    const { printed, failures } = await r.centre.runT0();

    // Every candidate got a paper despite the primary dying part-way.
    expect(failures).toEqual([]);
    expect(printed).toBe(4);
    expect(primary.jobs).toBeGreaterThanOrEqual(2);
    expect(secondary.jobs).toBeGreaterThanOrEqual(1);

    // The failover is in the evidence, per printer, with a reason.
    const failovers = r.centre.log.entries().filter((e) => e.type === "PRINTER_FAILOVER");
    expect(failovers.length).toBeGreaterThan(0);
    expect(failovers[0]!.payload["printer_id"]).toBe("hall-primary");
    expect(String(failovers[0]!.payload["reason"])).toContain("device-error");

    // And which printer each paper actually came off.
    const printedOn = new Set(
      r.centre.log
        .entries()
        .filter((e) => e.type === "PAPER_PRINTED")
        .map((e) => String(e.payload["printer_id"])),
    );
    expect(printedOn).toContain("hall-backup");

    await r.centre.close();
    await r.authority.close();
  }, 180_000);

  it("falls back to the spool directory when every printer is gone", async () => {
    const only = await printer();
    const spoolDir = await tempDir("zw-drill-spool-");
    const r = await rig({
      candidates: 2,
      printers: [{ printerId: "hall-only", url: only.url }],
      spoolDir,
    });
    await r.authority.scheduleRelease({
      examId: EXAM,
      bundleId: r.bundleId,
      releaseAt: Date.now() - 1000,
    });
    const out = await r.authority.release({
      bundleId: r.bundleId,
      shares: r.shares(["cust-1", "cust-2", "cust-3"]),
    });
    await r.centre.receiveWrappedKek(
      r.bundleId,
      out.wrapped.find((w) => w.centreId === CENTRE)!.sealed,
    );
    for (const qr of r.qrs) await r.centre.checkIn(qr);

    only.kill(); // the whole print room goes down

    const { printed, failures } = await r.centre.runT0();
    expect(failures).toEqual([]);
    expect(printed).toBe(2);
    // PDFs are on disk for the print room to handle manually.
    expect(await readdir(spoolDir)).toHaveLength(2);
    const transports = new Set(
      r.centre.log
        .entries()
        .filter((e) => e.type === "PAPER_PRINTED")
        .map((e) => String(e.payload["transport"])),
    );
    expect(transports).toContain("spool");

    await r.centre.close();
    await r.authority.close();
  }, 180_000);
});

describe("DRILL 2 — centre node destroyed mid-exam (runbooks/restore.md)", () => {
  it("a cold spare restored from signed state resumes and the log stays verifiable", async () => {
    const spoolDir = await tempDir("zw-drill-spool2-");
    const centreDir = await tempDir("zw-drill-c2-");
    const r = await rig({ candidates: 4, spoolDir, centreDir });

    await r.authority.scheduleRelease({
      examId: EXAM,
      bundleId: r.bundleId,
      releaseAt: Date.now() - 1000,
    });
    const out = await r.authority.release({
      bundleId: r.bundleId,
      shares: r.shares(["cust-1", "cust-2", "cust-3"]),
    });
    const wrapped = out.wrapped.find((w) => w.centreId === CENTRE)!.sealed;
    await r.centre.receiveWrappedKek(r.bundleId, wrapped);

    // Two candidates are served, then the node dies.
    for (const qr of r.qrs) await r.centre.checkIn(qr);
    await r.centre.printPaper("D-01", (await r.centre.generatePaper("D-01")).pdf);
    await r.centre.printPaper("D-02", (await r.centre.generatePaper("D-02")).pdf);
    const entriesBefore = r.centre.log.size();
    await r.centre.close(); // simulates the node being destroyed

    // Restore: state directory is copied to the cold spare from backup.
    const spareDir = await tempDir("zw-drill-spare-");
    await cp(centreDir, spareDir, { recursive: true });

    const spare = await CentreNode.open({
      centreId: CENTRE,
      examId: EXAM,
      statePath: join(spareDir, "centre.db"),
      logPath: join(spareDir, "log.db"),
      provider: await VaultKeyProvider.open({
        keystorePath: join(spareDir, "keystore.json"),
        passphrase: Buffer.from("c", "utf8"),
      }),
      authorityPublicKey: r.authority.publicKey,
      spoolDir,
    });

    // Restored state remembers custody and who was already served.
    expect(spare.store.checkins()).toHaveLength(4);
    expect(spare.store.paper("D-01")?.printedAt).not.toBeNull();
    expect(spare.log.size()).toBe(entriesBefore);

    // The KEK is NOT restored — it was memory-only (I-CTR-1), which is the
    // point: a stolen backup cannot decrypt the bundle.
    await expect(spare.generatePaper("D-03")).rejects.toMatchObject({ code: "KEK_NOT_HELD" });

    // The runbook's step: re-deliver the wrapped KEK to the spare.
    await spare.receiveWrappedKek(r.bundleId, wrapped);

    // Already-served seats are not reprinted; the remaining two are.
    await expect(spare.generatePaper("D-01")).rejects.toMatchObject({
      code: "ALREADY_GENERATED",
    });
    await spare.printPaper("D-03", (await spare.generatePaper("D-03")).pdf);
    await spare.printPaper("D-04", (await spare.generatePaper("D-04")).pdf);
    await spare.closeExam();
    await spare.checkpoint();

    // The restored log is still a valid chain across the discontinuity.
    const report = await verifyEvidence(spare.log.evidence(EXAM), {});
    expect(report.findings.filter((f) => f.severity === "fatal")).toEqual([]);
    expect(report.ok).toBe(true);

    const printedSeats = spare.log
      .entries()
      .filter((e) => e.type === "PAPER_PRINTED")
      .map((e) => String(e.payload["seat"]));
    expect(printedSeats.sort()).toEqual(["D-01", "D-02", "D-03", "D-04"]);

    await spare.close();
    await r.authority.close();
  }, 180_000);
});

describe("DRILL 3 — network down at T-0 (runbooks/exam-day.md §offline-release)", () => {
  it("custodians present in person release onto signed media and the exam runs", async () => {
    const spoolDir = await tempDir("zw-drill-spool3-");
    const r = await rig({ candidates: 3, spoolDir });

    await r.authority.scheduleRelease({
      examId: EXAM,
      bundleId: r.bundleId,
      releaseAt: Date.now() - 1000,
    });

    // No network: the authority produces a signed medium instead.
    const { medium } = await r.authority.releaseOffline({
      bundleId: r.bundleId,
      shares: r.shares(["cust-2", "cust-3", "cust-5"]),
    });

    // A courier could swap the medium; the centre must refuse that.
    const swapped = {
      ...medium,
      entries: [{ centreId: CENTRE, sealedHex: "00".repeat(80) }],
    };
    await expect(r.centre.receiveOfflineMedium(swapped)).rejects.toMatchObject({
      code: "MEDIUM_INVALID",
    });

    await r.centre.receiveOfflineMedium(medium);
    for (const qr of r.qrs) await r.centre.checkIn(qr);
    const { printed, failures } = await r.centre.runT0();
    expect(failures).toEqual([]);
    expect(printed).toBe(3);
    await r.centre.closeExam();

    await r.centre.close();
    await r.authority.close();
  }, 180_000);
});
