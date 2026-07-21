import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateBoxKeyPair, sealOpen, type BoxKeyPair } from "@zw/crypto";
import { VaultKeyProvider } from "@zw/kms-vault";
import { Authority } from "../src/authority.js";
import type { Blueprint, ItemBank } from "../src/bank.js";

const dirs: string[] = [];

export async function tempDir(prefix = "zw-authority-"): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

export async function cleanupDirs(): Promise<void> {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
}

export interface Custodian {
  custodianId: string;
  keys: BoxKeyPair;
}

export interface Harness {
  authority: Authority;
  custodians: Custodian[];
  centres: Array<{ centreId: string; keys: BoxKeyPair }>;
  dir: string;
  /** Open the sealed share issued to a custodian for a bundle. */
  openShare(bundleId: string, custodianId: string): Buffer;
  close(): Promise<void>;
}

export async function newAuthority(
  opts: { custodians?: number; centres?: number; now?: () => number } = {},
): Promise<Harness> {
  const dir = await tempDir();
  const provider = await VaultKeyProvider.open({
    keystorePath: join(dir, "keystore.json"),
    passphrase: Buffer.from("test-passphrase-not-for-production", "utf8"),
  });
  const authority = await Authority.open({
    statePath: join(dir, "authority.db"),
    logPath: join(dir, "log.db"),
    provider,
    ...(opts.now ? { now: opts.now } : {}),
  });

  const custodians: Custodian[] = [];
  for (let i = 1; i <= (opts.custodians ?? 5); i++) {
    const keys = generateBoxKeyPair();
    const custodianId = `cust-${i}`;
    authority.enrolCustodian({
      custodianId,
      name: `Custodian ${i}`,
      boxPublicKey: keys.publicKey,
      certFingerprint: `fp-cust-${i}`,
    });
    custodians.push({ custodianId, keys });
  }

  const centres: Array<{ centreId: string; keys: BoxKeyPair }> = [];
  for (let i = 0; i < (opts.centres ?? 2); i++) {
    const keys = generateBoxKeyPair();
    const centreId = `CENTRE-${String.fromCharCode(65 + i)}`;
    await authority.enrolCentre({
      centreId,
      boxPublicKey: keys.publicKey,
      certFingerprint: `fp-${centreId}`,
      hardwareId: `tpm-${i}`,
    });
    centres.push({ centreId, keys });
  }

  return {
    authority,
    custodians,
    centres,
    dir,
    openShare(bundleId: string, custodianId: string): Buffer {
      const rec = authority.store
        .shares(bundleId)
        .find((s) => s.custodianId === custodianId);
      if (!rec) throw new Error(`no share for ${custodianId} on ${bundleId}`);
      const c = custodians.find((x) => x.custodianId === custodianId)!;
      return sealOpen(rec.sealed, c.keys.publicKey, c.keys.secretKey);
    },
    async close() {
      await authority.close();
    },
  };
}

/** A small but blueprint-satisfiable bank. */
export function sampleBank(examId = "EXAM-2026-PHYS"): ItemBank {
  const items = [];
  for (const subject of ["mechanics", "optics"]) {
    for (const difficulty of ["easy", "medium", "hard"] as const) {
      for (let i = 0; i < 8; i++) {
        items.push({
          id: `${subject}-${difficulty}-${i}`,
          subject,
          difficulty,
          body: `A ${difficulty} ${subject} question number ${i}. What is the answer?`,
          options: [`option A${i}`, `option B${i}`, `option C${i}`, `option D${i}`],
          correctIndex: i % 4,
        });
      }
    }
  }
  return { examId, items };
}

export function sampleBlueprint(examId = "EXAM-2026-PHYS"): Blueprint {
  return {
    examId,
    title: "Physics Paper I",
    durationMinutes: 180,
    slots: [
      { subject: "mechanics", difficulty: "easy", count: 2 },
      { subject: "mechanics", difficulty: "medium", count: 2 },
      { subject: "optics", difficulty: "easy", count: 2 },
      { subject: "optics", difficulty: "hard", count: 1 },
    ],
  };
}
