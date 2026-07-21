import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VaultKeyProvider } from "@zw/kms-vault";
import { TransparencyLog } from "../src/index.js";
import type { EvidenceBundle } from "../src/types.js";

const dirs: string[] = [];

export async function tempDir(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "zw-log-"));
  dirs.push(d);
  return d;
}

export async function cleanupTempDirs(): Promise<void> {
  await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
  dirs.length = 0;
}

export interface TestLog {
  log: TransparencyLog;
  provider: VaultKeyProvider;
  dir: string;
  close(): Promise<void>;
}

export async function newTestLog(actor = "authority"): Promise<TestLog> {
  const dir = await tempDir();
  const provider = await VaultKeyProvider.open({
    keystorePath: join(dir, "keystore.json"),
    passphrase: Buffer.from("test-passphrase"),
  });
  const log = await TransparencyLog.open({
    dbPath: join(dir, "log.db"),
    actor,
    provider,
    signingKeyId: `${actor}-log`,
  });
  return {
    log,
    provider,
    dir,
    async close() {
      log.close();
      await provider.close();
    },
  };
}

/** A small but realistic exam-day log covering flows F1–F5. */
export async function populateExamLog(log: TransparencyLog): Promise<void> {
  await log.append({
    type: "BUNDLE_CREATED",
    payload: { exam_id: "EXAM-2026-01", bundle_hash: "a".repeat(64), item_count: 240 },
  });
  await log.append({
    type: "SHARES_ISSUED",
    payload: { exam_id: "EXAM-2026-01", threshold: 3, custodian_count: 5 },
  });
  await log.append({
    type: "BUNDLE_DISTRIBUTED",
    payload: { exam_id: "EXAM-2026-01", centre_id: "CENTRE-A", bundle_hash: "a".repeat(64) },
  });
  await log.append({
    type: "KEK_RELEASED",
    payload: { exam_id: "EXAM-2026-01", kek_fingerprint: "b".repeat(64), recipients: 3 },
  });
  await log.append({
    type: "PAPER_GENERATED",
    payload: { exam_id: "EXAM-2026-01", centre_id: "CENTRE-A", seat: "A-014", paper_hash: "c".repeat(64) },
  });
}

export function bundleOf(log: TransparencyLog, examId = "EXAM-2026-01"): EvidenceBundle {
  return {
    version: 1,
    exam_id: examId,
    entries: log.entries(),
    checkpoints: log.checkpoints(),
    signers: { authority: log.publicKey.toString("hex") },
  };
}
