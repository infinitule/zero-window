import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { VaultKeyProvider } from "@zw/kms-vault";
import {
  EvidenceFormatError,
  TransparencyLog,
  ZERO_HASH,
  bodyOf,
  computeCheckpointDigest,
  computeEntryHash,
  evidenceDigest,
  parseEvidence,
  readEvidenceFile,
  serializeEvidence,
  verifyCheckpointSelf,
  verifyEntrySelf,
  writeEvidenceFile,
} from "../src/index.js";
import { bundleOf, cleanupTempDirs, newTestLog, populateExamLog, tempDir } from "./helpers.js";

afterAll(cleanupTempDirs);

describe("TransparencyLog storage", () => {
  it("chains entries from a zero prevHash and reports size and head", async () => {
    const t = await newTestLog();
    expect(t.log.size()).toBe(0);
    expect(t.log.head()).toBeNull();

    const first = await t.log.append({ type: "CENTRE_ENROLLED", payload: { centre_id: "A" } });
    expect(first.seq).toBe(0);
    expect(first.prevHash).toBe(ZERO_HASH);

    const second = await t.log.append({ type: "CENTRE_ENROLLED", payload: { centre_id: "B" } });
    expect(second.seq).toBe(1);
    expect(second.prevHash).toBe(first.hash);

    expect(t.log.size()).toBe(2);
    expect(t.log.head()!.seq).toBe(1);
    await t.close();
  });

  it("persists across reopen and continues the chain", async () => {
    const dir = await tempDir();
    const provider = await VaultKeyProvider.open({
      keystorePath: join(dir, "ks.json"),
      passphrase: Buffer.from("pw"),
    });
    const open = () =>
      TransparencyLog.open({
        dbPath: join(dir, "log.db"),
        actor: "authority",
        provider,
        signingKeyId: "authority-log",
      });

    const log1 = await open();
    const a = await log1.append({ type: "BUNDLE_CREATED", payload: { exam_id: "E1" } });
    log1.close();

    const log2 = await open();
    const b = await log2.append({ type: "BUNDLE_DISTRIBUTED", payload: { exam_id: "E1" } });
    expect(b.seq).toBe(1);
    expect(b.prevHash).toBe(a.hash);
    // Same signing key across restarts.
    expect(b.signerPublicKey).toBe(a.signerPublicKey);
    log2.close();
    await provider.close();
  });

  it("accepts an explicit timestamp for offline/replay paths", async () => {
    const t = await newTestLog();
    const ts = Date.UTC(2026, 0, 15, 9, 0, 0);
    const e = await t.log.append({ type: "KEK_RELEASED", payload: { exam_id: "E" }, ts });
    expect(e.ts).toBe(ts);
    expect(verifyEntrySelf(e).ok).toBe(true);
    await t.close();
  });

  it("slices entries by range", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    expect(t.log.entries()).toHaveLength(5);
    expect(t.log.entries(2)).toHaveLength(3);
    expect(t.log.entries(1, 3).map((e) => e.seq)).toEqual([1, 2]);
    expect(t.log.entryHashes()).toHaveLength(5);
    await t.close();
  });

  it("refuses to checkpoint an empty log", async () => {
    const t = await newTestLog();
    await expect(t.log.createCheckpoint()).rejects.toThrow(/log is empty/);
    await t.close();
  });

  it("creates, stores and retrieves checkpoints; repeats are idempotent", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    expect(cp.size).toBe(5);
    expect(verifyCheckpointSelf(cp).ok).toBe(true);

    expect(t.log.checkpoint(5)!.root).toBe(cp.root);
    expect(t.log.checkpoint(99)).toBeNull();
    expect(t.log.latestCheckpoint()!.size).toBe(5);

    // Checkpointing the same size again must not fork the record.
    const again = await t.log.createCheckpoint();
    expect(again.root).toBe(cp.root);
    expect(t.log.checkpoints()).toHaveLength(1);

    await t.log.append({ type: "EXAM_CLOSED", payload: { centre_id: "A" } });
    const cp2 = await t.log.createCheckpoint();
    expect(cp2.size).toBe(6);
    expect(t.log.checkpoints().map((c) => c.size)).toEqual([5, 6]);
    expect(t.log.latestCheckpoint()!.size).toBe(6);
    await t.close();
  });

  it("latestCheckpoint returns null when none exist", async () => {
    const t = await newTestLog();
    expect(t.log.latestCheckpoint()).toBeNull();
    await t.close();
  });

  it("attachAnchors accumulates and never replaces existing anchors", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    const mk = (tsa: string) => ({
      backend: "rfc3161" as const,
      tsa,
      url: `https://${tsa}/tsr`,
      token: "",
      genTime: Date.now(),
      imprint: cp.root,
      hashAlgorithm: "sha256",
    });

    const one = t.log.attachAnchors(cp.size, [mk("tsa-a")]);
    expect(one.anchors).toHaveLength(1);
    const two = t.log.attachAnchors(cp.size, [mk("tsa-b")]);
    expect(two.anchors.map((a) => a.tsa)).toEqual(["tsa-a", "tsa-b"]);
    expect(t.log.checkpoint(cp.size)!.anchors).toHaveLength(2);

    expect(() => t.log.attachAnchors(999, [mk("x")])).toThrow(/no checkpoint of size 999/);
    await t.close();
  });

  it("entry hash and checkpoint digest are stable pure functions", async () => {
    const t = await newTestLog();
    const e = await t.log.append({ type: "PAPER_PRINTED", payload: { seat: "A-01" } });
    const h1 = computeEntryHash(bodyOf(e));
    const h2 = computeEntryHash(bodyOf(e));
    expect(h1.equals(h2)).toBe(true);
    expect(h1.toString("hex")).toBe(e.hash);

    const cp = await t.log.createCheckpoint();
    const d = computeCheckpointDigest({
      size: cp.size,
      root: cp.root,
      headHash: cp.headHash,
      ts: cp.ts,
    });
    expect(d).toHaveLength(32);
    await t.close();
  });

  it("verifyEntrySelf reports hash and signature failures distinctly", async () => {
    const t = await newTestLog();
    const e = await t.log.append({ type: "EXAM_CLOSED", payload: { centre_id: "A" } });

    const badHash = { ...e, hash: "0".repeat(64) };
    expect(verifyEntrySelf(badHash).reason).toMatch(/hash mismatch/);

    const badSig = { ...e, signature: "1".repeat(128) };
    expect(verifyEntrySelf(badSig).reason).toMatch(/signature does not verify/);
    await t.close();
  });

  it("verifyCheckpointSelf rejects a tampered checkpoint body", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    expect(verifyCheckpointSelf({ ...cp, ts: cp.ts + 1 }).reason).toMatch(
      /signature does not verify/,
    );
    await t.close();
  });

  it("evidenceDigest binds a set of lines", () => {
    const a = evidenceDigest(["one", "two"]);
    expect(a.equals(evidenceDigest(["one", "two"]))).toBe(true);
    expect(a.equals(evidenceDigest(["two", "one"]))).toBe(false);
  });
});

describe("evidence files", () => {
  it("writes and reads an evidence file from disk", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    await t.log.createCheckpoint();
    const dir = await tempDir();
    const path = join(dir, "evidence.ndjson");

    await writeEvidenceFile(path, bundleOf(t.log));
    const back = await readEvidenceFile(path);
    expect(back.entries).toHaveLength(5);
    expect(back.checkpoints).toHaveLength(1);
    expect(back.exam_id).toBe("EXAM-2026-01");
    await t.close();
  });

  it("rejects malformed evidence with the offending line number", async () => {
    expect(() => parseEvidence("")).toThrow(/file is empty/);
    expect(() => parseEvidence("not json\n")).toThrow(EvidenceFormatError);
    expect(() => parseEvidence("not json\n")).toThrow(/line 1: not valid JSON/);

    const header = JSON.stringify({
      record: "header",
      kind: "zero-window-evidence",
      version: 1,
      exam_id: "E",
      signers: {},
      entry_count: 0,
      checkpoint_count: 0,
    });
    expect(() => parseEvidence(`${header}\n${JSON.stringify({ record: "bogus" })}\n`)).toThrow(
      /unknown record type "bogus"/,
    );
    expect(() => parseEvidence(JSON.stringify({ record: "entry" }) + "\n")).toThrow(
      /missing header/,
    );
    expect(() => parseEvidence(`${header}\n${header}\n`)).toThrow(
      /header must be the first line/,
    );

    const badKind = JSON.stringify({ record: "header", kind: "other", version: 1 });
    expect(() => parseEvidence(`${badKind}\n`)).toThrow(/unexpected kind/);
    const badVersion = JSON.stringify({
      record: "header",
      kind: "zero-window-evidence",
      version: 9,
    });
    expect(() => parseEvidence(`${badVersion}\n`)).toThrow(/unsupported version 9/);
  });

  it("detects a checkpoint removed from an evidence file", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    await t.log.createCheckpoint();
    const text = serializeEvidence(bundleOf(t.log));
    // Drop the checkpoint line (last).
    const lines = text.trimEnd().split("\n");
    const without = lines.slice(0, -1).join("\n") + "\n";
    expect(() => parseEvidence(without)).toThrow(/declares 1 checkpoints but the file contains 0/);
    await t.close();
  });

  it("evidence serialization is deterministic regardless of input order", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    await t.log.createCheckpoint();
    const bundle = bundleOf(t.log);
    const shuffled = {
      ...bundle,
      entries: [...bundle.entries].reverse(),
    };
    expect(serializeEvidence(shuffled)).toBe(serializeEvidence(bundle));
    await t.close();
  });
});
