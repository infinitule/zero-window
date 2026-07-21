import { afterAll, describe, expect, it } from "vitest";
import {
  merkleRoot,
  parseEvidence,
  serializeEvidence,
  verifyChain,
  verifyCheckpoints,
  verifyEvidence,
  type Checkpoint,
  type EvidenceBundle,
  type LogEntry,
} from "../src/index.js";
import { bundleOf, cleanupTempDirs, newTestLog, populateExamLog } from "./helpers.js";

afterAll(cleanupTempDirs);

/**
 * The M2 tamper suite. Each case is a way an operator (T6) or an attacker
 * could try to rewrite the custody record. Every one must FAIL CLOSED with a
 * finding that names what happened and where — a verifier that says only
 * "invalid" is not usable in a dispute.
 */

async function baseline(): Promise<{ bundle: EvidenceBundle; close: () => Promise<void> }> {
  const t = await newTestLog();
  await populateExamLog(t.log);
  await t.log.createCheckpoint();
  return { bundle: bundleOf(t.log), close: t.close };
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function fatals(findings: { severity: string; code: string }[]): string[] {
  return findings.filter((f) => f.severity === "fatal").map((f) => f.code);
}

describe("tamper suite", () => {
  it("an untampered log verifies clean", async () => {
    const { bundle, close } = await baseline();
    const report = await verifyEvidence(bundle);
    expect(report.ok).toBe(true);
    expect(report.findings).toEqual([]);
    expect(report.entriesChecked).toBe(5);
    expect(report.checkpointsChecked).toBe(1);
    await close();
  });

  it("bit-flip in a payload is detected at the exact entry", async () => {
    const { bundle, close } = await baseline();
    const tampered = clone(bundle);
    // Change a paper hash — the kind of edit that would hide which seat a
    // leaked paper came from (T4).
    tampered.entries[4]!.payload["paper_hash"] = "d".repeat(64);

    const report = await verifyEvidence(tampered);
    expect(report.ok).toBe(false);
    const codes = fatals(report.findings);
    expect(codes).toContain("ENTRY_INVALID");
    const finding = report.findings.find((f) => f.code === "ENTRY_INVALID")!;
    expect(finding.at).toBe(4);
    expect(finding.message).toMatch(/hash mismatch/);
    await close();
  });

  it("editing a payload AND its stored hash still fails: the signature does not follow", async () => {
    // The Merkle root commits to entry hashes, so an attacker who edits a
    // payload must also rewrite the stored hash to keep the checkpoint root
    // intact. They cannot: the Ed25519 signature covers the same bytes as the
    // hash, and they do not hold the signing key. This is the property that
    // makes CHECKPOINT_ROOT_MISMATCH the *second* line of defence rather than
    // the first.
    const { bundle, close } = await baseline();
    const tampered = clone(bundle);
    const target = tampered.entries[4]!;
    target.payload["paper_hash"] = "d".repeat(64);

    // Recompute the hash the way the honest writer would, so the entry is
    // internally hash-consistent and the checkpoint root can be re-forged.
    const { computeEntryHash } = await import("../src/store.js");
    target.hash = computeEntryHash({
      seq: target.seq,
      ts: target.ts,
      type: target.type,
      actor: target.actor,
      payload: target.payload,
      prevHash: target.prevHash,
    }).toString("hex");
    const cp = tampered.checkpoints[0]!;
    cp.root = merkleRoot(tampered.entries.map((e) => Buffer.from(e.hash, "hex"))).toString("hex");
    cp.headHash = target.hash;

    const report = await verifyEvidence(tampered);
    expect(report.ok).toBe(false);
    const codes = fatals(report.findings);
    // Hash now matches, but the signature over those bytes does not.
    expect(codes).toContain("ENTRY_INVALID");
    expect(
      report.findings.find((f) => f.code === "ENTRY_INVALID")!.message,
    ).toMatch(/signature does not verify/);
    // And the re-forged checkpoint no longer carries a valid signature.
    expect(codes).toContain("CHECKPOINT_INVALID");
    await close();
  });

  it("bit-flip in a stored hash breaks the chain at the following entry", async () => {
    const { bundle, close } = await baseline();
    const tampered = clone(bundle);
    const original = tampered.entries[2]!.hash;
    tampered.entries[2]!.hash = original.slice(0, 63) + (original.endsWith("0") ? "1" : "0");

    const report = await verifyEvidence(tampered);
    expect(report.ok).toBe(false);
    const codes = fatals(report.findings);
    expect(codes).toContain("ENTRY_INVALID");
    expect(codes).toContain("CHAIN_BROKEN");
    const broken = report.findings.find((f) => f.code === "CHAIN_BROKEN")!;
    expect(broken.at).toBe(3);
    expect(broken.message).toMatch(/history has been modified/);
    await close();
  });

  it("dropping an entry is detected as a sequence gap and broken chain", async () => {
    const { bundle, close } = await baseline();
    const tampered = clone(bundle);
    // Remove the KEK_RELEASED record — an operator hiding when keys went out.
    tampered.entries.splice(3, 1);

    const findings = verifyChain(tampered.entries);
    const codes = fatals(findings);
    expect(codes).toContain("SEQ_DISCONTINUITY");
    expect(codes).toContain("CHAIN_BROKEN");
    // And the checkpoint still commits to five entries.
    const cpFindings = verifyCheckpoints(tampered.entries, tampered.checkpoints);
    expect(fatals(cpFindings)).toContain("CHECKPOINT_OVERRUN");
    await close();
  });

  it("dropping the first entry is detected even though the rest chains", async () => {
    const { bundle, close } = await baseline();
    const tampered = clone(bundle);
    tampered.entries.shift();

    const findings = verifyChain(tampered.entries);
    const codes = fatals(findings);
    expect(codes).toContain("CHAIN_ROOT_INVALID");
    expect(
      findings.find((f) => f.code === "CHAIN_ROOT_INVALID")!.message,
    ).toMatch(/entries before it have been removed/);
    await close();
  });

  it("reordering entries is detected", async () => {
    const { bundle, close } = await baseline();
    const tampered = clone(bundle);
    const a = tampered.entries[1]!;
    const b = tampered.entries[2]!;
    tampered.entries[1] = b;
    tampered.entries[2] = a;

    const codes = fatals(verifyChain(tampered.entries));
    expect(codes).toContain("SEQ_DISCONTINUITY");
    expect(codes).toContain("CHAIN_BROKEN");
    await close();
  });

  it("an appended entry with a forged signature is rejected", async () => {
    const { bundle, close } = await baseline();
    const tampered = clone(bundle);
    const last = tampered.entries[4]!;
    const forged: LogEntry = {
      seq: 5,
      ts: last.ts + 1000,
      type: "EXAM_CLOSED",
      actor: "authority",
      payload: { exam_id: "EXAM-2026-01", centre_id: "CENTRE-A" },
      prevHash: last.hash,
      hash: "e".repeat(64),
      signature: "f".repeat(128),
      signerPublicKey: last.signerPublicKey,
    };
    tampered.entries.push(forged);

    const report = await verifyEvidence(tampered);
    expect(report.ok).toBe(false);
    const finding = report.findings.find((f) => f.code === "ENTRY_INVALID" && f.at === 5)!;
    expect(finding.message).toMatch(/hash mismatch/);
    await close();
  });

  it("an entry re-signed with a substituted key is rejected against pinned signers", async () => {
    // The operator mints a new keypair, rewrites an entry, and re-signs it so
    // the entry is internally consistent. Pinned signers must catch it (T6).
    const attacker = await newTestLog("authority");
    await attacker.log.append({
      type: "PAPER_GENERATED",
      payload: { exam_id: "EXAM-2026-01", centre_id: "CENTRE-A", seat: "A-014", paper_hash: "9".repeat(64) },
    });
    const rewritten = attacker.log.entries()[0]!;

    const honest = await newTestLog("authority");
    await populateExamLog(honest.log);
    const honestKey = honest.log.publicKey.toString("hex");

    const tampered: EvidenceBundle = {
      version: 1,
      exam_id: "EXAM-2026-01",
      entries: [rewritten],
      checkpoints: [],
      signers: { authority: honestKey },
    };

    const report = await verifyEvidence(tampered);
    expect(report.ok).toBe(false);
    const finding = report.findings.find((f) => f.code === "SIGNER_UNTRUSTED")!;
    expect(finding.message).toMatch(/signed with a substituted key/);

    // Without pinning, the internally-consistent forgery would verify — which
    // is exactly why trustedSigners is not optional in the audit path.
    const unpinned = await verifyEvidence({ ...tampered, signers: {} }, { trustedSigners: {} });
    expect(unpinned.findings.some((f) => f.code === "SIGNER_UNKNOWN")).toBe(true);

    await attacker.close();
    await honest.close();
  });

  it("a forged checkpoint over altered entries is rejected", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    await t.log.createCheckpoint();
    const bundle = bundleOf(t.log);

    const tampered = clone(bundle);
    // Recompute a root over a *different* entry set and publish it as if it
    // were the real checkpoint, keeping the original signature.
    const fakeHashes = tampered.entries.map((e) => Buffer.from(e.hash, "hex")).slice(0, 3);
    tampered.checkpoints[0]!.root = merkleRoot(fakeHashes).toString("hex");

    const report = await verifyEvidence(tampered);
    expect(report.ok).toBe(false);
    // Changing the root invalidates the checkpoint signature.
    expect(fatals(report.findings)).toContain("CHECKPOINT_INVALID");
    await t.close();
  });

  it("a checkpoint re-signed over a truncated log is caught by root recomputation", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    await t.log.createCheckpoint();
    const full = bundleOf(t.log);

    // Operator drops the last two entries and issues a genuine checkpoint
    // over the shortened log, then presents it alongside the real one.
    const shortened = clone(full);
    shortened.entries = shortened.entries.slice(0, 3);
    const realCp = shortened.checkpoints[0]!;
    const forkCp: Checkpoint = {
      ...realCp,
      size: 3,
      root: merkleRoot(shortened.entries.map((e) => Buffer.from(e.hash, "hex"))).toString("hex"),
      headHash: shortened.entries[2]!.hash,
    };
    shortened.checkpoints = [forkCp, realCp];

    const report = await verifyEvidence(shortened);
    expect(report.ok).toBe(false);
    const codes = fatals(report.findings);
    // The real checkpoint covers 5 entries that are no longer present.
    expect(codes).toContain("CHECKPOINT_OVERRUN");
    // And the forged one has an invalid signature (body changed).
    expect(codes).toContain("CHECKPOINT_INVALID");
    await t.close();
  });

  it("two checkpoints at the same size with different roots are reported as a fork", async () => {
    const { bundle, close } = await baseline();
    const tampered = clone(bundle);
    const cp = tampered.checkpoints[0]!;
    tampered.checkpoints.push({ ...cp, root: "7".repeat(64) });

    const findings = verifyCheckpoints(tampered.entries, tampered.checkpoints);
    const codes = fatals(findings);
    expect(codes).toContain("CHECKPOINT_FORK");
    expect(
      findings.find((f) => f.code === "CHECKPOINT_FORK")!.message,
    ).toMatch(/forked history/);
    await close();
  });

  it("a checkpoint claiming more entries than exist is rejected", async () => {
    const { bundle, close } = await baseline();
    const tampered = clone(bundle);
    tampered.entries = tampered.entries.slice(0, 2);

    const findings = verifyCheckpoints(tampered.entries, tampered.checkpoints);
    const finding = findings.find((f) => f.code === "CHECKPOINT_OVERRUN")!;
    expect(finding.message).toMatch(/have been removed/);
    await close();
  });

  it("timestamp regression is reported as a warning, not silently accepted", async () => {
    const { bundle, close } = await baseline();
    const tampered = clone(bundle);
    tampered.entries[2]!.ts = tampered.entries[1]!.ts - 5000;

    const findings = verifyChain(tampered.entries);
    expect(findings.some((f) => f.code === "TIMESTAMP_REGRESSION")).toBe(true);
    // Editing ts also breaks the entry hash — both must be reported.
    expect(fatals(findings)).toContain("ENTRY_INVALID");
    await close();
  });

  it("evidence file truncation is detected by the header counts", async () => {
    const { bundle, close } = await baseline();
    const text = serializeEvidence(bundle);
    const lines = text.trimEnd().split("\n");
    const truncated = lines.slice(0, lines.length - 2).join("\n") + "\n";

    expect(() => parseEvidence(truncated)).toThrow(/truncated or has had records removed/);
    await close();
  });

  it("evidence round-trips byte-for-byte through serialize/parse", async () => {
    const { bundle, close } = await baseline();
    const text = serializeEvidence(bundle);
    const back = parseEvidence(text);
    expect(serializeEvidence(back)).toBe(text);

    const report = await verifyEvidence(back);
    expect(report.ok).toBe(true);
    await close();
  });

  it("the storage layer itself refuses UPDATE and DELETE (I-LOG-2)", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);

    // Reach the database the way an operator with shell access would.
    const Database = (await import("better-sqlite3")).default;
    const db = new Database(`${t.dir}/log.db`);
    expect(() => db.prepare("UPDATE entries SET payload = '{}' WHERE seq = 0").run()).toThrow(
      /append-only: UPDATE forbidden/,
    );
    expect(() => db.prepare("DELETE FROM entries WHERE seq = 0").run()).toThrow(
      /append-only: DELETE forbidden/,
    );
    db.close();
    await t.close();
  });
});
