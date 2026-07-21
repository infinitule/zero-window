import { afterAll, describe, expect, it } from "vitest";
import {
  verifyAnchors,
  verifyCheckpoints,
  verifyEvidence,
  type Anchor,
  type AnchorBackend,
  type Checkpoint,
  type EvidenceBundle,
} from "../src/index.js";
import { bundleOf, cleanupTempDirs, newTestLog, populateExamLog } from "./helpers.js";

afterAll(cleanupTempDirs);

function anchorFor(cp: Checkpoint, tsa: string, genTime: number): Anchor {
  return {
    backend: "rfc3161",
    tsa,
    url: `https://${tsa}/tsr`,
    token: "",
    genTime,
    imprint: cp.root,
    hashAlgorithm: "sha256",
  };
}

class AcceptingBackend implements AnchorBackend {
  constructor(readonly name: string) {}
  async anchor(): Promise<Anchor> {
    throw new Error("not used");
  }
  async verify(): Promise<void> {
    /* accepts */
  }
}

describe("verifier branch coverage", () => {
  it("rejects an unsupported evidence bundle version", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const bundle = { ...bundleOf(t.log), version: 2 } as unknown as EvidenceBundle;
    const report = await verifyEvidence(bundle);
    expect(report.ok).toBe(false);
    expect(report.findings.some((f) => f.code === "EVIDENCE_VERSION")).toBe(true);
    await t.close();
  });

  it("verifies an empty log without findings", async () => {
    const report = await verifyEvidence({
      version: 1,
      exam_id: "E",
      entries: [],
      checkpoints: [],
      signers: {},
    });
    expect(report.ok).toBe(true);
    expect(report.entriesChecked).toBe(0);
  });

  it("flags a checkpoint signed by an untrusted key", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    const findings = verifyCheckpoints(t.log.entries(), [cp], {
      trustedSigners: { authority: "aa".repeat(32) },
    });
    expect(findings.some((f) => f.code === "CHECKPOINT_SIGNER_UNTRUSTED")).toBe(true);
    await t.close();
  });

  it("flags a checkpoint whose head hash does not match the covered entries", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    // Keep the signature valid by verifying the head check independently:
    // a checkpoint whose body is untouched but whose entries were swapped.
    const entries = t.log.entries();
    const swapped = [...entries];
    const tmp = swapped[4]!;
    swapped[4] = { ...tmp, hash: "0".repeat(64) };
    const findings = verifyCheckpoints(swapped, [cp]);
    expect(findings.some((f) => f.code === "CHECKPOINT_HEAD_MISMATCH")).toBe(true);
    expect(findings.some((f) => f.code === "CHECKPOINT_ROOT_MISMATCH")).toBe(true);
    await t.close();
  });

  it("warns when checkpoint timestamps regress", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp1 = await t.log.createCheckpoint(Date.now());
    await t.log.append({ type: "EXAM_CLOSED", payload: { centre_id: "A" } });
    const cp2 = await t.log.createCheckpoint(cp1.ts - 10_000);
    const findings = verifyCheckpoints(t.log.entries(), [cp1, cp2]);
    expect(findings.some((f) => f.code === "CHECKPOINT_TIME_REGRESSION")).toBe(true);
    await t.close();
  });

  it("warns when an anchor's TSA has no configured verification backend", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    const withAnchor = { ...cp, anchors: [anchorFor(cp, "unknown-tsa", cp.ts)] };
    const res = await verifyAnchors([withAnchor], []);
    expect(res.anchorsChecked).toBe(0);
    const f = res.findings.find((x) => x.code === "ANCHOR_BACKEND_UNAVAILABLE")!;
    expect(f.message).toMatch(/no verification backend is configured/);
    await t.close();
  });

  it("fails when a TSA timestamped a root before the checkpoint claims to exist (T5/T6)", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    // TSA asserts a time an hour BEFORE the checkpoint's own timestamp: the
    // operator's clock claim cannot be reconciled with the external anchor.
    const withAnchor = { ...cp, anchors: [anchorFor(cp, "tsa-a", cp.ts - 3_600_000)] };
    const res = await verifyAnchors([withAnchor], [new AcceptingBackend("tsa-a")]);
    const f = res.findings.find((x) => x.code === "ANCHOR_PREDATES_CHECKPOINT")!;
    expect(f.message).toMatch(/cannot be trusted/);
    expect(res.anchorsChecked).toBe(1);
    await t.close();
  });

  it("warns when anchoring happened long after the checkpoint", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    const withAnchor = { ...cp, anchors: [anchorFor(cp, "tsa-a", cp.ts + 50 * 3_600_000)] };
    const res = await verifyAnchors([withAnchor], [new AcceptingBackend("tsa-a")]);
    const f = res.findings.find((x) => x.code === "ANCHOR_LATE")!;
    expect(f.message).toMatch(/unattested/);
    await t.close();
  });

  it("accepts an anchor whose time is consistent with its checkpoint", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    const withAnchor = { ...cp, anchors: [anchorFor(cp, "tsa-a", cp.ts + 2000)] };
    const res = await verifyAnchors([withAnchor], [new AcceptingBackend("tsa-a")]);
    expect(res.findings).toEqual([]);
    expect(res.anchorsChecked).toBe(1);
    await t.close();
  });

  it("runs anchor verification through verifyEvidence when backends are supplied", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    t.log.attachAnchors(cp.size, [anchorFor(cp, "tsa-a", cp.ts + 100)]);
    const report = await verifyEvidence(bundleOf(t.log), {
      anchorBackends: [new AcceptingBackend("tsa-a")],
      minAnchorsPerCheckpoint: 1,
    });
    expect(report.ok).toBe(true);
    expect(report.anchorsChecked).toBe(1);
    await t.close();
  });
});
