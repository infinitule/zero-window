import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Authority, encodeAdmitToken, splitBank, type ItemBank, type Blueprint } from "@zw/authority";
import { CentreNode } from "@zw/centre";
import { generateBoxKeyPair, sealOpen } from "@zw/crypto";
import { VaultKeyProvider } from "@zw/kms-vault";
import type { EvidenceBundle } from "@zw/log";
import { audit, type AuditInput } from "../src/audit.js";
import { attentionRows, renderReport, signReport, verifyReport } from "../src/report.js";

/**
 * The verifier is tested the way it will be used: against evidence exported
 * from a real exam run, and against that same evidence after the kinds of
 * manipulation a dishonest operator would attempt. A hostile auditor must be
 * able to catch every one — that is the product.
 */

const EXAM = "EXAM-2026-AUD";
const CENTRE = "CENTRE-V";

function bank(examId = EXAM): ItemBank {
  const items = [];
  for (const subject of ["mechanics", "optics"]) {
    for (const difficulty of ["easy", "medium", "hard"] as const) {
      for (let i = 0; i < 6; i++) {
        items.push({
          id: `${subject}-${difficulty}-${i}`,
          subject,
          difficulty,
          body: `A ${difficulty} ${subject} question ${i} with enough text to wrap lines?`,
          options: [`a${i}`, `b${i}`, `c${i}`, `d${i}`],
          correctIndex: i % 4,
        });
      }
    }
  }
  return { examId, items };
}

function blueprint(examId = EXAM): Blueprint {
  return {
    examId,
    title: "Audit Exam",
    durationMinutes: 120,
    slots: [
      { subject: "mechanics", difficulty: "easy", count: 2 },
      { subject: "optics", difficulty: "hard", count: 2 },
    ],
  };
}

/** One full real exam, evidence exported. Built once — ~10s of crypto+PDF. */
interface World {
  authorityEvidence: EvidenceBundle;
  centreEvidence: EvidenceBundle;
  paperContent: ReturnType<typeof splitBank>["paper"];
  signers: Record<string, string>;
}

let world: World;
const dirs: string[] = [];

beforeAll(async () => {
  const aDir = await mkdtemp(join(tmpdir(), "zw-aud-a-"));
  const cDir = await mkdtemp(join(tmpdir(), "zw-aud-c-"));
  dirs.push(aDir, cDir);

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
    statePath: join(cDir, "c.db"),
    logPath: join(cDir, "log.db"),
    provider: await VaultKeyProvider.open({
      keystorePath: join(cDir, "ks.json"),
      passphrase: Buffer.from("c", "utf8"),
    }),
    authorityPublicKey: authority.publicKey,
    spoolDir: join(cDir, "spool"),
  });
  await authority.enrolCentre({
    centreId: CENTRE,
    boxPublicKey: centre.boxPublicKey,
    certFingerprint: "fp",
    hardwareId: "hw-1",
  });

  const b = bank();
  const bp = blueprint();
  const provisioned = await authority.provision({ bank: b, blueprint: bp, threshold: 3 });
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

  const tokens = await authority.issueAdmitTokens({
    examId: EXAM,
    centreId: CENTRE,
    salt: Authority.newRegistrationSalt(),
    expiresAt: Date.now() + 86_400_000,
    candidates: [
      { registrationId: "R-1", seat: "A-01" },
      { registrationId: "R-2", seat: "A-02" },
    ],
  });

  await authority.scheduleRelease({
    examId: EXAM,
    bundleId: provisioned.paper.bundleId,
    releaseAt: Date.now() - 500,
  });
  const shareOf = (id: string) => {
    const rec = authority.store
      .shares(provisioned.paper.bundleId)
      .find((s) => s.custodianId === id)!;
    const c = custodians.find((x) => x.custodianId === id)!;
    return { custodianId: id, shareBlob: sealOpen(rec.sealed, c.keys.publicKey, c.keys.secretKey) };
  };
  const outcome = await authority.release({
    bundleId: provisioned.paper.bundleId,
    shares: [shareOf("cust-1"), shareOf("cust-2"), shareOf("cust-4")],
  });
  await centre.receiveWrappedKek(
    provisioned.paper.bundleId,
    outcome.wrapped.find((w) => w.centreId === CENTRE)!.sealed,
  );

  for (const t of tokens) await centre.checkIn(encodeAdmitToken(t));
  const t0 = await centre.runT0();
  if (t0.failures.length > 0) throw new Error(`T-0 failed: ${JSON.stringify(t0.failures)}`);
  await centre.closeExam();

  await authority.checkpoint();
  await centre.checkpoint();

  world = {
    authorityEvidence: authority.log.evidence(EXAM),
    centreEvidence: centre.log.evidence(EXAM),
    paperContent: splitBank(b, bp).paper,
    signers: {
      authority: authority.publicKey.toString("hex"),
      [`centre-${CENTRE}`]: centre.log.publicKey.toString("hex"),
    },
  };
  await centre.close();
  await authority.close();
}, 180_000);

afterAll(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

function baseInput(): AuditInput {
  return {
    authority: structuredClone(world.authorityEvidence),
    centres: [structuredClone(world.centreEvidence)],
    trustedSigners: world.signers,
    paperContent: structuredClone(world.paperContent),
  };
}

function row(reportThreats: Awaited<ReturnType<typeof audit>>, id: string) {
  return reportThreats.threats.find((t) => t.threat === id)!;
}

describe("audit of an honest exam", () => {
  it("resolves every evaluated threat row to PASS", async () => {
    const report = await audit(baseInput());
    expect(report.overall).toBe("PASS");
    for (const t of report.threats) {
      expect(t.verdict, `${t.threat} (${t.title}): ${t.evidence.join(" | ")}`).not.toBe(
        "ATTENTION",
      );
    }
    // T5 is NOT_EVALUATED here (no anchor backends in unit tests — live TSA
    // anchoring is exercised in the M8 pilot); everything else is PASS.
    expect(row(report, "T5").verdict).toBe("NOT_EVALUATED");
    for (const id of ["T1", "T2", "T3", "T4", "T6", "T7", "T8", "T9", "T10"]) {
      expect(row(report, id).verdict, id).toBe("PASS");
    }
    expect(report.papersRederived).toBe(2);
  }, 120_000);

  it("produces a signed report that verifies and survives reformatting", async () => {
    const report = await audit(baseInput());
    const signed = signReport(report);
    expect(verifyReport(signed)).toBe(true);

    // Round-trip through JSON with different key order/whitespace.
    const reordered = JSON.parse(JSON.stringify(signed)) as typeof signed;
    expect(verifyReport(reordered)).toBe(true);

    // Any change to the body invalidates it — flip a verdict to its opposite
    // and pin that the flip actually changed the value.
    const tampered = structuredClone(signed);
    const t0 = tampered.body.threats[0]!;
    const flipped = t0.verdict === "PASS" ? "ATTENTION" : "PASS";
    expect(flipped).not.toBe(t0.verdict);
    t0.verdict = flipped;
    expect(verifyReport(tampered)).toBe(false);

    // So does editing the evidence text of a finding.
    const tampered2 = structuredClone(signed);
    tampered2.body.threats[1]!.evidence[0] = "everything was fine, honestly";
    expect(verifyReport(tampered2)).toBe(false);

    const text = renderReport(signed);
    expect(text).toContain("ZERO-WINDOW AUDIT REPORT");
    expect(text).toContain("overall: PASS");
  }, 120_000);
});

describe("what the auditor is and is not given", () => {
  it("without an out-of-band signer list, the report says trust rests on the bundles", async () => {
    const input = baseInput();
    delete input.trustedSigners;
    const report = await audit(input);
    // Still PASS — the evidence is internally consistent — but the caveat is
    // stated rather than hidden (I-VER-1).
    expect(report.overall).toBe("PASS");
    expect(row(report, "T6").evidence.join(" ")).toContain(
      "no out-of-band signer list supplied",
    );
  }, 120_000);

  it("without the paper disclosure, T4 is NOT_EVALUATED rather than assumed", async () => {
    const input = baseInput();
    delete input.paperContent;
    const report = await audit(input);
    expect(row(report, "T4").verdict).toBe("NOT_EVALUATED");
    expect(row(report, "T4").evidence.join(" ")).toContain("not disclosed");
    expect(report.papersRederived).toBe(0);
    // A NOT_EVALUATED row must not silently become an overall PASS claim
    // about that threat, but it does not fail the audit either.
    expect(report.overall).toBe("PASS");
  }, 120_000);

  it("caps paper re-derivation when asked", async () => {
    const input = baseInput();
    input.maxPapersToRederive = 1;
    const report = await audit(input);
    expect(report.papersRederived).toBe(1);
  }, 120_000);

  it("T5: anchors are verified through auditor-supplied backends", async () => {
    const input = baseInput();
    // A backend under the auditor's control, standing in for a real TSA
    // client (live TSAs are exercised in @zw/log and in the M8 pilot).
    const verified: string[] = [];
    input.anchorBackends = [
      {
        name: "auditor-tsa",
        anchor: () => {
          throw new Error("auditors do not create anchors");
        },
        verify: async (anchor, root) => {
          verified.push(`${anchor.tsa}:${root.toString("hex").slice(0, 8)}`);
        },
      },
    ];
    const report = await audit(input);
    // No anchors were attached in this run, so the policy minimum is unmet
    // and the row is ATTENTION — silence is not treated as success.
    expect(row(report, "T5").verdict).toBe("ATTENTION");
    expect(row(report, "T5").evidence.join(" ")).toContain("policy requires 2");
  }, 120_000);

  it("T5: a log with no checkpoints at all is flagged", async () => {
    const input = baseInput();
    input.centres[0]!.checkpoints = [];
    input.anchorBackends = [];
    input.minAnchors = 1;
    const report = await audit(input);
    expect(row(report, "T5").evidence.join(" ")).toContain("no checkpoints at all");
  }, 120_000);

  it("T10: a centre that never reached EXAM_CLOSED is flagged", async () => {
    const input = baseInput();
    input.centres[0]!.entries = input.centres[0]!.entries.filter(
      (e) => e.type !== "EXAM_CLOSED",
    );
    const report = await audit(input);
    expect(row(report, "T10").verdict).toBe("ATTENTION");
  }, 120_000);

  it("T10: printer failovers are surfaced as custody-relevant facts", async () => {
    const input = baseInput();
    const template = input.centres[0]!.entries.find((e) => e.type === "PAPER_PRINTED")!;
    input.centres[0]!.entries.push({
      ...structuredClone(template),
      type: "PRINTER_FAILOVER",
      payload: {
        centre_id: CENTRE,
        exam_id: EXAM,
        printer_id: "hall-primary",
        reason: "connect ECONNREFUSED 10.0.0.5:631",
      },
    });
    const report = await audit(input);
    expect(row(report, "T10").evidence.join(" ")).toContain("hall-primary");
  }, 120_000);
});

describe("report rendering and signature handling", () => {
  it("renders findings and rejects a malformed signature without throwing", async () => {
    const input = baseInput();
    const gen = input.centres[0]!.entries.find((e) => e.type === "PAPER_GENERATED")!;
    gen.payload["paper_hash"] = "00".repeat(32);
    const report = await audit(input);
    const signed = signReport(report);

    const text = renderReport(signed);
    expect(text).toContain("FINDINGS");
    expect(text).toContain("overall: ATTENTION");
    expect(attentionRows(report).length).toBeGreaterThan(0);

    expect(verifyReport({ ...signed, signature: "not-hex-at-all" })).toBe(false);
    expect(verifyReport({ ...signed, signerPublicKey: "" })).toBe(false);
  }, 120_000);
});

describe("hostile-operator scenarios", () => {
  it("T6: an edited entry breaks the chain fatally", async () => {
    const input = baseInput();
    const gen = input.centres[0]!.entries.find((e) => e.type === "PAPER_GENERATED")!;
    gen.payload["paper_hash"] = "00".repeat(32);
    const report = await audit(input);
    expect(report.overall).toBe("ATTENTION");
    expect(row(report, "T6").verdict).toBe("ATTENTION");
  }, 120_000);

  it("T6: a signer key not on the auditor's list is caught even with valid signatures", async () => {
    const input = baseInput();
    // The operator hands over evidence self-declaring a different key set —
    // e.g. after re-signing history with a fresh key.
    input.trustedSigners = {
      ...world.signers,
      [`centre-${CENTRE}`]: "aa".repeat(32),
    };
    const report = await audit(input);
    expect(report.overall).toBe("ATTENTION");
  }, 120_000);

  it("T3: a centre receiving a different bundle than was distributed is caught", async () => {
    const input = baseInput();
    // Rebuild the centre's BUNDLE_RECEIVED with a different hash while also
    // fixing up its chain would require the signing key; the audit must
    // catch the semantic mismatch even if the chain were somehow intact, so
    // test at the semantic layer with chain findings tolerated.
    const recv = input.centres[0]!.entries.find((e) => e.type === "BUNDLE_RECEIVED")!;
    recv.payload["bundle_hash"] = "ff".repeat(32);
    const report = await audit(input);
    expect(row(report, "T3").verdict).toBe("ATTENTION");
    expect(row(report, "T3").evidence.join(" ")).toContain("hash mismatch");
  }, 120_000);

  it("T4: substituted paper content is caught against the committed hash", async () => {
    const input = baseInput();
    input.paperContent!.items[0]!.body = "REPLACED QUESTION — what the operator claims was asked";
    const report = await audit(input);
    expect(row(report, "T4").verdict).toBe("ATTENTION");
    expect(row(report, "T4").evidence.join(" ")).toContain("not the bundle that was used");
  }, 120_000);

  it("T4: a forged paper_hash in the log fails re-derivation", async () => {
    const input = baseInput();
    const gen = input.centres[0]!.entries.find((e) => e.type === "PAPER_GENERATED")!;
    gen.payload["paper_hash"] = "ab".repeat(32);
    const report = await audit(input);
    expect(row(report, "T4").verdict).toBe("ATTENTION");
    expect(row(report, "T4").evidence.join(" ")).toContain("NOT what this system generates");
  }, 120_000);

  it("T7: a paper generated for a token that never checked in is caught", async () => {
    const input = baseInput();
    const centreEv = input.centres[0]!;
    centreEv.entries = centreEv.entries.filter((e) => {
      return !(
        e.type === "CANDIDATE_CHECKED_IN" && e.payload["seat"] === "A-01"
      );
    });
    const report = await audit(input);
    expect(row(report, "T7").verdict).toBe("ATTENTION");
    expect(row(report, "T7").evidence.join(" ")).toContain("never checked in");
  }, 120_000);

  it("T2: a release logged before its schedule is caught", async () => {
    const input = baseInput();
    const rel = input.authority.entries.find((e) => e.type === "KEK_RELEASED")!;
    rel.payload["released_at"] = Number(rel.payload["scheduled_at"]) - 60_000;
    const report = await audit(input);
    expect(row(report, "T2").verdict).toBe("ATTENTION");
    expect(row(report, "T2").evidence.join(" ")).toContain("before its scheduled T-0");
  }, 120_000);

  it("T9: a release approved by fewer custodians than threshold is caught", async () => {
    const input = baseInput();
    const rel = input.authority.entries.find((e) => e.type === "KEK_RELEASED")!;
    rel.payload["custodian_ids"] = ["cust-1"];
    const report = await audit(input);
    expect(row(report, "T9").verdict).toBe("ATTENTION");
  }, 120_000);

  it("T9: an approving custodian who was never issued a share is caught", async () => {
    const input = baseInput();
    const rel = input.authority.entries.find((e) => e.type === "KEK_RELEASED")!;
    rel.payload["custodian_ids"] = ["cust-1", "cust-2", "ghost-custodian"];
    const report = await audit(input);
    expect(row(report, "T9").verdict).toBe("ATTENTION");
    expect(row(report, "T9").evidence.join(" ")).toContain("never issued a share");
  }, 120_000);

  it("T8: PII smuggled into a payload is caught", async () => {
    const input = baseInput();
    const e = input.centres[0]!.entries.find((x) => x.type === "CANDIDATE_CHECKED_IN")!;
    e.payload["candidate_name"] = "A. Person";
    const report = await audit(input);
    expect(row(report, "T8").verdict).toBe("ATTENTION");
    expect(attentionRows(report).map((t) => t.threat)).toContain("T8");
  }, 120_000);

  it("early-release attempts downgrade T2 to ATTENTION even when refused", async () => {
    const input = baseInput();
    // Splice a (legitimately signed at the time, here simulated in payload
    // only) EARLY_RELEASE_ATTEMPT into the authority evidence.
    const template = input.authority.entries.find((e) => e.type === "RELEASE_SCHEDULED")!;
    input.authority.entries.push({
      ...structuredClone(template),
      type: "EARLY_RELEASE_ATTEMPT",
      payload: {
        bundle_id: `${EXAM}:paper`,
        exam_id: EXAM,
        early_by_ms: 120000,
        custodian_ids: ["cust-1", "cust-2", "cust-3"],
        release_at: 0,
        attempted_at: 0,
      },
    });
    const report = await audit(input);
    expect(row(report, "T2").verdict).toBe("ATTENTION");
    // The chain is of course also broken by the splice — both signals fire.
    expect(report.overall).toBe("ATTENTION");
  }, 120_000);
});
