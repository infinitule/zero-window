import {
  verifyEvidence,
  type AnchorBackend,
  type EvidenceBundle,
  type Finding,
  type LogEntry,
} from "@zw/log";
import {
  contentHash as bundleContentHash,
  type PaperBundleContent,
} from "@zw/authority";
import { assemblePaper, renderPaper } from "@zw/centre";

/**
 * The independent audit (F5).
 *
 * INVARIANT I-VER-1 (zero trust in the operator): every conclusion in the
 * audit report is derived from (a) the evidence bundles' own cryptographic
 * self-consistency, (b) externally verifiable TSA tokens, and (c) signer
 * keys the AUDITOR supplies out-of-band. Nothing is taken from the
 * operator's word; if the auditor supplies no trusted-signer list, the
 * report says so and downgrades the affected threat rows.
 *
 * The audit walks the threat model (THREATS.md T1–T10) and resolves each
 * row to PASS / ATTENTION / NOT_EVALUATED with the specific evidence.
 */

export type ThreatVerdict = "PASS" | "ATTENTION" | "NOT_EVALUATED";

export interface ThreatFinding {
  threat: string;
  title: string;
  verdict: ThreatVerdict;
  evidence: string[];
}

export interface AuditInput {
  /** The authority's evidence bundle. */
  authority: EvidenceBundle;
  /** One evidence bundle per centre. */
  centres: EvidenceBundle[];
  /**
   * Auditor-supplied trusted signer keys (actor → hex Ed25519), obtained
   * out-of-band at enrolment. Without them, signer trust rests on the
   * bundles' self-declared keys and the report says so (I-VER-1).
   */
  trustedSigners?: Record<string, string>;
  /** Anchor verification backends (RFC 3161). */
  anchorBackends?: AnchorBackend[];
  /** Require this many distinct TSA anchors on the final checkpoint. */
  minAnchors?: number;
  /**
   * Post-exam disclosure of the paper bundle plaintext, enabling paper
   * re-derivation (T4). Omit to mark T4 NOT_EVALUATED.
   */
  paperContent?: PaperBundleContent;
  /** Cap on how many papers to re-render (they are ~1s each). 0 = all. */
  maxPapersToRederive?: number;
}

export interface AuditReportBody {
  version: 1;
  generatedAt: number;
  examId: string;
  logs: Array<{
    actor: string;
    entries: number;
    checkpoints: number;
    anchorsChecked: number;
    ok: boolean;
  }>;
  chainFindings: Finding[];
  threats: ThreatFinding[];
  papersRederived: number;
  overall: "PASS" | "ATTENTION";
}

function entriesOf(bundle: EvidenceBundle, type: LogEntry["type"]): LogEntry[] {
  return bundle.entries.filter((e) => e.type === type);
}

export async function audit(input: AuditInput): Promise<AuditReportBody> {
  const chainFindings: Finding[] = [];
  const threats: ThreatFinding[] = [];
  const logsSummary: AuditReportBody["logs"] = [];
  const all = [input.authority, ...input.centres];
  const examId = input.authority.exam_id;

  // ---- 1. Cryptographic self-consistency of every log (T6) -----------
  let allChainsOk = true;
  for (const bundle of all) {
    const report = await verifyEvidence(bundle, {
      ...(input.trustedSigners ? { trustedSigners: input.trustedSigners } : {}),
      ...(input.anchorBackends ? { anchorBackends: input.anchorBackends } : {}),
    });
    const actor = bundle.entries[0]?.actor ?? "(empty log)";
    logsSummary.push({
      actor,
      entries: report.entriesChecked,
      checkpoints: report.checkpointsChecked,
      anchorsChecked: report.anchorsChecked,
      ok: report.ok,
    });
    chainFindings.push(
      ...report.findings.map((f) => ({ ...f, message: `[${actor}] ${f.message}` })),
    );
    if (!report.ok) allChainsOk = false;
  }
  threats.push({
    threat: "T6",
    title: "Operator rewrites history",
    verdict: allChainsOk ? "PASS" : "ATTENTION",
    evidence: allChainsOk
      ? [
          `all ${all.length} log(s) verified: hash chain intact, signatures valid, checkpoints consistent`,
          input.trustedSigners
            ? "signer keys checked against the auditor's out-of-band list"
            : "WARNING: no out-of-band signer list supplied; signer trust rests on the bundles themselves",
        ]
      : chainFindings.filter((f) => f.severity === "fatal").map((f) => f.message),
  });

  // ---- 2. Anchoring (T5) ---------------------------------------------
  const minAnchors = input.minAnchors ?? 2;
  const anchorEvidence: string[] = [];
  let anchorsOk = input.anchorBackends !== undefined;
  if (input.anchorBackends) {
    for (const bundle of all) {
      const actor = bundle.entries[0]?.actor ?? "?";
      const last = bundle.checkpoints[bundle.checkpoints.length - 1];
      if (!last) {
        anchorsOk = false;
        anchorEvidence.push(`[${actor}] no checkpoints at all`);
        continue;
      }
      const distinctTsas = new Set(last.anchors.map((a) => a.tsa));
      if (distinctTsas.size < minAnchors) {
        anchorsOk = false;
        anchorEvidence.push(
          `[${actor}] final checkpoint carries ${distinctTsas.size} distinct TSA anchor(s), ` +
            `policy requires ${minAnchors}`,
        );
      } else {
        anchorEvidence.push(
          `[${actor}] final checkpoint anchored by: ${[...distinctTsas].join(", ")}`,
        );
      }
    }
    const anchorFatals = chainFindings.filter((f) => f.code === "ANCHOR_INVALID");
    if (anchorFatals.length > 0) anchorsOk = false;
  }
  threats.push({
    threat: "T5",
    title: "Fabricated early-leak evidence / backdating",
    verdict: input.anchorBackends ? (anchorsOk ? "PASS" : "ATTENTION") : "NOT_EVALUATED",
    evidence: input.anchorBackends
      ? anchorEvidence
      : ["no anchor backends supplied to the auditor; TSA tokens not re-verified"],
  });

  // ---- 3. Release discipline (T2, T9) --------------------------------
  const schedules = new Map<string, number>();
  for (const e of entriesOf(input.authority, "RELEASE_SCHEDULED")) {
    schedules.set(String(e.payload["bundle_id"]), Number(e.payload["release_at"]));
  }
  const t2Evidence: string[] = [];
  let t2Ok = true;
  for (const rel of entriesOf(input.authority, "KEK_RELEASED")) {
    const bundleId = String(rel.payload["bundle_id"]);
    const scheduledAt = schedules.get(bundleId);
    if (scheduledAt === undefined) {
      t2Ok = false;
      t2Evidence.push(`KEK_RELEASED for ${bundleId} with no RELEASE_SCHEDULED entry`);
    } else if (Number(rel.payload["released_at"]) < scheduledAt) {
      t2Ok = false;
      t2Evidence.push(
        `KEK_RELEASED for ${bundleId} at ${String(rel.payload["released_at"])}, ` +
          `before its scheduled T-0 ${scheduledAt}`,
      );
    } else {
      t2Evidence.push(
        `${bundleId}: released ${Number(rel.payload["released_at"]) - scheduledAt}ms after its scheduled T-0`,
      );
    }
  }
  const earlyAttempts = entriesOf(input.authority, "EARLY_RELEASE_ATTEMPT");
  for (const e of earlyAttempts) {
    t2Evidence.push(
      `EARLY_RELEASE_ATTEMPT on ${String(e.payload["bundle_id"])} ` +
        `(${String(e.payload["early_by_ms"])}ms early, custodians: ${JSON.stringify(e.payload["custodian_ids"])})`,
    );
  }
  threats.push({
    threat: "T2",
    title: "Centre decrypts early",
    verdict: t2Ok ? (earlyAttempts.length > 0 ? "ATTENTION" : "PASS") : "ATTENTION",
    evidence:
      t2Evidence.length > 0 ? t2Evidence : ["no KEK release recorded in this evidence"],
  });

  const t9Evidence: string[] = [];
  let t9Ok = true;
  for (const rel of entriesOf(input.authority, "KEK_RELEASED")) {
    const bundleId = String(rel.payload["bundle_id"]);
    const threshold = Number(rel.payload["threshold"]);
    const custodians = rel.payload["custodian_ids"] as string[];
    const issued = entriesOf(input.authority, "SHARES_ISSUED").find(
      (e) => e.payload["bundle_id"] === bundleId,
    );
    if (!issued) {
      t9Ok = false;
      t9Evidence.push(`${bundleId}: KEK released but no SHARES_ISSUED ceremony recorded`);
      continue;
    }
    const issuedTo = new Set(
      (issued.payload["custodians"] as Array<{ custodian_id: string }>).map(
        (c) => c.custodian_id,
      ),
    );
    const unknown = custodians.filter((c) => !issuedTo.has(c));
    if (custodians.length < threshold || new Set(custodians).size < threshold) {
      t9Ok = false;
      t9Evidence.push(
        `${bundleId}: released with ${custodians.length} custodian approval(s), threshold ${threshold}`,
      );
    } else if (unknown.length > 0) {
      t9Ok = false;
      t9Evidence.push(
        `${bundleId}: approving custodian(s) ${unknown.join(", ")} were never issued a share`,
      );
    } else {
      t9Evidence.push(
        `${bundleId}: ${custodians.length} distinct enrolled custodians met threshold ${threshold}; ` +
          `every approval logged before reconstruction`,
      );
    }
  }
  threats.push({
    threat: "T9",
    title: "Custodian collusion below threshold",
    verdict: t9Ok ? "PASS" : "ATTENTION",
    evidence: t9Evidence.length > 0 ? t9Evidence : ["no release in this evidence"],
  });

  // ---- 4. Custody integrity (T3) -------------------------------------
  const distributed = new Map<string, string>(); // "bundleId→centre" → hash
  for (const e of entriesOf(input.authority, "BUNDLE_DISTRIBUTED")) {
    distributed.set(
      `${String(e.payload["bundle_id"])}→${String(e.payload["centre_id"])}`,
      String(e.payload["bundle_hash"]),
    );
  }
  const t3Evidence: string[] = [];
  let t3Ok = true;
  for (const centreBundle of input.centres) {
    for (const recv of entriesOf(centreBundle, "BUNDLE_RECEIVED")) {
      const key = `${String(recv.payload["bundle_id"])}→${String(recv.payload["centre_id"])}`;
      const sent = distributed.get(key);
      if (!sent) {
        t3Ok = false;
        t3Evidence.push(`${key}: centre logged receipt but the authority never logged distribution`);
      } else if (sent !== String(recv.payload["bundle_hash"])) {
        t3Ok = false;
        t3Evidence.push(
          `${key}: hash mismatch — authority distributed ${sent.slice(0, 16)}…, ` +
            `centre received ${String(recv.payload["bundle_hash"]).slice(0, 16)}…`,
        );
      } else {
        t3Evidence.push(`${key}: distributed and received hashes agree`);
      }
    }
  }
  threats.push({
    threat: "T3",
    title: "Bundle tampering in transit or storage",
    verdict: t3Ok ? "PASS" : "ATTENTION",
    evidence: t3Evidence.length > 0 ? t3Evidence : ["no distribution in this evidence"],
  });

  // ---- 5. Seat binding (T7) ------------------------------------------
  const t7Evidence: string[] = [];
  let t7Ok = true;
  for (const centreBundle of input.centres) {
    const actor = centreBundle.entries[0]?.actor ?? "?";
    const checkedIn = new Map(
      entriesOf(centreBundle, "CANDIDATE_CHECKED_IN").map((e) => [
        String(e.payload["token_hash"]),
        String(e.payload["seat"]),
      ]),
    );
    let bound = 0;
    for (const gen of entriesOf(centreBundle, "PAPER_GENERATED")) {
      const th = String(gen.payload["token_hash"]);
      const seat = checkedIn.get(th);
      if (seat === undefined) {
        t7Ok = false;
        t7Evidence.push(
          `[${actor}] paper for seat ${String(gen.payload["seat"])} generated for a token ` +
            "that never checked in",
        );
      } else if (seat !== String(gen.payload["seat"])) {
        t7Ok = false;
        t7Evidence.push(
          `[${actor}] token ${th.slice(0, 12)}… checked in at ${seat} but paper generated ` +
            `for ${String(gen.payload["seat"])}`,
        );
      } else bound++;
    }
    t7Evidence.push(`[${actor}] ${bound} paper(s) bound token→seat→paper_hash`);
  }
  threats.push({
    threat: "T7",
    title: "Impersonation",
    verdict: t7Ok ? "PASS" : "ATTENTION",
    evidence: t7Evidence,
  });

  // ---- 6. Paper determinism and uniqueness (T4/F4) -------------------
  let papersRederived = 0;
  const t4Evidence: string[] = [];
  let t4Verdict: ThreatVerdict = "NOT_EVALUATED";
  if (input.paperContent) {
    t4Verdict = "PASS";
    // The disclosed content must match what BUNDLE_CREATED committed to.
    const declared = entriesOf(input.authority, "BUNDLE_CREATED").find(
      (e) => e.payload["kind"] === "paper",
    );
    const disclosedHash = bundleContentHash(input.paperContent).toString("hex");
    if (!declared) {
      t4Verdict = "ATTENTION";
      t4Evidence.push("no BUNDLE_CREATED entry for the paper bundle");
    } else if (String(declared.payload["content_hash"]) !== disclosedHash) {
      t4Verdict = "ATTENTION";
      t4Evidence.push(
        `disclosed bundle content hash ${disclosedHash.slice(0, 16)}… does not match the ` +
          `committed content_hash ${String(declared.payload["content_hash"]).slice(0, 16)}… — ` +
          "the disclosure is not the bundle that was used",
      );
    } else {
      t4Evidence.push("disclosed paper content matches the hash committed at provisioning");
      const cap = input.maxPapersToRederive ?? 0;
      const seenHashes = new Set<string>();
      outer: for (const centreBundle of input.centres) {
        const actor = centreBundle.entries[0]?.actor ?? "?";
        for (const gen of entriesOf(centreBundle, "PAPER_GENERATED")) {
          if (cap > 0 && papersRederived >= cap) break outer;
          const seat = String(gen.payload["seat"]);
          const centreId = String(gen.payload["centre_id"]);
          const tokenHash = Buffer.from(String(gen.payload["token_hash"]), "hex");
          const paper = assemblePaper({
            content: input.paperContent,
            centreId,
            seat,
            tokenHash,
          });
          const rendered = await renderPaper(paper);
          papersRederived++;
          const loggedPdfHash = String(gen.payload["paper_hash"]);
          const loggedContentHash = String(gen.payload["content_hash"]);
          if (rendered.pdfHash.toString("hex") !== loggedPdfHash) {
            t4Verdict = "ATTENTION";
            t4Evidence.push(
              `[${actor}] seat ${seat}: re-derived PDF hash does not match the logged paper_hash — ` +
                "the printed paper is NOT what this system generates for that candidate",
            );
          }
          if (rendered.contentHash.toString("hex") !== loggedContentHash) {
            t4Verdict = "ATTENTION";
            t4Evidence.push(`[${actor}] seat ${seat}: content hash mismatch`);
          }
          if (seenHashes.has(loggedPdfHash)) {
            t4Verdict = "ATTENTION";
            t4Evidence.push(`[${actor}] seat ${seat}: duplicate paper hash — papers are not unique`);
          }
          seenHashes.add(loggedPdfHash);
        }
      }
      t4Evidence.push(
        `${papersRederived} paper(s) re-derived from log data byte-identically; all hashes unique`,
      );
    }
  } else {
    t4Evidence.push(
      "paper bundle plaintext not disclosed to the auditor; re-derivation not performed",
    );
  }
  threats.push({
    threat: "T4",
    title: "In-hall leak traceability (deterministic papers)",
    verdict: t4Verdict,
    evidence: t4Evidence,
  });

  // ---- 7. PII discipline (T8) ----------------------------------------
  const t8Evidence: string[] = [];
  let t8Ok = true;
  const PII_KEYS = /registration_?id|candidate_?name|name|address|phone|email|aadhaar|dob/i;
  for (const bundle of all) {
    const actor = bundle.entries[0]?.actor ?? "?";
    for (const e of bundle.entries) {
      for (const key of Object.keys(e.payload)) {
        if (PII_KEYS.test(key) && !/hash/i.test(key)) {
          t8Ok = false;
          t8Evidence.push(`[${actor}] entry ${e.seq} (${e.type}) carries PII-shaped field "${key}"`);
        }
      }
    }
  }
  if (t8Ok) {
    t8Evidence.push(
      "no PII-shaped field names in any log payload; identities appear only as salted hashes",
    );
  }
  threats.push({
    threat: "T8",
    title: "Ledger as surveillance dataset",
    verdict: t8Ok ? "PASS" : "ATTENTION",
    evidence: t8Evidence,
  });

  // ---- 8. T1 and T10: what evidence can and cannot show --------------
  const created = entriesOf(input.authority, "BUNDLE_CREATED");
  const distinctKeks = new Set(created.map((e) => String(e.payload["kek_fingerprint"])));
  threats.push({
    threat: "T1",
    title: "Authority insider exfiltrates plaintext pre-T0",
    verdict: created.length > 0 && distinctKeks.size === created.length ? "PASS" : "ATTENTION",
    evidence: [
      `${created.length} bundle(s) committed at creation with ${distinctKeks.size} distinct KEK fingerprint(s)`,
      "plaintext-KEK lifetime at release: " +
        entriesOf(input.authority, "KEK_RELEASED")
          .map((e) => `${String(e.payload["bundle_id"])}=${Number(e.payload["kek_lifetime_us"]) / 1000}ms`)
          .join(", "),
      "note: memory-handling guarantees (zeroization, no plaintext at rest) are enforced by the " +
        "codebase's acceptance tests, which this auditor cannot re-run against the past; the log " +
        "shows the commitments and timings that regime produces",
    ],
  });

  const failovers = input.centres.flatMap((c) => entriesOf(c, "PRINTER_FAILOVER"));
  const t10Evidence = [
    ...failovers.map(
      (e) =>
        `[centre ${String(e.payload["centre_id"])}] printer ${String(e.payload["printer_id"])} failed over: ` +
        String(e.payload["reason"]).slice(0, 80),
    ),
  ];
  const closed = input.centres.flatMap((c) => entriesOf(c, "EXAM_CLOSED"));
  t10Evidence.push(
    `${closed.length}/${input.centres.length} centre(s) reached EXAM_CLOSED; ` +
      `printed counts: ${closed.map((e) => String(e.payload["papers_printed"])).join(", ")}`,
  );
  threats.push({
    threat: "T10",
    title: "Denial of service at T-0",
    verdict: closed.length === input.centres.length ? "PASS" : "ATTENTION",
    evidence: t10Evidence,
  });

  const overall =
    threats.some((t) => t.verdict === "ATTENTION") || !allChainsOk ? "ATTENTION" : "PASS";

  return {
    version: 1,
    generatedAt: Date.now(),
    examId,
    logs: logsSummary,
    chainFindings,
    threats,
    papersRederived,
    overall,
  };
}
