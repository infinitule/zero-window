import { canonicalJson } from "@zw/authority";
import {
  generateSigningKeyPair,
  signDomain,
  verifyDomain,
  zeroFree,
} from "@zw/crypto";
import type { AuditReportBody, ThreatFinding } from "./audit.js";

/**
 * Signed audit report. The auditor signs the canonical JSON of the body with
 * their OWN key — the point is that the report's conclusions are attributable
 * to the auditor and tamper-evident in transit to whoever commissioned the
 * audit. Canonical JSON makes the signature survive reformatting.
 */

export const REPORT_DOMAIN = "audit-report";

export interface SignedAuditReport {
  body: AuditReportBody;
  signature: string;
  signerPublicKey: string;
}

export function signReport(body: AuditReportBody): SignedAuditReport {
  const kp = generateSigningKeyPair();
  try {
    const signature = signDomain(REPORT_DOMAIN, canonicalJson(body as unknown as Record<string, unknown>), kp.secretKey);
    return {
      body,
      signature: signature.toString("hex"),
      signerPublicKey: kp.publicKey.toString("hex"),
    };
  } finally {
    zeroFree(kp.secretKey);
  }
}

export function verifyReport(report: SignedAuditReport): boolean {
  try {
    return verifyDomain(
      REPORT_DOMAIN,
      canonicalJson(report.body as unknown as Record<string, unknown>),
      Buffer.from(report.signature, "hex"),
      Buffer.from(report.signerPublicKey, "hex"),
    );
  } catch {
    return false;
  }
}

/** Human-readable rendering for the operator console and the README. */
export function renderReport(report: SignedAuditReport): string {
  const b = report.body;
  const lines: string[] = [];
  const rule = "=".repeat(72);
  lines.push(rule);
  lines.push(`ZERO-WINDOW AUDIT REPORT — ${b.examId}`);
  lines.push(`generated ${new Date(b.generatedAt).toISOString()}   overall: ${b.overall}`);
  lines.push(rule);
  lines.push("");
  lines.push("LOGS");
  for (const l of b.logs) {
    lines.push(
      `  ${l.actor.padEnd(20)} ${String(l.entries).padStart(5)} entries  ` +
        `${String(l.checkpoints).padStart(3)} checkpoints  ` +
        `${String(l.anchorsChecked).padStart(3)} anchors verified  ${l.ok ? "OK" : "FAILED"}`,
    );
  }
  lines.push("");
  lines.push("THREAT MODEL");
  for (const t of b.threats.sort((x, y) => x.threat.localeCompare(y.threat, "en", { numeric: true }))) {
    lines.push(`  ${t.threat.padEnd(4)} ${t.verdict.padEnd(14)} ${t.title}`);
    for (const e of t.evidence) lines.push(`         · ${e}`);
  }
  lines.push("");
  if (b.chainFindings.length > 0) {
    lines.push("FINDINGS");
    for (const f of b.chainFindings) {
      lines.push(`  [${f.severity.toUpperCase()}] ${f.code}${f.at !== undefined ? ` @${f.at}` : ""}: ${f.message}`);
    }
    lines.push("");
  }
  lines.push(`papers re-derived byte-identically: ${b.papersRederived}`);
  lines.push(`report signature: ${report.signature.slice(0, 32)}… (Ed25519, key ${report.signerPublicKey.slice(0, 16)}…)`);
  lines.push(rule);
  return lines.join("\n") + "\n";
}

export function attentionRows(body: AuditReportBody): ThreatFinding[] {
  return body.threats.filter((t) => t.verdict === "ATTENTION");
}
