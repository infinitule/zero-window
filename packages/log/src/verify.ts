import { merkleRoot } from "./merkle.js";
import {
  ZERO_HASH,
  verifyCheckpointSelf,
  verifyEntrySelf,
} from "./store.js";
import type { AnchorBackend } from "./anchor.js";
import type { Checkpoint, EvidenceBundle, LogEntry } from "./types.js";

/**
 * Independent verification of a log. Takes only data — entries, checkpoints,
 * trusted signer keys — so the auditor's copy of this code never touches the
 * operator's database or services (acceptance criterion: zero trust in the
 * operator).
 *
 * Every check FAILS CLOSED: any problem produces a finding naming the exact
 * position and what was expected. Silence is never a pass.
 */

export type FindingSeverity = "fatal" | "warning";

export interface Finding {
  severity: FindingSeverity;
  code: string;
  message: string;
  /** Entry sequence number or checkpoint size the finding refers to. */
  at?: number;
}

export interface VerificationReport {
  ok: boolean;
  entriesChecked: number;
  checkpointsChecked: number;
  anchorsChecked: number;
  findings: Finding[];
}

export interface VerifyOptions {
  /**
   * Public keys the auditor accepts, by actor name (hex Ed25519). An entry
   * signed by a key not listed for its actor is a fatal finding even if the
   * signature itself is valid — otherwise an operator could sign history with
   * a freshly minted key.
   */
  trustedSigners?: Record<string, string>;
  /** Backends used to re-verify anchors. Omit to skip anchor verification. */
  anchorBackends?: AnchorBackend[];
  /**
   * Require every checkpoint to carry anchors from at least this many
   * distinct TSAs. Default 0 (report only).
   */
  minAnchorsPerCheckpoint?: number;
}

function fatal(code: string, message: string, at?: number): Finding {
  return at === undefined ? { severity: "fatal", code, message } : { severity: "fatal", code, message, at };
}

function warn(code: string, message: string, at?: number): Finding {
  return at === undefined ? { severity: "warning", code, message } : { severity: "warning", code, message, at };
}

/**
 * Verify the entry chain: per-entry hash and signature, sequence continuity,
 * prevHash linkage, monotonic timestamps, and signer trust.
 */
export function verifyChain(entries: LogEntry[], opts: VerifyOptions = {}): Finding[] {
  const findings: Finding[] = [];
  if (entries.length === 0) return findings;

  let prev: LogEntry | null = null;
  for (const [i, entry] of entries.entries()) {
    // Sequence numbers must be dense and ordered — a gap means a dropped
    // entry, a repeat means an injected one.
    if (entry.seq !== i) {
      findings.push(
        fatal(
          "SEQ_DISCONTINUITY",
          `entry at position ${i} declares seq ${entry.seq}: the log has a gap, a duplicate, or has been reordered`,
          entry.seq,
        ),
      );
    }

    const self = verifyEntrySelf(entry);
    if (!self.ok) {
      findings.push(
        fatal("ENTRY_INVALID", `entry ${entry.seq} (${entry.type}): ${self.reason}`, entry.seq),
      );
    }

    // Chain linkage.
    if (prev === null) {
      if (entry.prevHash !== ZERO_HASH) {
        findings.push(
          fatal(
            "CHAIN_ROOT_INVALID",
            `first entry must have an all-zero prevHash, found ${entry.prevHash}: entries before it have been removed`,
            entry.seq,
          ),
        );
      }
    } else if (entry.prevHash !== prev.hash) {
      findings.push(
        fatal(
          "CHAIN_BROKEN",
          `entry ${entry.seq} links to prevHash ${entry.prevHash} but entry ${prev.seq} hashes to ${prev.hash}: history has been modified, reordered, or spliced at this point`,
          entry.seq,
        ),
      );
    }

    // Timestamps must not go backwards. Clock skew within a service is a
    // warning; it is evidence quality, not proof of tampering.
    if (prev !== null && entry.ts < prev.ts) {
      findings.push(
        warn(
          "TIMESTAMP_REGRESSION",
          `entry ${entry.seq} is timestamped ${new Date(entry.ts).toISOString()}, before entry ${prev.seq} at ${new Date(prev.ts).toISOString()}`,
          entry.seq,
        ),
      );
    }

    if (opts.trustedSigners) {
      const trusted = opts.trustedSigners[entry.actor];
      if (trusted === undefined) {
        findings.push(
          fatal(
            "SIGNER_UNKNOWN",
            `entry ${entry.seq} was written by actor "${entry.actor}", which is not in the trusted signer set`,
            entry.seq,
          ),
        );
      } else if (trusted !== entry.signerPublicKey) {
        findings.push(
          fatal(
            "SIGNER_UNTRUSTED",
            `entry ${entry.seq} is signed by ${entry.signerPublicKey} but actor "${entry.actor}" is pinned to ${trusted}: the log was signed with a substituted key`,
            entry.seq,
          ),
        );
      }
    }

    prev = entry;
  }

  return findings;
}

/**
 * Verify checkpoints against the entries they claim to cover: signature,
 * Merkle root recomputation, and head-hash linkage.
 */
export function verifyCheckpoints(
  entries: LogEntry[],
  checkpoints: Checkpoint[],
  opts: VerifyOptions = {},
): Finding[] {
  const findings: Finding[] = [];
  const hashes = entries.map((e) => Buffer.from(e.hash, "hex"));

  for (const cp of checkpoints) {
    const self = verifyCheckpointSelf(cp);
    if (!self.ok) {
      findings.push(fatal("CHECKPOINT_INVALID", self.reason ?? "invalid", cp.size));
      continue;
    }

    if (cp.size > entries.length) {
      findings.push(
        fatal(
          "CHECKPOINT_OVERRUN",
          `checkpoint claims to cover ${cp.size} entries but the log holds ${entries.length}: entries covered by a published checkpoint have been removed`,
          cp.size,
        ),
      );
      continue;
    }

    const covered = hashes.slice(0, cp.size);
    const recomputed = merkleRoot(covered).toString("hex");
    if (recomputed !== cp.root) {
      findings.push(
        fatal(
          "CHECKPOINT_ROOT_MISMATCH",
          `checkpoint at size ${cp.size} commits to root ${cp.root} but the entries recompute to ${recomputed}: entries covered by this checkpoint have been altered`,
          cp.size,
        ),
      );
    }

    const head = entries[cp.size - 1];
    if (head && head.hash !== cp.headHash) {
      findings.push(
        fatal(
          "CHECKPOINT_HEAD_MISMATCH",
          `checkpoint at size ${cp.size} names head ${cp.headHash} but entry ${cp.size - 1} hashes to ${head.hash}`,
          cp.size,
        ),
      );
    }

    if (opts.trustedSigners) {
      const pinned = Object.values(opts.trustedSigners);
      if (pinned.length > 0 && !pinned.includes(cp.signerPublicKey)) {
        findings.push(
          fatal(
            "CHECKPOINT_SIGNER_UNTRUSTED",
            `checkpoint at size ${cp.size} is signed by ${cp.signerPublicKey}, which is not a trusted signer`,
            cp.size,
          ),
        );
      }
    }

    const min = opts.minAnchorsPerCheckpoint ?? 0;
    const distinctTsas = new Set(cp.anchors.map((a) => a.tsa));
    if (distinctTsas.size < min) {
      findings.push(
        fatal(
          "CHECKPOINT_UNDER_ANCHORED",
          `checkpoint at size ${cp.size} is anchored to ${distinctTsas.size} independent TSA(s), policy requires ${min}`,
          cp.size,
        ),
      );
    }
  }

  // Checkpoints must be consistent with each other: a larger checkpoint must
  // extend a smaller one, never contradict it.
  const sorted = [...checkpoints].sort((a, b) => a.size - b.size);
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1]!;
    const cur = sorted[i]!;
    if (prev.size === cur.size && prev.root !== cur.root) {
      findings.push(
        fatal(
          "CHECKPOINT_FORK",
          `two checkpoints at size ${cur.size} publish different roots (${prev.root} and ${cur.root}): the operator has published a forked history`,
          cur.size,
        ),
      );
    }
    if (cur.ts < prev.ts) {
      findings.push(
        warn(
          "CHECKPOINT_TIME_REGRESSION",
          `checkpoint at size ${cur.size} is timestamped before the smaller checkpoint at size ${prev.size}`,
          cur.size,
        ),
      );
    }
  }

  return findings;
}

/**
 * Verify anchor tokens: each must structurally bind to its checkpoint root,
 * and its asserted time must be consistent with the checkpoint it anchors.
 */
export async function verifyAnchors(
  checkpoints: Checkpoint[],
  backends: AnchorBackend[],
): Promise<{ findings: Finding[]; anchorsChecked: number }> {
  const findings: Finding[] = [];
  let anchorsChecked = 0;

  for (const cp of checkpoints) {
    const root = Buffer.from(cp.root, "hex");
    for (const anchor of cp.anchors) {
      const backend = backends.find((b) => b.name === anchor.tsa);
      if (!backend) {
        findings.push(
          warn(
            "ANCHOR_BACKEND_UNAVAILABLE",
            `checkpoint ${cp.size} carries an anchor from "${anchor.tsa}", for which no verification backend is configured; token not checked`,
            cp.size,
          ),
        );
        continue;
      }
      try {
        await backend.verify(anchor, root);
        anchorsChecked++;
      } catch (err) {
        findings.push(
          fatal(
            "ANCHOR_INVALID",
            `checkpoint ${cp.size}, anchor from ${anchor.tsa}: ${(err as Error).message}`,
            cp.size,
          ),
        );
        continue;
      }

      // A TSA asserting a time far from when we say we checkpointed is
      // exactly the T5/T6 signal worth surfacing.
      const skew = anchor.genTime - cp.ts;
      if (skew < -60_000) {
        findings.push(
          fatal(
            "ANCHOR_PREDATES_CHECKPOINT",
            `checkpoint ${cp.size} claims ${new Date(cp.ts).toISOString()} but ${anchor.tsa} timestamped its root at ${new Date(anchor.genTime).toISOString()}, ${Math.round(-skew / 1000)}s earlier: the checkpoint timestamp cannot be trusted`,
            cp.size,
          ),
        );
      } else if (skew > 24 * 60 * 60 * 1000) {
        findings.push(
          warn(
            "ANCHOR_LATE",
            `checkpoint ${cp.size} was anchored by ${anchor.tsa} ${Math.round(skew / 3_600_000)}h after it was created; the window before anchoring is unattested`,
            cp.size,
          ),
        );
      }
    }
  }

  return { findings, anchorsChecked };
}

/** Full verification of an evidence bundle. */
export async function verifyEvidence(
  bundle: EvidenceBundle,
  opts: VerifyOptions = {},
): Promise<VerificationReport> {
  const findings: Finding[] = [];

  if (bundle.version !== 1) {
    findings.push(
      fatal("EVIDENCE_VERSION", `unsupported evidence bundle version ${String(bundle.version)}`),
    );
  }

  const effective: VerifyOptions = {
    ...opts,
    trustedSigners: opts.trustedSigners ?? bundle.signers,
  };

  findings.push(...verifyChain(bundle.entries, effective));
  findings.push(...verifyCheckpoints(bundle.entries, bundle.checkpoints, effective));

  let anchorsChecked = 0;
  if (opts.anchorBackends && opts.anchorBackends.length > 0) {
    const res = await verifyAnchors(bundle.checkpoints, opts.anchorBackends);
    findings.push(...res.findings);
    anchorsChecked = res.anchorsChecked;
  }

  return {
    ok: !findings.some((f) => f.severity === "fatal"),
    entriesChecked: bundle.entries.length,
    checkpointsChecked: bundle.checkpoints.length,
    anchorsChecked,
    findings,
  };
}
