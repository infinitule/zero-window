import type { CanonicalValue } from "./canonical.js";

/**
 * Transparency log event vocabulary. Every custody event in flows F1–F5 maps
 * to exactly one of these.
 *
 * PRIVACY INVARIANT I-LOG-1 (threat T8): the log carries hashes, timestamps,
 * identifiers and counts ONLY. No candidate names, no registration numbers,
 * no exam content, and no key material. `token_hash` is a hash of the admit
 * token, not the token. Enforced by test in @zw/verifier and by the payload
 * schemas below. See PRIVACY.md.
 */
export const EVENT_TYPES = [
  // F1 provisioning
  "BUNDLE_CREATED",
  "SHARES_ISSUED",
  "BUNDLE_DISTRIBUTED",
  "BUNDLE_RECEIVED",
  // F2 registration
  "ADMIT_TOKENS_ISSUED",
  // F3 threshold release
  "RELEASE_SCHEDULED",
  "EARLY_RELEASE_ATTEMPT",
  "CUSTODIAN_APPROVED",
  "KEK_RELEASED",
  "KEK_RECEIVED",
  // F4 generation and printing
  "CANDIDATE_CHECKED_IN",
  "PAPER_GENERATED",
  "PAPER_PRINTED",
  "PRINTER_FAILOVER",
  // F5 close and audit
  "EXAM_CLOSED",
  "ANSWER_KEY_RELEASED",
  // operational
  "CENTRE_ENROLLED",
  "CENTRE_RESTORED",
  "CHECKPOINT",
] as const;

export type EventType = (typeof EVENT_TYPES)[number];

export interface LogEntry {
  /** 0-based position in the log. */
  seq: number;
  /** Integer milliseconds since epoch, from the writing service's clock. */
  ts: number;
  type: EventType;
  /** Which service instance wrote this (e.g. "authority", "centre-A"). */
  actor: string;
  /** Event-specific fields. Must satisfy I-LOG-1. */
  payload: Record<string, CanonicalValue>;
  /** hex BLAKE2b-256 of the previous entry's `hash`; all-zero for seq 0. */
  prevHash: string;
  /** hex BLAKE2b-256 over the domain-separated canonical entry body. */
  hash: string;
  /** hex Ed25519 signature over the same bytes as `hash`, by `actor`'s key. */
  signature: string;
  /** hex Ed25519 public key that produced `signature`. */
  signerPublicKey: string;
}

/** The fields covered by `hash` and `signature` — everything but them. */
export interface LogEntryBody {
  seq: number;
  ts: number;
  type: EventType;
  actor: string;
  payload: Record<string, CanonicalValue>;
  prevHash: string;
}

export interface Checkpoint {
  /** Number of entries covered: this checkpoint commits to seq 0..size-1. */
  size: number;
  /** hex Merkle root over entry hashes 0..size-1 (RFC 6962 hashing). */
  root: string;
  /** hex hash of the entry at seq size-1 — ties the root to the chain. */
  headHash: string;
  ts: number;
  /** hex Ed25519 signature over the canonical checkpoint body. */
  signature: string;
  signerPublicKey: string;
  /** RFC 3161 tokens anchoring `root`, one per TSA. */
  anchors: Anchor[];
}

export interface CheckpointBody {
  size: number;
  root: string;
  headHash: string;
  ts: number;
}

export interface Anchor {
  /** Anchor backend that produced this token. */
  backend: "rfc3161" | "opentimestamps";
  /** Human-readable TSA identity, e.g. "freetsa.org". */
  tsa: string;
  /** TSA endpoint the token came from. */
  url: string;
  /** base64 DER TimeStampToken (RFC 3161) or OTS proof. */
  token: string;
  /** Genuine time asserted by the TSA, integer ms. Parsed from the token. */
  genTime: number;
  /** hex of the message imprint the TSA signed — must equal the root. */
  imprint: string;
  /** Hash algorithm OID used in the message imprint. */
  hashAlgorithm: string;
}

/** Portable evidence bundle: what an auditor receives. */
export interface EvidenceBundle {
  version: 1;
  exam_id: string;
  entries: LogEntry[];
  checkpoints: Checkpoint[];
  /** Public keys trusted to sign entries, by actor. hex Ed25519. */
  signers: Record<string, string>;
}
