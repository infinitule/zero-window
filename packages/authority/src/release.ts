import { domainHash, verifyDomain, type KekRecipient, type KeyProvider } from "@zw/crypto";
import type { TransparencyLog } from "@zw/log";
import type { Histogram, Counter, Logger } from "@zw/ops";
import { canonicalJson } from "./bank.js";
import type { AuthorityStore } from "./store.js";

/**
 * F3 threshold release.
 *
 * INVARIANT I-REL-1 (T2): release is refused before the scheduled T-0. The
 * schedule is signed by the authority and verified on every attempt, so an
 * operator who edits the schedule row in SQLite invalidates the signature and
 * the release refuses rather than proceeding early.
 *
 * INVARIANT I-REL-2 (T1): the reconstructed plaintext KEK exists only inside
 * the key provider's reconstruct-wrap-release call, in locked memory, and is
 * zeroized before that call returns — on the failure path too. Its lifetime
 * is measured and must stay under RELEASE_BUDGET_MS.
 *
 * INVARIANT I-REL-3: an early attempt is never silently dropped. It is
 * logged as EARLY_RELEASE_ATTEMPT and surfaced as a metric an alert can fire
 * on, because a custodian trying to release early is the single most
 * important signal this system can produce.
 */

/** Plaintext-KEK lifetime budget (F3). Exceeding it fails the release. */
export const RELEASE_BUDGET_MS = 500;

export const SCHEDULE_DOMAIN = "release-schedule";

export interface ScheduleBody {
  v: number;
  examId: string;
  bundleId: string;
  /** Epoch ms of T-0. */
  releaseAt: number;
}

export function scheduleBytes(body: ScheduleBody): Buffer {
  return canonicalJson(body);
}

export async function signSchedule(
  provider: KeyProvider,
  signingKeyId: string,
  body: ScheduleBody,
): Promise<string> {
  return (await provider.sign(signingKeyId, SCHEDULE_DOMAIN, scheduleBytes(body))).toString("hex");
}

export function verifyScheduleSignature(
  body: ScheduleBody,
  signatureHex: string,
  authorityPublicKey: Buffer,
): boolean {
  let sig: Buffer;
  try {
    sig = Buffer.from(signatureHex, "hex");
  } catch {
    return false;
  }
  return verifyDomain(SCHEDULE_DOMAIN, scheduleBytes(body), sig, authorityPublicKey);
}

export class ReleaseError extends Error {
  constructor(
    message: string,
    readonly code:
      | "UNKNOWN_BUNDLE"
      | "NO_SCHEDULE"
      | "SCHEDULE_TAMPERED"
      | "TOO_EARLY"
      | "INSUFFICIENT_SHARES"
      | "SHARE_INVALID"
      | "NO_RECIPIENTS"
      | "BUDGET_EXCEEDED"
      | "ALREADY_RELEASED",
  ) {
    super(message);
    this.name = "ReleaseError";
  }
}

export interface ReleaseMetrics {
  kekLifetime: Histogram;
  releasesTotal: Counter;
  earlyAttemptsTotal: Counter;
  budgetExceededTotal: Counter;
}

export interface ReleaseDeps {
  provider: KeyProvider;
  store: AuthorityStore;
  log: TransparencyLog;
  authorityPublicKey: Buffer;
  metrics?: ReleaseMetrics;
  logger?: Logger;
  now?: () => number;
}

export interface SubmittedShare {
  custodianId: string;
  /** Serialized ShamirShare, as opened by the custodian from their sealed envelope. */
  shareBlob: Buffer;
}

export interface ReleaseOutcome {
  bundleId: string;
  examId: string;
  /** Per-centre wrapped KEKs, sealed to each centre's box public key. */
  wrapped: Array<{ centreId: string; sealed: Buffer }>;
  kekLifetimeMs: number;
  custodians: string[];
}

/**
 * Perform a threshold release. Callers: the mTLS release endpoint (online)
 * and `zw-authority release --offline` (custodians physically present).
 * Both share this path so the offline fallback cannot drift from the primary.
 */
export async function performRelease(
  opts: {
    bundleId: string;
    shares: SubmittedShare[];
    /** Restrict release to these centres; defaults to all that received the bundle. */
    centreIds?: string[];
    /** Override for the offline path where the operator asserts the time. */
    now?: number;
  },
  deps: ReleaseDeps,
): Promise<ReleaseOutcome> {
  const now = opts.now ?? deps.now?.() ?? Date.now();
  const { store, provider, log, metrics, logger } = deps;

  const bundle = store.bundle(opts.bundleId);
  if (!bundle) {
    throw new ReleaseError(`unknown bundle ${opts.bundleId}`, "UNKNOWN_BUNDLE");
  }

  const schedule = store.schedule(opts.bundleId);
  if (!schedule) {
    throw new ReleaseError(
      `no release schedule for ${opts.bundleId}: refusing to release a bundle that was never scheduled`,
      "NO_SCHEDULE",
    );
  }

  // I-REL-1: the schedule is only trustworthy if its signature still verifies.
  const scheduleBody: ScheduleBody = {
    v: 1,
    examId: schedule.examId,
    bundleId: schedule.bundleId,
    releaseAt: schedule.releaseAt,
  };
  if (!verifyScheduleSignature(scheduleBody, schedule.signature, deps.authorityPublicKey)) {
    throw new ReleaseError(
      `release schedule for ${opts.bundleId} does not verify against the authority key: ` +
        "the schedule has been altered since it was signed",
      "SCHEDULE_TAMPERED",
    );
  }

  if (now < schedule.releaseAt) {
    // I-REL-3: refuse, record, alert — never silently drop.
    const earlyByMs = schedule.releaseAt - now;
    metrics?.earlyAttemptsTotal.inc({ exam_id: bundle.examId, bundle_id: opts.bundleId });
    logger?.warn("early release attempt refused", {
      bundle_id: opts.bundleId,
      exam_id: bundle.examId,
      early_by_ms: earlyByMs,
      custodians: opts.shares.map((s) => s.custodianId),
    });
    await log.append({
      type: "EARLY_RELEASE_ATTEMPT",
      payload: {
        bundle_id: opts.bundleId,
        exam_id: bundle.examId,
        release_at: schedule.releaseAt,
        attempted_at: now,
        early_by_ms: earlyByMs,
        custodian_ids: opts.shares.map((s) => s.custodianId),
      },
      ts: now,
    });
    throw new ReleaseError(
      `release refused: T-0 for ${opts.bundleId} is ${new Date(schedule.releaseAt).toISOString()}, ` +
        `${Math.ceil(earlyByMs / 1000)}s away`,
      "TOO_EARLY",
    );
  }

  if (opts.shares.length < bundle.threshold) {
    throw new ReleaseError(
      `${opts.shares.length} share(s) submitted, threshold for ${opts.bundleId} is ${bundle.threshold}`,
      "INSUFFICIENT_SHARES",
    );
  }

  const seen = new Set<string>();
  for (const s of opts.shares) {
    if (seen.has(s.custodianId)) {
      throw new ReleaseError(
        `custodian ${s.custodianId} submitted more than one share: ` +
          "a threshold cannot be met by one custodian submitting repeatedly",
        "SHARE_INVALID",
      );
    }
    seen.add(s.custodianId);
    if (!store.custodian(s.custodianId)) {
      throw new ReleaseError(`custodian ${s.custodianId} is not enrolled`, "SHARE_INVALID");
    }
  }

  const centreIds = opts.centreIds ?? store.distributedCentres(opts.bundleId);
  if (centreIds.length === 0) {
    throw new ReleaseError(
      `bundle ${opts.bundleId} has not been distributed to any centre: nothing to release to`,
      "NO_RECIPIENTS",
    );
  }
  const recipients: KekRecipient[] = centreIds.map((centreId) => {
    const centre = store.centre(centreId);
    if (!centre) throw new ReleaseError(`centre ${centreId} is not enrolled`, "NO_RECIPIENTS");
    return { recipientId: centreId, boxPublicKey: Buffer.from(centre.boxPublicKey, "hex") };
  });

  // Record each custodian's approval before reconstruction, so the evidence
  // of who authorised a release survives even if the release itself fails.
  for (const s of opts.shares) {
    await log.append({
      type: "CUSTODIAN_APPROVED",
      payload: {
        bundle_id: opts.bundleId,
        exam_id: bundle.examId,
        custodian_id: s.custodianId,
        share_hash: domainHash("submitted-share", s.shareBlob).toString("hex"),
      },
      ts: now,
    });
  }

  // I-REL-2: the entire plaintext-KEK lifetime is inside this call.
  const result = await provider.reconstructWrapRelease(
    opts.shares.map((s) => s.shareBlob),
    recipients,
    Buffer.from(bundle.kekFingerprint, "hex"),
  );
  const kekLifetimeMs = result.plaintextKekLifetimeUs / 1000;

  metrics?.kekLifetime.observe(kekLifetimeMs, { exam_id: bundle.examId });
  if (kekLifetimeMs > RELEASE_BUDGET_MS) {
    // The KEK is already zeroized; the release is failed because a run that
    // blew the budget indicates the host is not fit for this duty (paging,
    // contention, a debugger attached) and must be investigated before T-0.
    metrics?.budgetExceededTotal.inc({ exam_id: bundle.examId });
    logger?.error("plaintext KEK lifetime exceeded budget", {
      bundle_id: opts.bundleId,
      kek_lifetime_ms: kekLifetimeMs,
      budget_ms: RELEASE_BUDGET_MS,
    });
    throw new ReleaseError(
      `plaintext KEK lifetime ${kekLifetimeMs.toFixed(1)}ms exceeded the ` +
        `${RELEASE_BUDGET_MS}ms budget; KEK was zeroized and the release was failed`,
      "BUDGET_EXCEEDED",
    );
  }

  const releasedAt = now;
  const wrapped = result.wrapped.map((w) => ({ centreId: w.recipientId, sealed: w.sealed }));
  for (const w of wrapped) {
    store.recordRelease(opts.bundleId, w.centreId, releasedAt, w.sealed);
  }

  await log.append({
    type: "KEK_RELEASED",
    payload: {
      bundle_id: opts.bundleId,
      exam_id: bundle.examId,
      kek_fingerprint: bundle.kekFingerprint,
      threshold: bundle.threshold,
      custodian_ids: opts.shares.map((s) => s.custodianId),
      centre_ids: wrapped.map((w) => w.centreId),
      // Microseconds as an integer: canonical JSON admits integers only, so
      // that an evidence bundle re-encodes byte-identically on any platform
      // (a float would not). The budget is expressed in ms; the log keeps
      // full resolution.
      kek_lifetime_us: result.plaintextKekLifetimeUs,
      kek_budget_ms: RELEASE_BUDGET_MS,
      scheduled_at: schedule.releaseAt,
      released_at: releasedAt,
    },
    ts: releasedAt,
  });

  metrics?.releasesTotal.inc({ exam_id: bundle.examId, bundle_id: opts.bundleId });
  logger?.info("threshold release complete", {
    bundle_id: opts.bundleId,
    centres: wrapped.length,
    kek_lifetime_ms: kekLifetimeMs,
  });

  return {
    bundleId: opts.bundleId,
    examId: bundle.examId,
    wrapped,
    kekLifetimeMs,
    custodians: opts.shares.map((s) => s.custodianId),
  };
}

/**
 * Offline release medium (F3 fallback, T10): a signed, self-describing
 * envelope written to removable media when the network is unavailable. The
 * centre verifies the signature before unwrapping, so media substitution is
 * detectable.
 */
export interface OfflineReleaseMedium {
  v: number;
  bundleId: string;
  examId: string;
  releasedAt: number;
  kekFingerprint: string;
  entries: Array<{ centreId: string; sealedHex: string }>;
  signature: string;
}

export async function buildOfflineMedium(
  outcome: ReleaseOutcome,
  kekFingerprint: string,
  provider: KeyProvider,
  signingKeyId: string,
  releasedAt: number,
): Promise<OfflineReleaseMedium> {
  const body = {
    v: 1,
    bundleId: outcome.bundleId,
    examId: outcome.examId,
    releasedAt,
    kekFingerprint,
    entries: outcome.wrapped.map((w) => ({
      centreId: w.centreId,
      sealedHex: w.sealed.toString("hex"),
    })),
  };
  const signature = await provider.sign(signingKeyId, "offline-release", canonicalJson(body));
  return { ...body, signature: signature.toString("hex") };
}

export function verifyOfflineMedium(
  medium: OfflineReleaseMedium,
  authorityPublicKey: Buffer,
): boolean {
  const { signature, ...body } = medium;
  let sig: Buffer;
  try {
    sig = Buffer.from(signature, "hex");
  } catch {
    return false;
  }
  return verifyDomain("offline-release", canonicalJson(body), sig, authorityPublicKey);
}
