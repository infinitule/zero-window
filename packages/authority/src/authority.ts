import { randomBytes, type KeyProvider } from "@zw/crypto";
import { TransparencyLog } from "@zw/log";
import { Logger, MetricsRegistry, HealthRegistry, type Counter, type Histogram } from "@zw/ops";
import {
  issueAdmitToken,
  registrationHash,
  type AdmitToken,
} from "./admit.js";
import { provisionExam, recordDistribution, type ProvisionOptions, type ProvisionResult } from "./provision.js";
import {
  buildOfflineMedium,
  performRelease,
  signSchedule,
  RELEASE_BUDGET_MS,
  type OfflineReleaseMedium,
  type ReleaseDeps,
  type ReleaseMetrics,
  type ReleaseOutcome,
  type SubmittedShare,
} from "./release.js";
import { AuthorityStore } from "./store.js";

/**
 * The authority service: a façade binding the store, transparency log, key
 * provider and metrics together. The HTTP layer (mTLS Fastify) and the CLI
 * are both thin wrappers over this class, so the online and offline paths
 * cannot diverge in behaviour.
 */

export interface AuthorityOptions {
  actor?: string;
  statePath: string;
  logPath: string;
  provider: KeyProvider;
  signingKeyId?: string;
  logger?: Logger;
  metricsRegistry?: MetricsRegistry;
  version?: string;
  now?: () => number;
}

export class Authority {
  readonly metrics: MetricsRegistry;
  readonly health: HealthRegistry;
  readonly logger: Logger;

  private readonly releaseMetrics: ReleaseMetrics;
  private readonly admitIssued: Counter;
  private readonly bundlesCreated: Counter;
  private readonly ingestDuration: Histogram;

  private constructor(
    readonly store: AuthorityStore,
    readonly log: TransparencyLog,
    private readonly provider: KeyProvider,
    private readonly signingKeyId: string,
    readonly publicKey: Buffer,
    opts: AuthorityOptions,
  ) {
    this.logger = opts.logger ?? new Logger({ service: "authority" });
    this.metrics = opts.metricsRegistry ?? new MetricsRegistry();
    this.health = new HealthRegistry("authority", opts.version ?? "1.0.0");
    this.now = opts.now ?? (() => Date.now());

    this.releaseMetrics = {
      // Buckets straddle the 500ms budget so an alert can fire on the ratio
      // of releases approaching it, before one actually breaches.
      kekLifetime: this.metrics.histogram(
        "zw_authority_plaintext_kek_lifetime_ms",
        "Lifetime of a reconstructed plaintext KEK, milliseconds (budget 500ms)",
        [1, 5, 10, 25, 50, 100, 250, 500, 1000],
      ),
      releasesTotal: this.metrics.counter(
        "zw_authority_releases_total",
        "Threshold releases completed",
      ),
      earlyAttemptsTotal: this.metrics.counter(
        "zw_authority_early_release_attempts_total",
        "Release attempts refused because T-0 had not arrived",
      ),
      budgetExceededTotal: this.metrics.counter(
        "zw_authority_kek_budget_exceeded_total",
        "Releases failed because the plaintext KEK lifetime budget was exceeded",
      ),
    };
    this.admitIssued = this.metrics.counter(
      "zw_authority_admit_tokens_issued_total",
      "Admit tokens issued",
    );
    this.bundlesCreated = this.metrics.counter(
      "zw_authority_bundles_created_total",
      "Exam bundles built and encrypted",
    );
    this.ingestDuration = this.metrics.histogram(
      "zw_authority_provision_duration_ms",
      "Wall time of a full provisioning run",
      [100, 500, 1000, 5000, 30000],
    );

    this.metrics
      .gauge("zw_authority_kek_lifetime_budget_ms", "Configured plaintext KEK lifetime budget")
      .set(RELEASE_BUDGET_MS);

    this.health.addLiveness("log", () => {
      this.log.size();
      return { status: "pass" as const };
    });
    this.health.addReadiness("key_provider", () => ({
      status: "pass" as const,
      detail: this.provider.kind,
    }));
    this.health.addReadiness("centres_enrolled", () => {
      const n = this.store.centres().length;
      return n > 0
        ? { status: "pass" as const, detail: `${n} centre(s)` }
        : { status: "warn" as const, detail: "no centres enrolled" };
    });
  }

  private readonly now: () => number;

  static async open(opts: AuthorityOptions): Promise<Authority> {
    const signingKeyId = opts.signingKeyId ?? "authority-signing";
    const store = AuthorityStore.open(opts.statePath);
    const log = await TransparencyLog.open({
      dbPath: opts.logPath,
      actor: opts.actor ?? "authority",
      provider: opts.provider,
      signingKeyId,
    });
    const publicKey = await opts.provider.ensureSigningKey(signingKeyId);
    return new Authority(store, log, opts.provider, signingKeyId, publicKey, opts);
  }

  // -- enrolment -------------------------------------------------------

  async enrolCentre(r: {
    centreId: string;
    boxPublicKey: Buffer;
    certFingerprint: string;
    hardwareId: string;
  }): Promise<void> {
    const at = this.now();
    this.store.enrolCentre({
      centreId: r.centreId,
      boxPublicKey: r.boxPublicKey.toString("hex"),
      certFingerprint: r.certFingerprint,
      hardwareId: r.hardwareId,
      enrolledAt: at,
    });
    await this.log.append({
      type: "CENTRE_ENROLLED",
      payload: {
        centre_id: r.centreId,
        cert_fingerprint: r.certFingerprint,
        hardware_id: r.hardwareId,
        box_public_key: r.boxPublicKey.toString("hex"),
      },
      ts: at,
    });
    this.metrics.gauge("zw_authority_centres_enrolled", "Enrolled centres").set(
      this.store.centres().length,
    );
  }

  enrolCustodian(r: {
    custodianId: string;
    name: string;
    boxPublicKey: Buffer;
    certFingerprint: string;
  }): void {
    this.store.enrolCustodian({
      custodianId: r.custodianId,
      name: r.name,
      boxPublicKey: r.boxPublicKey.toString("hex"),
      certFingerprint: r.certFingerprint,
      enrolledAt: this.now(),
    });
  }

  // -- F1 provisioning -------------------------------------------------

  async provision(
    opts: Omit<ProvisionOptions, "custodians" | "now"> & {
      custodians?: Array<{ custodianId: string; boxPublicKey: Buffer }>;
    },
  ): Promise<ProvisionResult> {
    const started = Date.now();
    const custodians =
      opts.custodians ??
      this.store.custodians().map((c) => ({
        custodianId: c.custodianId,
        boxPublicKey: Buffer.from(c.boxPublicKey, "hex"),
      }));
    const result = await provisionExam(
      { ...opts, custodians, now: this.now },
      { provider: this.provider, store: this.store, log: this.log },
    );
    this.bundlesCreated.inc({ exam_id: result.examId }, 2);
    this.ingestDuration.observe(Date.now() - started, { exam_id: result.examId });
    this.logger.info("exam provisioned", {
      exam_id: result.examId,
      paper_bundle: result.paper.bundleId,
      answers_bundle: result.answers.bundleId,
      threshold: opts.threshold,
      custodians: custodians.length,
    });
    return result;
  }

  async distribute(bundleId: string, centreId: string): Promise<void> {
    await recordDistribution(
      bundleId,
      centreId,
      { store: this.store, log: this.log },
      this.now(),
    );
  }

  // -- F2 admit tokens -------------------------------------------------

  /** Per-exam salt for registration-ID hashing (I-ADMIT-1). */
  static newRegistrationSalt(): Buffer {
    return randomBytes(32);
  }

  async issueAdmitTokens(opts: {
    examId: string;
    centreId: string;
    salt: Buffer;
    expiresAt: number;
    candidates: Array<{ registrationId: string; seat: string }>;
  }): Promise<AdmitToken[]> {
    const at = this.now();
    const tokens: AdmitToken[] = [];
    for (const c of opts.candidates) {
      const token = await issueAdmitToken(this.provider, this.signingKeyId, {
        examId: opts.examId,
        centreId: opts.centreId,
        seat: c.seat,
        registrationHash: registrationHash(opts.salt, c.registrationId),
        expiresAt: opts.expiresAt,
      });
      tokens.push(token);
    }
    // The log records the COUNT and the set of token hashes, never the
    // registration ids or the tokens themselves (T8).
    const { admitTokenHash } = await import("./admit.js");
    for (const [i, t] of tokens.entries()) {
      const { signature: _sig, ...body } = t;
      this.store.putAdmitToken({
        tokenHash: admitTokenHash(body).toString("hex"),
        examId: opts.examId,
        centreId: opts.centreId,
        seat: opts.candidates[i]!.seat,
        issuedAt: at,
      });
    }
    await this.log.append({
      type: "ADMIT_TOKENS_ISSUED",
      payload: {
        exam_id: opts.examId,
        centre_id: opts.centreId,
        count: tokens.length,
        expires_at: opts.expiresAt,
        token_hashes: tokens.map((t) => {
          const { signature: _s, ...body } = t;
          return admitTokenHash(body).toString("hex");
        }),
      },
      ts: at,
    });
    this.admitIssued.inc({ exam_id: opts.examId, centre_id: opts.centreId }, tokens.length);
    return tokens;
  }

  // -- F3 release ------------------------------------------------------

  async scheduleRelease(opts: {
    examId: string;
    bundleId: string;
    releaseAt: number;
  }): Promise<void> {
    const body = { v: 1, examId: opts.examId, bundleId: opts.bundleId, releaseAt: opts.releaseAt };
    const signature = await signSchedule(this.provider, this.signingKeyId, body);
    const at = this.now();
    this.store.putSchedule({ ...opts, signature, createdAt: at });
    await this.log.append({
      type: "RELEASE_SCHEDULED",
      payload: {
        bundle_id: opts.bundleId,
        exam_id: opts.examId,
        release_at: opts.releaseAt,
        schedule_signature: signature,
      },
      ts: at,
    });
  }

  async release(opts: {
    bundleId: string;
    shares: SubmittedShare[];
    centreIds?: string[];
    now?: number;
  }): Promise<ReleaseOutcome> {
    const deps: ReleaseDeps = {
      provider: this.provider,
      store: this.store,
      log: this.log,
      authorityPublicKey: this.publicKey,
      metrics: this.releaseMetrics,
      logger: this.logger,
      now: this.now,
    };
    return performRelease(opts, deps);
  }

  /**
   * Offline release (F3 fallback, T10): perform the threshold release and
   * package the wrapped KEKs into a signed medium for physical transport.
   * Shares the same `performRelease` path as the online endpoint, so the
   * fallback cannot drift from the primary — including the schedule check,
   * the KEK-lifetime budget and every log event.
   */
  async releaseOffline(opts: {
    bundleId: string;
    shares: SubmittedShare[];
    centreIds?: string[];
    now?: number;
  }): Promise<{ outcome: ReleaseOutcome; medium: OfflineReleaseMedium }> {
    const outcome = await this.release(opts);
    const bundle = this.store.bundle(opts.bundleId);
    if (!bundle) throw new Error(`unknown bundle ${opts.bundleId}`);
    const medium = await buildOfflineMedium(
      outcome,
      bundle.kekFingerprint,
      this.provider,
      this.signingKeyId,
      opts.now ?? this.now(),
    );
    return { outcome, medium };
  }

  // -- F5 close --------------------------------------------------------

  async closeExam(examId: string, centreId: string): Promise<void> {
    await this.log.append({
      type: "EXAM_CLOSED",
      payload: { exam_id: examId, centre_id: centreId },
      ts: this.now(),
    });
  }

  async checkpoint(): Promise<void> {
    await this.log.createCheckpoint(this.now());
  }

  async close(): Promise<void> {
    this.log.close();
    this.store.close();
    await this.provider.close();
  }
}
