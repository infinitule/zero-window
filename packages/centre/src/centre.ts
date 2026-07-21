import {
  domainHash,
  parseAead,
  type KeyProvider,
} from "@zw/crypto";
import { TransparencyLog } from "@zw/log";
import {
  bundleAssociatedData,
  decodeAdmitToken,
  verifyAdmitToken,
  verifyOfflineMedium,
  type AdmitToken,
  type OfflineReleaseMedium,
  type PaperBundleContent,
} from "@zw/authority";
import { HealthRegistry, Logger, MetricsRegistry, type Counter } from "@zw/ops";
import { assemblePaper } from "./assemble.js";
import { renderPaper } from "./render.js";
import { PrintService, type PrinterTarget } from "./print.js";
import { CentreStore } from "./store.js";

/**
 * The centre node daemon core.
 *
 * INVARIANT I-CTR-2 (autonomy, T10): every method needed on exam day after
 * key receipt — checkIn, generatePaper, printPaper, closeExam — takes no
 * network dependency of any kind. The authority could vanish the moment the
 * wrapped KEK arrives and the exam proceeds to completion. This is enforced
 * by construction (no client object is reachable from those paths) and by
 * the autonomy integration test, which kills the authority mid-exam.
 */

export interface CentreOptions {
  centreId: string;
  examId: string;
  statePath: string;
  logPath: string;
  provider: KeyProvider;
  /** Ed25519 key the authority signs with; verified out-of-band at enrolment. */
  authorityPublicKey: Buffer;
  printers?: PrinterTarget[];
  spoolDir?: string;
  logger?: Logger;
  now?: () => number;
}

export class CentreError extends Error {
  constructor(
    message: string,
    readonly code:
      | "BUNDLE_HASH_MISMATCH"
      | "BUNDLE_UNKNOWN"
      | "DUPLICATE_BUNDLE"
      | "KEK_NOT_HELD"
      | "KEK_FINGERPRINT_MISMATCH"
      | "MEDIUM_INVALID"
      | "ADMIT_REFUSED"
      | "DUPLICATE_CHECKIN"
      | "SEAT_TAKEN"
      | "SEAT_MISMATCH"
      | "NOT_CHECKED_IN"
      | "ALREADY_GENERATED"
      | "NOT_GENERATED",
  ) {
    super(message);
    this.name = "CentreError";
  }
}

const BOX_KEY_ID = "centre-box";

export class CentreNode {
  readonly metrics: MetricsRegistry;
  readonly health: HealthRegistry;
  readonly logger: Logger;

  private readonly checkinsTotal: Counter;
  private readonly papersGenerated: Counter;
  private readonly admitRefused: Counter;
  private printService: PrintService | null;
  /** bundleId → in-memory KEK id inside the provider. Never persisted. */
  private readonly heldKeks = new Map<string, string>();
  private readonly now: () => number;

  private constructor(
    readonly store: CentreStore,
    readonly log: TransparencyLog,
    private readonly provider: KeyProvider,
    readonly boxPublicKey: Buffer,
    private readonly opts: CentreOptions,
  ) {
    this.logger = opts.logger ?? new Logger({ service: `centre-${opts.centreId}` });
    this.metrics = new MetricsRegistry();
    this.health = new HealthRegistry(`centre-${opts.centreId}`, "1.0.0");
    this.now = opts.now ?? (() => Date.now());

    this.checkinsTotal = this.metrics.counter("zw_centre_checkins_total", "Candidates checked in");
    this.papersGenerated = this.metrics.counter(
      "zw_centre_papers_generated_total",
      "Papers generated",
    );
    this.admitRefused = this.metrics.counter(
      "zw_centre_admit_refused_total",
      "Admit tokens refused at check-in",
    );

    this.printService =
      (opts.printers?.length ?? 0) > 0 || opts.spoolDir
        ? new PrintService({
            printers: opts.printers ?? [],
            ...(opts.spoolDir ? { spoolDir: opts.spoolDir } : {}),
            logger: this.logger,
            metrics: {
              printedTotal: this.metrics.counter("zw_centre_papers_printed_total", "Papers printed"),
              failoversTotal: this.metrics.counter(
                "zw_centre_printer_failovers_total",
                "Printer failovers",
              ),
            },
            onFailover: async (fromPrinterId, reason) => {
              await this.log.append({
                type: "PRINTER_FAILOVER",
                payload: {
                  centre_id: this.opts.centreId,
                  exam_id: this.opts.examId,
                  printer_id: fromPrinterId,
                  reason: reason.slice(0, 200),
                },
                ts: this.now(),
              });
            },
          })
        : null;

    // Liveness: the process and its log. Readiness: whether T-0 duties can
    // be performed. Authority connectivity is deliberately NOT a check on
    // either (I-CTR-2): after key receipt its absence is normal operation.
    this.health.addLiveness("log", () => {
      this.log.size();
      return { status: "pass" as const };
    });
    this.health.addReadiness("bundle", () => {
      const b = this.store.bundle(this.paperBundleId());
      return b
        ? { status: "pass" as const }
        : { status: "warn" as const, detail: "paper bundle not yet received" };
    });
    this.health.addReadiness("kek", () => {
      return this.heldKeks.has(this.paperBundleId())
        ? { status: "pass" as const }
        : { status: "warn" as const, detail: "KEK not yet released" };
    });
    this.health.addReadiness("printing", () => {
      return this.printService
        ? { status: "pass" as const }
        : { status: "fail" as const, detail: "no printers or spool directory configured" };
    });
  }

  static async open(opts: CentreOptions): Promise<CentreNode> {
    const store = CentreStore.open(opts.statePath);
    const log = await TransparencyLog.open({
      dbPath: opts.logPath,
      actor: `centre-${opts.centreId}`,
      provider: opts.provider,
      signingKeyId: "centre-signing",
    });
    const boxPublicKey = await opts.provider.ensureBoxKey(BOX_KEY_ID);
    return new CentreNode(store, log, opts.provider, boxPublicKey, opts);
  }

  paperBundleId(): string {
    return `${this.opts.examId}:paper`;
  }

  // -- custody (F1 receive side, T3) -----------------------------------

  /**
   * Accept a ciphertext bundle. `expected` comes from the authority's
   * BUNDLE_DISTRIBUTED statement (relayed log entry); the centre verifies the
   * envelope hash BEFORE storing. A mismatched bundle is refused and the
   * refusal is evidence.
   */
  async receiveBundle(
    envelope: Buffer,
    expected: {
      bundleId: string;
      examId: string;
      kind: "paper" | "answers";
      bundleHash: string;
      kekFingerprint: string;
      threshold: number;
    },
  ): Promise<void> {
    const got = domainHash("bundle-envelope", envelope).toString("hex");
    if (got !== expected.bundleHash) {
      throw new CentreError(
        `bundle ${expected.bundleId} hash mismatch: expected ${expected.bundleHash}, ` +
          `computed ${got} — refusing custody (T3)`,
        "BUNDLE_HASH_MISMATCH",
      );
    }
    // Envelope must parse as AEAD ciphertext — refuse plaintext masquerading.
    parseAead(envelope);
    if (this.store.bundle(expected.bundleId)) {
      throw new CentreError(`bundle ${expected.bundleId} already held`, "DUPLICATE_BUNDLE");
    }
    const at = this.now();
    this.store.putBundle({
      bundleId: expected.bundleId,
      examId: expected.examId,
      kind: expected.kind,
      bundleHash: expected.bundleHash,
      kekFingerprint: expected.kekFingerprint,
      threshold: expected.threshold,
      receivedAt: at,
      ciphertext: envelope,
    });
    await this.log.append({
      type: "BUNDLE_RECEIVED",
      payload: {
        bundle_id: expected.bundleId,
        exam_id: expected.examId,
        centre_id: this.opts.centreId,
        bundle_hash: expected.bundleHash,
        bytes: envelope.length,
      },
      ts: at,
    });
  }

  // -- key receipt (F3 receive side) -----------------------------------

  /** Accept a wrapped KEK (online release path). Memory-only (I-CTR-1). */
  async receiveWrappedKek(bundleId: string, sealed: Buffer): Promise<void> {
    const bundle = this.store.bundle(bundleId);
    if (!bundle) {
      throw new CentreError(`no bundle ${bundleId} in custody`, "BUNDLE_UNKNOWN");
    }
    const kekId = `kek:${bundleId}`;
    const fp = await this.provider.unwrapKek(kekId, sealed, BOX_KEY_ID);
    if (fp.toString("hex") !== bundle.kekFingerprint) {
      await this.provider.discardKek(kekId);
      throw new CentreError(
        `unwrapped KEK fingerprint ${fp.toString("hex")} does not match the bundle's ` +
          `committed fingerprint ${bundle.kekFingerprint} — discarded`,
        "KEK_FINGERPRINT_MISMATCH",
      );
    }
    this.heldKeks.set(bundleId, kekId);
    await this.log.append({
      type: "KEK_RECEIVED",
      payload: {
        bundle_id: bundleId,
        exam_id: bundle.examId,
        centre_id: this.opts.centreId,
        kek_fingerprint: bundle.kekFingerprint,
      },
      ts: this.now(),
    });
  }

  /** Accept an offline release medium (T10 fallback), verifying its signature. */
  async receiveOfflineMedium(medium: OfflineReleaseMedium): Promise<void> {
    if (!verifyOfflineMedium(medium, this.opts.authorityPublicKey)) {
      throw new CentreError(
        "offline release medium signature does not verify against the authority key — " +
          "possible substitution; do not use",
        "MEDIUM_INVALID",
      );
    }
    const entry = medium.entries.find((e) => e.centreId === this.opts.centreId);
    if (!entry) {
      throw new CentreError(
        `offline medium for ${medium.bundleId} carries no entry for ${this.opts.centreId}`,
        "MEDIUM_INVALID",
      );
    }
    await this.receiveWrappedKek(medium.bundleId, Buffer.from(entry.sealedHex, "hex"));
  }

  // -- check-in (F2 verify side, T7) -----------------------------------

  async checkIn(qrOrToken: string | AdmitToken): Promise<{ seat: string; tokenHash: string }> {
    let token: AdmitToken;
    try {
      token = typeof qrOrToken === "string" ? decodeAdmitToken(qrOrToken) : qrOrToken;
    } catch (err) {
      this.admitRefused.inc({ code: "MALFORMED" });
      throw new CentreError(`admit token unreadable: ${(err as Error).message}`, "ADMIT_REFUSED");
    }

    const verdict = verifyAdmitToken(token, this.opts.authorityPublicKey, {
      examId: this.opts.examId,
      centreId: this.opts.centreId,
      now: this.now(),
    });
    if (!verdict.ok) {
      this.admitRefused.inc({ code: verdict.code });
      this.logger.warn("admit token refused", { code: verdict.code, reason: verdict.reason });
      throw new CentreError(`admit refused: ${verdict.reason}`, "ADMIT_REFUSED");
    }

    const tokenHash = verdict.tokenHash.toString("hex");
    if (this.store.checkinByToken(tokenHash)) {
      throw new CentreError(
        `this admit token is already checked in — a candidate cannot enter twice`,
        "DUPLICATE_CHECKIN",
      );
    }
    const existingSeat = this.store.checkinBySeat(token.seat);
    if (existingSeat) {
      throw new CentreError(
        `seat ${token.seat} is already occupied by another candidate`,
        "SEAT_TAKEN",
      );
    }

    const at = this.now();
    this.store.putCheckin({
      tokenHash,
      seat: token.seat,
      registrationHash: token.registrationHash,
      checkedInAt: at,
    });
    // T7: the log binds token hash → seat. No registration id, no name (T8).
    await this.log.append({
      type: "CANDIDATE_CHECKED_IN",
      payload: {
        exam_id: this.opts.examId,
        centre_id: this.opts.centreId,
        seat: token.seat,
        token_hash: tokenHash,
      },
      ts: at,
    });
    this.checkinsTotal.inc();
    return { seat: token.seat, tokenHash };
  }

  // -- T-0 generation and printing (F4) --------------------------------

  async generatePaper(seat: string): Promise<{ pdf: Buffer; paperHash: string }> {
    const checkin = this.store.checkinBySeat(seat);
    if (!checkin) {
      throw new CentreError(`no candidate checked in at seat ${seat}`, "NOT_CHECKED_IN");
    }
    if (this.store.paper(seat)) {
      throw new CentreError(
        `paper for seat ${seat} was already generated — a second generation would be ` +
          "evidence of a duplicate print attempt",
        "ALREADY_GENERATED",
      );
    }

    const bundleId = this.paperBundleId();
    const bundle = this.store.bundle(bundleId);
    if (!bundle) throw new CentreError(`no bundle ${bundleId} in custody`, "BUNDLE_UNKNOWN");
    const kekId = this.heldKeks.get(bundleId);
    if (!kekId) {
      throw new CentreError(
        `KEK for ${bundleId} has not been released to this centre — generation before ` +
          "release is structurally impossible (T2)",
        "KEK_NOT_HELD",
      );
    }

    const ad = bundleAssociatedData(bundleId, "paper", bundle.examId);
    const plaintext = await this.provider.aeadDecryptWithKek(
      kekId,
      parseAead(bundle.ciphertext),
      ad,
    );
    let content: PaperBundleContent;
    try {
      content = JSON.parse(plaintext.toString("utf8")) as PaperBundleContent;
    } finally {
      plaintext.fill(0);
    }

    const paper = assemblePaper({
      content,
      centreId: this.opts.centreId,
      seat,
      tokenHash: Buffer.from(checkin.tokenHash, "hex"),
    });
    const rendered = await renderPaper(paper);

    const at = this.now();
    this.store.putPaper({
      seat,
      tokenHash: checkin.tokenHash,
      paperHash: rendered.pdfHash.toString("hex"),
      contentHash: rendered.contentHash.toString("hex"),
      pageCount: rendered.pageCount,
      generatedAt: at,
      printedAt: null,
      printerId: null,
      jobRef: null,
      transport: null,
    });
    await this.log.append({
      type: "PAPER_GENERATED",
      payload: {
        exam_id: this.opts.examId,
        centre_id: this.opts.centreId,
        seat,
        token_hash: checkin.tokenHash,
        paper_hash: rendered.pdfHash.toString("hex"),
        content_hash: rendered.contentHash.toString("hex"),
        page_count: rendered.pageCount,
      },
      ts: at,
    });
    this.papersGenerated.inc();
    return { pdf: rendered.pdf, paperHash: rendered.pdfHash.toString("hex") };
  }

  async printPaper(seat: string, pdf: Buffer): Promise<void> {
    const record = this.store.paper(seat);
    if (!record) {
      throw new CentreError(`no generated paper for seat ${seat}`, "NOT_GENERATED");
    }
    if (!this.printService) {
      throw new CentreError("no printers or spool directory configured", "NOT_GENERATED");
    }
    // Refuse to print bytes that do not match the logged hash — the print
    // path cannot be used to substitute content past the log (T3/T4).
    const got = domainHash("paper-pdf", pdf).toString("hex");
    if (got !== record.paperHash) {
      throw new CentreError(
        `PDF for seat ${seat} does not match its logged paper_hash — refusing to print`,
        "SEAT_MISMATCH",
      );
    }

    const result = await this.printService.print(pdf, `${this.opts.examId} ${seat}`);
    const at = this.now();
    this.store.markPrinted(seat, at, result.printerId, result.jobRef, result.transport);
    await this.log.append({
      type: "PAPER_PRINTED",
      payload: {
        exam_id: this.opts.examId,
        centre_id: this.opts.centreId,
        seat,
        paper_hash: record.paperHash,
        printer_id: result.printerId,
        ipp_job_id: result.jobRef,
        transport: result.transport,
      },
      ts: at,
    });
  }

  /** T-0: generate and print for every checked-in candidate. */
  async runT0(): Promise<{ printed: number; failures: Array<{ seat: string; error: string }> }> {
    const failures: Array<{ seat: string; error: string }> = [];
    let printed = 0;
    for (const checkin of this.store.checkins()) {
      try {
        const { pdf } = await this.generatePaper(checkin.seat);
        await this.printPaper(checkin.seat, pdf);
        printed++;
      } catch (err) {
        failures.push({ seat: checkin.seat, error: (err as Error).message });
        this.logger.error("T-0 generation/print failed for seat", {
          seat: checkin.seat,
          error: (err as Error).message,
        });
      }
    }
    return { printed, failures };
  }

  // -- close (F5) ------------------------------------------------------

  async closeExam(): Promise<void> {
    await this.log.append({
      type: "EXAM_CLOSED",
      payload: {
        exam_id: this.opts.examId,
        centre_id: this.opts.centreId,
        candidates: this.store.checkins().length,
        papers_printed: this.store.papers().filter((p) => p.printedAt !== null).length,
      },
      ts: this.now(),
    });
    // KEKs are of no further use; drop them from memory.
    for (const [bundleId, kekId] of this.heldKeks) {
      await this.provider.discardKek(kekId);
      this.heldKeks.delete(bundleId);
    }
  }

  async checkpoint(): Promise<void> {
    await this.log.createCheckpoint(this.now());
  }

  async close(): Promise<void> {
    for (const kekId of this.heldKeks.values()) {
      await this.provider.discardKek(kekId);
    }
    this.heldKeks.clear();
    this.log.close();
    this.store.close();
    await this.provider.close();
  }
}
