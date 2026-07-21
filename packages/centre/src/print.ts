import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import ipp from "ipp";
import type { Logger, Counter } from "@zw/ops";

/**
 * Printing (F4, T10).
 *
 * Primary path: IPP (RFC 8011) Print-Job followed by Get-Job-Attributes
 * polling until the job reaches a terminal state. "Submitted" is not
 * "printed": a job can sit queued on a dead printer forever, and at T-0 that
 * is indistinguishable from success unless we poll for completion.
 *
 * Failover (I-PRN-1): printers are configured as an ordered list. A printer
 * that refuses the connection, errors the job, or fails to complete within
 * the deadline is marked suspect and the job moves to the next printer. The
 * failover itself is evidence (PRINTER_FAILOVER in the log) because "papers
 * came off the backup printer" is a custody-relevant fact.
 *
 * Fallback: --spool-dir writes the PDF to a directory for print-room
 * workflows where the room's own operators drive the physical printers.
 */

/** RFC 8011 §5.3.7 job-state enum. */
export const JOB_STATE = {
  pending: 3,
  "pending-held": 4,
  processing: 5,
  "processing-stopped": 6,
  canceled: 7,
  aborted: 8,
  completed: 9,
} as const;

const TERMINAL_STATES = new Set<number>([
  JOB_STATE.canceled,
  JOB_STATE.aborted,
  JOB_STATE.completed,
]);

export interface PrinterTarget {
  printerId: string;
  /** e.g. http://cups-host:631/printers/hall-a */
  url: string;
}

export interface PrintServiceOptions {
  printers: PrinterTarget[];
  /** Directory fallback; used when `printers` is empty or exhausted if set. */
  spoolDir?: string;
  /** Poll interval while a job is non-terminal. */
  pollIntervalMs?: number;
  /** Per-printer deadline for a job to complete. */
  jobDeadlineMs?: number;
  logger?: Logger;
  metrics?: { printedTotal: Counter; failoversTotal: Counter };
  /** Called when a printer is failed over. Wired to the transparency log. */
  onFailover?: (fromPrinterId: string, reason: string) => Promise<void> | void;
}

export interface PrintResult {
  transport: "ipp" | "spool";
  printerId: string;
  /** IPP job id, or the spool filename for spool transport. */
  jobRef: string;
  /** Printers that were tried and failed before this one succeeded. */
  failedOver: Array<{ printerId: string; reason: string }>;
}

export class PrintError extends Error {
  constructor(
    message: string,
    readonly attempts: Array<{ printerId: string; reason: string }>,
  ) {
    super(message);
    this.name = "PrintError";
  }
}

interface ExecuteResult {
  response: ipp.IppResponse;
}

function execute(
  printer: ipp.PrinterInstance,
  operation: string,
  message: ipp.IppRequest,
): Promise<ExecuteResult> {
  return new Promise((resolve, reject) => {
    printer.execute(operation, message, (error, response) => {
      if (error) reject(error);
      else resolve({ response });
    });
  });
}

function firstJobGroup(response: ipp.IppResponse): ipp.IppGroup | undefined {
  const g = response["job-attributes-tag"];
  return Array.isArray(g) ? g[0] : g;
}

function jobStateOf(group: ipp.IppGroup | undefined): number | undefined {
  const raw = group?.["job-state"];
  if (typeof raw === "number") return raw;
  if (typeof raw === "string") {
    // Servers may return the keyword instead of the enum.
    return (JOB_STATE as Record<string, number>)[raw];
  }
  return undefined;
}

export class PrintService {
  private readonly pollIntervalMs: number;
  private readonly jobDeadlineMs: number;

  constructor(private readonly opts: PrintServiceOptions) {
    this.pollIntervalMs = opts.pollIntervalMs ?? 500;
    this.jobDeadlineMs = opts.jobDeadlineMs ?? 60_000;
    if (opts.printers.length === 0 && !opts.spoolDir) {
      throw new Error("PrintService: configure at least one printer or a spool directory");
    }
  }

  /**
   * Print a PDF, failing over across printers, spooling as a last resort if
   * configured. Throws PrintError with per-printer reasons when every path
   * is exhausted.
   */
  async print(pdf: Buffer, jobName: string): Promise<PrintResult> {
    const failed: Array<{ printerId: string; reason: string }> = [];

    for (const target of this.opts.printers) {
      try {
        const jobRef = await this.printViaIpp(target, pdf, jobName);
        this.opts.metrics?.printedTotal.inc({ printer_id: target.printerId, transport: "ipp" });
        return { transport: "ipp", printerId: target.printerId, jobRef, failedOver: [...failed] };
      } catch (err) {
        const reason = (err as Error).message;
        failed.push({ printerId: target.printerId, reason });
        this.opts.metrics?.failoversTotal.inc({ printer_id: target.printerId });
        this.opts.logger?.warn("printer failed, failing over", {
          printer_id: target.printerId,
          job_name: jobName,
          reason,
        });
        await this.opts.onFailover?.(target.printerId, reason);
      }
    }

    if (this.opts.spoolDir) {
      const jobRef = await this.spool(pdf, jobName);
      this.opts.metrics?.printedTotal.inc({ printer_id: "spool", transport: "spool" });
      return { transport: "spool", printerId: "spool", jobRef, failedOver: [...failed] };
    }

    throw new PrintError(
      `all ${this.opts.printers.length} printer(s) failed for job "${jobName}": ` +
        failed.map((f) => `${f.printerId}: ${f.reason}`).join("; "),
      failed,
    );
  }

  private async printViaIpp(
    target: PrinterTarget,
    pdf: Buffer,
    jobName: string,
  ): Promise<string> {
    const printer = ipp.Printer(target.url);

    const submit = await execute(printer, "Print-Job", {
      "operation-attributes-tag": {
        "requesting-user-name": "zw-centre",
        "job-name": jobName,
        "document-format": "application/pdf",
      },
      data: pdf,
    });
    if (!submit.response.statusCode.startsWith("successful")) {
      throw new Error(`Print-Job refused: ${submit.response.statusCode}`);
    }
    const jobGroup = firstJobGroup(submit.response);
    const jobId = jobGroup?.["job-id"];
    if (typeof jobId !== "number") {
      throw new Error("printer accepted the job but returned no job-id");
    }

    // Poll to completion — RFC 8011 job-state, not wishful thinking.
    const deadline = Date.now() + this.jobDeadlineMs;
    for (;;) {
      const poll = await execute(printer, "Get-Job-Attributes", {
        "operation-attributes-tag": {
          "job-id": jobId,
          "requesting-user-name": "zw-centre",
          "requested-attributes": ["job-state", "job-state-reasons"],
        },
      });
      const state = jobStateOf(firstJobGroup(poll.response));
      if (state === JOB_STATE.completed) return String(jobId);
      if (state !== undefined && TERMINAL_STATES.has(state)) {
        const reasons = firstJobGroup(poll.response)?.["job-state-reasons"];
        throw new Error(
          `job ${jobId} ended in state ${state} (${String(reasons ?? "no reason reported")})`,
        );
      }
      if (Date.now() > deadline) {
        throw new Error(
          `job ${jobId} did not complete within ${this.jobDeadlineMs}ms (last state ${String(state)})`,
        );
      }
      await new Promise((r) => setTimeout(r, this.pollIntervalMs));
    }
  }

  private async spool(pdf: Buffer, jobName: string): Promise<string> {
    const dir = this.opts.spoolDir!;
    await mkdir(dir, { recursive: true });
    // Job name is caller-controlled; keep the filename safe and unique.
    const safe = jobName.replace(/[^A-Za-z0-9._-]/g, "_");
    const file = `${Date.now()}-${safe}.pdf`;
    await writeFile(join(dir, file), pdf);
    this.opts.logger?.info("spooled to directory", { file, dir });
    return file;
  }
}
