import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ipp from "ipp";
import { afterEach, describe, expect, it } from "vitest";
import { PrintError, PrintService } from "../src/print.js";

/**
 * These tests run a real IPP responder: requests are decoded with ipp.parse
 * and answered with ipp.serialize, so the PrintService is exercised against
 * genuine RFC 8010 wire format — the same encode/decode path CUPS speaks.
 * The CUPS container itself is exercised in CI (M7/M8 compose).
 */

type JobScript = Array<number>; // successive job-state values returned by polls

/**
 * The ipp serializer takes enum attributes as their KEYWORD string and maps
 * them to wire enums itself (enums["job-state"]["completed"] → 9); handing it
 * the number would make it emit garbage bytes. The client's parser performs
 * the reverse mapping, so PrintService sees keywords too.
 */
const STATE_KEYWORD: Record<number, string> = {
  3: "pending",
  4: "pending-held",
  5: "processing",
  6: "processing-stopped",
  7: "canceled",
  8: "aborted",
  9: "completed",
};

interface FakePrinter {
  server: Server;
  url: string;
  requests: string[];
  close(): Promise<void>;
}

const printers: FakePrinter[] = [];
const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(printers.splice(0).map((p) => p.close()));
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function fakePrinter(opts: {
  /** job-states returned by successive Get-Job-Attributes calls; last repeats */
  script: JobScript;
  refuseSubmit?: boolean;
}): Promise<FakePrinter> {
  const requests: string[] = [];
  let polls = 0;

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const parsed = ipp.parse(Buffer.concat(chunks));
      const op = String(parsed.operation);
      requests.push(op);
      const id = parsed.id ?? 1;

      let response: ipp.IppRequest;
      if (op === "Print-Job") {
        response = opts.refuseSubmit
          ? { version: "2.0", statusCode: "server-error-service-unavailable", id }
          : {
              version: "2.0",
              statusCode: "successful-ok",
              id,
              "job-attributes-tag": {
                "job-id": 101,
                "job-state": STATE_KEYWORD[3]!,
                "job-uri": "ipp://fake/jobs/101",
              },
            };
      } else if (op === "Get-Job-Attributes") {
        const state = opts.script[Math.min(polls, opts.script.length - 1)]!;
        polls++;
        response = {
          version: "2.0",
          statusCode: "successful-ok",
          id,
          "job-attributes-tag": {
            "job-id": 101,
            "job-state": STATE_KEYWORD[state]!,
            "job-state-reasons": state === 8 ? "aborted-by-system" : "none",
          },
        };
      } else {
        response = { version: "2.0", statusCode: "server-error-operation-not-supported", id };
      }

      res.setHeader("content-type", "application/ipp");
      res.end(ipp.serialize(response));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const fp: FakePrinter = {
    server,
    url: `http://127.0.0.1:${port}/printers/test`,
    requests,
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
      }),
  };
  printers.push(fp);
  return fp;
}

/** A URL that nothing listens on. */
async function deadPrinterUrl(): Promise<string> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return `http://127.0.0.1:${port}/printers/dead`;
}

const PDF = Buffer.from("%PDF-1.7\nfake body for transport tests\n%%EOF\n");

describe("PrintService over real IPP wire format", () => {
  it("submits, polls to completion and reports the job id", async () => {
    const printer = await fakePrinter({ script: [5, 5, 9] }); // processing → completed
    const svc = new PrintService({
      printers: [{ printerId: "hall-a", url: printer.url }],
      pollIntervalMs: 10,
    });
    const result = await svc.print(PDF, "EXAM-1 seat A-01");
    expect(result).toMatchObject({ transport: "ipp", printerId: "hall-a", jobRef: "101" });
    expect(result.failedOver).toEqual([]);
    expect(printer.requests[0]).toBe("Print-Job");
    expect(printer.requests.filter((r) => r === "Get-Job-Attributes").length).toBe(3);
  });

  it("I-PRN-1: fails over from a dead printer to the secondary", async () => {
    const dead = await deadPrinterUrl();
    const healthy = await fakePrinter({ script: [9] });
    const failovers: string[] = [];
    const svc = new PrintService({
      printers: [
        { printerId: "hall-primary", url: dead },
        { printerId: "hall-backup", url: healthy.url },
      ],
      pollIntervalMs: 10,
      onFailover: (id, reason) => {
        failovers.push(`${id}:${reason.slice(0, 30)}`);
      },
    });
    const result = await svc.print(PDF, "job");
    expect(result.printerId).toBe("hall-backup");
    expect(result.failedOver).toHaveLength(1);
    expect(result.failedOver[0]!.printerId).toBe("hall-primary");
    expect(failovers).toHaveLength(1);
  });

  it("treats an aborted job as failure and fails over", async () => {
    const aborting = await fakePrinter({ script: [5, 8] }); // processing → aborted
    const healthy = await fakePrinter({ script: [9] });
    const svc = new PrintService({
      printers: [
        { printerId: "flaky", url: aborting.url },
        { printerId: "good", url: healthy.url },
      ],
      pollIntervalMs: 10,
    });
    const result = await svc.print(PDF, "job");
    expect(result.printerId).toBe("good");
    expect(result.failedOver[0]!.reason).toContain("state 8");
    expect(result.failedOver[0]!.reason).toContain("aborted-by-system");
  });

  it("a job stuck in processing hits the deadline and fails over", async () => {
    const stuck = await fakePrinter({ script: [5] }); // forever processing
    const healthy = await fakePrinter({ script: [9] });
    const svc = new PrintService({
      printers: [
        { printerId: "stuck", url: stuck.url },
        { printerId: "good", url: healthy.url },
      ],
      pollIntervalMs: 10,
      jobDeadlineMs: 80,
    });
    const result = await svc.print(PDF, "job");
    expect(result.printerId).toBe("good");
    expect(result.failedOver[0]!.reason).toContain("did not complete within 80ms");
  });

  it("a refused submission fails over with the IPP status code", async () => {
    const refusing = await fakePrinter({ script: [], refuseSubmit: true });
    const healthy = await fakePrinter({ script: [9] });
    const svc = new PrintService({
      printers: [
        { printerId: "refusing", url: refusing.url },
        { printerId: "good", url: healthy.url },
      ],
      pollIntervalMs: 10,
    });
    const result = await svc.print(PDF, "job");
    expect(result.failedOver[0]!.reason).toContain("server-error-service-unavailable");
  });

  it("spool-dir fallback engages when all printers are exhausted", async () => {
    const dead = await deadPrinterUrl();
    const dir = await mkdtemp(join(tmpdir(), "zw-spool-"));
    dirs.push(dir);
    const svc = new PrintService({
      printers: [{ printerId: "only", url: dead }],
      spoolDir: dir,
      pollIntervalMs: 10,
    });
    const result = await svc.print(PDF, "EXAM-1 seat A/01 weird:name");
    expect(result.transport).toBe("spool");
    const files = await readdir(dir);
    expect(files).toHaveLength(1);
    // Unsafe filename characters were sanitized.
    expect(files[0]).toMatch(/EXAM-1_seat_A_01_weird_name\.pdf$/);
    const spooled = await readFile(join(dir, files[0]!));
    expect(spooled.equals(PDF)).toBe(true);
  });

  it("pure spool mode works with no printers configured", async () => {
    const dir = await mkdtemp(join(tmpdir(), "zw-spool-"));
    dirs.push(dir);
    const svc = new PrintService({ printers: [], spoolDir: dir });
    const result = await svc.print(PDF, "job");
    expect(result.transport).toBe("spool");
  });

  it("throws PrintError with per-printer reasons when everything fails", async () => {
    const dead1 = await deadPrinterUrl();
    const dead2 = await deadPrinterUrl();
    const svc = new PrintService({
      printers: [
        { printerId: "p1", url: dead1 },
        { printerId: "p2", url: dead2 },
      ],
      pollIntervalMs: 10,
    });
    try {
      await svc.print(PDF, "job");
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(PrintError);
      const pe = err as PrintError;
      expect(pe.attempts).toHaveLength(2);
      expect(pe.message).toContain("p1:");
      expect(pe.message).toContain("p2:");
    }
  });

  it("refuses a configuration with neither printers nor spool", () => {
    expect(() => new PrintService({ printers: [] })).toThrow(/at least one printer/);
  });
});
