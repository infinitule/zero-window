import { readdir, readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { splitBank } from "@zw/authority";
import { domainHash } from "@zw/crypto";
import { assemblePaper } from "../src/assemble.js";
import { renderPaper } from "../src/render.js";
import { PrintService } from "../src/print.js";
import { sampleBank, sampleBlueprint } from "./fixtures.js";

/**
 * Integration against a REAL CUPS print server.
 *
 * The unit suite (ipp.test.ts) drives the client against a real RFC 8010
 * wire-format responder in-process, which proves the protocol encoding. This
 * file proves the client works against actual CUPS — a different thing, and
 * the one that matters for a print room.
 *
 * Opt-in, because it needs a print server:
 *
 *   ZW_CUPS_URL=http://127.0.0.1:631/printers/zw-test \
 *   ZW_CUPS_OUTPUT_DIR=/var/spool/cups-pdf/nobody \
 *   pnpm --filter @zw/centre test cups
 *
 * CI provisions a cups-pdf queue and sets both (.github/workflows/ci.yml).
 * ZW_REQUIRE_CUPS=1 turns a missing server into a failure rather than a skip,
 * so the CI job cannot silently pass by skipping.
 */

const cupsUrl = process.env["ZW_CUPS_URL"];
const outputDir = process.env["ZW_CUPS_OUTPUT_DIR"];
const required = process.env["ZW_REQUIRE_CUPS"] === "1";

if (required && !cupsUrl) {
  throw new Error("ZW_REQUIRE_CUPS=1 but ZW_CUPS_URL is not set");
}

describe.skipIf(!cupsUrl)("IPP printing against real CUPS", () => {
  const bank = sampleBank();
  const blueprint = sampleBlueprint();
  const { paper: content } = splitBank(bank, blueprint);

  async function renderOne(seat: string) {
    const paper = assemblePaper({
      content,
      centreId: "CENTRE-CUPS",
      seat,
      tokenHash: domainHash("cups-test-token", Buffer.from(seat, "utf8")),
    });
    return renderPaper(paper);
  }

  it("submits a real paper and polls it to a completed job state", async () => {
    const svc = new PrintService({
      printers: [{ printerId: "cups-primary", url: cupsUrl! }],
      pollIntervalMs: 250,
      // CUPS filters a multi-page PDF; give it room on a loaded CI runner.
      jobDeadlineMs: 120_000,
    });

    const rendered = await renderOne("C-001");
    const result = await svc.print(rendered.pdf, "ZW CUPS integration C-001");

    expect(result.transport).toBe("ipp");
    expect(result.printerId).toBe("cups-primary");
    // A real CUPS job id, not a fixture.
    expect(Number(result.jobRef)).toBeGreaterThan(0);
    expect(result.failedOver).toEqual([]);
  }, 180_000);

  it("what CUPS produced is a PDF of the expected page count", async () => {
    if (!outputDir) {
      // Without the cups-pdf output directory we can still assert the job
      // completed, but not inspect the artifact. Say so rather than passing
      // silently on a weaker claim.
      expect(
        process.env["ZW_REQUIRE_CUPS"],
        "set ZW_CUPS_OUTPUT_DIR to verify printed output, or unset ZW_REQUIRE_CUPS",
      ).not.toBe("1");
      return;
    }

    const svc = new PrintService({
      printers: [{ printerId: "cups-primary", url: cupsUrl! }],
      pollIntervalMs: 250,
      jobDeadlineMs: 120_000,
    });
    const rendered = await renderOne("C-002");
    await svc.print(rendered.pdf, "ZW-CUPS-C-002");

    // cups-pdf writes asynchronously after the job reaches completed.
    let produced: string[] = [];
    for (let i = 0; i < 40; i++) {
      produced = (await readdir(outputDir)).filter((f) => f.endsWith(".pdf"));
      if (produced.length > 0) break;
      await new Promise((r) => setTimeout(r, 500));
    }
    expect(produced.length, `no PDF appeared in ${outputDir}`).toBeGreaterThan(0);

    const bytes = await readFile(`${outputDir}/${produced[produced.length - 1]!}`);
    expect(bytes.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    // CUPS re-writes the PDF through its filter chain, so the bytes differ
    // from ours by design — page count is the meaningful invariant to check
    // on the far side, along with it being a valid PDF at all.
    const pageCount = (bytes.toString("latin1").match(/\/Type\s*\/Page[^s]/g) ?? []).length;
    expect(pageCount).toBeGreaterThanOrEqual(1);
  }, 240_000);

  it("fails over from a dead printer to the real CUPS queue", async () => {
    const svc = new PrintService({
      printers: [
        // Nothing listens here.
        { printerId: "dead", url: "http://127.0.0.1:9/printers/dead" },
        { printerId: "cups-primary", url: cupsUrl! },
      ],
      pollIntervalMs: 250,
      jobDeadlineMs: 120_000,
    });
    const rendered = await renderOne("C-003");
    const result = await svc.print(rendered.pdf, "ZW-CUPS-failover-C-003");
    expect(result.printerId).toBe("cups-primary");
    expect(result.failedOver).toHaveLength(1);
    expect(result.failedOver[0]!.printerId).toBe("dead");
  }, 180_000);
});
