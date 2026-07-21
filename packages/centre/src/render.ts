import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import fontkit from "@pdf-lib/fontkit";
import { PDFDocument, PDFFont, PDFPage, rgb } from "pdf-lib";
import { domainHash, hex } from "@zw/crypto";
import { canonicalJson } from "@zw/authority";
import type { AssembledPaper } from "./assemble.js";
import { paperContentHash } from "./assemble.js";
import { qrMatrix, qrPayload } from "./qr.js";

/**
 * Deterministic PDF rendering (F4).
 *
 * INVARIANT I-GEN-3: rendering is a pure function of the AssembledPaper.
 * Everything that could vary is pinned:
 *   - fonts are embedded from files vendored in this package (Go family,
 *     BSD-licensed — assets/LICENSE.fonts), never system fonts;
 *   - CreationDate/ModDate are fixed to the epoch; producer/creator strings
 *     are constants;
 *   - layout uses font metrics only (no locale, no platform text APIs);
 *   - the QR matrix is a pure function of its payload.
 *
 * The byte-identical re-render test and the verifier's re-derivation (M6)
 * both depend on this invariant, and it is the dispute-resolution mechanism:
 * a claimed "leaked paper" either re-derives exactly from the log or it is
 * not a paper this system printed.
 *
 * Tamper-evident pagination: every page footer carries `Page n of N` and a
 * 12-hex-char prefix of a hash chain over the page BODY lines:
 *   chain_1 = H(paper-page-chain, content_hash ‖ page_1_lines)
 *   chain_n = H(paper-page-chain, chain_{n-1} ‖ page_n_lines)
 * Substituting, removing or reordering any printed page breaks every later
 * page's footer against a re-derivation.
 */

const A4 = { width: 595.28, height: 841.89 } as const;
const MARGIN = 54;
const BODY_SIZE = 10.5;
const OPTION_INDENT = 22;
const LINE_GAP = 3.2;
const FOOTER_SIZE = 8;
const HEADER_RULE_GAP = 10;

const assetsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "assets");
const FONT_REGULAR = readFileSync(join(assetsDir, "Go-Regular.ttf"));
const FONT_BOLD = readFileSync(join(assetsDir, "Go-Bold.ttf"));
const FONT_MONO = readFileSync(join(assetsDir, "Go-Mono.ttf"));

interface Line {
  text: string;
  font: "regular" | "bold" | "mono";
  size: number;
  indent: number;
  /** extra vertical space before this line */
  spaceBefore: number;
}

interface LaidOutPage {
  lines: Line[];
}

function wrap(text: string, font: PDFFont, size: number, maxWidth: number): string[] {
  const words = text.split(/\s+/).filter((w) => w.length > 0);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    const candidate = current.length === 0 ? word : `${current} ${word}`;
    if (font.widthOfTextAtSize(candidate, size) <= maxWidth || current.length === 0) {
      current = candidate;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current.length > 0) lines.push(current);
  return lines.length > 0 ? lines : [""];
}

function lineHeight(font: PDFFont, size: number): number {
  return font.heightAtSize(size) + LINE_GAP;
}

export interface RenderedPaper {
  pdf: Buffer;
  /** BLAKE2b-256 of the PDF bytes — what PAPER_GENERATED logs as paper_hash. */
  pdfHash: Buffer;
  contentHash: Buffer;
  pageCount: number;
  /** Full page-chain values, one per page (the footer prints a prefix). */
  pageChain: string[];
}

const OPTION_LETTERS = "ABCDEFGHIJ";

export async function renderPaper(paper: AssembledPaper): Promise<RenderedPaper> {
  const contentHash = paperContentHash(paper);

  const doc = await PDFDocument.create();
  doc.registerFontkit(fontkit);
  const regular = await doc.embedFont(FONT_REGULAR, { subset: true });
  const bold = await doc.embedFont(FONT_BOLD, { subset: true });
  const mono = await doc.embedFont(FONT_MONO, { subset: true });
  const fonts = { regular, bold, mono } as const;

  // Deterministic metadata (I-GEN-3). The epoch, not "now".
  const epoch = new Date(0);
  doc.setCreationDate(epoch);
  doc.setModificationDate(epoch);
  doc.setProducer("zero-window/1.0");
  doc.setCreator("zw-centre");
  doc.setTitle(`${paper.examId} ${paper.centreId} ${paper.seat}`);

  const textWidth = A4.width - 2 * MARGIN;

  // ---- Pass 1: flow content into abstract lines --------------------------
  const flowed: Line[] = [];
  for (const q of paper.questions) {
    const qLines = wrap(`Q${q.number}. ${q.body}`, fonts.bold, BODY_SIZE, textWidth);
    qLines.forEach((text, i) =>
      flowed.push({
        text,
        font: "bold",
        size: BODY_SIZE,
        indent: 0,
        spaceBefore: i === 0 ? 10 : 0,
      }),
    );
    q.options.forEach((opt, oi) => {
      const label = `(${OPTION_LETTERS[oi] ?? "?"}) `;
      const optLines = wrap(label + opt, fonts.regular, BODY_SIZE, textWidth - OPTION_INDENT);
      optLines.forEach((text, i) =>
        flowed.push({
          text,
          font: "regular",
          size: BODY_SIZE,
          indent: OPTION_INDENT + (i > 0 ? 12 : 0),
          spaceBefore: i === 0 && oi === 0 ? 4 : 0,
        }),
      );
    });
  }

  // ---- Pass 2: paginate --------------------------------------------------
  const headerHeight = 118; // page 1: title block + QR zone
  const contHeaderHeight = 30; // later pages: thin identity line
  const footerReserve = 34;

  const pages: LaidOutPage[] = [];
  let current: Line[] = [];
  let cursor = A4.height - MARGIN - headerHeight;
  for (const line of flowed) {
    const f = fonts[line.font];
    const h = line.spaceBefore + lineHeight(f, line.size);
    if (cursor - h < MARGIN + footerReserve) {
      pages.push({ lines: current });
      current = [];
      cursor = A4.height - MARGIN - contHeaderHeight;
    }
    cursor -= h;
    current.push(line);
  }
  pages.push({ lines: current });
  const pageCount = pages.length;

  // ---- Page hash chain ---------------------------------------------------
  const pageChain: string[] = [];
  let prev = contentHash;
  for (const page of pages) {
    const digest = domainHash("paper-page-chain", [
      prev,
      canonicalJson(page.lines.map((l) => l.text)),
    ]);
    pageChain.push(hex(digest));
    prev = digest;
  }

  // ---- Pass 3: draw ------------------------------------------------------
  const qrText = qrPayload({
    examId: paper.examId,
    centreId: paper.centreId,
    seat: paper.seat,
    contentHash,
  });
  const matrix = qrMatrix(qrText);

  pages.forEach((page, pi) => {
    const p = doc.addPage([A4.width, A4.height]);
    let y = A4.height - MARGIN;

    if (pi === 0) {
      drawFirstPageHeader(p, paper, fonts, matrix);
      y -= headerHeight;
    } else {
      p.drawText(`${paper.examId} · ${paper.centreId} · Seat ${paper.seat}`, {
        x: MARGIN,
        y: y - 10,
        size: 8.5,
        font: mono,
        color: rgb(0.25, 0.25, 0.25),
      });
      y -= contHeaderHeight;
    }

    for (const line of page.lines) {
      const f = fonts[line.font];
      y -= line.spaceBefore + lineHeight(f, line.size);
      p.drawText(line.text, {
        x: MARGIN + line.indent,
        y,
        size: line.size,
        font: f,
        color: rgb(0, 0, 0),
      });
    }

    // Footer: tamper-evident pagination (I-GEN-3).
    const footer = `Page ${pi + 1} of ${pageCount} · ${pageChain[pi]!.slice(0, 12)} · ${paper.seat}`;
    const fw = mono.widthOfTextAtSize(footer, FOOTER_SIZE);
    p.drawLine({
      start: { x: MARGIN, y: MARGIN - 6 },
      end: { x: A4.width - MARGIN, y: MARGIN - 6 },
      thickness: 0.5,
      color: rgb(0.6, 0.6, 0.6),
    });
    p.drawText(footer, {
      x: (A4.width - fw) / 2,
      y: MARGIN - 18,
      size: FOOTER_SIZE,
      font: mono,
      color: rgb(0.25, 0.25, 0.25),
    });
  });

  const pdf = Buffer.from(await doc.save({ useObjectStreams: false }));
  return {
    pdf,
    pdfHash: domainHash("paper-pdf", pdf),
    contentHash,
    pageCount,
    pageChain,
  };
}

function drawFirstPageHeader(
  page: PDFPage,
  paper: AssembledPaper,
  fonts: { regular: PDFFont; bold: PDFFont; mono: PDFFont },
  matrix: ReturnType<typeof qrMatrix>,
): void {
  const top = A4.height - MARGIN;

  // QR block, top-right. Quiet zone of 4 modules per the QR spec.
  const qrSize = 86;
  const module = qrSize / (matrix.size + 8);
  const qrX = A4.width - MARGIN - qrSize;
  const qrY = top - qrSize;
  page.drawRectangle({
    x: qrX,
    y: qrY,
    width: qrSize,
    height: qrSize,
    color: rgb(1, 1, 1),
  });
  for (let my = 0; my < matrix.size; my++) {
    for (let mx = 0; mx < matrix.size; mx++) {
      if (!matrix.get(mx, my)) continue;
      page.drawRectangle({
        x: qrX + (mx + 4) * module,
        y: qrY + qrSize - (my + 5) * module,
        width: module,
        height: module,
        color: rgb(0, 0, 0),
      });
    }
  }

  const textMax = A4.width - 2 * MARGIN - qrSize - 12;
  let y = top - 16;
  for (const line of wrap(paper.title, fonts.bold, 15, textMax)) {
    page.drawText(line, { x: MARGIN, y, size: 15, font: fonts.bold });
    y -= 19;
  }
  y -= 2;
  const meta = [
    `Examination ${paper.examId}`,
    `Centre ${paper.centreId} · Seat ${paper.seat}`,
    `Duration ${paper.durationMinutes} minutes · ${paper.questions.length} questions`,
  ];
  for (const m of meta) {
    page.drawText(m, { x: MARGIN, y, size: 9.5, font: fonts.regular });
    y -= 13;
  }
  page.drawText(`Paper ${paper.tokenHashHex.slice(0, 16)}`, {
    x: MARGIN,
    y,
    size: 8,
    font: fonts.mono,
    color: rgb(0.3, 0.3, 0.3),
  });

  page.drawLine({
    start: { x: MARGIN, y: top - 118 + HEADER_RULE_GAP },
    end: { x: A4.width - MARGIN, y: top - 118 + HEADER_RULE_GAP },
    thickness: 1,
    color: rgb(0, 0, 0),
  });
}
