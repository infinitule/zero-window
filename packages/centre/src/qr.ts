import { create as createQr } from "qrcode";

/**
 * QR payload for a printed paper (T4):
 *   { v, e: examId, c: centreId, s: seat, h: paper content-hash prefix }
 *
 * The hash is of the assembled CONTENT, not the PDF bytes — the QR is inside
 * the PDF, so a PDF-byte hash would be circular. The content hash pins the
 * exact questions and option order on this candidate's paper; the log binds
 * it to the PDF hash.
 */
export interface QrPayload {
  v: 1;
  e: string;
  c: string;
  s: string;
  h: string;
}

export function qrPayload(opts: {
  examId: string;
  centreId: string;
  seat: string;
  contentHash: Buffer;
}): string {
  const payload: QrPayload = {
    v: 1,
    e: opts.examId,
    c: opts.centreId,
    s: opts.seat,
    h: opts.contentHash.subarray(0, 12).toString("hex"),
  };
  // Key order is fixed by construction here; JSON.stringify preserves
  // insertion order for string keys, so the QR bytes are deterministic.
  return JSON.stringify(payload);
}

export interface QrMatrix {
  size: number;
  /** get(x, y) — true for a dark module. */
  get(x: number, y: number): boolean;
}

/**
 * QR modules for a payload. qrcode's `create` is a pure function of
 * (text, options) — no clock, no randomness — so the matrix is deterministic.
 * Error correction Q (~25%) because exam-hall papers get folded and smudged.
 */
export function qrMatrix(text: string): QrMatrix {
  const code = createQr(text, { errorCorrectionLevel: "Q" });
  const size = code.modules.size;
  const data = code.modules.data;
  return {
    size,
    get(x: number, y: number): boolean {
      return data[y * size + x] === 1;
    },
  };
}
