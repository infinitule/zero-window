import { readFile, writeFile } from "node:fs/promises";
import { canonicalize, type CanonicalValue } from "./canonical.js";
import type { Checkpoint, EvidenceBundle, LogEntry } from "./types.js";

/**
 * Portable evidence format: newline-delimited canonical JSON.
 *
 * Chosen over a database dump because an auditor must be able to verify the
 * log with a text editor, `sha256sum`, and this package — no SQLite version
 * compatibility, no binary format to reverse. Each line is one record,
 * canonically serialized (I-CANON-1), so the file's bytes are reproducible
 * from the records and vice versa.
 *
 * Line 1 is a header; then entries in sequence order; then checkpoints in
 * size order.
 */

export interface EvidenceHeader {
  kind: "zero-window-evidence";
  version: 1;
  exam_id: string;
  /** Public keys trusted to sign, by actor. */
  signers: Record<string, string>;
  entry_count: number;
  checkpoint_count: number;
}

type EvidenceLine =
  | ({ record: "header" } & EvidenceHeader)
  | ({ record: "entry" } & LogEntry)
  | ({ record: "checkpoint" } & Checkpoint);

export function serializeEvidence(bundle: EvidenceBundle): string {
  const header: EvidenceLine = {
    record: "header",
    kind: "zero-window-evidence",
    version: 1,
    exam_id: bundle.exam_id,
    signers: bundle.signers,
    entry_count: bundle.entries.length,
    checkpoint_count: bundle.checkpoints.length,
  };

  const lines: string[] = [canonicalize(header as unknown as CanonicalValue)];
  for (const e of [...bundle.entries].sort((a, b) => a.seq - b.seq)) {
    lines.push(canonicalize({ record: "entry", ...e } as unknown as CanonicalValue));
  }
  for (const c of [...bundle.checkpoints].sort((a, b) => a.size - b.size)) {
    lines.push(canonicalize({ record: "checkpoint", ...c } as unknown as CanonicalValue));
  }
  return lines.join("\n") + "\n";
}

export class EvidenceFormatError extends Error {
  constructor(message: string, readonly line: number) {
    super(`evidence file line ${line}: ${message}`);
    this.name = "EvidenceFormatError";
  }
}

export function parseEvidence(text: string): EvidenceBundle {
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) throw new EvidenceFormatError("file is empty", 0);

  let header: EvidenceHeader | null = null;
  const entries: LogEntry[] = [];
  const checkpoints: Checkpoint[] = [];

  for (const [i, line] of lines.entries()) {
    let parsed: { record?: string } & Record<string, unknown>;
    try {
      parsed = JSON.parse(line) as { record?: string } & Record<string, unknown>;
    } catch (err) {
      throw new EvidenceFormatError(`not valid JSON: ${(err as Error).message}`, i + 1);
    }
    switch (parsed.record) {
      case "header": {
        if (i !== 0) throw new EvidenceFormatError("header must be the first line", i + 1);
        const h = parsed as unknown as EvidenceHeader;
        if (h.kind !== "zero-window-evidence") {
          throw new EvidenceFormatError(`unexpected kind "${String(h.kind)}"`, i + 1);
        }
        if (h.version !== 1) {
          throw new EvidenceFormatError(`unsupported version ${String(h.version)}`, i + 1);
        }
        header = h;
        break;
      }
      case "entry": {
        const { record: _r, ...rest } = parsed;
        entries.push(rest as unknown as LogEntry);
        break;
      }
      case "checkpoint": {
        const { record: _r, ...rest } = parsed;
        checkpoints.push(rest as unknown as Checkpoint);
        break;
      }
      default:
        throw new EvidenceFormatError(
          `unknown record type ${JSON.stringify(parsed.record ?? null)}`,
          i + 1,
        );
    }
  }

  if (!header) throw new EvidenceFormatError("missing header record", 1);

  // The header's counts are part of the evidence: a truncated file must be
  // detected here rather than silently verifying as a shorter valid log.
  if (entries.length !== header.entry_count) {
    throw new EvidenceFormatError(
      `header declares ${header.entry_count} entries but the file contains ${entries.length}: the evidence file is truncated or has had records removed`,
      1,
    );
  }
  if (checkpoints.length !== header.checkpoint_count) {
    throw new EvidenceFormatError(
      `header declares ${header.checkpoint_count} checkpoints but the file contains ${checkpoints.length}`,
      1,
    );
  }

  return {
    version: 1,
    exam_id: header.exam_id,
    entries,
    checkpoints,
    signers: header.signers,
  };
}

export async function writeEvidenceFile(path: string, bundle: EvidenceBundle): Promise<void> {
  await writeFile(path, serializeEvidence(bundle), { mode: 0o444 });
}

export async function readEvidenceFile(path: string): Promise<EvidenceBundle> {
  return parseEvidence(await readFile(path, "utf8"));
}
