import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Centre node local state.
 *
 * INVARIANT I-CTR-1 (T1/T2): before T-0 this database holds exam content
 * ONLY as AEAD ciphertext. There is no table for plaintext content, no table
 * for KEKs (an unwrapped KEK lives solely in provider memory), and generated
 * papers are not persisted — a paper exists as plaintext only in memory
 * between generation and the printer, plus its hashes in the log. Enforced by
 * the acceptance scan plus the schema itself.
 */

export interface CentreBundleRecord {
  bundleId: string;
  examId: string;
  kind: "paper" | "answers";
  bundleHash: string;
  kekFingerprint: string;
  threshold: number;
  receivedAt: number;
  ciphertext: Buffer;
}

export interface CheckinRecord {
  tokenHash: string;
  seat: string;
  registrationHash: string;
  checkedInAt: number;
}

export interface PaperRecord {
  seat: string;
  tokenHash: string;
  paperHash: string;
  contentHash: string;
  pageCount: number;
  generatedAt: number;
  printedAt: number | null;
  printerId: string | null;
  jobRef: string | null;
  transport: string | null;
}

export class CentreStore {
  private constructor(private readonly db: Database.Database) {}

  static open(dbPath: string): CentreStore {
    if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });
    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = FULL");
    db.exec(`
      CREATE TABLE IF NOT EXISTS bundles (
        bundle_id       TEXT PRIMARY KEY,
        exam_id         TEXT NOT NULL,
        kind            TEXT NOT NULL CHECK (kind IN ('paper','answers')),
        bundle_hash     TEXT NOT NULL,
        kek_fingerprint TEXT NOT NULL,
        threshold       INTEGER NOT NULL,
        received_at     INTEGER NOT NULL,
        ciphertext      BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS checkins (
        token_hash        TEXT PRIMARY KEY,
        seat              TEXT NOT NULL UNIQUE,
        registration_hash TEXT NOT NULL,
        checked_in_at     INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS papers (
        seat         TEXT PRIMARY KEY,
        token_hash   TEXT NOT NULL UNIQUE REFERENCES checkins(token_hash),
        paper_hash   TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        page_count   INTEGER NOT NULL,
        generated_at INTEGER NOT NULL,
        printed_at   INTEGER,
        printer_id   TEXT,
        job_ref      TEXT,
        transport    TEXT
      );
    `);
    return new CentreStore(db);
  }

  putBundle(r: CentreBundleRecord): void {
    this.db
      .prepare(
        `INSERT INTO bundles (bundle_id, exam_id, kind, bundle_hash, kek_fingerprint,
                              threshold, received_at, ciphertext)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        r.bundleId,
        r.examId,
        r.kind,
        r.bundleHash,
        r.kekFingerprint,
        r.threshold,
        r.receivedAt,
        r.ciphertext,
      );
  }

  bundle(bundleId: string): CentreBundleRecord | null {
    const row = this.db.prepare(`SELECT * FROM bundles WHERE bundle_id = ?`).get(bundleId);
    if (!row) return null;
    const r = row as Record<string, unknown>;
    return {
      bundleId: r["bundle_id"] as string,
      examId: r["exam_id"] as string,
      kind: r["kind"] as "paper" | "answers",
      bundleHash: r["bundle_hash"] as string,
      kekFingerprint: r["kek_fingerprint"] as string,
      threshold: r["threshold"] as number,
      receivedAt: r["received_at"] as number,
      ciphertext: r["ciphertext"] as Buffer,
    };
  }

  putCheckin(r: CheckinRecord): void {
    this.db
      .prepare(
        `INSERT INTO checkins (token_hash, seat, registration_hash, checked_in_at)
         VALUES (?, ?, ?, ?)`,
      )
      .run(r.tokenHash, r.seat, r.registrationHash, r.checkedInAt);
  }

  checkinByToken(tokenHash: string): CheckinRecord | null {
    const row = this.db.prepare(`SELECT * FROM checkins WHERE token_hash = ?`).get(tokenHash);
    return row ? toCheckin(row as Record<string, unknown>) : null;
  }

  checkinBySeat(seat: string): CheckinRecord | null {
    const row = this.db.prepare(`SELECT * FROM checkins WHERE seat = ?`).get(seat);
    return row ? toCheckin(row as Record<string, unknown>) : null;
  }

  checkins(): CheckinRecord[] {
    return this.db
      .prepare(`SELECT * FROM checkins ORDER BY seat`)
      .all()
      .map((r) => toCheckin(r as Record<string, unknown>));
  }

  putPaper(r: PaperRecord): void {
    this.db
      .prepare(
        `INSERT INTO papers (seat, token_hash, paper_hash, content_hash, page_count,
                             generated_at, printed_at, printer_id, job_ref, transport)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        r.seat,
        r.tokenHash,
        r.paperHash,
        r.contentHash,
        r.pageCount,
        r.generatedAt,
        r.printedAt,
        r.printerId,
        r.jobRef,
        r.transport,
      );
  }

  markPrinted(seat: string, printedAt: number, printerId: string, jobRef: string, transport: string): void {
    this.db
      .prepare(
        `UPDATE papers SET printed_at = ?, printer_id = ?, job_ref = ?, transport = ?
         WHERE seat = ?`,
      )
      .run(printedAt, printerId, jobRef, transport, seat);
  }

  paper(seat: string): PaperRecord | null {
    const row = this.db.prepare(`SELECT * FROM papers WHERE seat = ?`).get(seat);
    if (!row) return null;
    const r = row as Record<string, unknown>;
    return {
      seat: r["seat"] as string,
      tokenHash: r["token_hash"] as string,
      paperHash: r["paper_hash"] as string,
      contentHash: r["content_hash"] as string,
      pageCount: r["page_count"] as number,
      generatedAt: r["generated_at"] as number,
      printedAt: r["printed_at"] as number | null,
      printerId: r["printer_id"] as string | null,
      jobRef: r["job_ref"] as string | null,
      transport: r["transport"] as string | null,
    };
  }

  papers(): PaperRecord[] {
    return this.db
      .prepare(`SELECT seat FROM papers ORDER BY seat`)
      .all()
      .map((r) => this.paper((r as { seat: string }).seat)!);
  }

  close(): void {
    this.db.close();
  }
}

function toCheckin(r: Record<string, unknown>): CheckinRecord {
  return {
    tokenHash: r["token_hash"] as string,
    seat: r["seat"] as string,
    registrationHash: r["registration_hash"] as string,
    checkedInAt: r["checked_in_at"] as number,
  };
}
