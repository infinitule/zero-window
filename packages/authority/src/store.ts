import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Authority local state. Distinct from the transparency log: this is
 * mutable operational state (enrolments, schedules, bundle metadata), while
 * the log is the append-only evidence chain. Nothing here is authoritative
 * for an auditor — everything an auditor needs is in the log.
 *
 * INVARIANT I-AUTH-1: this database never holds plaintext exam content, a
 * KEK, or a custodian share. Bundles are stored as ciphertext; shares are
 * stored only sealed to their custodian's public key. Enforced by the
 * no-plaintext-at-rest acceptance test.
 */

export interface CentreRecord {
  centreId: string;
  /** X25519 public key the wrapped KEK is sealed to. */
  boxPublicKey: string;
  /** Certificate fingerprint presented at mTLS enrolment. */
  certFingerprint: string;
  hardwareId: string;
  enrolledAt: number;
}

export interface CustodianRecord {
  custodianId: string;
  name: string;
  boxPublicKey: string;
  certFingerprint: string;
  enrolledAt: number;
}

export interface BundleRecord {
  bundleId: string;
  examId: string;
  kind: "paper" | "answers";
  /** hex BLAKE2b of the ciphertext envelope. */
  bundleHash: string;
  /** hex BLAKE2b of the canonical plaintext content (committed at build). */
  contentHash: string;
  kekFingerprint: string;
  threshold: number;
  shareCount: number;
  createdAt: number;
  /** Ciphertext envelope. Never plaintext (I-AUTH-1). */
  ciphertext: Buffer;
}

export interface ShareRecord {
  bundleId: string;
  custodianId: string;
  x: number;
  /** Sealed to the custodian's box public key. Never a raw share (I-AUTH-1). */
  sealed: Buffer;
  issuedAt: number;
}

export interface ScheduleRecord {
  examId: string;
  bundleId: string;
  /** Epoch ms of T-0. Release before this is refused (T2). */
  releaseAt: number;
  /** Ed25519 signature by the authority over the canonical schedule. */
  signature: string;
  createdAt: number;
}

export interface AdmitTokenRecord {
  tokenHash: string;
  examId: string;
  centreId: string;
  seat: string;
  issuedAt: number;
}

export class AuthorityStore {
  private constructor(private readonly db: Database.Database) {}

  static open(dbPath: string): AuthorityStore {
    if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });
    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = FULL");
    db.pragma("foreign_keys = ON");
    db.exec(`
      CREATE TABLE IF NOT EXISTS centres (
        centre_id        TEXT PRIMARY KEY,
        box_public_key   TEXT NOT NULL,
        cert_fingerprint TEXT NOT NULL,
        hardware_id      TEXT NOT NULL,
        enrolled_at      INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS custodians (
        custodian_id     TEXT PRIMARY KEY,
        name             TEXT NOT NULL,
        box_public_key   TEXT NOT NULL,
        cert_fingerprint TEXT NOT NULL,
        enrolled_at      INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS bundles (
        bundle_id       TEXT PRIMARY KEY,
        exam_id         TEXT NOT NULL,
        kind            TEXT NOT NULL CHECK (kind IN ('paper','answers')),
        bundle_hash     TEXT NOT NULL,
        content_hash    TEXT NOT NULL,
        kek_fingerprint TEXT NOT NULL,
        threshold       INTEGER NOT NULL,
        share_count     INTEGER NOT NULL,
        created_at      INTEGER NOT NULL,
        ciphertext      BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS shares (
        bundle_id    TEXT NOT NULL REFERENCES bundles(bundle_id),
        custodian_id TEXT NOT NULL REFERENCES custodians(custodian_id),
        x            INTEGER NOT NULL,
        sealed       BLOB NOT NULL,
        issued_at    INTEGER NOT NULL,
        PRIMARY KEY (bundle_id, custodian_id)
      );
      CREATE TABLE IF NOT EXISTS schedules (
        exam_id    TEXT NOT NULL,
        bundle_id  TEXT NOT NULL REFERENCES bundles(bundle_id),
        release_at INTEGER NOT NULL,
        signature  TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (exam_id, bundle_id)
      );
      CREATE TABLE IF NOT EXISTS admit_tokens (
        token_hash TEXT PRIMARY KEY,
        exam_id    TEXT NOT NULL,
        centre_id  TEXT NOT NULL,
        seat       TEXT NOT NULL,
        issued_at  INTEGER NOT NULL,
        UNIQUE (exam_id, centre_id, seat)
      );
      CREATE TABLE IF NOT EXISTS distributions (
        bundle_id      TEXT NOT NULL REFERENCES bundles(bundle_id),
        centre_id      TEXT NOT NULL REFERENCES centres(centre_id),
        distributed_at INTEGER NOT NULL,
        PRIMARY KEY (bundle_id, centre_id)
      );
      CREATE TABLE IF NOT EXISTS releases (
        bundle_id   TEXT NOT NULL REFERENCES bundles(bundle_id),
        centre_id   TEXT NOT NULL REFERENCES centres(centre_id),
        released_at INTEGER NOT NULL,
        wrapped     BLOB NOT NULL,
        PRIMARY KEY (bundle_id, centre_id)
      );
    `);
    return new AuthorityStore(db);
  }

  // -- centres ---------------------------------------------------------

  enrolCentre(r: CentreRecord): void {
    this.db
      .prepare(
        `INSERT INTO centres (centre_id, box_public_key, cert_fingerprint, hardware_id, enrolled_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(centre_id) DO UPDATE SET
           box_public_key = excluded.box_public_key,
           cert_fingerprint = excluded.cert_fingerprint,
           hardware_id = excluded.hardware_id,
           enrolled_at = excluded.enrolled_at`,
      )
      .run(r.centreId, r.boxPublicKey, r.certFingerprint, r.hardwareId, r.enrolledAt);
  }

  centres(): CentreRecord[] {
    return this.db
      .prepare(`SELECT * FROM centres ORDER BY centre_id`)
      .all()
      .map((row) => rowToCentre(row as Record<string, unknown>));
  }

  centre(centreId: string): CentreRecord | null {
    const row = this.db.prepare(`SELECT * FROM centres WHERE centre_id = ?`).get(centreId);
    return row ? rowToCentre(row as Record<string, unknown>) : null;
  }

  // -- custodians ------------------------------------------------------

  enrolCustodian(r: CustodianRecord): void {
    this.db
      .prepare(
        `INSERT INTO custodians (custodian_id, name, box_public_key, cert_fingerprint, enrolled_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(custodian_id) DO UPDATE SET
           name = excluded.name,
           box_public_key = excluded.box_public_key,
           cert_fingerprint = excluded.cert_fingerprint`,
      )
      .run(r.custodianId, r.name, r.boxPublicKey, r.certFingerprint, r.enrolledAt);
  }

  custodians(): CustodianRecord[] {
    return this.db
      .prepare(`SELECT * FROM custodians ORDER BY custodian_id`)
      .all()
      .map((row) => rowToCustodian(row as Record<string, unknown>));
  }

  custodian(id: string): CustodianRecord | null {
    const row = this.db.prepare(`SELECT * FROM custodians WHERE custodian_id = ?`).get(id);
    return row ? rowToCustodian(row as Record<string, unknown>) : null;
  }

  // -- bundles ---------------------------------------------------------

  putBundle(r: BundleRecord): void {
    this.db
      .prepare(
        `INSERT INTO bundles (bundle_id, exam_id, kind, bundle_hash, content_hash,
                              kek_fingerprint, threshold, share_count, created_at, ciphertext)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        r.bundleId,
        r.examId,
        r.kind,
        r.bundleHash,
        r.contentHash,
        r.kekFingerprint,
        r.threshold,
        r.shareCount,
        r.createdAt,
        r.ciphertext,
      );
  }

  bundle(bundleId: string): BundleRecord | null {
    const row = this.db.prepare(`SELECT * FROM bundles WHERE bundle_id = ?`).get(bundleId);
    return row ? rowToBundle(row as Record<string, unknown>) : null;
  }

  bundles(examId?: string): BundleRecord[] {
    const rows = examId
      ? this.db.prepare(`SELECT * FROM bundles WHERE exam_id = ? ORDER BY created_at`).all(examId)
      : this.db.prepare(`SELECT * FROM bundles ORDER BY created_at`).all();
    return rows.map((r) => rowToBundle(r as Record<string, unknown>));
  }

  // -- shares ----------------------------------------------------------

  putShare(r: ShareRecord): void {
    this.db
      .prepare(
        `INSERT INTO shares (bundle_id, custodian_id, x, sealed, issued_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(r.bundleId, r.custodianId, r.x, r.sealed, r.issuedAt);
  }

  shares(bundleId: string): ShareRecord[] {
    return this.db
      .prepare(`SELECT * FROM shares WHERE bundle_id = ? ORDER BY x`)
      .all(bundleId)
      .map((row) => {
        const r = row as Record<string, unknown>;
        return {
          bundleId: r["bundle_id"] as string,
          custodianId: r["custodian_id"] as string,
          x: r["x"] as number,
          sealed: r["sealed"] as Buffer,
          issuedAt: r["issued_at"] as number,
        };
      });
  }

  // -- schedules -------------------------------------------------------

  putSchedule(r: ScheduleRecord): void {
    this.db
      .prepare(
        `INSERT INTO schedules (exam_id, bundle_id, release_at, signature, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(exam_id, bundle_id) DO UPDATE SET
           release_at = excluded.release_at,
           signature = excluded.signature,
           created_at = excluded.created_at`,
      )
      .run(r.examId, r.bundleId, r.releaseAt, r.signature, r.createdAt);
  }

  schedule(bundleId: string): ScheduleRecord | null {
    const row = this.db.prepare(`SELECT * FROM schedules WHERE bundle_id = ?`).get(bundleId);
    if (!row) return null;
    const r = row as Record<string, unknown>;
    return {
      examId: r["exam_id"] as string,
      bundleId: r["bundle_id"] as string,
      releaseAt: r["release_at"] as number,
      signature: r["signature"] as string,
      createdAt: r["created_at"] as number,
    };
  }

  // -- admit tokens ----------------------------------------------------

  putAdmitToken(r: AdmitTokenRecord): void {
    this.db
      .prepare(
        `INSERT INTO admit_tokens (token_hash, exam_id, centre_id, seat, issued_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(r.tokenHash, r.examId, r.centreId, r.seat, r.issuedAt);
  }

  admitTokenCount(examId: string, centreId: string): number {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS n FROM admit_tokens WHERE exam_id = ? AND centre_id = ?`)
      .get(examId, centreId) as { n: number };
    return row.n;
  }

  // -- distribution and release ----------------------------------------

  recordDistribution(bundleId: string, centreId: string, at: number): void {
    this.db
      .prepare(
        `INSERT INTO distributions (bundle_id, centre_id, distributed_at) VALUES (?, ?, ?)
         ON CONFLICT(bundle_id, centre_id) DO UPDATE SET distributed_at = excluded.distributed_at`,
      )
      .run(bundleId, centreId, at);
  }

  distributedCentres(bundleId: string): string[] {
    return this.db
      .prepare(`SELECT centre_id FROM distributions WHERE bundle_id = ? ORDER BY centre_id`)
      .all(bundleId)
      .map((r) => (r as { centre_id: string }).centre_id);
  }

  recordRelease(bundleId: string, centreId: string, at: number, wrapped: Buffer): void {
    this.db
      .prepare(
        `INSERT INTO releases (bundle_id, centre_id, released_at, wrapped) VALUES (?, ?, ?, ?)
         ON CONFLICT(bundle_id, centre_id) DO UPDATE SET
           released_at = excluded.released_at, wrapped = excluded.wrapped`,
      )
      .run(bundleId, centreId, at, wrapped);
  }

  release(bundleId: string, centreId: string): { releasedAt: number; wrapped: Buffer } | null {
    const row = this.db
      .prepare(`SELECT released_at, wrapped FROM releases WHERE bundle_id = ? AND centre_id = ?`)
      .get(bundleId, centreId);
    if (!row) return null;
    const r = row as { released_at: number; wrapped: Buffer };
    return { releasedAt: r.released_at, wrapped: r.wrapped };
  }

  close(): void {
    this.db.close();
  }
}

function rowToCentre(r: Record<string, unknown>): CentreRecord {
  return {
    centreId: r["centre_id"] as string,
    boxPublicKey: r["box_public_key"] as string,
    certFingerprint: r["cert_fingerprint"] as string,
    hardwareId: r["hardware_id"] as string,
    enrolledAt: r["enrolled_at"] as number,
  };
}

function rowToCustodian(r: Record<string, unknown>): CustodianRecord {
  return {
    custodianId: r["custodian_id"] as string,
    name: r["name"] as string,
    boxPublicKey: r["box_public_key"] as string,
    certFingerprint: r["cert_fingerprint"] as string,
    enrolledAt: r["enrolled_at"] as number,
  };
}

function rowToBundle(r: Record<string, unknown>): BundleRecord {
  return {
    bundleId: r["bundle_id"] as string,
    examId: r["exam_id"] as string,
    kind: r["kind"] as "paper" | "answers",
    bundleHash: r["bundle_hash"] as string,
    contentHash: r["content_hash"] as string,
    kekFingerprint: r["kek_fingerprint"] as string,
    threshold: r["threshold"] as number,
    shareCount: r["share_count"] as number,
    createdAt: r["created_at"] as number,
    ciphertext: r["ciphertext"] as Buffer,
  };
}
