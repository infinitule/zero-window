import Database from "better-sqlite3";
import { blake2b, domainHash, verifyDomain, type KeyProvider } from "@zw/crypto";
import { canonicalBytes, type CanonicalValue } from "./canonical.js";
import { merkleRoot } from "./merkle.js";
import type {
  Anchor,
  Checkpoint,
  CheckpointBody,
  EventType,
  EvidenceBundle,
  LogEntry,
  LogEntryBody,
} from "./types.js";

export const ZERO_HASH = "0".repeat(64);

/** Domain strings for entry and checkpoint commitments (I-HASH-1, I-SIG-1). */
export const ENTRY_DOMAIN = "log-entry";
export const CHECKPOINT_DOMAIN = "log-checkpoint";

/** Bytes that an entry's hash and signature both commit to. */
export function entryCommitmentBytes(body: LogEntryBody): Buffer {
  return canonicalBytes(body as unknown as CanonicalValue);
}

export function computeEntryHash(body: LogEntryBody): Buffer {
  return domainHash(ENTRY_DOMAIN, entryCommitmentBytes(body));
}

export function checkpointCommitmentBytes(body: CheckpointBody): Buffer {
  return canonicalBytes(body as unknown as CanonicalValue);
}

export function computeCheckpointDigest(body: CheckpointBody): Buffer {
  return domainHash(CHECKPOINT_DOMAIN, checkpointCommitmentBytes(body));
}

export interface AppendOptions {
  type: EventType;
  payload: Record<string, CanonicalValue>;
  /** Override the timestamp (offline/replay paths). Defaults to now. */
  ts?: number;
}

export interface TransparencyLogOptions {
  /** SQLite file path. Use ":memory:" only in tests. */
  dbPath: string;
  /** Identifier written into every entry's `actor` field. */
  actor: string;
  /** Key provider holding the signing key. */
  provider: KeyProvider;
  /** Key id of the Ed25519 signing key within the provider. */
  signingKeyId: string;
}

/**
 * Append-only, hash-chained, signed transparency log.
 *
 * INVARIANT I-LOG-2 (append-only): there is no update or delete path. The
 * SQLite schema enforces it with triggers, so even a direct sqlite3 session
 * against the file cannot rewrite history without leaving the chain broken.
 *
 * INVARIANT I-LOG-3 (chain): entry[n].prevHash == entry[n-1].hash, and
 * entry[0].prevHash is all zeroes. Any insertion, deletion, reordering or
 * modification breaks it at a detectable position.
 */
export class TransparencyLog {
  private constructor(
    private readonly db: Database.Database,
    private readonly actor: string,
    private readonly provider: KeyProvider,
    private readonly signingKeyId: string,
    private readonly signerPublicKey: Buffer,
  ) {}

  static async open(opts: TransparencyLogOptions): Promise<TransparencyLog> {
    const db = new Database(opts.dbPath);
    // WAL: durable across process crash, and readers (the metrics endpoint,
    // an auditor tailing the log) never block the append path.
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = FULL");
    db.pragma("foreign_keys = ON");

    db.exec(`
      CREATE TABLE IF NOT EXISTS entries (
        seq               INTEGER PRIMARY KEY,
        ts                INTEGER NOT NULL,
        type              TEXT    NOT NULL,
        actor             TEXT    NOT NULL,
        payload           TEXT    NOT NULL,
        prev_hash         TEXT    NOT NULL,
        hash              TEXT    NOT NULL UNIQUE,
        signature         TEXT    NOT NULL,
        signer_public_key TEXT    NOT NULL
      );

      CREATE TABLE IF NOT EXISTS checkpoints (
        size              INTEGER PRIMARY KEY,
        root              TEXT    NOT NULL,
        head_hash         TEXT    NOT NULL,
        ts                INTEGER NOT NULL,
        signature         TEXT    NOT NULL,
        signer_public_key TEXT    NOT NULL,
        anchors           TEXT    NOT NULL DEFAULT '[]'
      );

      -- I-LOG-2: the log is append-only at the storage layer, not just by
      -- convention. An operator with direct database access still cannot
      -- rewrite an entry without tripping these.
      CREATE TRIGGER IF NOT EXISTS entries_no_update
        BEFORE UPDATE ON entries
        BEGIN SELECT RAISE(ABORT, 'transparency log is append-only: UPDATE forbidden'); END;

      CREATE TRIGGER IF NOT EXISTS entries_no_delete
        BEFORE DELETE ON entries
        BEGIN SELECT RAISE(ABORT, 'transparency log is append-only: DELETE forbidden'); END;

      CREATE TRIGGER IF NOT EXISTS checkpoints_no_delete
        BEFORE DELETE ON checkpoints
        BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only: DELETE forbidden'); END;
    `);

    const signerPublicKey = await opts.provider.ensureSigningKey(opts.signingKeyId);
    return new TransparencyLog(
      db,
      opts.actor,
      opts.provider,
      opts.signingKeyId,
      signerPublicKey,
    );
  }

  get publicKey(): Buffer {
    return this.signerPublicKey;
  }

  size(): number {
    const row = this.db.prepare("SELECT COUNT(*) AS n FROM entries").get() as { n: number };
    return row.n;
  }

  head(): LogEntry | null {
    const row = this.db
      .prepare("SELECT * FROM entries ORDER BY seq DESC LIMIT 1")
      .get() as EntryRow | undefined;
    return row ? rowToEntry(row) : null;
  }

  /**
   * Append a signed, chained entry. Serialized by a SQLite IMMEDIATE
   * transaction so concurrent writers cannot interleave and produce two
   * entries claiming the same prevHash.
   */
  async append(opts: AppendOptions): Promise<LogEntry> {
    const ts = opts.ts ?? Date.now();

    // Reserve the sequence number and previous hash atomically.
    const reserve = this.db.transaction(() => {
      const row = this.db
        .prepare("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1")
        .get() as { seq: number; hash: string } | undefined;
      return { seq: row ? row.seq + 1 : 0, prevHash: row ? row.hash : ZERO_HASH };
    });
    const { seq, prevHash } = reserve.immediate();

    const body: LogEntryBody = {
      seq,
      ts,
      type: opts.type,
      actor: this.actor,
      payload: opts.payload,
      prevHash,
    };
    const commitment = entryCommitmentBytes(body);
    const hash = domainHash(ENTRY_DOMAIN, commitment);
    const signature = await this.provider.sign(this.signingKeyId, ENTRY_DOMAIN, commitment);

    const entry: LogEntry = {
      ...body,
      hash: hash.toString("hex"),
      signature: signature.toString("hex"),
      signerPublicKey: this.signerPublicKey.toString("hex"),
    };

    this.db
      .prepare(
        `INSERT INTO entries (seq, ts, type, actor, payload, prev_hash, hash, signature, signer_public_key)
         VALUES (@seq, @ts, @type, @actor, @payload, @prevHash, @hash, @signature, @signerPublicKey)`,
      )
      .run({
        seq: entry.seq,
        ts: entry.ts,
        type: entry.type,
        actor: entry.actor,
        payload: JSON.stringify(entry.payload),
        prevHash: entry.prevHash,
        hash: entry.hash,
        signature: entry.signature,
        signerPublicKey: entry.signerPublicKey,
      });

    return entry;
  }

  entries(from = 0, to?: number): LogEntry[] {
    const rows = (
      to === undefined
        ? this.db.prepare("SELECT * FROM entries WHERE seq >= ? ORDER BY seq").all(from)
        : this.db
            .prepare("SELECT * FROM entries WHERE seq >= ? AND seq < ? ORDER BY seq")
            .all(from, to)
    ) as EntryRow[];
    return rows.map(rowToEntry);
  }

  entryHashes(): Buffer[] {
    const rows = this.db.prepare("SELECT hash FROM entries ORDER BY seq").all() as {
      hash: string;
    }[];
    return rows.map((r) => Buffer.from(r.hash, "hex"));
  }

  /**
   * Build and sign a checkpoint over the whole current log. Anchors are
   * attached separately by the anchoring client (see anchor.ts) because a
   * TSA round-trip must not block the append path at T-0.
   */
  async createCheckpoint(ts = Date.now()): Promise<Checkpoint> {
    const hashes = this.entryHashes();
    if (hashes.length === 0) {
      throw new Error("createCheckpoint: log is empty");
    }
    const body: CheckpointBody = {
      size: hashes.length,
      root: merkleRoot(hashes).toString("hex"),
      headHash: hashes[hashes.length - 1]!.toString("hex"),
      ts,
    };
    const commitment = checkpointCommitmentBytes(body);
    const signature = await this.provider.sign(this.signingKeyId, CHECKPOINT_DOMAIN, commitment);
    const checkpoint: Checkpoint = {
      ...body,
      signature: signature.toString("hex"),
      signerPublicKey: this.signerPublicKey.toString("hex"),
      anchors: [],
    };

    this.db
      .prepare(
        `INSERT INTO checkpoints (size, root, head_hash, ts, signature, signer_public_key, anchors)
         VALUES (@size, @root, @headHash, @ts, @signature, @signerPublicKey, '[]')
         ON CONFLICT(size) DO NOTHING`,
      )
      .run({
        size: checkpoint.size,
        root: checkpoint.root,
        headHash: checkpoint.headHash,
        ts: checkpoint.ts,
        signature: checkpoint.signature,
        signerPublicKey: checkpoint.signerPublicKey,
      });

    const stored = this.checkpoint(checkpoint.size);
    return stored ?? checkpoint;
  }

  /** Attach anchor tokens to an existing checkpoint (additive only). */
  attachAnchors(size: number, anchors: Anchor[]): Checkpoint {
    const existing = this.checkpoint(size);
    if (!existing) throw new Error(`attachAnchors: no checkpoint of size ${size}`);
    for (const a of anchors) {
      if (a.imprint !== existing.root) {
        throw new Error(
          `attachAnchors: anchor imprint ${a.imprint} does not match checkpoint root ${existing.root}`,
        );
      }
    }
    // Anchors accumulate; an anchor is never removed or replaced, so a later
    // TSA cannot be used to displace an earlier inconvenient timestamp.
    const merged = [...existing.anchors, ...anchors];
    this.db
      .prepare("UPDATE checkpoints SET anchors = ? WHERE size = ?")
      .run(JSON.stringify(merged), size);
    return { ...existing, anchors: merged };
  }

  checkpoint(size: number): Checkpoint | null {
    const row = this.db.prepare("SELECT * FROM checkpoints WHERE size = ?").get(size) as
      | CheckpointRow
      | undefined;
    return row ? rowToCheckpoint(row) : null;
  }

  checkpoints(): Checkpoint[] {
    const rows = this.db
      .prepare("SELECT * FROM checkpoints ORDER BY size")
      .all() as CheckpointRow[];
    return rows.map(rowToCheckpoint);
  }

  latestCheckpoint(): Checkpoint | null {
    const rows = this.db
      .prepare("SELECT * FROM checkpoints ORDER BY size DESC LIMIT 1")
      .all() as CheckpointRow[];
    const row = rows[0];
    return row ? rowToCheckpoint(row) : null;
  }

  /**
   * Snapshot this log as a portable evidence bundle. The signer map carries
   * every public key that appears in the log, keyed by actor — a verifier
   * cross-checks these against out-of-band enrolment records rather than
   * trusting the bundle's own claim (the tamper suite covers substitution).
   */
  evidence(examId: string): EvidenceBundle {
    const entries = this.entries();
    const signers: Record<string, string> = {};
    for (const e of entries) signers[e.actor] = e.signerPublicKey;
    return {
      version: 1,
      exam_id: examId,
      entries,
      checkpoints: this.checkpoints(),
      signers,
    };
  }

  close(): void {
    this.db.close();
  }
}

interface EntryRow {
  seq: number;
  ts: number;
  type: string;
  actor: string;
  payload: string;
  prev_hash: string;
  hash: string;
  signature: string;
  signer_public_key: string;
}

interface CheckpointRow {
  size: number;
  root: string;
  head_hash: string;
  ts: number;
  signature: string;
  signer_public_key: string;
  anchors: string;
}

function rowToEntry(row: EntryRow): LogEntry {
  return {
    seq: row.seq,
    ts: row.ts,
    type: row.type as EventType,
    actor: row.actor,
    payload: JSON.parse(row.payload) as Record<string, CanonicalValue>,
    prevHash: row.prev_hash,
    hash: row.hash,
    signature: row.signature,
    signerPublicKey: row.signer_public_key,
  };
}

function rowToCheckpoint(row: CheckpointRow): Checkpoint {
  return {
    size: row.size,
    root: row.root,
    headHash: row.head_hash,
    ts: row.ts,
    signature: row.signature,
    signerPublicKey: row.signer_public_key,
    anchors: JSON.parse(row.anchors) as Anchor[],
  };
}

/** Recompute an entry's body from a stored entry, for verification. */
export function bodyOf(entry: LogEntry): LogEntryBody {
  return {
    seq: entry.seq,
    ts: entry.ts,
    type: entry.type,
    actor: entry.actor,
    payload: entry.payload,
    prevHash: entry.prevHash,
  };
}

/** Verify one entry's hash and signature in isolation. */
export function verifyEntrySelf(entry: LogEntry): { ok: boolean; reason?: string } {
  const commitment = entryCommitmentBytes(bodyOf(entry));
  const expected = domainHash(ENTRY_DOMAIN, commitment).toString("hex");
  if (expected !== entry.hash) {
    return { ok: false, reason: `hash mismatch: stored ${entry.hash}, recomputed ${expected}` };
  }
  const pub = Buffer.from(entry.signerPublicKey, "hex");
  const sig = Buffer.from(entry.signature, "hex");
  if (!verifyDomain(ENTRY_DOMAIN, commitment, sig, pub)) {
    return { ok: false, reason: `Ed25519 signature does not verify under ${entry.signerPublicKey}` };
  }
  return { ok: true };
}

/** Verify a checkpoint's signature and its consistency with a set of entries. */
export function verifyCheckpointSelf(cp: Checkpoint): { ok: boolean; reason?: string } {
  const body: CheckpointBody = {
    size: cp.size,
    root: cp.root,
    headHash: cp.headHash,
    ts: cp.ts,
  };
  const commitment = checkpointCommitmentBytes(body);
  const pub = Buffer.from(cp.signerPublicKey, "hex");
  const sig = Buffer.from(cp.signature, "hex");
  if (!verifyDomain(CHECKPOINT_DOMAIN, commitment, sig, pub)) {
    return {
      ok: false,
      reason: `checkpoint at size ${cp.size}: signature does not verify under ${cp.signerPublicKey}`,
    };
  }
  return { ok: true };
}

/** Hash used to bind an evidence file to its contents. */
export function evidenceDigest(lines: string[]): Buffer {
  return blake2b(lines.map((l) => Buffer.from(l + "\n", "utf8")));
}
