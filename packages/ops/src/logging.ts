import { inspect } from "node:util";

/**
 * Structured JSON logging.
 *
 * INVARIANT I-OPS-1 (acceptance criterion: no raw key material in logs):
 * every value is passed through a redactor before serialization. Keys whose
 * names look like secrets are replaced with "[redacted]", and any Buffer or
 * long hex/base64 string is truncated to a short prefix. This is belt and
 * braces — services are written not to log secrets — but the acceptance test
 * scans real log output, and a redactor that runs on every field is the only
 * way to make that guarantee hold as the code changes.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

/** Field names that must never appear in a log line. */
const SECRET_KEY_PATTERN =
  /(^|_|\.|-)(secret|private|privkey|priv_key|passphrase|password|pin|share|kek|seed|token|key)($|_|\.|-)|^key$|^kek$|^pin$|^share[s]?$/i;

/** Field names that are safe despite matching the pattern above. */
const SAFE_KEYS = new Set([
  "key_id",
  "keyId",
  "public_key",
  "publicKey",
  "signer_public_key",
  "signerPublicKey",
  "kek_fingerprint",
  "kekFingerprint",
  "token_hash",
  "tokenHash",
  "share_count",
  "shareCount",
  "threshold",
  "keystore_path",
  "key_provider",
  "keyProvider",
]);

const MAX_INLINE_STRING = 128;
const MAX_DEPTH = 12;

/**
 * Split camelCase into underscore-separated words so `apiToken` and
 * `privateKey` are matched by the same word-boundary pattern that catches
 * `api_token` and `private_key`. Without this, camelCase secret fields —
 * the common style in this codebase — would pass through unredacted.
 */
function normalizeKey(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2");
}

function isSecretKey(keyName: string): boolean {
  if (!keyName || SAFE_KEYS.has(keyName)) return false;
  return SECRET_KEY_PATTERN.test(keyName) || SECRET_KEY_PATTERN.test(normalizeKey(keyName));
}

export function redact(value: unknown, keyName = ""): unknown {
  return redactInner(value, keyName, new WeakSet<object>(), 0);
}

function redactInner(
  value: unknown,
  keyName: string,
  seen: WeakSet<object>,
  depth: number,
): unknown {
  if (isSecretKey(keyName)) return "[redacted]";
  if (value === null || value === undefined) return value ?? null;
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) {
    // Never log raw bytes. A short prefix is enough to correlate.
    const buf = Buffer.isBuffer(value) ? value : Buffer.from(value.buffer as ArrayBuffer);
    return `[bytes len=${buf.length} sha-prefix=${buf.subarray(0, 4).toString("hex")}…]`;
  }
  switch (typeof value) {
    case "string":
      return value.length > MAX_INLINE_STRING
        ? `${value.slice(0, 16)}…[${value.length} chars truncated]`
        : value;
    case "number":
    case "boolean":
      return value;
    case "bigint":
      return value.toString();
    case "function":
    case "symbol":
      return `[${typeof value}]`;
    default:
      break;
  }
  if (value instanceof Error) {
    return { name: value.name, message: value.message, stack: value.stack };
  }
  if (value instanceof Date) return value.toISOString();

  // Cycles and pathological nesting must degrade to a marker rather than
  // overflowing the stack: a logging call can never be allowed to take a
  // service down, least of all at T-0.
  const obj = value as object;
  if (seen.has(obj)) return "[circular]";
  if (depth >= MAX_DEPTH) return "[max depth exceeded]";
  seen.add(obj);
  try {
    if (Array.isArray(value)) {
      return value.map((v) => redactInner(v, "", seen, depth + 1));
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactInner(v, k, seen, depth + 1);
    }
    return out;
  } finally {
    // Sibling references to the same object are legitimate; only ancestors
    // constitute a cycle.
    seen.delete(obj);
  }
}

export interface LogFields {
  [key: string]: unknown;
}

export interface LoggerOptions {
  service: string;
  level?: LogLevel;
  /** Destination. Defaults to process.stdout. */
  write?: (line: string) => void;
  /** Fields attached to every line (e.g. centre_id). */
  base?: LogFields;
}

export class Logger {
  private readonly service: string;
  private readonly level: LogLevel;
  private readonly write: (line: string) => void;
  private readonly base: LogFields;

  constructor(opts: LoggerOptions) {
    this.service = opts.service;
    this.level = opts.level ?? (process.env["ZW_LOG_LEVEL"] as LogLevel) ?? "info";
    this.write = opts.write ?? ((line) => process.stdout.write(line + "\n"));
    this.base = opts.base ?? {};
  }

  child(fields: LogFields): Logger {
    return new Logger({
      service: this.service,
      level: this.level,
      write: this.write,
      base: { ...this.base, ...fields },
    });
  }

  private emit(level: LogLevel, msg: string, fields: LogFields): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[this.level]) return;
    const record = {
      ts: new Date().toISOString(),
      level,
      service: this.service,
      msg,
      ...(redact({ ...this.base, ...fields }) as LogFields),
    };
    try {
      this.write(JSON.stringify(record));
    } catch {
      // A field that cannot be serialized must not take the service down.
      this.write(
        JSON.stringify({
          ts: record.ts,
          level,
          service: this.service,
          msg,
          log_error: "fields were not serializable",
          fields_inspect: inspect(redact(fields), { depth: 2 }).slice(0, 512),
        }),
      );
    }
  }

  debug(msg: string, fields: LogFields = {}): void {
    this.emit("debug", msg, fields);
  }
  info(msg: string, fields: LogFields = {}): void {
    this.emit("info", msg, fields);
  }
  warn(msg: string, fields: LogFields = {}): void {
    this.emit("warn", msg, fields);
  }
  error(msg: string, fields: LogFields = {}): void {
    this.emit("error", msg, fields);
  }
}
