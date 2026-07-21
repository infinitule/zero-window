/**
 * Canonical JSON serialization (RFC 8785 / JCS subset).
 *
 * INVARIANT I-CANON-1: the bytes a signature or hash commits to must be
 * reproducible by any independent implementation, years later, from the
 * exported evidence file alone. Two encoders that disagree on key order or
 * number formatting would make a valid log look forged. So:
 *
 *   - object keys sorted by UTF-16 code unit (JS default sort), recursively
 *   - no insignificant whitespace
 *   - strings escaped per JSON with the shortest form (\b \t \n \f \r \" \\,
 *     \u00XX for other control characters)
 *   - numbers: integers only, in the safe-integer range. Floats are REJECTED
 *     rather than serialized, because JSON float round-tripping is exactly
 *     the class of ambiguity this format exists to avoid. Timestamps are
 *     integer milliseconds; everything else numeric in the log is a count.
 *   - undefined values are rejected, not silently dropped
 *   - Buffers are not accepted: binary must be explicitly base64 or hex
 *     encoded by the caller, so the encoding is visible in the evidence file
 */

export type CanonicalValue =
  | string
  | number
  | boolean
  | null
  | CanonicalValue[]
  | { [key: string]: CanonicalValue };

export class CanonicalizationError extends Error {
  /** JSON path of the offending value, always rooted at "$". */
  readonly path: string;

  constructor(message: string, path: string) {
    const rooted = `$${path}`;
    super(`${message} (at ${rooted})`);
    this.name = "CanonicalizationError";
    this.path = rooted;
  }
}

function escapeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    switch (ch) {
      case '"':
        out += '\\"';
        break;
      case "\\":
        out += "\\\\";
        break;
      case "\b":
        out += "\\b";
        break;
      case "\f":
        out += "\\f";
        break;
      case "\n":
        out += "\\n";
        break;
      case "\r":
        out += "\\r";
        break;
      case "\t":
        out += "\\t";
        break;
      default:
        if (code < 0x20) {
          out += `\\u${code.toString(16).padStart(4, "0")}`;
        } else {
          out += ch;
        }
    }
  }
  return out + '"';
}

function encode(value: unknown, path: string): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number": {
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError(`non-finite number ${String(value)}`, path);
      }
      if (!Number.isInteger(value)) {
        throw new CanonicalizationError(
          `non-integer number ${value}: canonical JSON accepts integers only`,
          path,
        );
      }
      if (!Number.isSafeInteger(value)) {
        throw new CanonicalizationError(`number ${value} outside safe-integer range`, path);
      }
      // -0 must serialize as 0 so it cannot produce two encodings.
      return Object.is(value, -0) ? "0" : String(value);
    }

    case "string":
      return escapeString(value);

    case "undefined":
      throw new CanonicalizationError("undefined is not representable", path);

    case "bigint":
      throw new CanonicalizationError("bigint is not representable", path);

    case "function":
    case "symbol":
      throw new CanonicalizationError(`${typeof value} is not representable`, path);

    case "object":
      break;

    default:
      throw new CanonicalizationError(`unsupported type ${typeof value}`, path);
  }

  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) {
    throw new CanonicalizationError(
      "binary values must be explicitly encoded (base64/hex) by the caller",
      path,
    );
  }

  if (Array.isArray(value)) {
    return `[${value.map((v, i) => encode(v, `${path}[${i}]`)).join(",")}]`;
  }

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const v = obj[k];
    // An explicitly-undefined property is a bug in the caller, not an
    // absent field — dropping it silently would change what gets signed.
    if (v === undefined) {
      throw new CanonicalizationError(`property "${k}" is undefined`, path);
    }
    parts.push(`${escapeString(k)}:${encode(v, `${path}.${k}`)}`);
  }
  return `{${parts.join(",")}}`;
}

/** Canonical JSON string. */
export function canonicalize(value: CanonicalValue): string {
  return encode(value, "");
}

/** Canonical JSON as UTF-8 bytes — what hashes and signatures commit to. */
export function canonicalBytes(value: CanonicalValue): Buffer {
  return Buffer.from(canonicalize(value), "utf8");
}
