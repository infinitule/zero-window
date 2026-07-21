/**
 * Minimal DER encoder/decoder — only what RFC 3161 timestamping needs.
 *
 * Written in-tree rather than pulled from a general ASN.1 library because the
 * verifier must be auditable end to end: an auditor reading this file can
 * confirm exactly which bytes are produced and how a TimeStampToken is
 * parsed, with no dependency that could change parsing behaviour between
 * versions. Scope is deliberately narrow — this is not a general ASN.1
 * implementation and rejects anything outside the RFC 3161 profile.
 */

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
} as const;

export class Asn1Error extends Error {
  constructor(message: string) {
    super(`ASN.1: ${message}`);
    this.name = "Asn1Error";
  }
}

// ---------------------------------------------------------------- encoding

function encodeLength(len: number): Buffer {
  if (len < 0) throw new Asn1Error("negative length");
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  if (bytes.length > 4) throw new Asn1Error("length too large");
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function derEncode(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

export function derInteger(value: number | Buffer): Buffer {
  if (Buffer.isBuffer(value)) {
    // Prepend 0x00 if the high bit is set, so it stays a positive INTEGER.
    const needsPad = (value[0] ?? 0) & 0x80;
    return derEncode(TAG.INTEGER, needsPad ? Buffer.concat([Buffer.from([0]), value]) : value);
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Asn1Error(`unsupported INTEGER value ${value}`);
  }
  if (value === 0) return derEncode(TAG.INTEGER, Buffer.from([0]));
  const bytes: number[] = [];
  let n = value;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  if ((bytes[0] ?? 0) & 0x80) bytes.unshift(0);
  return derEncode(TAG.INTEGER, Buffer.from(bytes));
}

export function derOid(oid: string): Buffer {
  const parts = oid.split(".").map((p) => {
    const n = Number(p);
    if (!Number.isSafeInteger(n) || n < 0) throw new Asn1Error(`bad OID arc "${p}" in ${oid}`);
    return n;
  });
  if (parts.length < 2) throw new Asn1Error(`OID needs at least two arcs: ${oid}`);
  const first = parts[0]!;
  const second = parts[1]!;
  if (first > 2 || (first < 2 && second >= 40)) {
    throw new Asn1Error(`invalid OID prefix ${first}.${second}`);
  }
  const bytes: number[] = [first * 40 + second];
  for (const arc of parts.slice(2)) {
    if (arc === 0) {
      bytes.push(0);
      continue;
    }
    const chunk: number[] = [];
    let n = arc;
    while (n > 0) {
      chunk.unshift((n & 0x7f) | (chunk.length ? 0x80 : 0));
      n = Math.floor(n / 128);
    }
    bytes.push(...chunk);
  }
  return derEncode(TAG.OID, Buffer.from(bytes));
}

export function derNull(): Buffer {
  return Buffer.from([TAG.NULL, 0x00]);
}

export function derOctetString(data: Buffer): Buffer {
  return derEncode(TAG.OCTET_STRING, data);
}

export function derSequence(...items: Buffer[]): Buffer {
  return derEncode(TAG.SEQUENCE, Buffer.concat(items));
}

export function derBoolean(value: boolean): Buffer {
  return derEncode(TAG.BOOLEAN, Buffer.from([value ? 0xff : 0x00]));
}

// ---------------------------------------------------------------- decoding

export interface Asn1Node {
  tag: number;
  /** Offset of the tag byte within the buffer this was parsed from. */
  start: number;
  /** Offset just past the end of the value. */
  end: number;
  /** Raw content bytes (excluding tag and length). */
  value: Buffer;
  /** Whole TLV, tag through end of content — needed for re-hashing. */
  raw: Buffer;
  children?: Asn1Node[];
}

function isConstructed(tag: number): boolean {
  return (tag & 0x20) !== 0;
}

export function derDecode(buf: Buffer, offset = 0): Asn1Node {
  if (offset >= buf.length) throw new Asn1Error("truncated: no tag byte");
  const tag = buf[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new Asn1Error("multi-byte tags are not supported");
  let p = offset + 1;
  if (p >= buf.length) throw new Asn1Error("truncated: no length byte");
  const first = buf[p]!;
  p++;
  let len: number;
  if (first < 0x80) {
    len = first;
  } else {
    const nBytes = first & 0x7f;
    if (nBytes === 0) throw new Asn1Error("indefinite length is not valid in DER");
    if (nBytes > 4) throw new Asn1Error("length exceeds 4 bytes");
    if (p + nBytes > buf.length) throw new Asn1Error("truncated length");
    len = 0;
    for (let i = 0; i < nBytes; i++) len = len * 256 + buf[p + i]!;
    p += nBytes;
  }
  const end = p + len;
  if (end > buf.length) {
    throw new Asn1Error(`truncated value: need ${end} bytes, have ${buf.length}`);
  }
  const value = buf.subarray(p, end);
  const node: Asn1Node = {
    tag,
    start: offset,
    end,
    value,
    raw: buf.subarray(offset, end),
  };
  if (isConstructed(tag)) {
    node.children = derDecodeSeq(value);
  }
  return node;
}

export function derDecodeSeq(buf: Buffer): Asn1Node[] {
  const out: Asn1Node[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const node = derDecode(buf, offset);
    out.push(node);
    offset = node.end;
  }
  return out;
}

export function decodeOid(node: Asn1Node): string {
  if (node.tag !== TAG.OID) throw new Asn1Error(`expected OID, got tag 0x${node.tag.toString(16)}`);
  const b = node.value;
  if (b.length === 0) throw new Asn1Error("empty OID");
  const first = b[0]!;
  const arcs = [Math.floor(first / 40), first % 40];
  let acc = 0;
  for (let i = 1; i < b.length; i++) {
    const byte = b[i]!;
    acc = acc * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      arcs.push(acc);
      acc = 0;
    }
  }
  if (acc !== 0) throw new Asn1Error("OID ends mid-arc");
  return arcs.join(".");
}

export function decodeInteger(node: Asn1Node): number {
  if (node.tag !== TAG.INTEGER) {
    throw new Asn1Error(`expected INTEGER, got tag 0x${node.tag.toString(16)}`);
  }
  if (node.value.length > 6) throw new Asn1Error("INTEGER too large for a JS number");
  let n = 0;
  for (const byte of node.value) n = n * 256 + byte;
  return n;
}

/**
 * Decode ASN.1 GeneralizedTime to integer milliseconds since epoch.
 * RFC 3161 requires GeneralizedTime in UTC ("Z"), optionally with fractional
 * seconds. Local-time and offset forms are rejected: a timestamp whose zone
 * is ambiguous is not evidence.
 */
export function decodeGeneralizedTime(node: Asn1Node): number {
  if (node.tag !== TAG.GENERALIZED_TIME) {
    throw new Asn1Error(`expected GeneralizedTime, got tag 0x${node.tag.toString(16)}`);
  }
  const s = node.value.toString("ascii");
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:[.,](\d+))?Z$/.exec(s);
  if (!m) {
    throw new Asn1Error(`GeneralizedTime "${s}" is not in the required YYYYMMDDHHMMSS[.f]Z form`);
  }
  const [, y, mo, d, h, mi, sec, frac] = m;
  const ms = frac ? Math.round(Number(`0.${frac}`) * 1000) : 0;
  const t = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(sec), ms);
  if (!Number.isFinite(t)) throw new Asn1Error(`GeneralizedTime "${s}" is not a valid instant`);
  return t;
}
