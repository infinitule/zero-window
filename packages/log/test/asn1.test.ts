import { describe, expect, it } from "vitest";
import {
  Asn1Error,
  TAG,
  decodeGeneralizedTime,
  decodeInteger,
  decodeOid,
  derDecode,
  derDecodeSeq,
  derEncode,
  derInteger,
  derNull,
  derOctetString,
  derOid,
  derSequence,
} from "../src/asn1.js";

describe("DER encoding", () => {
  it("encodes short and long form lengths", () => {
    expect(derEncode(0x04, Buffer.alloc(3)).subarray(0, 2)).toEqual(Buffer.from([0x04, 0x03]));
    // 200 bytes -> 0x81 0xC8
    expect(derEncode(0x04, Buffer.alloc(200)).subarray(0, 3)).toEqual(
      Buffer.from([0x04, 0x81, 0xc8]),
    );
    // 300 bytes -> 0x82 0x01 0x2C
    expect(derEncode(0x04, Buffer.alloc(300)).subarray(0, 4)).toEqual(
      Buffer.from([0x04, 0x82, 0x01, 0x2c]),
    );
  });

  it("encodes INTEGERs with a leading zero when the high bit is set", () => {
    expect(derInteger(0)).toEqual(Buffer.from([0x02, 0x01, 0x00]));
    expect(derInteger(1)).toEqual(Buffer.from([0x02, 0x01, 0x01]));
    expect(derInteger(127)).toEqual(Buffer.from([0x02, 0x01, 0x7f]));
    // 128 needs a pad byte to stay positive
    expect(derInteger(128)).toEqual(Buffer.from([0x02, 0x02, 0x00, 0x80]));
    expect(derInteger(256)).toEqual(Buffer.from([0x02, 0x02, 0x01, 0x00]));
    // Buffer form pads the same way
    expect(derInteger(Buffer.from([0x80]))).toEqual(Buffer.from([0x02, 0x02, 0x00, 0x80]));
    expect(derInteger(Buffer.from([0x7f]))).toEqual(Buffer.from([0x02, 0x01, 0x7f]));
  });

  it("rejects unsupported INTEGER values", () => {
    expect(() => derInteger(-1)).toThrowError(Asn1Error);
    expect(() => derInteger(1.5)).toThrow(/unsupported INTEGER/);
  });

  it("encodes OIDs per X.690 and round-trips them", () => {
    // sha256: 2.16.840.1.101.3.4.2.1
    const sha256 = derOid("2.16.840.1.101.3.4.2.1");
    expect(sha256[0]).toBe(TAG.OID);
    expect(decodeOid(derDecode(sha256))).toBe("2.16.840.1.101.3.4.2.1");

    for (const oid of [
      "1.2.840.113549.1.1.11",
      "1.2.840.10045.4.3.2",
      "1.3.14.3.2.26",
      "2.5.4.3",
      "1.2.3",
    ]) {
      expect(decodeOid(derDecode(derOid(oid)))).toBe(oid);
    }
  });

  it("rejects malformed OIDs", () => {
    expect(() => derOid("1")).toThrow(/at least two arcs/);
    expect(() => derOid("1.x")).toThrow(/bad OID arc/);
    expect(() => derOid("3.1")).toThrow(/invalid OID prefix/);
    expect(() => derOid("1.40")).toThrow(/invalid OID prefix/);
  });

  it("builds nested structures", () => {
    const seq = derSequence(derInteger(1), derOctetString(Buffer.from("ab")), derNull());
    const node = derDecode(seq);
    expect(node.tag).toBe(TAG.SEQUENCE);
    expect(node.children).toHaveLength(3);
    expect(decodeInteger(node.children![0]!)).toBe(1);
    expect(node.children![1]!.value.toString()).toBe("ab");
    expect(node.children![2]!.tag).toBe(TAG.NULL);
  });
});

describe("DER decoding", () => {
  it("rejects truncated and malformed input", () => {
    expect(() => derDecode(Buffer.alloc(0))).toThrow(/no tag byte/);
    expect(() => derDecode(Buffer.from([0x30]))).toThrow(/no length byte/);
    expect(() => derDecode(Buffer.from([0x30, 0x05, 0x01]))).toThrow(/truncated value/);
    expect(() => derDecode(Buffer.from([0x30, 0x81]))).toThrow(/truncated length/);
    // Indefinite length is BER, not DER.
    expect(() => derDecode(Buffer.from([0x30, 0x80, 0x00, 0x00]))).toThrow(/indefinite length/);
    // Length over 4 bytes.
    expect(() => derDecode(Buffer.from([0x30, 0x85, 1, 1, 1, 1, 1]))).toThrow(/exceeds 4 bytes/);
    // Multi-byte tags are out of scope.
    expect(() => derDecode(Buffer.from([0x1f, 0x01, 0x00]))).toThrow(/multi-byte tags/);
  });

  it("decodes a sequence of TLVs", () => {
    const buf = Buffer.concat([derInteger(1), derInteger(2), derInteger(3)]);
    expect(derDecodeSeq(buf).map(decodeInteger)).toEqual([1, 2, 3]);
  });

  it("rejects type confusion in decoders", () => {
    const int = derDecode(derInteger(5));
    expect(() => decodeOid(int)).toThrow(/expected OID/);
    const oid = derDecode(derOid("1.2.3"));
    expect(() => decodeInteger(oid)).toThrow(/expected INTEGER/);
    expect(() => decodeGeneralizedTime(oid)).toThrow(/expected GeneralizedTime/);
  });

  it("rejects oversized INTEGERs rather than silently losing precision", () => {
    const big = derEncode(TAG.INTEGER, Buffer.alloc(8, 0x7f));
    expect(() => decodeInteger(derDecode(big))).toThrow(/too large for a JS number/);
  });

  it("rejects an OID that ends mid-arc", () => {
    // Final byte has the continuation bit set.
    const bad = derEncode(TAG.OID, Buffer.from([0x2a, 0x86]));
    expect(() => decodeOid(derDecode(bad))).toThrow(/ends mid-arc/);
    expect(() => decodeOid(derDecode(derEncode(TAG.OID, Buffer.alloc(0))))).toThrow(/empty OID/);
  });
});

describe("GeneralizedTime", () => {
  const gt = (s: string) => derDecode(derEncode(TAG.GENERALIZED_TIME, Buffer.from(s, "ascii")));

  it("decodes UTC times with and without fractional seconds", () => {
    expect(decodeGeneralizedTime(gt("20260721082530Z"))).toBe(
      Date.UTC(2026, 6, 21, 8, 25, 30, 0),
    );
    expect(decodeGeneralizedTime(gt("20260721082530.5Z"))).toBe(
      Date.UTC(2026, 6, 21, 8, 25, 30, 500),
    );
    expect(decodeGeneralizedTime(gt("20260721082530.123Z"))).toBe(
      Date.UTC(2026, 6, 21, 8, 25, 30, 123),
    );
  });

  it("rejects ambiguous forms: local time and UTC offsets are not evidence", () => {
    expect(() => decodeGeneralizedTime(gt("20260721082530"))).toThrow(/required YYYYMMDD/);
    expect(() => decodeGeneralizedTime(gt("20260721082530+0530"))).toThrow(/required YYYYMMDD/);
    expect(() => decodeGeneralizedTime(gt("2026072108Z"))).toThrow(/required YYYYMMDD/);
    expect(() => decodeGeneralizedTime(gt("not-a-time"))).toThrow(/required YYYYMMDD/);
  });
});
