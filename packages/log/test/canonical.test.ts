import { describe, expect, it } from "vitest";
import { CanonicalizationError, canonicalBytes, canonicalize } from "../src/canonical.js";

describe("canonical JSON (I-CANON-1)", () => {
  it("sorts object keys recursively", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize({ z: { y: 1, x: 2 }, a: 3 })).toBe('{"a":3,"z":{"x":2,"y":1}}');
  });

  it("produces identical output for objects built in different orders", () => {
    const a: Record<string, unknown> = {};
    a["seq"] = 1;
    a["type"] = "PAPER_GENERATED";
    a["actor"] = "centre-A";

    const b: Record<string, unknown> = {};
    b["actor"] = "centre-A";
    b["type"] = "PAPER_GENERATED";
    b["seq"] = 1;

    expect(canonicalize(a as never)).toBe(canonicalize(b as never));
  });

  it("emits no insignificant whitespace", () => {
    expect(canonicalize({ a: [1, 2, 3], b: "x" })).toBe('{"a":[1,2,3],"b":"x"}');
  });

  it("escapes control characters and quotes deterministically", () => {
    expect(canonicalize({ s: 'a"b\\c' })).toBe('{"s":"a\\"b\\\\c"}');
    expect(canonicalize({ s: "\n\t\r\b\f" })).toBe('{"s":"\\n\\t\\r\\b\\f"}');
    expect(canonicalize({ s: "" })).toBe('{"s":"\\u0001"}');
  });

  it("preserves non-ASCII characters as UTF-8 rather than escaping them", () => {
    const out = canonicalize({ s: "परीक्षा" });
    expect(out).toBe('{"s":"परीक्षा"}');
    expect(canonicalBytes({ s: "परीक्षा" }).toString("utf8")).toBe(out);
  });

  it("rejects floats: JSON float round-tripping is exactly the ambiguity to avoid", () => {
    expect(() => canonicalize({ x: 1.5 })).toThrowError(CanonicalizationError);
    expect(() => canonicalize({ x: 0.1 })).toThrow(/integers only/);
  });

  it("rejects non-finite and unsafe numbers", () => {
    expect(() => canonicalize({ x: NaN })).toThrow(/non-finite/);
    expect(() => canonicalize({ x: Infinity })).toThrow(/non-finite/);
    expect(() => canonicalize({ x: Number.MAX_SAFE_INTEGER + 2 })).toThrow(/safe-integer/);
  });

  it("normalizes -0 to 0 so a value cannot have two encodings", () => {
    expect(canonicalize({ x: -0 })).toBe('{"x":0}');
    expect(canonicalize({ x: 0 })).toBe('{"x":0}');
  });

  it("rejects undefined rather than silently dropping a field", () => {
    // Dropping it would change what gets signed without anyone noticing.
    expect(() => canonicalize({ a: 1, b: undefined } as never)).toThrow(/undefined/);
    expect(() => canonicalize([undefined] as never)).toThrow(/undefined/);
  });

  it("rejects binary values so the encoding is always explicit in evidence", () => {
    expect(() => canonicalize({ b: Buffer.from("x") } as never)).toThrow(/explicitly encoded/);
    expect(() => canonicalize({ b: new Uint8Array([1]) } as never)).toThrow(/explicitly encoded/);
  });

  it("rejects bigint, functions and symbols", () => {
    expect(() => canonicalize({ x: 1n } as never)).toThrow(/bigint/);
    expect(() => canonicalize({ x: () => 0 } as never)).toThrow(/function/);
    expect(() => canonicalize({ x: Symbol("s") } as never)).toThrow(/symbol/);
  });

  it("reports the path of the offending value", () => {
    try {
      canonicalize({ entries: [{ payload: { seat: 1.5 } }] } as never);
      expect.unreachable("should have thrown");
    } catch (err) {
      expect((err as CanonicalizationError).path).toBe("$.entries[0].payload.seat");
    }
  });

  it("handles null, booleans, empty structures", () => {
    expect(canonicalize({ a: null, b: true, c: false, d: [], e: {} })).toBe(
      '{"a":null,"b":true,"c":false,"d":[],"e":{}}',
    );
  });

  it("array order is significant and preserved", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
    expect(canonicalize([1, 2, 3])).not.toBe(canonicalize([3, 2, 1]));
  });
});
