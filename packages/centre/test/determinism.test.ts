import { describe, expect, it } from "vitest";
import { splitBank } from "@zw/authority";
import { domainHash } from "@zw/crypto";
import { assemblePaper, paperContentHash, paperSeed } from "../src/assemble.js";
import { DeterministicStream } from "../src/prng.js";
import { renderPaper } from "../src/render.js";
import { sampleBank, sampleBlueprint } from "./fixtures.js";

const bank = sampleBank();
const blueprint = sampleBlueprint();
const { paper: content } = splitBank(bank, blueprint);

function tokenHash(n: number): Buffer {
  return domainHash("test-token", Buffer.from(`candidate-${n}`, "utf8"));
}

describe("DeterministicStream (I-GEN-1)", () => {
  it("produces an identical stream for an identical seed", () => {
    const a = new DeterministicStream(Buffer.alloc(32, 7));
    const b = new DeterministicStream(Buffer.alloc(32, 7));
    for (let i = 0; i < 1000; i++) expect(a.nextUint32()).toBe(b.nextUint32());
  });

  it("diverges on a different seed", () => {
    const a = new DeterministicStream(Buffer.alloc(32, 7));
    const b = new DeterministicStream(Buffer.alloc(32, 8));
    const va = Array.from({ length: 8 }, () => a.nextUint32());
    const vb = Array.from({ length: 8 }, () => b.nextUint32());
    expect(va).not.toEqual(vb);
  });

  it("nextBelow is unbiased across its range (chi-square)", () => {
    const s = new DeterministicStream(Buffer.alloc(32, 1));
    const n = 7; // does not divide 2^32 — the modulo-bias case
    const counts = new Array<number>(n).fill(0);
    const N = 70_000;
    for (let i = 0; i < N; i++) counts[s.nextBelow(n)]!++;
    const expected = N / n;
    const chi2 = counts.reduce((acc, c) => acc + ((c - expected) ** 2) / expected, 0);
    // 99.9% critical value for 6 dof ≈ 22.46.
    expect(chi2).toBeLessThan(23);
  });

  it("sample draws without replacement and respects pool bounds", () => {
    const s = new DeterministicStream(Buffer.alloc(32, 2));
    const picked = s.sample([1, 2, 3, 4, 5], 5);
    expect([...picked].sort()).toEqual([1, 2, 3, 4, 5]);
    expect(() => s.sample([1], 2)).toThrow(/requested 2 from pool of 1/);
    expect(() => s.nextBelow(0)).toThrow(/positive integer/);
  });

  it("shuffle does not mutate its input", () => {
    const s = new DeterministicStream(Buffer.alloc(32, 3));
    const input = [1, 2, 3, 4];
    const out = s.shuffle(input);
    expect(input).toEqual([1, 2, 3, 4]);
    expect([...out].sort()).toEqual([1, 2, 3, 4]);
  });
});

describe("paper assembly (I-GEN-2, T4)", () => {
  it("is a pure function of (content, centre, token)", () => {
    const a = assemblePaper({ content, centreId: "C-A", seat: "A-01", tokenHash: tokenHash(1) });
    const b = assemblePaper({ content, centreId: "C-A", seat: "A-01", tokenHash: tokenHash(1) });
    expect(paperContentHash(a).equals(paperContentHash(b))).toBe(true);
  });

  it("is independent of item storage order", () => {
    const reversed = { ...content, items: [...content.items].reverse() };
    const a = assemblePaper({ content, centreId: "C-A", seat: "A-01", tokenHash: tokenHash(1) });
    const b = assemblePaper({
      content: reversed,
      centreId: "C-A",
      seat: "A-01",
      tokenHash: tokenHash(1),
    });
    expect(paperContentHash(a).equals(paperContentHash(b))).toBe(true);
  });

  it("different candidates receive different papers", () => {
    const papers = Array.from({ length: 30 }, (_, i) =>
      assemblePaper({ content, centreId: "C-A", seat: `A-${i}`, tokenHash: tokenHash(i) }),
    );
    const hashes = new Set(papers.map((p) => paperContentHash(p).toString("hex")));
    expect(hashes.size).toBe(30);
  });

  it("satisfies the blueprint exactly for every candidate", () => {
    for (let i = 0; i < 10; i++) {
      const p = assemblePaper({ content, centreId: "C-A", seat: `A-${i}`, tokenHash: tokenHash(i) });
      let expected = 0;
      for (const slot of blueprint.slots) {
        const got = p.questions.filter(
          (q) => q.subject === slot.subject && q.difficulty === slot.difficulty,
        );
        expect(got).toHaveLength(slot.count);
        expected += slot.count;
      }
      expect(p.questions).toHaveLength(expected);
      // Question numbering is sequential from 1.
      expect(p.questions.map((q) => q.number)).toEqual(
        Array.from({ length: expected }, (_, k) => k + 1),
      );
    }
  });

  it("optionOrder recovers the authored option for every printed position", () => {
    const p = assemblePaper({ content, centreId: "C-A", seat: "A-01", tokenHash: tokenHash(4) });
    for (const q of p.questions) {
      const authored = bank.items.find((it) => it.id === q.itemId)!;
      q.options.forEach((printed, i) => {
        expect(printed).toBe(authored.options[q.optionOrder[i]!]);
      });
    }
  });

  it("refuses inconsistent bundles rather than producing a wrong paper", () => {
    const badBlueprint = {
      ...content,
      blueprint: { ...blueprint, examId: "SOME-OTHER-EXAM" },
    };
    expect(() =>
      assemblePaper({ content: badBlueprint, centreId: "C", seat: "S", tokenHash: tokenHash(0) }),
    ).toThrow(/blueprint is for SOME-OTHER-EXAM/);

    const starved = {
      ...content,
      items: content.items.filter((i) => i.difficulty !== "hard"),
    };
    expect(() =>
      assemblePaper({ content: starved, centreId: "C", seat: "S", tokenHash: tokenHash(0) }),
    ).toThrow(/needs 2 items, bundle has 0/);
  });

  it("rejects a seed of the wrong length", () => {
    expect(() => new DeterministicStream(Buffer.alloc(31))).toThrow(/32 bytes/);
  });

  it("the seed binds exam, centre and token (F4)", () => {
    const s1 = paperSeed("E-1", "C-A", tokenHash(1));
    expect(paperSeed("E-2", "C-A", tokenHash(1)).equals(s1)).toBe(false);
    expect(paperSeed("E-1", "C-B", tokenHash(1)).equals(s1)).toBe(false);
    expect(paperSeed("E-1", "C-A", tokenHash(2)).equals(s1)).toBe(false);
    expect(paperSeed("E-1", "C-A", tokenHash(1)).equals(s1)).toBe(true);
  });
});

describe("PDF rendering (I-GEN-3): the byte-identical re-render requirement", () => {
  it("renders byte-identically across repeated runs", async () => {
    const paper = assemblePaper({
      content,
      centreId: "CENTRE-A",
      seat: "A-01",
      tokenHash: tokenHash(1),
    });
    const first = await renderPaper(paper);
    for (let i = 0; i < 3; i++) {
      const again = await renderPaper(paper);
      expect(again.pdf.equals(first.pdf), `render ${i} differed`).toBe(true);
      expect(again.pdfHash.equals(first.pdfHash)).toBe(true);
      expect(again.pageChain).toEqual(first.pageChain);
    }
  }, 60_000);

  it("re-derivation from log data reproduces the identical PDF (dispute path)", async () => {
    // Everything the verifier holds after the exam: bundle plaintext,
    // exam/centre ids, and the token hash from CANDIDATE_CHECKED_IN.
    const th = tokenHash(9);
    const original = await renderPaper(
      assemblePaper({ content, centreId: "CENTRE-B", seat: "B-07", tokenHash: th }),
    );

    // Independent re-derivation, as the verifier will do it in M6.
    const rederived = await renderPaper(
      assemblePaper({
        content: JSON.parse(JSON.stringify(content)) as typeof content,
        centreId: "CENTRE-B",
        seat: "B-07",
        tokenHash: Buffer.from(th),
      }),
    );
    expect(rederived.pdf.equals(original.pdf)).toBe(true);
  }, 60_000);

  it("produces a real PDF with embedded fonts and the expected page count", async () => {
    const paper = assemblePaper({
      content,
      centreId: "CENTRE-A",
      seat: "A-01",
      tokenHash: tokenHash(2),
    });
    const r = await renderPaper(paper);
    expect(r.pdf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    expect(r.pageCount).toBeGreaterThanOrEqual(1);
    expect(r.pageChain).toHaveLength(r.pageCount);
    const s = r.pdf.toString("latin1");
    // Embedded font programs, not references to system fonts.
    expect(s).toContain("FontFile2");
    // No modification timestamp drift: both dates are the epoch.
    expect(s).toContain("D:19700101000000Z");
  }, 60_000);

  it("page chain changes when any page's content changes", async () => {
    const a = await renderPaper(
      assemblePaper({ content, centreId: "C-A", seat: "A-01", tokenHash: tokenHash(1) }),
    );
    const b = await renderPaper(
      assemblePaper({ content, centreId: "C-A", seat: "A-02", tokenHash: tokenHash(2) }),
    );
    expect(a.pageChain[0]).not.toBe(b.pageChain[0]);
  }, 60_000);
});
