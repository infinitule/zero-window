import { describe, expect, it } from "vitest";
import { blake2b } from "@zw/crypto";
import {
  emptyRoot,
  inclusionProof,
  leafHash,
  merkleRoot,
  nodeHash,
  verifyInclusion,
} from "../src/merkle.js";

const h = (s: string): Buffer => blake2b(Buffer.from(s, "utf8"));

describe("RFC 6962 Merkle tree", () => {
  it("empty tree hashes the empty string", () => {
    expect(merkleRoot([]).equals(emptyRoot())).toBe(true);
    expect(merkleRoot([]).equals(blake2b(Buffer.alloc(0)))).toBe(true);
  });

  it("single-leaf root is the leaf hash", () => {
    const a = h("a");
    expect(merkleRoot([a]).equals(leafHash(a))).toBe(true);
  });

  it("two-leaf root matches the manual computation", () => {
    const a = h("a");
    const b = h("b");
    expect(merkleRoot([a, b]).equals(nodeHash(leafHash(a), leafHash(b)))).toBe(true);
  });

  it("splits at the largest power of two below n (RFC 6962 §2.1)", () => {
    const leaves = ["a", "b", "c"].map(h);
    // For n=3: k=2, so root = node(node(leaf a, leaf b), leaf c)
    const expected = nodeHash(
      nodeHash(leafHash(leaves[0]!), leafHash(leaves[1]!)),
      leafHash(leaves[2]!),
    );
    expect(merkleRoot(leaves).equals(expected)).toBe(true);
  });

  it("domain-separates leaves from interior nodes (I-MT-1)", () => {
    // Without the 0x00/0x01 prefixes, a two-leaf tree's root would be
    // indistinguishable from a leaf whose content is the concatenation —
    // the classic second-preimage attack.
    const a = h("a");
    expect(leafHash(a).equals(blake2b(a))).toBe(false);
    expect(nodeHash(a, a).equals(leafHash(Buffer.concat([a, a])))).toBe(false);
  });

  it("root changes if any leaf changes", () => {
    const leaves = ["a", "b", "c", "d", "e"].map(h);
    const base = merkleRoot(leaves);
    for (let i = 0; i < leaves.length; i++) {
      const modified = [...leaves];
      modified[i] = h(`${i}-tampered`);
      expect(merkleRoot(modified).equals(base)).toBe(false);
    }
  });

  it("root changes if leaves are reordered", () => {
    const leaves = ["a", "b", "c", "d"].map(h);
    const swapped = [leaves[1]!, leaves[0]!, leaves[2]!, leaves[3]!];
    expect(merkleRoot(swapped).equals(merkleRoot(leaves))).toBe(false);
  });

  it("inclusion proofs verify for every leaf at many tree sizes", () => {
    for (let n = 1; n <= 33; n++) {
      const leaves = Array.from({ length: n }, (_, i) => h(`leaf-${i}`));
      const root = merkleRoot(leaves);
      for (let i = 0; i < n; i++) {
        const proof = inclusionProof(leaves, i);
        expect(
          verifyInclusion(leaves[i]!, i, n, proof, root),
          `size ${n}, index ${i}`,
        ).toBe(true);
      }
    }
  });

  it("inclusion proofs fail for a wrong leaf, index, size, or root", () => {
    const leaves = Array.from({ length: 7 }, (_, i) => h(`leaf-${i}`));
    const root = merkleRoot(leaves);
    const proof = inclusionProof(leaves, 3);

    expect(verifyInclusion(leaves[3]!, 3, 7, proof, root)).toBe(true);
    expect(verifyInclusion(h("not-in-tree"), 3, 7, proof, root)).toBe(false);
    expect(verifyInclusion(leaves[3]!, 4, 7, proof, root)).toBe(false);
    expect(verifyInclusion(leaves[3]!, 3, 4, proof, root)).toBe(false);
    expect(verifyInclusion(leaves[3]!, 3, 7, proof, h("other-root"))).toBe(false);
    // A truncated or padded proof must fail, not verify against a partial path.
    expect(verifyInclusion(leaves[3]!, 3, 7, proof.slice(1), root)).toBe(false);
    expect(verifyInclusion(leaves[3]!, 3, 7, [...proof, h("extra")], root)).toBe(false);
    expect(verifyInclusion(leaves[3]!, -1, 7, proof, root)).toBe(false);
    expect(verifyInclusion(leaves[3]!, 7, 7, proof, root)).toBe(false);
  });

  it("a forged proof cannot make an absent leaf verify", () => {
    const leaves = Array.from({ length: 8 }, (_, i) => h(`leaf-${i}`));
    const root = merkleRoot(leaves);
    const forged = Array.from({ length: 3 }, (_, i) => h(`forged-${i}`));
    expect(verifyInclusion(h("evidence-we-never-logged"), 2, 8, forged, root)).toBe(false);
  });

  it("an inclusion proof does not by itself pin the tree size (RFC 6962 property)", () => {
    // Index 3 descends identically in trees of size 6 and 7, so the same
    // proof verifies at both. This is why ZERO-WINDOW never takes `size`
    // from the presenting party: it is covered by the checkpoint signature
    // and the anchored root. Asserted here so the property is a documented,
    // tested characteristic rather than a latent surprise.
    const leaves = Array.from({ length: 7 }, (_, i) => h(`leaf-${i}`));
    const root = merkleRoot(leaves);
    const proof = inclusionProof(leaves, 3);
    expect(verifyInclusion(leaves[3]!, 3, 7, proof, root)).toBe(true);
    expect(verifyInclusion(leaves[3]!, 3, 6, proof, root)).toBe(true);
    // A size whose path shape differs is still rejected.
    expect(verifyInclusion(leaves[3]!, 3, 4, proof, root)).toBe(false);
  });

  it("rejects out-of-range proof requests", () => {
    const leaves = [h("a"), h("b")];
    expect(() => inclusionProof(leaves, 2)).toThrow(/out of range/);
    expect(() => inclusionProof(leaves, -1)).toThrow(/out of range/);
  });
});
