import { blake2b } from "@zw/crypto";

/**
 * RFC 6962 Merkle tree hashing, with BLAKE2b-256 in place of SHA-256.
 *
 * The leaf/node domain prefixes (0x00 / 0x01) are the point: without them a
 * leaf could be presented as an interior node and a forged inclusion proof
 * constructed (the classic second-preimage attack on naive Merkle trees).
 * INVARIANT I-MT-1: every hash input is prefixed.
 */

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

/** MTH({}) — the hash of the empty string, per RFC 6962 §2.1. */
export function emptyRoot(): Buffer {
  return blake2b(Buffer.alloc(0));
}

export function leafHash(entryHash: Buffer): Buffer {
  return blake2b([LEAF_PREFIX, entryHash]);
}

export function nodeHash(left: Buffer, right: Buffer): Buffer {
  return blake2b([NODE_PREFIX, left, right]);
}

/**
 * Merkle Tree Hash over a list of already-hashed entries.
 * Split point is the largest power of two strictly less than n (RFC 6962).
 */
export function merkleRoot(entryHashes: Buffer[]): Buffer {
  if (entryHashes.length === 0) return emptyRoot();
  const leaves = entryHashes.map(leafHash);
  return rootOf(leaves);
}

function rootOf(nodes: Buffer[]): Buffer {
  if (nodes.length === 1) return nodes[0]!;
  const k = largestPowerOfTwoBelow(nodes.length);
  return nodeHash(rootOf(nodes.slice(0, k)), rootOf(nodes.slice(k)));
}

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * Inclusion proof for leaf `index` in a tree of `size` leaves (RFC 6962 §2.1.1).
 * Returned bottom-up: each element is the sibling hash at that level.
 */
export function inclusionProof(entryHashes: Buffer[], index: number): Buffer[] {
  if (index < 0 || index >= entryHashes.length) {
    throw new Error(`inclusionProof: index ${index} out of range for size ${entryHashes.length}`);
  }
  const leaves = entryHashes.map(leafHash);
  const proof: Buffer[] = [];
  build(leaves, index, proof);
  return proof;
}

function build(nodes: Buffer[], index: number, proof: Buffer[]): void {
  if (nodes.length === 1) return;
  const k = largestPowerOfTwoBelow(nodes.length);
  if (index < k) {
    build(nodes.slice(0, k), index, proof);
    proof.push(rootOf(nodes.slice(k)));
  } else {
    build(nodes.slice(k), index - k, proof);
    proof.push(rootOf(nodes.slice(0, k)));
  }
}

/**
 * Recompute the root from a leaf and its inclusion proof.
 *
 * `inclusionProof` emits siblings bottom-up (deepest first), so verification
 * consumes them from the END as it descends — mirroring the construction
 * exactly. A proof of the wrong length fails rather than verifying against a
 * partially consumed path.
 *
 * IMPORTANT (inherent to RFC 6962): an inclusion proof does not by itself
 * pin the tree SIZE. Different sizes can yield the same path shape for a
 * given index — e.g. index 3 descends identically in trees of size 6 and 7 —
 * so a proof valid at one size can verify at another. The size must
 * therefore come from an authenticated source, never from the party
 * presenting the proof. In ZERO-WINDOW it always does: `size` is covered by
 * the checkpoint's Ed25519 signature and by the TSA-anchored root
 * (see Checkpoint in types.ts), so an operator cannot restate the size of a
 * tree they have already published.
 */
export function verifyInclusion(
  entryHash: Buffer,
  index: number,
  size: number,
  proof: Buffer[],
  expectedRoot: Buffer,
): boolean {
  if (index < 0 || index >= size || size < 1) return false;
  const computed = recompute(leafHash(entryHash), index, size, proof, proof.length - 1);
  return computed !== null && computed.equals(expectedRoot);
}

function recompute(
  hash: Buffer,
  index: number,
  n: number,
  proof: Buffer[],
  p: number,
): Buffer | null {
  // Base: reached the leaf level. The proof must be exactly consumed.
  if (n === 1) return p === -1 ? hash : null;
  const sibling = proof[p];
  if (!sibling) return null;
  const k = largestPowerOfTwoBelow(n);
  if (index < k) {
    const left = recompute(hash, index, k, proof, p - 1);
    return left === null ? null : nodeHash(left, sibling);
  }
  const right = recompute(hash, index - k, n - k, proof, p - 1);
  return right === null ? null : nodeHash(sibling, right);
}
