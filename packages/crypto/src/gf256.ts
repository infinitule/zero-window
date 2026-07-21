/**
 * GF(2^8) arithmetic over the AES reduction polynomial x^8+x^4+x^3+x+1
 * (0x11b), generator 0x03. Table-based; tables are built once at module load.
 *
 * Side-channel note: table lookups are not constant-time on all
 * micro-architectures. Shamir arithmetic runs only inside the ceremony /
 * release paths on operator-controlled hardware, never in a network-facing
 * request handler with attacker-controlled secrets; accepted residual risk is
 * recorded in DECISIONS.md (D-7).
 */

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    // multiply x by generator 0x03 = x * 2 ^ x
    const x2 = (x << 1) ^ (x & 0x80 ? 0x11b : 0);
    x = (x2 ^ x) & 0xff;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
})();

export function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a]! + LOG[b]!]!;
}

export function gfInv(a: number): number {
  if (a === 0) throw new Error("gfInv(0) undefined");
  return EXP[255 - LOG[a]!]!;
}

export function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error("gfDiv by zero");
  if (a === 0) return 0;
  return EXP[(LOG[a]! + 255 - LOG[b]!) % 255]!;
}

export function gfAdd(a: number, b: number): number {
  return (a ^ b) & 0xff;
}

/** Horner evaluation of a polynomial (coeffs[0] is the constant term). */
export function gfPolyEval(coeffs: Uint8Array, x: number): number {
  let y = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    y = gfAdd(gfMul(y, x), coeffs[i]!);
  }
  return y;
}
