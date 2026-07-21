import { domainHash, verifyDomain, type KeyProvider } from "@zw/crypto";
import { canonicalJson } from "./bank.js";

/**
 * Admit tokens (F2).
 *
 * An admit token is an Ed25519-signed statement binding a candidate's
 * registration-ID HASH to an exam, centre and seat. It is verified OFFLINE at
 * the centre — a centre that has lost connectivity must still be able to
 * admit candidates (T10) — so the token carries everything needed to check
 * it, and the centre needs only the authority's public key.
 *
 * INVARIANT I-ADMIT-1 (T8): the token never carries the registration ID
 * itself, a name, or any other PII — only a salted hash of the registration
 * ID. The salt is per-exam, so the same candidate across two exams produces
 * unlinkable token hashes, and a stolen ledger cannot be joined against a
 * population register by brute-forcing a known-format ID.
 */

export const ADMIT_TOKEN_DOMAIN = "admit-token";
export const ADMIT_TOKEN_VERSION = 1;

export interface AdmitTokenBody {
  v: number;
  examId: string;
  centreId: string;
  seat: string;
  /** hex BLAKE2b(salt ‖ registrationId) — never the id itself (I-ADMIT-1). */
  registrationHash: string;
  /** Epoch ms after which the token is not admissible. */
  expiresAt: number;
}

export interface AdmitToken extends AdmitTokenBody {
  /** hex Ed25519 signature over the canonical body. */
  signature: string;
}

export function admitTokenBodyBytes(body: AdmitTokenBody): Buffer {
  return canonicalJson(body);
}

/** The token's own identity, used as the seat binding key in the log. */
export function admitTokenHash(token: AdmitTokenBody): Buffer {
  return domainHash("admit-token-id", admitTokenBodyBytes(token));
}

/**
 * Hash a registration ID under a per-exam salt. The salt must be held by the
 * registration system and the authority only; it never enters the log.
 */
export function registrationHash(salt: Buffer, registrationId: string): Buffer {
  return domainHash("registration-id", [salt, Buffer.from(registrationId, "utf8")]);
}

export interface IssueAdmitTokenOptions {
  examId: string;
  centreId: string;
  seat: string;
  registrationHash: Buffer;
  expiresAt: number;
}

export async function issueAdmitToken(
  provider: KeyProvider,
  signingKeyId: string,
  opts: IssueAdmitTokenOptions,
): Promise<AdmitToken> {
  const body: AdmitTokenBody = {
    v: ADMIT_TOKEN_VERSION,
    examId: opts.examId,
    centreId: opts.centreId,
    seat: opts.seat,
    registrationHash: opts.registrationHash.toString("hex"),
    expiresAt: opts.expiresAt,
  };
  const signature = await provider.sign(
    signingKeyId,
    ADMIT_TOKEN_DOMAIN,
    admitTokenBodyBytes(body),
  );
  return { ...body, signature: signature.toString("hex") };
}

export type AdmitVerdict =
  | { ok: true; tokenHash: Buffer }
  | { ok: false; reason: string; code: AdmitFailureCode };

export type AdmitFailureCode =
  | "MALFORMED"
  | "UNSUPPORTED_VERSION"
  | "BAD_SIGNATURE"
  | "WRONG_EXAM"
  | "WRONG_CENTRE"
  | "EXPIRED";

/**
 * Offline verification at the centre. Fails closed with a specific code so
 * the invigilator is told what is wrong, not merely that admission failed.
 */
export function verifyAdmitToken(
  token: AdmitToken,
  authorityPublicKey: Buffer,
  expect: { examId: string; centreId: string; now?: number },
): AdmitVerdict {
  const now = expect.now ?? Date.now();

  if (
    typeof token !== "object" ||
    typeof token.examId !== "string" ||
    typeof token.centreId !== "string" ||
    typeof token.seat !== "string" ||
    typeof token.registrationHash !== "string" ||
    typeof token.expiresAt !== "number" ||
    typeof token.signature !== "string"
  ) {
    return { ok: false, code: "MALFORMED", reason: "token is missing required fields" };
  }
  if (token.v !== ADMIT_TOKEN_VERSION) {
    return {
      ok: false,
      code: "UNSUPPORTED_VERSION",
      reason: `token version ${String(token.v)} is not supported by this centre`,
    };
  }

  const { signature, ...body } = token;
  let sigBuf: Buffer;
  try {
    sigBuf = Buffer.from(signature, "hex");
  } catch {
    return { ok: false, code: "MALFORMED", reason: "signature is not valid hex" };
  }

  // Signature is checked BEFORE the field comparisons below, so an attacker
  // cannot learn which fields a centre expects by probing with forged tokens.
  if (!verifyDomain(ADMIT_TOKEN_DOMAIN, admitTokenBodyBytes(body), sigBuf, authorityPublicKey)) {
    return {
      ok: false,
      code: "BAD_SIGNATURE",
      reason: "signature does not verify against the authority key",
    };
  }
  if (token.examId !== expect.examId) {
    return {
      ok: false,
      code: "WRONG_EXAM",
      reason: `token is for exam ${token.examId}, this centre is running ${expect.examId}`,
    };
  }
  if (token.centreId !== expect.centreId) {
    return {
      ok: false,
      code: "WRONG_CENTRE",
      reason: `token is for centre ${token.centreId}, this is ${expect.centreId}`,
    };
  }
  if (now > token.expiresAt) {
    return {
      ok: false,
      code: "EXPIRED",
      reason: `token expired at ${new Date(token.expiresAt).toISOString()}`,
    };
  }
  return { ok: true, tokenHash: admitTokenHash(body) };
}

/**
 * Compact wire encoding for the QR code. base64url of canonical JSON — the
 * token is ~200 bytes, well within QR capacity at high error correction, and
 * a printed admit card must survive being folded in a pocket.
 */
export function encodeAdmitToken(token: AdmitToken): string {
  return canonicalJson(token).toString("base64url");
}

export function decodeAdmitToken(encoded: string): AdmitToken {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    throw new Error("admit token is not valid base64url-encoded JSON");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("admit token did not decode to an object");
  }
  return parsed as AdmitToken;
}
