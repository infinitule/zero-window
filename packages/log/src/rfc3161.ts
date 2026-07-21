import { randomBytes } from "@zw/crypto";
import { verifyCmsSignature } from "./cms.js";
import {
  Asn1Error,
  TAG,
  decodeGeneralizedTime,
  decodeInteger,
  decodeOid,
  derBoolean,
  derDecode,
  derEncode,
  derInteger,
  derNull,
  derOctetString,
  derOid,
  derSequence,
  type Asn1Node,
} from "./asn1.js";

/**
 * RFC 3161 Time-Stamp Protocol: request construction and response parsing.
 *
 * This module builds requests, parses responses, verifies the structural
 * bindings that make a token evidence (status, message imprint equality,
 * hash algorithm, nonce echo, asserted genTime), AND verifies the TSA's CMS
 * SignerInfo signature over the token content — see cms.ts.
 *
 * Scope boundary (honest): certificate CHAIN validation to a trust anchor,
 * and revocation checking, are the auditor's policy decisions and belong to
 * @zw/verifier, which is configured with the TSA roots the deploying agency
 * accepts. A token verified here proves the holder of the embedded
 * certificate's private key signed our root at the asserted time; whether
 * that certificate belongs to a TSA you trust is a separate, explicit
 * decision. SECURITY.md §"What a TSA token proves" states this precisely.
 */

export const OID = {
  /** id-sha256 */
  sha256: "2.16.840.1.101.3.4.2.1",
  /** id-sha512 */
  sha512: "2.16.840.1.101.3.4.2.3",
  /** id-ct-TSTInfo */
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  /** id-signedData */
  signedData: "1.2.840.113549.1.7.2",
} as const;

export type TsaHashAlgorithm = "sha256" | "sha512";

export interface TimeStampRequestOptions {
  /** Digest of the data being timestamped, using `hashAlgorithm`. */
  imprint: Buffer;
  hashAlgorithm: TsaHashAlgorithm;
  /** Ask the TSA to include its signing certificate in the token. */
  certReq?: boolean;
  /** Replay protection; echoed by the TSA in TSTInfo. */
  nonce?: Buffer;
}

export interface TokenSigner {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  certificatePem: string;
}

export interface ParsedTimeStampToken {
  /** Asserted signing time, integer ms since epoch. */
  genTime: number;
  /** Hex message imprint the TSA signed over. */
  imprint: string;
  /** OID of the imprint hash algorithm. */
  hashAlgorithmOid: string;
  /** TSA policy OID from TSTInfo. */
  policyOid: string;
  serialNumber: string;
  /** Nonce echoed by the TSA, hex, when present. */
  nonce?: string;
  /** Accuracy in milliseconds, when the TSA states it. */
  accuracyMs?: number;
  /** DER of the whole TimeStampToken (ContentInfo). */
  der: Buffer;
  /**
   * Present when the CMS signature was verified (the default). Identifies the
   * certificate whose key signed the timestamp. Absent only when parsing was
   * explicitly requested without signature verification.
   */
  signer?: TokenSigner;
}

const DIGEST_LENGTHS: Record<TsaHashAlgorithm, number> = { sha256: 32, sha512: 64 };
const OID_BY_ALG: Record<TsaHashAlgorithm, string> = {
  sha256: OID.sha256,
  sha512: OID.sha512,
};

export class Rfc3161Error extends Error {
  constructor(
    message: string,
    readonly kind:
      | "REQUEST_INVALID"
      | "RESPONSE_MALFORMED"
      | "STATUS_REJECTED"
      | "IMPRINT_MISMATCH"
      | "NONCE_MISMATCH",
  ) {
    super(message);
    this.name = "Rfc3161Error";
  }
}

/**
 * Build a DER TimeStampReq (RFC 3161 §2.4.1):
 *
 *   TimeStampReq ::= SEQUENCE {
 *     version        INTEGER { v1(1) },
 *     messageImprint MessageImprint,
 *     reqPolicy      TSAPolicyId OPTIONAL,
 *     nonce          INTEGER     OPTIONAL,
 *     certReq        BOOLEAN     DEFAULT FALSE,
 *     extensions [0] IMPLICIT Extensions OPTIONAL }
 */
export function buildTimeStampRequest(opts: TimeStampRequestOptions): {
  der: Buffer;
  nonce: Buffer;
} {
  const expected = DIGEST_LENGTHS[opts.hashAlgorithm];
  if (opts.imprint.length !== expected) {
    throw new Rfc3161Error(
      `imprint is ${opts.imprint.length} bytes, ${opts.hashAlgorithm} requires ${expected}`,
      "REQUEST_INVALID",
    );
  }
  // 8 random bytes with the top bit cleared, so the DER INTEGER stays
  // positive without a pad byte that some TSAs echo inconsistently.
  const nonce = opts.nonce ?? randomBytes(8);
  const nonceForDer = Buffer.from(nonce);
  nonceForDer[0] = (nonceForDer[0] ?? 0) & 0x7f;

  const messageImprint = derSequence(
    derSequence(derOid(OID_BY_ALG[opts.hashAlgorithm]), derNull()),
    derOctetString(opts.imprint),
  );

  const parts = [derInteger(1), messageImprint, derInteger(nonceForDer)];
  if (opts.certReq !== false) parts.push(derBoolean(true));

  return { der: derSequence(...parts), nonce: nonceForDer };
}

/**
 * Parse a DER TimeStampResp (RFC 3161 §2.4.2) and return the token.
 *
 *   TimeStampResp ::= SEQUENCE {
 *     status          PKIStatusInfo,
 *     timeStampToken  TimeStampToken OPTIONAL }
 */
export function parseTimeStampResponse(der: Buffer): ParsedTimeStampToken {
  let resp: Asn1Node;
  try {
    resp = derDecode(der);
  } catch (err) {
    throw new Rfc3161Error(
      `response is not valid DER: ${(err as Error).message}`,
      "RESPONSE_MALFORMED",
    );
  }
  if (resp.tag !== TAG.SEQUENCE || !resp.children || resp.children.length === 0) {
    throw new Rfc3161Error("response is not a TimeStampResp SEQUENCE", "RESPONSE_MALFORMED");
  }

  const statusInfo = resp.children[0]!;
  if (statusInfo.tag !== TAG.SEQUENCE || !statusInfo.children?.length) {
    throw new Rfc3161Error("PKIStatusInfo missing or malformed", "RESPONSE_MALFORMED");
  }
  const status = decodeInteger(statusInfo.children[0]!);
  // 0 = granted, 1 = grantedWithMods; everything else is a rejection.
  if (status !== 0 && status !== 1) {
    const failInfo = statusInfo.children
      .slice(1)
      .map((c) => {
        try {
          return c.tag === TAG.BIT_STRING ? `failInfo=0x${c.value.toString("hex")}` : "";
        } catch {
          return "";
        }
      })
      .filter(Boolean)
      .join(" ");
    throw new Rfc3161Error(
      `TSA rejected the request: PKIStatus=${status}${failInfo ? ` ${failInfo}` : ""}`,
      "STATUS_REJECTED",
    );
  }

  const token = resp.children[1];
  if (!token) {
    throw new Rfc3161Error(
      "TSA returned status granted but no TimeStampToken",
      "RESPONSE_MALFORMED",
    );
  }
  return parseTimeStampToken(token.raw);
}

/**
 * Parse a TimeStampToken (a CMS ContentInfo wrapping SignedData whose
 * encapsulated content is TSTInfo) and extract the fields that bind it to
 * our data.
 *
 *   TSTInfo ::= SEQUENCE {
 *     version        INTEGER { v1(1) },
 *     policy         TSAPolicyId,
 *     messageImprint MessageImprint,
 *     serialNumber   INTEGER,
 *     genTime        GeneralizedTime,
 *     accuracy       Accuracy OPTIONAL,
 *     ordering       BOOLEAN DEFAULT FALSE,
 *     nonce          INTEGER OPTIONAL, ... }
 */
export interface ParseTokenOptions {
  /**
   * Verify the CMS SignerInfo signature over the token's content. Default
   * true — a token whose signature does not verify is not evidence. Set
   * false ONLY to inspect a token already known to be invalid (diagnostics).
   */
  verifySignature?: boolean;
}

export function parseTimeStampToken(
  der: Buffer,
  opts: ParseTokenOptions = {},
): ParsedTimeStampToken {
  let contentInfo: Asn1Node;
  try {
    contentInfo = derDecode(der);
  } catch (err) {
    throw new Rfc3161Error(
      `token is not valid DER: ${(err as Error).message}`,
      "RESPONSE_MALFORMED",
    );
  }

  // Any ASN.1-level failure while walking the token structure is a
  // malformed token, not an internal error: callers handle exactly one
  // error type from this module (fail closed with a precise diagnostic).
  let tstInfoDer: Buffer;
  try {
    tstInfoDer = extractTstInfo(contentInfo);
  } catch (err) {
    if (err instanceof Rfc3161Error) throw err;
    throw new Rfc3161Error(
      `not a TimeStampToken: ${(err as Error).message}`,
      "RESPONSE_MALFORMED",
    );
  }
  let tst: Asn1Node;
  try {
    tst = derDecode(tstInfoDer);
  } catch (err) {
    throw new Rfc3161Error(
      `TSTInfo is not valid DER: ${(err as Error).message}`,
      "RESPONSE_MALFORMED",
    );
  }
  const fields = tst.children;
  if (!fields || fields.length < 5) {
    throw new Rfc3161Error("TSTInfo has too few fields", "RESPONSE_MALFORMED");
  }

  try {
    const policyOid = decodeOid(fields[1]!);
    const messageImprint = fields[2]!;
    const algSeq = messageImprint.children?.[0];
    const digest = messageImprint.children?.[1];
    if (!algSeq?.children?.[0] || !digest) {
      throw new Asn1Error("MessageImprint malformed");
    }
    const hashAlgorithmOid = decodeOid(algSeq.children[0]);
    const serialNumber = fields[3]!.value.toString("hex");
    const genTime = decodeGeneralizedTime(fields[4]!);

    let accuracyMs: number | undefined;
    let nonce: string | undefined;
    for (const f of fields.slice(5)) {
      if (f.tag === TAG.SEQUENCE && accuracyMs === undefined) {
        accuracyMs = decodeAccuracy(f);
      } else if (f.tag === TAG.INTEGER) {
        nonce = f.value.toString("hex");
      }
    }

    const result: ParsedTimeStampToken = {
      genTime,
      imprint: digest.value.toString("hex"),
      hashAlgorithmOid,
      policyOid,
      serialNumber,
      der,
    };
    if (nonce !== undefined) result.nonce = nonce;
    if (accuracyMs !== undefined) result.accuracyMs = accuracyMs;

    // The signature check is the difference between "this blob parses" and
    // "a TSA signed our root". On by default; failures are fatal.
    if (opts.verifySignature !== false) {
      const cms = verifyCmsSignature(der, tstInfoDer);
      result.signer = {
        subject: cms.signerSubject,
        issuer: cms.signerIssuer,
        validFrom: cms.validFrom,
        validTo: cms.validTo,
        certificatePem: cms.signerCertificatePem,
      };
    }
    return result;
  } catch (err) {
    if (err instanceof Rfc3161Error) throw err;
    throw new Rfc3161Error(`TSTInfo parse failed: ${(err as Error).message}`, "RESPONSE_MALFORMED");
  }
}

/** Accuracy ::= SEQUENCE { seconds INTEGER OPT, millis [0] OPT, micros [1] OPT } */
function decodeAccuracy(node: Asn1Node): number | undefined {
  let ms = 0;
  let seen = false;
  for (const c of node.children ?? []) {
    if (c.tag === TAG.INTEGER) {
      ms += decodeInteger(c) * 1000;
      seen = true;
    } else if (c.tag === 0x80) {
      let n = 0;
      for (const b of c.value) n = n * 256 + b;
      ms += n;
      seen = true;
    } else if (c.tag === 0x81) {
      let n = 0;
      for (const b of c.value) n = n * 256 + b;
      ms += n / 1000;
      seen = true;
    }
  }
  return seen ? Math.round(ms) : undefined;
}

/**
 * Walk ContentInfo → SignedData → encapContentInfo → eContent to find the
 * TSTInfo octets. Verifies the content type OIDs along the way rather than
 * assuming positions, so a structurally wrong token is rejected instead of
 * being read from the wrong offset.
 */
function extractTstInfo(contentInfo: Asn1Node): Buffer {
  const oidNode = contentInfo.children?.[0];
  if (!oidNode || decodeOid(oidNode) !== OID.signedData) {
    throw new Rfc3161Error(
      "token ContentInfo is not id-signedData — not a TimeStampToken",
      "RESPONSE_MALFORMED",
    );
  }
  // [0] EXPLICIT SignedData
  const explicit = contentInfo.children?.[1];
  const signedData = explicit?.children?.[0];
  if (!signedData?.children) {
    throw new Rfc3161Error("SignedData missing from token", "RESPONSE_MALFORMED");
  }
  // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo, ... }
  const encap = signedData.children.find(
    (c) => c.tag === TAG.SEQUENCE && c.children?.[0]?.tag === TAG.OID,
  );
  const encapOid = encap?.children?.[0];
  if (!encap || !encapOid || decodeOid(encapOid) !== OID.tstInfo) {
    throw new Rfc3161Error(
      "encapContentInfo is not id-ct-TSTInfo — not a TimeStampToken",
      "RESPONSE_MALFORMED",
    );
  }
  // eContent [0] EXPLICIT OCTET STRING containing the DER TSTInfo
  const eContentExplicit = encap.children?.[1];
  const octets = eContentExplicit?.children?.[0];
  if (!octets || octets.tag !== TAG.OCTET_STRING) {
    throw new Rfc3161Error("eContent OCTET STRING missing from token", "RESPONSE_MALFORMED");
  }
  return Buffer.from(octets.value);
}

/**
 * Structural verification of a token against what we asked to be timestamped.
 * This is the check that makes backdating claims falsifiable: the TSA signed
 * OUR root, at a time it asserts, with a nonce we chose.
 */
export function verifyTokenBinding(
  token: ParsedTimeStampToken,
  expected: { imprint: Buffer; hashAlgorithm: TsaHashAlgorithm; nonce?: Buffer },
): void {
  const wantOid = OID_BY_ALG[expected.hashAlgorithm];
  if (token.hashAlgorithmOid !== wantOid) {
    throw new Rfc3161Error(
      `token hash algorithm ${token.hashAlgorithmOid} does not match requested ${expected.hashAlgorithm} (${wantOid})`,
      "IMPRINT_MISMATCH",
    );
  }
  const wantImprint = expected.imprint.toString("hex");
  if (token.imprint !== wantImprint) {
    throw new Rfc3161Error(
      `token imprint ${token.imprint} does not match the data timestamped (${wantImprint})`,
      "IMPRINT_MISMATCH",
    );
  }
  if (expected.nonce) {
    const want = expected.nonce.toString("hex").replace(/^0+/, "");
    const got = (token.nonce ?? "").replace(/^0+/, "");
    if (want !== got) {
      throw new Rfc3161Error(
        `token nonce ${token.nonce ?? "(absent)"} does not echo the requested nonce — possible replay of an older token`,
        "NONCE_MISMATCH",
      );
    }
  }
}

/** DER-encode an explicit [n] wrapper — exported for fixture construction. */
export function derExplicit(n: number, content: Buffer): Buffer {
  return derEncode(0xa0 | n, content);
}
