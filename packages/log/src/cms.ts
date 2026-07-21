import { X509Certificate, constants, createHash, verify as cryptoVerify } from "node:crypto";
import {
  TAG,
  decodeOid,
  derDecode,
  derEncode,
  type Asn1Node,
} from "./asn1.js";

/**
 * CMS SignedData signature verification for RFC 3161 TimeStampTokens.
 *
 * This is what turns a token from "a blob that parses" into evidence: the TSA
 * cryptographically signed a structure that commits to our Merkle root, at a
 * time it asserts. Without this check a token could be corrupted, or lifted
 * from another document, and still appear to verify structurally.
 *
 * What is checked here:
 *   1. The SignerInfo signature verifies under the embedded signing
 *      certificate's public key, over the DER-re-encoded signedAttrs.
 *   2. The messageDigest signed attribute equals the digest of the
 *      encapsulated TSTInfo — binding the signature to the content.
 *   3. The contentType signed attribute is id-ct-TSTInfo.
 *
 * What is deliberately NOT checked here (and is the auditor's policy call,
 * performed by @zw/verifier against configured trust anchors): whether the
 * signing certificate chains to a root the auditor trusts, and its revocation
 * status. A token that verifies here proves the holder of that certificate's
 * key signed our root; whether that certificate is a TSA you trust is a
 * separate, explicitly configured decision. SECURITY.md §"What a TSA token
 * proves" states this.
 */

const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";

const DIGEST_BY_OID: Record<string, string> = {
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};

/** Signature algorithm OIDs → { key type, digest } */
const SIG_BY_OID: Record<string, { type: "rsa" | "ec" | "rsa-pss"; digest?: string }> = {
  "1.2.840.113549.1.1.1": { type: "rsa" }, // rsaEncryption — digest from digestAlgorithm
  "1.2.840.113549.1.1.11": { type: "rsa", digest: "sha256" },
  "1.2.840.113549.1.1.12": { type: "rsa", digest: "sha384" },
  "1.2.840.113549.1.1.13": { type: "rsa", digest: "sha512" },
  "1.2.840.113549.1.1.5": { type: "rsa", digest: "sha1" },
  "1.2.840.113549.1.1.10": { type: "rsa-pss" },
  "1.2.840.10045.4.3.2": { type: "ec", digest: "sha256" },
  "1.2.840.10045.4.3.3": { type: "ec", digest: "sha384" },
  "1.2.840.10045.4.3.4": { type: "ec", digest: "sha512" },
};

export class CmsError extends Error {
  constructor(message: string) {
    super(`CMS: ${message}`);
    this.name = "CmsError";
  }
}

export interface CmsVerificationResult {
  /** PEM of the certificate whose key verified the signature. */
  signerCertificatePem: string;
  signerSubject: string;
  signerIssuer: string;
  validFrom: string;
  validTo: string;
  digestAlgorithm: string;
  signatureAlgorithm: string;
}

function children(node: Asn1Node, what: string): Asn1Node[] {
  if (!node.children) throw new CmsError(`${what} is not a constructed type`);
  return node.children;
}

/**
 * Verify the CMS SignedData signature inside a TimeStampToken.
 * `tstInfoDer` is the encapsulated TSTInfo content the signature must cover.
 */
export function verifyCmsSignature(tokenDer: Buffer, tstInfoDer: Buffer): CmsVerificationResult {
  let contentInfo: Asn1Node;
  try {
    contentInfo = derDecode(tokenDer);
  } catch (err) {
    throw new CmsError(`token is not valid DER: ${(err as Error).message}`);
  }

  const ciChildren = children(contentInfo, "ContentInfo");
  const explicit = ciChildren[1];
  const signedData = explicit?.children?.[0];
  if (!signedData) throw new CmsError("SignedData missing");
  const sdChildren = children(signedData, "SignedData");

  // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
  //                certificates [0] IMPLICIT OPTIONAL, crls [1] OPTIONAL,
  //                signerInfos SET }
  const signerInfos = sdChildren.find(
    (c, i) => c.tag === TAG.SET && i > 2, // the SET after encapContentInfo
  );
  if (!signerInfos?.children?.length) throw new CmsError("signerInfos missing or empty");
  const signerInfo = signerInfos.children[0]!;
  const siChildren = children(signerInfo, "SignerInfo");

  // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
  //                signedAttrs [0] IMPLICIT OPTIONAL, signatureAlgorithm,
  //                signature, unsignedAttrs [1] OPTIONAL }
  const digestAlgSeq = siChildren.find((c) => c.tag === TAG.SEQUENCE && c.children?.[0]?.tag === TAG.OID);
  const digestOidNode = digestAlgSeq?.children?.[0];
  if (!digestOidNode) throw new CmsError("SignerInfo digestAlgorithm missing");
  const digestAlgorithm = DIGEST_BY_OID[decodeOid(digestOidNode)];
  if (!digestAlgorithm) {
    throw new CmsError(`unsupported digest algorithm OID ${decodeOid(digestOidNode)}`);
  }

  const signedAttrs = siChildren.find((c) => c.tag === 0xa0);
  if (!signedAttrs) {
    throw new CmsError(
      "SignerInfo has no signedAttrs: RFC 3161 requires signed attributes in a TimeStampToken",
    );
  }

  // The two signature-relevant sequences after signedAttrs.
  const afterAttrs = siChildren.slice(siChildren.indexOf(signedAttrs) + 1);
  const sigAlgSeq = afterAttrs.find((c) => c.tag === TAG.SEQUENCE);
  const sigOidNode = sigAlgSeq?.children?.[0];
  if (!sigOidNode) throw new CmsError("signatureAlgorithm missing");
  const sigOid = decodeOid(sigOidNode);
  const sigSpec = SIG_BY_OID[sigOid];
  if (!sigSpec) throw new CmsError(`unsupported signature algorithm OID ${sigOid}`);

  const signatureNode = afterAttrs.find((c) => c.tag === TAG.OCTET_STRING);
  if (!signatureNode) throw new CmsError("signature OCTET STRING missing");

  // --- 1. signed attributes must bind to the content ------------------
  const attrs = children(signedAttrs, "signedAttrs");
  let sawContentType = false;
  let messageDigest: Buffer | null = null;
  for (const attr of attrs) {
    const oidNode = attr.children?.[0];
    const valueSet = attr.children?.[1];
    if (!oidNode || !valueSet?.children?.[0]) continue;
    const oid = decodeOid(oidNode);
    if (oid === OID_CONTENT_TYPE) {
      if (decodeOid(valueSet.children[0]) !== OID_TST_INFO) {
        throw new CmsError("signed contentType attribute is not id-ct-TSTInfo");
      }
      sawContentType = true;
    } else if (oid === OID_MESSAGE_DIGEST) {
      messageDigest = Buffer.from(valueSet.children[0].value);
    }
  }
  if (!sawContentType) throw new CmsError("signed attributes lack a contentType attribute");
  if (!messageDigest) throw new CmsError("signed attributes lack a messageDigest attribute");

  const actualDigest = createHash(digestAlgorithm).update(tstInfoDer).digest();
  if (!actualDigest.equals(messageDigest)) {
    throw new CmsError(
      `signed messageDigest ${messageDigest.toString("hex")} does not match the ${digestAlgorithm} digest of TSTInfo (${actualDigest.toString("hex")}): the token's content has been altered`,
    );
  }

  // --- 2. locate the signing certificate ------------------------------
  const certsNode = sdChildren.find((c) => c.tag === 0xa0);
  const certNodes = certsNode?.children ?? [];
  if (certNodes.length === 0) {
    throw new CmsError(
      "token carries no certificates: cannot verify the TSA signature (request with certReq=true)",
    );
  }

  // --- 3. verify the signature over re-encoded signedAttrs -------------
  // RFC 5652 §5.4: the signature is computed over the DER encoding of
  // signedAttrs as a SET OF, not over the [0] IMPLICIT tagging used in the
  // message. Re-tag 0xA0 -> 0x31.
  const signedAttrsDer = derEncode(TAG.SET, Buffer.concat(attrs.map((a) => a.raw)));
  const signature = Buffer.from(signatureNode.value);

  const errors: string[] = [];
  for (const certNode of certNodes) {
    let cert: X509Certificate;
    try {
      cert = new X509Certificate(Buffer.from(certNode.raw));
    } catch (err) {
      errors.push(`certificate parse failed: ${(err as Error).message}`);
      continue;
    }
    const digest = sigSpec.digest ?? digestAlgorithm;
    try {
      const ok =
        sigSpec.type === "rsa-pss"
          ? cryptoVerify(
              digest,
              signedAttrsDer,
              {
                key: cert.publicKey,
                padding: constants.RSA_PKCS1_PSS_PADDING,
                saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
              },
              signature,
            )
          : cryptoVerify(digest, signedAttrsDer, cert.publicKey, signature);
      if (ok) {
        return {
          signerCertificatePem: cert.toString(),
          signerSubject: cert.subject,
          signerIssuer: cert.issuer,
          validFrom: cert.validFrom,
          validTo: cert.validTo,
          digestAlgorithm: digest,
          signatureAlgorithm: sigOid,
        };
      }
      errors.push(`signature did not verify under ${cert.subject.replace(/\n/g, " ")}`);
    } catch (err) {
      errors.push(`verification error with ${cert.subject.replace(/\n/g, " ")}: ${(err as Error).message}`);
    }
  }

  throw new CmsError(
    `no embedded certificate verifies the timestamp signature (${certNodes.length} tried): ${errors.join("; ")}`,
  );
}
