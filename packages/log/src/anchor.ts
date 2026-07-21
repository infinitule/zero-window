import { createHash } from "node:crypto";
import {
  Rfc3161Error,
  buildTimeStampRequest,
  parseTimeStampResponse,
  verifyTokenBinding,
  type TsaHashAlgorithm,
} from "./rfc3161.js";
import type { Anchor } from "./types.js";

/**
 * Anchoring: publish the log's Merkle root to parties who are not us, so that
 * "the operator rewrote history" (T6) and "this leak predates the exam" (T5)
 * become claims a third party can falsify.
 *
 * RFC 3161 message imprints use SHA-2 because that is what TSAs accept; this
 * is the one place the stack is not BLAKE2b. The imprint is a hash OF our
 * root, so the TSA's algorithm choice does not weaken the log's own hashing.
 */

export interface AnchorBackend {
  readonly name: string;
  /** Stamp a root and return a verifiable anchor. */
  anchor(root: Buffer): Promise<Anchor>;
  /** Re-check a stored anchor's structural binding to a root. */
  verify(anchor: Anchor, root: Buffer): Promise<void>;
}

export interface TsaConfig {
  /** Human-readable TSA identity recorded in the evidence, e.g. "freetsa.org". */
  name: string;
  url: string;
  hashAlgorithm?: TsaHashAlgorithm;
  /** Milliseconds before a TSA request is abandoned. */
  timeoutMs?: number;
  /** Optional HTTP basic auth, for commercial TSAs that require it. */
  auth?: { username: string; password: string };
}

/**
 * Public TSAs validated against this client. DigiCert and Sectigo are
 * operated independently of each other and of FreeTSA — the point of using
 * more than one is that no single operator's cooperation can move a
 * timestamp. INTEGRATIONS.md records rate limits and what an agency must
 * arrange for production volumes.
 */
export const PUBLIC_TSAS: Readonly<Record<string, TsaConfig>> = Object.freeze({
  freetsa: { name: "freetsa.org", url: "https://freetsa.org/tsr" },
  digicert: { name: "digicert", url: "http://timestamp.digicert.com" },
  sectigo: { name: "sectigo", url: "http://timestamp.sectigo.com" },
});

export class Rfc3161AnchorBackend implements AnchorBackend {
  readonly name: string;

  constructor(private readonly config: TsaConfig) {
    this.name = config.name;
  }

  private get hashAlgorithm(): TsaHashAlgorithm {
    return this.config.hashAlgorithm ?? "sha256";
  }

  private imprintOf(root: Buffer): Buffer {
    return createHash(this.hashAlgorithm).update(root).digest();
  }

  async anchor(root: Buffer): Promise<Anchor> {
    const imprint = this.imprintOf(root);
    const { der, nonce } = buildTimeStampRequest({
      imprint,
      hashAlgorithm: this.hashAlgorithm,
      certReq: true,
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs ?? 15_000);
    let responseBytes: Buffer;
    try {
      const headers: Record<string, string> = {
        "content-type": "application/timestamp-query",
        accept: "application/timestamp-reply",
      };
      if (this.config.auth) {
        const { username, password } = this.config.auth;
        headers["authorization"] = `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
      }
      const res = await fetch(this.config.url, {
        method: "POST",
        headers,
        body: der,
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`TSA ${this.config.name} returned HTTP ${res.status} ${res.statusText}`);
      }
      responseBytes = Buffer.from(await res.arrayBuffer());
    } catch (err) {
      if (controller.signal.aborted) {
        throw new Error(
          `TSA ${this.config.name} timed out after ${this.config.timeoutMs ?? 15_000}ms`,
        );
      }
      throw new Error(`TSA ${this.config.name} request failed: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }

    const token = parseTimeStampResponse(responseBytes);
    // Fail closed if the TSA signed anything other than exactly our imprint,
    // or replayed a token minted for a different nonce.
    verifyTokenBinding(token, { imprint, hashAlgorithm: this.hashAlgorithm, nonce });

    return {
      backend: "rfc3161",
      tsa: this.config.name,
      url: this.config.url,
      token: token.der.toString("base64"),
      genTime: token.genTime,
      imprint: root.toString("hex"),
      hashAlgorithm: this.hashAlgorithm,
    };
  }

  async verify(anchor: Anchor, root: Buffer): Promise<void> {
    if (anchor.backend !== "rfc3161") {
      throw new Rfc3161Error(
        `anchor backend "${anchor.backend}" cannot be verified by the RFC 3161 backend`,
        "RESPONSE_MALFORMED",
      );
    }
    if (anchor.imprint !== root.toString("hex")) {
      throw new Rfc3161Error(
        `anchor claims root ${anchor.imprint} but the checkpoint root is ${root.toString("hex")}`,
        "IMPRINT_MISMATCH",
      );
    }
    const alg = (anchor.hashAlgorithm as TsaHashAlgorithm) ?? "sha256";
    const { parseTimeStampToken } = await import("./rfc3161.js");
    const token = parseTimeStampToken(Buffer.from(anchor.token, "base64"));
    verifyTokenBinding(token, {
      imprint: createHash(alg).update(root).digest(),
      hashAlgorithm: alg,
    });
    if (token.genTime !== anchor.genTime) {
      throw new Rfc3161Error(
        `anchor records genTime ${new Date(anchor.genTime).toISOString()} but the token asserts ${new Date(token.genTime).toISOString()}`,
        "RESPONSE_MALFORMED",
      );
    }
  }
}

export interface AnchorResult {
  anchors: Anchor[];
  failures: { backend: string; error: string }[];
}

/**
 * Anchor a root to several backends concurrently.
 *
 * Policy (T10): a TSA being down must not stop an exam. `minRequired`
 * (default 1) anchors must succeed or this throws; failures are always
 * returned so the caller can log and alert on a degraded anchor set. The
 * exam-day runbook treats "anchored to fewer than two independent TSAs" as
 * an incident to resolve before the final checkpoint, not a reason to halt
 * at T-0.
 */
export async function anchorToAll(
  backends: AnchorBackend[],
  root: Buffer,
  minRequired = 1,
): Promise<AnchorResult> {
  if (backends.length === 0) throw new Error("anchorToAll: no anchor backends configured");
  const settled = await Promise.allSettled(backends.map((b) => b.anchor(root)));
  const anchors: Anchor[] = [];
  const failures: { backend: string; error: string }[] = [];
  settled.forEach((r, i) => {
    if (r.status === "fulfilled") anchors.push(r.value);
    else failures.push({ backend: backends[i]!.name, error: (r.reason as Error).message });
  });
  if (anchors.length < minRequired) {
    throw new Error(
      `anchoring failed: ${anchors.length} of ${backends.length} succeeded, ${minRequired} required. ` +
        failures.map((f) => `${f.backend}: ${f.error}`).join("; "),
    );
  }
  return { anchors, failures };
}
