import { request as httpsRequest, type RequestOptions } from "node:https";
import { tlsClientOptions, type MtlsMaterial } from "@zw/ca";
import type { CentreNode } from "./centre.js";

/**
 * Centre → authority sync client (mTLS).
 *
 * Used in exactly two windows: bundle custody transfer (days before the
 * exam) and wrapped-KEK pickup (at T-0, online path). Nothing on the
 * exam-day critical path after key receipt touches this module (I-CTR-2) —
 * the autonomy test kills the authority and the exam completes.
 */

export interface SyncOptions {
  authorityHost: string;
  authorityPort: number;
  /** TLS servername for SNI/verification; the authority cert's SAN. */
  servername?: string;
  tls: MtlsMaterial;
  timeoutMs?: number;
}

export class SyncError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
    readonly retryable: boolean,
  ) {
    super(message);
    this.name = "SyncError";
  }
}

export class AuthoritySyncClient {
  constructor(private readonly opts: SyncOptions) {}

  private async get(path: string): Promise<{ status: number; body: unknown }> {
    const tls = tlsClientOptions(this.opts.tls, this.opts.servername ?? "localhost");
    const options: RequestOptions = {
      host: this.opts.authorityHost,
      port: this.opts.authorityPort,
      path,
      method: "GET",
      timeout: this.opts.timeoutMs ?? 10_000,
      ...tls,
    };
    return new Promise((resolve, reject) => {
      const req = httpsRequest(options, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let body: unknown = null;
          try {
            body = text.length > 0 ? JSON.parse(text) : null;
          } catch {
            body = text;
          }
          resolve({ status: res.statusCode ?? 0, body });
        });
      });
      req.on("timeout", () => {
        req.destroy(new Error("request timed out"));
      });
      req.on("error", (err) =>
        reject(new SyncError(`authority unreachable: ${err.message}`, null, true)),
      );
      req.end();
    });
  }

  /** Fetch the authority's signing key (pinned at enrolment; compared, not trusted). */
  async authorityKey(): Promise<Buffer> {
    const { status, body } = await this.get("/v1/authority-key");
    if (status !== 200) throw new SyncError(`authority-key returned ${status}`, status, false);
    return Buffer.from((body as { publicKey: string }).publicKey, "hex");
  }

  /** Transfer bundle custody: fetch, verify hash, store (T3 checks inside). */
  async fetchBundle(centre: CentreNode, examId: string, kind: "paper" | "answers"): Promise<void> {
    const { status, body } = await this.get(`/v1/exam/${examId}/bundle/${kind}`);
    if (status === 403) {
      throw new SyncError(
        `authority refuses: this centre is not on the distribution list (${JSON.stringify(body)})`,
        status,
        false,
      );
    }
    if (status !== 200) {
      throw new SyncError(`bundle fetch returned ${status}: ${JSON.stringify(body)}`, status, status >= 500);
    }
    const b = body as {
      bundleId: string;
      examId: string;
      kind: "paper" | "answers";
      bundleHash: string;
      kekFingerprint: string;
      threshold: number;
      envelope: string;
    };
    await centre.receiveBundle(Buffer.from(b.envelope, "base64"), {
      bundleId: b.bundleId,
      examId: b.examId,
      kind: b.kind,
      bundleHash: b.bundleHash,
      kekFingerprint: b.kekFingerprint,
      threshold: b.threshold,
    });
  }

  /**
   * Poll for the wrapped KEK. Returns false while the release has not
   * happened (HTTP 425), true once the KEK is held. The caller decides the
   * polling cadence; at T-0 the exam-day runbook sets it to a few seconds.
   */
  async tryFetchKek(centre: CentreNode, examId: string, kind: "paper" | "answers"): Promise<boolean> {
    const { status, body } = await this.get(`/v1/exam/${examId}/release/${kind}`);
    if (status === 425) return false;
    if (status !== 200) {
      throw new SyncError(`release fetch returned ${status}: ${JSON.stringify(body)}`, status, status >= 500);
    }
    const r = body as { bundleId: string; sealed: string };
    await centre.receiveWrappedKek(r.bundleId, Buffer.from(r.sealed, "base64"));
    return true;
  }
}
