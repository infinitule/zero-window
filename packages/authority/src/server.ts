import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import type { TLSSocket } from "node:tls";
import {
  tlsServerOptions,
  checkPeerCertificate,
  PeerRejected,
  type MtlsMaterial,
  type RevocationList,
} from "@zw/ca";
import { MetricsRegistry } from "@zw/ops";
import type { Authority } from "./authority.js";
import { bundleId as makeBundleId } from "./provision.js";

/**
 * Authority HTTP API over mTLS.
 *
 * A thin shell over the Authority façade: every custody decision lives in
 * the façade (and is shared with the CLI), so nothing here can drift from
 * the offline paths. The transport's job is authentication and shape.
 *
 * INVARIANT I-SRV-1: the centre identity used for authorization is the CN of
 * the verified client certificate — never a request parameter. A centre can
 * fetch only its own bundle and its own wrapped KEK.
 */

export interface AuthorityServerOptions {
  authority: Authority;
  tls: MtlsMaterial;
  /** Verified against every peer when supplied (revocation fails closed). */
  crl?: RevocationList;
  host?: string;
  port?: number;
}

interface PeerInfo {
  centreId: string;
  hardwareId: string | undefined;
}

function peerOf(request: FastifyRequest, crl?: RevocationList): PeerInfo {
  const socket = request.raw.socket as TLSSocket;
  const identity = checkPeerCertificate(socket.getPeerX509Certificate(), {
    requireEku: "clientAuth",
    ...(crl ? { crl } : {}),
  });
  const cn = identity.subject.match(/CN=([^,\n]+)/)?.[1];
  if (!cn) throw new PeerRejected("client certificate has no CN", "NO_PEER_CERTIFICATE");
  return { centreId: cn, hardwareId: identity.hardwareId };
}

export async function buildAuthorityServer(
  opts: AuthorityServerOptions,
): Promise<FastifyInstance> {
  const { authority } = opts;

  const app = Fastify({
    https: tlsServerOptions(opts.tls),
    logger: false, // @zw/ops Logger is the structured log; Fastify's own is off
  });

  app.setErrorHandler((err: unknown, _req, reply) => {
    if (err instanceof PeerRejected) {
      void reply.status(403).send({ error: err.message, reason: err.reason });
      return;
    }
    const e = err as { statusCode?: unknown; message?: unknown };
    const status = typeof e.statusCode === "number" ? e.statusCode : 500;
    void reply.status(status).send({ error: String(e.message ?? "internal error") });
  });

  app.get("/v1/health/live", async () => authority.health.live());
  app.get("/v1/health/ready", async () => authority.health.ready());
  app.get("/metrics", async (_req, reply) => {
    void reply.type(MetricsRegistry.CONTENT_TYPE);
    return authority.metrics.expose();
  });

  /** Authority signing public key — centres pin this at enrolment. */
  app.get("/v1/authority-key", async () => ({
    publicKey: authority.publicKey.toString("hex"),
  }));

  /**
   * Bundle custody transfer. The centre is identified by its certificate;
   * the bundle must have been explicitly distributed to it (I-SRV-1).
   */
  app.get<{ Params: { examId: string; kind: string } }>(
    "/v1/exam/:examId/bundle/:kind",
    async (request, reply) => {
      const peer = peerOf(request, opts.crl);
      const { examId, kind } = request.params;
      if (kind !== "paper" && kind !== "answers") {
        return reply.status(400).send({ error: `unknown bundle kind ${kind}` });
      }
      const id = makeBundleId(examId, kind);
      const bundle = authority.store.bundle(id);
      if (!bundle) return reply.status(404).send({ error: `no bundle ${id}` });
      const distributed = authority.store.distributedCentres(id);
      if (!distributed.includes(peer.centreId)) {
        return reply.status(403).send({
          error: `bundle ${id} has not been distributed to ${peer.centreId}`,
        });
      }
      return {
        bundleId: bundle.bundleId,
        examId: bundle.examId,
        kind: bundle.kind,
        bundleHash: bundle.bundleHash,
        kekFingerprint: bundle.kekFingerprint,
        threshold: bundle.threshold,
        envelope: bundle.ciphertext.toString("base64"),
      };
    },
  );

  /**
   * Wrapped-KEK pickup. 425 (Too Early) until the threshold release has
   * happened — a centre polling this endpoint before T-0 learns nothing but
   * "not yet", and the polling itself is not an early-release attempt (T2:
   * those are custodian share submissions, logged on the release path).
   */
  app.get<{ Params: { examId: string; kind: string } }>(
    "/v1/exam/:examId/release/:kind",
    async (request, reply) => {
      const peer = peerOf(request, opts.crl);
      const { examId, kind } = request.params;
      if (kind !== "paper" && kind !== "answers") {
        return reply.status(400).send({ error: `unknown bundle kind ${kind}` });
      }
      const id = makeBundleId(examId, kind);
      const release = authority.store.release(id, peer.centreId);
      if (!release) {
        const schedule = authority.store.schedule(id);
        return reply.status(425).send({
          error: `KEK for ${id} has not been released to ${peer.centreId}`,
          ...(schedule ? { scheduledAt: schedule.releaseAt } : {}),
        });
      }
      return {
        bundleId: id,
        sealed: release.wrapped.toString("base64"),
        releasedAt: release.releasedAt,
      };
    },
  );

  /**
   * Custodian share submission (online release path). The custodian
   * authenticates with their client certificate; shares accumulate and the
   * release fires when the threshold is met. Failures surface the precise
   * ReleaseError code so the ceremony operator knows what is wrong.
   */
  const pendingShares = new Map<string, Map<string, Buffer>>();
  app.post<{
    Params: { examId: string; kind: string };
    Body: { custodianId: string; shareHex: string };
  }>("/v1/exam/:examId/release/:kind/shares", async (request, reply) => {
    peerOf(request, opts.crl); // authenticated custodian or operator console
    const { examId, kind } = request.params;
    if (kind !== "paper" && kind !== "answers") {
      return reply.status(400).send({ error: `unknown bundle kind ${kind}` });
    }
    const { custodianId, shareHex } = request.body;
    if (typeof custodianId !== "string" || typeof shareHex !== "string") {
      return reply.status(400).send({ error: "custodianId and shareHex are required" });
    }
    const id = makeBundleId(examId, kind);
    const bundle = authority.store.bundle(id);
    if (!bundle) return reply.status(404).send({ error: `no bundle ${id}` });

    let box = pendingShares.get(id);
    if (!box) {
      box = new Map();
      pendingShares.set(id, box);
    }
    box.set(custodianId, Buffer.from(shareHex, "hex"));

    if (box.size < bundle.threshold) {
      return { status: "pending", submitted: box.size, threshold: bundle.threshold };
    }

    const shares = [...box.entries()].map(([cid, blob]) => ({
      custodianId: cid,
      shareBlob: blob,
    }));
    try {
      const outcome = await authority.release({ bundleId: id, shares });
      pendingShares.delete(id);
      return {
        status: "released",
        centres: outcome.wrapped.map((w) => w.centreId),
        kekLifetimeMs: outcome.kekLifetimeMs,
      };
    } catch (err) {
      const e = err as Error & { code?: string };
      // Early attempts keep the submitted shares: the same custodians retry
      // at T-0 without re-entering material. Invalid-share failures clear
      // the box so a poisoned share cannot wedge the ceremony.
      if (e.code !== "TOO_EARLY") pendingShares.delete(id);
      return reply.status(e.code === "TOO_EARLY" ? 425 : 409).send({
        error: e.message,
        ...(e.code ? { code: e.code } : {}),
      });
    }
  });

  const host = opts.host ?? "127.0.0.1";
  const port = opts.port ?? 0;
  await app.listen({ host, port });
  return app;
}
