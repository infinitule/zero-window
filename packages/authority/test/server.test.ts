import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpsRequest } from "node:https";
import type { AddressInfo } from "node:net";
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { CertificateAuthority, tlsClientOptions, type IssuedCertificate } from "@zw/ca";
import { generateBoxKeyPair, sealOpen } from "@zw/crypto";
import { VaultKeyProvider } from "@zw/kms-vault";
import { Authority } from "../src/authority.js";
import { buildAuthorityServer } from "../src/server.js";
import { sampleBank, sampleBlueprint } from "./helpers.js";

/**
 * The mTLS API. Every request here crosses a real TLS 1.3 socket with
 * certificates from the real internal CA — the authorization decisions under
 * test (I-SRV-1) depend on the verified client certificate, so a mocked
 * transport would test nothing.
 */

const EXAM = "EXAM-2026-SRV";
const dirs: string[] = [];
const servers: FastifyInstance[] = [];
const closers: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
  await Promise.all(closers.splice(0).map((c) => c()));
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function tempDir(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "zw-srv-"));
  dirs.push(d);
  return d;
}

interface Rig {
  authority: Authority;
  port: number;
  ca: CertificateAuthority;
  certs: Record<string, IssuedCertificate>;
  centreKeys: Record<string, ReturnType<typeof generateBoxKeyPair>>;
  custodians: Array<{ custodianId: string; keys: ReturnType<typeof generateBoxKeyPair> }>;
  bundleId: string;
  get(path: string, centre: string): Promise<{ status: number; body: unknown }>;
  post(path: string, centre: string, payload: unknown): Promise<{ status: number; body: unknown }>;
}

async function rig(opts: { centres?: string[] } = {}): Promise<Rig> {
  const centreIds = opts.centres ?? ["CENTRE-A", "CENTRE-B"];
  const caDir = await tempDir();
  const ca = await CertificateAuthority.open({ dir: caDir });
  await ca.initialize();
  const serverCert = await ca.issue({
    role: "authority-server",
    commonName: "authority",
    sans: ["localhost", "127.0.0.1"],
  });

  const aDir = await tempDir();
  const provider = await VaultKeyProvider.open({
    keystorePath: join(aDir, "keystore.json"),
    passphrase: Buffer.from("srv", "utf8"),
  });
  const authority = await Authority.open({
    statePath: join(aDir, "a.db"),
    logPath: join(aDir, "log.db"),
    provider,
  });
  closers.push(() => authority.close());

  const custodians = Array.from({ length: 5 }, (_, i) => ({
    custodianId: `cust-${i + 1}`,
    keys: generateBoxKeyPair(),
  }));
  for (const c of custodians) {
    authority.enrolCustodian({
      custodianId: c.custodianId,
      name: c.custodianId,
      boxPublicKey: c.keys.publicKey,
      certFingerprint: "",
    });
  }

  const certs: Record<string, IssuedCertificate> = {};
  const centreKeys: Record<string, ReturnType<typeof generateBoxKeyPair>> = {};
  for (const id of centreIds) {
    certs[id] = await ca.issue({
      role: "centre-client",
      commonName: id,
      hardwareId: `tpm-${id}`,
    });
    centreKeys[id] = generateBoxKeyPair();
    await authority.enrolCentre({
      centreId: id,
      boxPublicKey: centreKeys[id]!.publicKey,
      certFingerprint: certs[id]!.record.fingerprint,
      hardwareId: `tpm-${id}`,
    });
  }

  const provisioned = await authority.provision({
    bank: sampleBank(EXAM),
    blueprint: sampleBlueprint(EXAM),
    threshold: 3,
  });

  const app = await buildAuthorityServer({
    authority,
    tls: { cert: serverCert.chainPem, key: serverCert.privateKeyPem, ca: ca.trustBundlePem() },
  });
  servers.push(app);
  const port = (app.server.address() as AddressInfo).port;

  const call = (
    method: "GET" | "POST",
    path: string,
    centre: string,
    payload?: unknown,
  ): Promise<{ status: number; body: unknown }> => {
    const tls = tlsClientOptions(
      { cert: certs[centre]!.chainPem, key: certs[centre]!.privateKeyPem, ca: ca.trustBundlePem() },
      "localhost",
    );
    const data = payload === undefined ? undefined : JSON.stringify(payload);
    return new Promise((resolve, reject) => {
      const req = httpsRequest(
        {
          host: "127.0.0.1",
          port,
          path,
          method,
          ...tls,
          ...(data
            ? { headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data) } }
            : {}),
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            let body: unknown = text;
            try {
              body = JSON.parse(text);
            } catch {
              /* keep raw */
            }
            resolve({ status: res.statusCode ?? 0, body });
          });
        },
      );
      req.on("error", reject);
      if (data) req.write(data);
      req.end();
    });
  };

  return {
    authority,
    port,
    ca,
    certs,
    centreKeys,
    custodians,
    bundleId: provisioned.paper.bundleId,
    get: (p, c) => call("GET", p, c),
    post: (p, c, payload) => call("POST", p, c, payload),
  };
}

describe("authority API over mTLS", () => {
  it("serves health, metrics and the authority public key", async () => {
    const r = await rig();
    const live = await r.get("/v1/health/live", "CENTRE-A");
    expect(live.status).toBe(200);
    expect((live.body as { status: string }).status).toBe("pass");

    const metrics = await r.get("/metrics", "CENTRE-A");
    expect(metrics.status).toBe(200);
    expect(String(metrics.body)).toContain("zw_authority_kek_lifetime_budget_ms");

    const key = await r.get("/v1/authority-key", "CENTRE-A");
    expect((key.body as { publicKey: string }).publicKey).toBe(
      r.authority.publicKey.toString("hex"),
    );
  }, 60_000);

  it("I-SRV-1: a centre can fetch a bundle only after it is distributed to IT", async () => {
    const r = await rig();
    // Distributed to A only.
    await r.authority.distribute(r.bundleId, "CENTRE-A");

    const forA = await r.get(`/v1/exam/${EXAM}/bundle/paper`, "CENTRE-A");
    expect(forA.status).toBe(200);
    expect((forA.body as { bundleHash: string }).bundleHash).toMatch(/^[0-9a-f]{64}$/);

    // B presents a valid certificate but was never given this bundle.
    const forB = await r.get(`/v1/exam/${EXAM}/bundle/paper`, "CENTRE-B");
    expect(forB.status).toBe(403);
    expect(String((forB.body as { error: string }).error)).toContain("CENTRE-B");
  }, 60_000);

  it("rejects unknown bundle kinds and unknown exams", async () => {
    const r = await rig();
    expect((await r.get(`/v1/exam/${EXAM}/bundle/sideways`, "CENTRE-A")).status).toBe(400);
    expect((await r.get(`/v1/exam/NO-SUCH-EXAM/bundle/paper`, "CENTRE-A")).status).toBe(404);
  }, 60_000);

  it("T2: the release endpoint returns 425 until the threshold release happens", async () => {
    const r = await rig();
    await r.authority.distribute(r.bundleId, "CENTRE-A");
    await r.authority.scheduleRelease({
      examId: EXAM,
      bundleId: r.bundleId,
      releaseAt: Date.now() + 3_600_000,
    });

    const early = await r.get(`/v1/exam/${EXAM}/release/paper`, "CENTRE-A");
    expect(early.status).toBe(425);
    expect((early.body as { scheduledAt: number }).scheduledAt).toBeGreaterThan(Date.now());
  }, 60_000);

  it("delivers a wrapped KEK only to the centre it was sealed for", async () => {
    const r = await rig();
    for (const id of ["CENTRE-A", "CENTRE-B"]) await r.authority.distribute(r.bundleId, id);
    await r.authority.scheduleRelease({
      examId: EXAM,
      bundleId: r.bundleId,
      releaseAt: Date.now() - 1000,
    });
    const shareOf = (id: string) => {
      const rec = r.authority.store.shares(r.bundleId).find((s) => s.custodianId === id)!;
      const c = r.custodians.find((x) => x.custodianId === id)!;
      return { custodianId: id, shareBlob: sealOpen(rec.sealed, c.keys.publicKey, c.keys.secretKey) };
    };
    await r.authority.release({
      bundleId: r.bundleId,
      shares: [shareOf("cust-1"), shareOf("cust-2"), shareOf("cust-3")],
    });

    const forA = await r.get(`/v1/exam/${EXAM}/release/paper`, "CENTRE-A");
    expect(forA.status).toBe(200);
    const sealedA = Buffer.from((forA.body as { sealed: string }).sealed, "base64");

    // A's envelope opens with A's key and NOT with B's.
    const a = r.centreKeys["CENTRE-A"]!;
    const b = r.centreKeys["CENTRE-B"]!;
    expect(sealOpen(sealedA, a.publicKey, a.secretKey)).toHaveLength(32);
    expect(() => sealOpen(sealedA, b.publicKey, b.secretKey)).toThrow();

    // B gets its own, different envelope.
    const forB = await r.get(`/v1/exam/${EXAM}/release/paper`, "CENTRE-B");
    const sealedB = Buffer.from((forB.body as { sealed: string }).sealed, "base64");
    expect(sealedB.equals(sealedA)).toBe(false);
    expect(sealOpen(sealedB, b.publicKey, b.secretKey)).toHaveLength(32);
  }, 60_000);

  it("accumulates custodian shares and fires the release at threshold", async () => {
    const r = await rig();
    await r.authority.distribute(r.bundleId, "CENTRE-A");
    await r.authority.scheduleRelease({
      examId: EXAM,
      bundleId: r.bundleId,
      releaseAt: Date.now() - 1000,
    });
    const shareHex = (id: string) => {
      const rec = r.authority.store.shares(r.bundleId).find((s) => s.custodianId === id)!;
      const c = r.custodians.find((x) => x.custodianId === id)!;
      return sealOpen(rec.sealed, c.keys.publicKey, c.keys.secretKey).toString("hex");
    };
    const url = `/v1/exam/${EXAM}/release/paper/shares`;

    const first = await r.post(url, "CENTRE-A", { custodianId: "cust-1", shareHex: shareHex("cust-1") });
    expect(first.body).toMatchObject({ status: "pending", submitted: 1, threshold: 3 });

    await r.post(url, "CENTRE-A", { custodianId: "cust-2", shareHex: shareHex("cust-2") });
    const third = await r.post(url, "CENTRE-A", {
      custodianId: "cust-4",
      shareHex: shareHex("cust-4"),
    });
    expect(third.status).toBe(200);
    expect((third.body as { status: string }).status).toBe("released");
    expect((third.body as { centres: string[] }).centres).toContain("CENTRE-A");
  }, 60_000);

  it("returns 425 and RETAINS shares when submitted before T-0", async () => {
    const r = await rig();
    await r.authority.distribute(r.bundleId, "CENTRE-A");
    await r.authority.scheduleRelease({
      examId: EXAM,
      bundleId: r.bundleId,
      releaseAt: Date.now() + 3_600_000,
    });
    const shareHex = (id: string) => {
      const rec = r.authority.store.shares(r.bundleId).find((s) => s.custodianId === id)!;
      const c = r.custodians.find((x) => x.custodianId === id)!;
      return sealOpen(rec.sealed, c.keys.publicKey, c.keys.secretKey).toString("hex");
    };
    const url = `/v1/exam/${EXAM}/release/paper/shares`;
    await r.post(url, "CENTRE-A", { custodianId: "cust-1", shareHex: shareHex("cust-1") });
    await r.post(url, "CENTRE-A", { custodianId: "cust-2", shareHex: shareHex("cust-2") });
    const early = await r.post(url, "CENTRE-A", {
      custodianId: "cust-3",
      shareHex: shareHex("cust-3"),
    });

    expect(early.status).toBe(425);
    expect((early.body as { code: string }).code).toBe("TOO_EARLY");
    // The attempt is evidence.
    expect(
      r.authority.log.entries().filter((e) => e.type === "EARLY_RELEASE_ATTEMPT"),
    ).toHaveLength(1);

    // Shares are retained so the same custodians can retry at T-0 without
    // re-entering material — resubmitting one share must now be enough.
    await r.authority.scheduleRelease({
      examId: EXAM,
      bundleId: r.bundleId,
      releaseAt: Date.now() - 1000,
    });
    const retry = await r.post(url, "CENTRE-A", {
      custodianId: "cust-3",
      shareHex: shareHex("cust-3"),
    });
    expect((retry.body as { status: string }).status).toBe("released");
  }, 60_000);

  it("rejects malformed share submissions", async () => {
    const r = await rig();
    const url = `/v1/exam/${EXAM}/release/paper/shares`;
    expect((await r.post(url, "CENTRE-A", { custodianId: 42 })).status).toBe(400);
    expect(
      (await r.post(`/v1/exam/${EXAM}/release/nonsense/shares`, "CENTRE-A", {
        custodianId: "cust-1",
        shareHex: "00",
      })).status,
    ).toBe(400);
    expect(
      (await r.post(`/v1/exam/NOPE/release/paper/shares`, "CENTRE-A", {
        custodianId: "cust-1",
        shareHex: "00",
      })).status,
    ).toBe(404);
  }, 60_000);
});
