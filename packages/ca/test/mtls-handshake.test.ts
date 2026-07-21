import { createServer, connect, type TLSSocket } from "node:tls";
import { X509Certificate } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AddressInfo } from "node:net";
import { afterAll, describe, expect, it } from "vitest";
import {
  CertificateAuthority,
  RevocationList,
  checkPeerCertificate,
  tlsClientOptions,
  tlsServerOptions,
  type IssuedCertificate,
} from "../src/index.js";

/**
 * Real TLS 1.3 handshakes through Node's TLS stack. Unit-testing the
 * certificate contents proves they are shaped correctly; only an actual
 * handshake proves the material we generate is accepted by a TLS
 * implementation and that a peer without a valid client certificate is
 * genuinely refused.
 */

const dirs: string[] = [];
const servers: ReturnType<typeof createServer>[] = [];

afterAll(async () => {
  await Promise.all(
    servers.map((s) => new Promise<void>((r) => s.close(() => r()))),
  );
  await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
});

interface Fixture {
  ca: CertificateAuthority;
  server: IssuedCertificate;
  client: IssuedCertificate;
}

async function fixture(): Promise<Fixture> {
  const dir = await mkdtemp(join(tmpdir(), "zw-mtls-"));
  dirs.push(dir);
  const ca = await CertificateAuthority.open({ dir });
  await ca.initialize();
  const server = await ca.issue({
    role: "authority-server",
    commonName: "localhost",
    sans: ["localhost", "127.0.0.1"],
  });
  const client = await ca.issue({
    role: "centre-client",
    commonName: "CENTRE-A",
    hardwareId: "tpm-node-1",
  });
  return { ca, server, client };
}

/** Start an mTLS listener that applies our application-level peer checks. */
async function listen(
  f: Fixture,
  opts: { crl?: RevocationList; expectHardwareId?: string } = {},
): Promise<{ port: number; lastError: () => string | null; accepted: () => number }> {
  let lastError: string | null = null;
  let accepted = 0;
  const server = createServer(
    tlsServerOptions({
      cert: f.server.chainPem,
      key: f.server.privateKeyPem,
      ca: f.ca.trustBundlePem(),
    }),
    (socket: TLSSocket) => {
      // Reached only when Node's TLS stack has already verified the client
      // chain against our trust bundle.
      accepted++;
      try {
        const peer = socket.getPeerX509Certificate();
        const identity = checkPeerCertificate(peer, {
          requireEku: "clientAuth",
          ...(opts.crl ? { crl: opts.crl } : {}),
          ...(opts.expectHardwareId !== undefined
            ? { expectHardwareId: opts.expectHardwareId }
            : {}),
        });
        socket.end(`ok:${identity.hardwareId}`);
      } catch (err) {
        lastError = (err as Error).message;
        socket.end("rejected");
      }
    },
  );
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: (server.address() as AddressInfo).port,
    lastError: () => lastError,
    accepted: () => accepted,
  };
}

/**
 * Attempt a connection and wait for it to reach a terminal state — data,
 * clean close, or error. Used where the point is that the server refused,
 * which in TLS 1.3 the client may observe as any of the three.
 */
async function settle(
  port: number,
  f: Fixture,
  clientCert: { cert: string; key: string } | undefined,
): Promise<void> {
  await new Promise<void>((resolve) => {
    const socket = connect({
      port,
      host: "127.0.0.1",
      ca: f.ca.trustBundlePem(),
      servername: "localhost",
      minVersion: "TLSv1.3",
      ...(clientCert ?? {}),
    });
    const done = () => {
      socket.destroy();
      resolve();
    };
    socket.on("error", done);
    socket.on("close", done);
    socket.on("end", done);
    socket.on("data", done);
    socket.setTimeout(3000, done);
  });
  // Give the server's async rejection a turn to land before asserting.
  await new Promise((r) => setTimeout(r, 50));
}

function request(
  port: number,
  clientOpts: { cert: string; key: string; ca: string },
): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(
      { port, host: "127.0.0.1", ...tlsClientOptions(clientOpts, "localhost") },
      () => {
        let data = "";
        socket.on("data", (c) => (data += c.toString()));
        socket.on("end", () => resolve(data));
      },
    );
    socket.on("error", reject);
    socket.setTimeout(5000, () => {
      socket.destroy();
      reject(new Error("timeout"));
    });
  });
}

describe("real mTLS handshakes", () => {
  it("a properly issued client connects and is identified by hardware id", async () => {
    const f = await fixture();
    const { port } = await listen(f, { expectHardwareId: "tpm-node-1" });
    const response = await request(port, {
      cert: f.client.chainPem,
      key: f.client.privateKeyPem,
      ca: f.ca.trustBundlePem(),
    });
    expect(response).toBe("ok:tpm-node-1");
  });

  it("negotiates TLS 1.3", async () => {
    const f = await fixture();
    const { port } = await listen(f);
    const protocol = await new Promise<string>((resolve, reject) => {
      const socket = connect(
        {
          port,
          host: "127.0.0.1",
          ...tlsClientOptions(
            { cert: f.client.chainPem, key: f.client.privateKeyPem, ca: f.ca.trustBundlePem() },
            "localhost",
          ),
        },
        () => {
          const p = socket.getProtocol() ?? "";
          socket.destroy();
          resolve(p);
        },
      );
      socket.on("error", reject);
    });
    expect(protocol).toBe("TLSv1.3");
  });

  it("refuses a client presenting no certificate", async () => {
    const f = await fixture();
    const { port, accepted } = await listen(f);
    // TLS 1.3 SEMANTICS THAT MATTER OPERATIONALLY: the client's connect
    // callback fires as soon as it has verified the SERVER. The server
    // validates the client certificate afterwards, so a rejected client sees
    // a successful "connect" and only learns it was refused on a subsequent
    // read/write. A service must therefore never treat "connected" as
    // "authenticated" — the authoritative signal is that the server's
    // connection handler never ran.
    await settle(port, f, undefined);
    expect(accepted()).toBe(0);
  });

  it("refuses a client certificate from a different CA", async () => {
    const f = await fixture();
    const otherDir = await mkdtemp(join(tmpdir(), "zw-mtls-other-"));
    dirs.push(otherDir);
    const otherCa = await CertificateAuthority.open({ dir: otherDir });
    await otherCa.initialize();
    const impostor = await otherCa.issue({
      role: "centre-client",
      commonName: "CENTRE-A",
      hardwareId: "tpm-node-1",
    });

    const { port, accepted } = await listen(f);
    // Identical subject and hardware id, but the chain does not verify
    // against our trust bundle, so the server never accepts the connection.
    await settle(port, f, {
      cert: impostor.chainPem,
      key: impostor.privateKeyPem,
    });
    expect(accepted()).toBe(0);
  });

  it("refuses a revoked client at the application layer after the handshake", async () => {
    const f = await fixture();
    await f.ca.revoke(f.client.record.serial, "keyCompromise");
    const crl = RevocationList.parse(await f.ca.generateCrl());

    const { port, lastError } = await listen(f, { crl });
    const response = await request(port, {
      cert: f.client.chainPem,
      key: f.client.privateKeyPem,
      ca: f.ca.trustBundlePem(),
    });
    // TLS itself still succeeds — revocation is ours to enforce, and we do.
    expect(response).toBe("rejected");
    expect(lastError()).toMatch(/is revoked/);
  });

  it("refuses a client whose hardware binding does not match its enrolment", async () => {
    const f = await fixture();
    const { port, lastError } = await listen(f, { expectHardwareId: "tpm-a-different-box" });
    const response = await request(port, {
      cert: f.client.chainPem,
      key: f.client.privateKeyPem,
      ca: f.ca.trustBundlePem(),
    });
    expect(response).toBe("rejected");
    expect(lastError()).toMatch(/may have been copied to another machine/);
  });

  it("accepts the replacement certificate after rotation and refuses the old one", async () => {
    const f = await fixture();
    const replacement = await f.ca.rotate(f.client.record.serial);
    const crl = RevocationList.parse(await f.ca.generateCrl());
    const { port, lastError } = await listen(f, { crl });

    const good = await request(port, {
      cert: replacement.chainPem,
      key: replacement.privateKeyPem,
      ca: f.ca.trustBundlePem(),
    });
    expect(good).toBe("ok:tpm-node-1");

    const stale = await request(port, {
      cert: f.client.chainPem,
      key: f.client.privateKeyPem,
      ca: f.ca.trustBundlePem(),
    });
    expect(stale).toBe("rejected");
    expect(lastError()).toMatch(/is revoked/);
  });

  it("the server certificate the client validated carries serverAuth EKU", async () => {
    const f = await fixture();
    const { port } = await listen(f);
    const peerCert = await new Promise<X509Certificate>((resolve, reject) => {
      const socket = connect(
        {
          port,
          host: "127.0.0.1",
          ...tlsClientOptions(
            { cert: f.client.chainPem, key: f.client.privateKeyPem, ca: f.ca.trustBundlePem() },
            "localhost",
          ),
        },
        () => {
          const cert = socket.getPeerX509Certificate();
          socket.destroy();
          if (!cert) reject(new Error("no server certificate"));
          else resolve(cert);
        },
      );
      socket.on("error", reject);
    });

    const checked = checkPeerCertificate(peerCert, { requireEku: "serverAuth" });
    expect(checked.serial).toBe(f.server.record.serial);
  });
});
