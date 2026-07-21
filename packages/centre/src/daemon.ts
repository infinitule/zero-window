#!/usr/bin/env node
import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { VaultKeyProvider } from "@zw/kms-vault";
import { GracefulShutdown, Logger, MetricsRegistry } from "@zw/ops";
import { CentreNode } from "./centre.js";
import { AuthoritySyncClient } from "./sync.js";
import type { PrinterTarget } from "./print.js";

/**
 * Long-running centre node (deploy/systemd/zw-centre.service).
 *
 * Two loops:
 *   1. sync — fetch the bundle, then poll for the wrapped KEK until T-0.
 *      Stops the moment the KEK is held.
 *   2. serve — a LOCAL-ONLY health and metrics listener on the loopback
 *      interface for the hall operator's console and the node exporter.
 *
 * INVARIANT I-CTR-2: once the KEK is held, the sync loop stops and nothing
 * on the exam-day path touches the network again. Losing the authority after
 * that point is normal operation, not a fault (T10).
 */

function env(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined) {
    process.stderr.write(`${name} is required\n`);
    process.exit(2);
  }
  return v;
}

function parsePrinters(raw: string | undefined): PrinterTarget[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((pair) => {
      const eq = pair.indexOf("=");
      if (eq === -1) throw new Error(`ZW_PRINTERS entries must be id=url, got "${pair}"`);
      return { printerId: pair.slice(0, eq), url: pair.slice(eq + 1) };
    });
}

async function main(): Promise<void> {
  const dirFlagIndex = process.argv.indexOf("--dir");
  const stateDir = resolve(
    dirFlagIndex !== -1 ? (process.argv[dirFlagIndex + 1] ?? "") : env("ZW_STATE_DIR", "./centre-state"),
  );
  await mkdir(stateDir, { recursive: true });

  const centreId = env("ZW_CENTRE_ID");
  const examId = env("ZW_EXAM_ID");
  const logger = new Logger({
    service: `centre-${centreId}`,
    level: (process.env["ZW_LOG_LEVEL"] as "info") ?? "info",
  });

  const passphrase = process.env["ZW_VAULT_PASSPHRASE"];
  const provider = await VaultKeyProvider.open({
    keystorePath: join(stateDir, "keystore.json"),
    ...(passphrase ? { passphrase: Buffer.from(passphrase, "utf8") } : {}),
  });

  const authorityKeyHex = env("ZW_AUTHORITY_KEY");
  const spoolDir = process.env["ZW_SPOOL_DIR"] ?? "/var/spool/zero-window";
  const centre = await CentreNode.open({
    centreId,
    examId,
    statePath: join(stateDir, "centre.db"),
    logPath: join(stateDir, "log.db"),
    provider,
    authorityPublicKey: Buffer.from(authorityKeyHex, "hex"),
    printers: parsePrinters(process.env["ZW_PRINTERS"]),
    spoolDir,
    logger,
  });

  // ---- local health/metrics listener (loopback only) ------------------
  const adminPort = Number(env("ZW_ADMIN_PORT", "9464"));
  const admin = createServer((req, res) => {
    const send = (code: number, type: string, body: string) => {
      res.writeHead(code, { "content-type": type });
      res.end(body);
    };
    const url = req.url ?? "/";
    if (url === "/metrics") {
      send(200, MetricsRegistry.CONTENT_TYPE, centre.metrics.expose());
    } else if (url === "/health/live") {
      void centre.health.live().then((r) =>
        send(r.status === "fail" ? 503 : 200, "application/json", JSON.stringify(r)),
      );
    } else if (url === "/health/ready") {
      void centre.health.ready().then((r) =>
        send(r.status === "fail" ? 503 : 200, "application/json", JSON.stringify(r)),
      );
    } else {
      send(404, "text/plain", "not found\n");
    }
  });
  // Loopback only: this endpoint exposes operational state and must not be
  // reachable from the hall network.
  await new Promise<void>((r) => admin.listen(adminPort, "127.0.0.1", r));

  // ---- sync loop -------------------------------------------------------
  const authorityHost = process.env["ZW_AUTHORITY_HOST"];
  let syncTimer: NodeJS.Timeout | undefined;

  if (authorityHost) {
    const tlsDir = env("ZW_TLS_DIR", join(stateDir, "tls"));
    const sync = new AuthoritySyncClient({
      authorityHost,
      authorityPort: Number(env("ZW_AUTHORITY_PORT", "8443")),
      servername: process.env["ZW_AUTHORITY_SERVERNAME"] ?? authorityHost,
      tls: {
        cert: await readFile(join(tlsDir, "chain.pem"), "utf8"),
        key: await readFile(join(tlsDir, "key.pem"), "utf8"),
        ca: await readFile(join(tlsDir, "ca.pem"), "utf8"),
      },
    });

    const intervalMs = Number(env("ZW_SYNC_INTERVAL_MS", "5000"));
    const tick = async (): Promise<void> => {
      try {
        if (!centre.store.bundle(centre.paperBundleId())) {
          await sync.fetchBundle(centre, examId, "paper");
          logger.info("bundle custody accepted from authority");
        }
        const held = await sync.tryFetchKek(centre, examId, "paper");
        if (held) {
          logger.info("KEK received; sync loop stopping — the node is now autonomous");
          if (syncTimer) clearInterval(syncTimer);
          syncTimer = undefined;
        }
      } catch (err) {
        // Connectivity failures are expected and non-fatal: the node keeps
        // whatever it already holds and retries. It must never exit here.
        logger.warn("sync attempt failed; will retry", { error: (err as Error).message });
      }
    };
    syncTimer = setInterval(() => void tick(), intervalMs);
    syncTimer.unref();
    void tick();
  } else {
    logger.info("no ZW_AUTHORITY_HOST configured: offline mode, expecting signed media");
  }

  logger.info("centre node started", {
    centre_id: centreId,
    exam_id: examId,
    state_dir: stateDir,
    spool_dir: spoolDir,
    admin_port: adminPort,
    printers: parsePrinters(process.env["ZW_PRINTERS"]).map((p) => p.printerId),
    box_public_key: centre.boxPublicKey.toString("hex"),
  });

  const shutdown = new GracefulShutdown({
    timeoutMs: 15_000,
    onEvent: (event, fields) => logger.info(event, fields),
    exit: (code) => process.exit(code),
  });
  shutdown.register("centre", () => centre.close());
  shutdown.register("admin", () => new Promise<void>((r) => admin.close(() => r())));
  shutdown.register("sync", () => {
    if (syncTimer) clearInterval(syncTimer);
  });
  shutdown.install();
}

main().catch((err: unknown) => {
  process.stderr.write(`centre node failed to start: ${(err as Error).message}\n`);
  process.exit(1);
});
