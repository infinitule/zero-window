#!/usr/bin/env node
import { readFile, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { VaultKeyProvider } from "@zw/kms-vault";
import { RevocationList } from "@zw/ca";
import { GracefulShutdown, Logger } from "@zw/ops";
import { Authority } from "./authority.js";
import { buildAuthorityServer } from "./server.js";

/**
 * Long-running authority service (deploy/systemd/zw-authority.service).
 *
 * Configuration is environment-only: systemd delivers the vault passphrase
 * through its credential store, so nothing sensitive appears in the unit
 * file, the process arguments, or `ps` output.
 */

function env(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined) {
    process.stderr.write(`${name} is required\n`);
    process.exit(2);
  }
  return v;
}

async function main(): Promise<void> {
  const dirFlagIndex = process.argv.indexOf("--dir");
  const stateDir = resolve(
    dirFlagIndex !== -1 ? (process.argv[dirFlagIndex + 1] ?? "") : env("ZW_STATE_DIR", "./authority-state"),
  );
  await mkdir(stateDir, { recursive: true });

  const logger = new Logger({
    service: "authority",
    level: (process.env["ZW_LOG_LEVEL"] as "info") ?? "info",
  });

  const passphrase = process.env["ZW_VAULT_PASSPHRASE"];
  const provider = await VaultKeyProvider.open({
    keystorePath: join(stateDir, "keystore.json"),
    ...(passphrase ? { passphrase: Buffer.from(passphrase, "utf8") } : {}),
  });

  const authority = await Authority.open({
    statePath: join(stateDir, "authority.db"),
    logPath: join(stateDir, "log.db"),
    provider,
    logger,
  });

  const tlsDir = env("ZW_TLS_DIR", join(stateDir, "tls"));
  const tls = {
    cert: await readFile(join(tlsDir, "chain.pem"), "utf8"),
    key: await readFile(join(tlsDir, "key.pem"), "utf8"),
    ca: await readFile(join(tlsDir, "ca.pem"), "utf8"),
  };

  // I-CA-3: if a CRL path is configured it must load and be fresh, or the
  // service refuses to start. Revocation that silently degrades is not
  // revocation.
  const crlPath = process.env["ZW_CRL_PATH"];
  const crl = crlPath ? await RevocationList.load(crlPath) : undefined;
  if (crl) crl.assertFresh(new Date());

  const host = env("ZW_BIND_HOST", "0.0.0.0");
  const port = Number(env("ZW_BIND_PORT", "8443"));
  const app = await buildAuthorityServer({
    authority,
    tls,
    ...(crl ? { crl } : {}),
    host,
    port,
  });

  logger.info("authority listening", {
    host,
    port,
    key_provider: provider.kind,
    state_dir: stateDir,
    crl: crlPath ?? "none",
    public_key: authority.publicKey.toString("hex"),
  });

  const shutdown = new GracefulShutdown({
    timeoutMs: 15_000,
    onEvent: (event, fields) => logger.info(event, fields),
    exit: (code) => process.exit(code),
  });
  shutdown.register("authority", () => authority.close());
  shutdown.register("http", () => app.close());
  shutdown.install();
}

main().catch((err: unknown) => {
  process.stderr.write(`authority failed to start: ${(err as Error).message}\n`);
  process.exit(1);
});
