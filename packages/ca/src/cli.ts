#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { CaError, CertificateAuthority } from "./ca.js";
import type { CertRole, RevocationReason } from "./types.js";

/**
 * `zw-ca` — certificate lifecycle for the ZERO-WINDOW PKI.
 *
 * Operator-facing: every command prints what it did and where it wrote
 * files, because the key-ceremony runbook is executed by someone who has
 * never read this code.
 */

const USAGE = `zw-ca — ZERO-WINDOW internal certificate authority

USAGE
  zw-ca <command> [options]

COMMANDS
  init                    Create the root CA and first issuing intermediate
  issue                   Issue a leaf certificate
  rotate                  Replace a leaf certificate and supersede the old one
  rotate-intermediate     Issue a new issuing CA from the root
  revoke                  Revoke a certificate
  crl                     Generate and publish a signed CRL
  list                    List issued certificates
  bundle                  Print the trust bundle (root + intermediates)

COMMON OPTIONS
  --dir <path>            CA directory (default: ./ca, or $ZW_CA_DIR)

init
  --org <name>            Organization for every subject
  --country <code>        Two-letter country code
  --out <path>            Directory to write root/intermediate material into

issue
  --role <role>           authority-server | centre-client | custodian-client | auditor-client
  --cn <name>             Common name (e.g. the centre id)
  --san <name>            DNS name or IP; repeatable (server certificates)
  --hardware-id <id>      Hardware identifier; REQUIRED for centre/custodian
  --days <n>              Lifetime override
  --out <path>            Directory to write cert.pem, key.pem, chain.pem, ca.pem

rotate
  --serial <hex>          Certificate to replace
  --days <n>              Lifetime override
  --out <path>            Directory to write the replacement material into

rotate-intermediate
  --root-key <path>       PEM of the offline root private key
  --out <path>            Directory to write the new intermediate into

revoke
  --serial <hex>          Certificate to revoke
  --reason <reason>       unspecified | keyCompromise | caCompromise |
                          affiliationChanged | superseded | cessationOfOperation

crl
  --hours <n>             Validity window (default 24). A stale CRL fails closed.
  --out <path>            Write the CRL here as well as into the CA directory

list
  --role <role>           Filter by role
  --json                  Machine-readable output
`;

interface Args {
  command: string;
  flags: Map<string, string[]>;
}

function parseArgs(argv: string[]): Args {
  const command = argv[0] ?? "";
  const flags = new Map<string, string[]>();
  for (let i = 1; i < argv.length; i++) {
    const token = argv[i]!;
    if (!token.startsWith("--")) continue;
    const name = token.slice(2);
    const next = argv[i + 1];
    const value = next !== undefined && !next.startsWith("--") ? (i++, next) : "true";
    const existing = flags.get(name);
    if (existing) existing.push(value);
    else flags.set(name, [value]);
  }
  return { command, flags };
}

function flag(args: Args, name: string): string | undefined {
  return args.flags.get(name)?.[0];
}

function requireFlag(args: Args, name: string): string {
  const value = flag(args, name);
  if (value === undefined) {
    throw new UsageError(`missing required option --${name}`);
  }
  return value;
}

class UsageError extends Error {}

async function writeMaterial(
  outDir: string,
  material: { record: { pem: string; serial: string }; privateKeyPem: string; chainPem: string },
  trustBundle: string,
): Promise<void> {
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, "cert.pem"), material.record.pem, { mode: 0o644 });
  await writeFile(join(outDir, "key.pem"), material.privateKeyPem, { mode: 0o600 });
  await writeFile(join(outDir, "chain.pem"), material.chainPem, { mode: 0o644 });
  await writeFile(join(outDir, "ca.pem"), trustBundle, { mode: 0o644 });
}

async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args.command === "" || args.command === "help" || args.flags.has("help")) {
    process.stdout.write(USAGE);
    return args.command === "" ? 1 : 0;
  }

  const dir = flag(args, "dir") ?? process.env["ZW_CA_DIR"] ?? "./ca";

  switch (args.command) {
    case "init": {
      const ca = await CertificateAuthority.open({
        dir,
        ...(flag(args, "org") !== undefined ? { organization: flag(args, "org")! } : {}),
        ...(flag(args, "country") !== undefined ? { country: flag(args, "country")! } : {}),
      });
      const { root, intermediate } = await ca.initialize();
      process.stdout.write(
        `Initialized CA in ${dir}\n` +
          `  root serial         ${root.record.serial}\n` +
          `  root fingerprint    ${root.record.fingerprint}\n` +
          `  root expires        ${root.record.notAfter}\n` +
          `  intermediate serial ${intermediate.record.serial}\n` +
          `  intermediate expires ${intermediate.record.notAfter}\n\n` +
          `NEXT STEP (runbooks/key-ceremony.md §3): move the ROOT private key\n` +
          `  ${join(dir, "private", `${root.record.serial}.key.pem`)}\n` +
          `to offline media and delete it from this host. The CA continues to\n` +
          `issue with the intermediate; the root key is only needed to rotate it.\n`,
      );
      const out = flag(args, "out");
      if (out !== undefined) {
        await mkdir(out, { recursive: true });
        await writeFile(join(out, "root.pem"), root.record.pem, { mode: 0o644 });
        await writeFile(join(out, "root.key.pem"), root.privateKeyPem, { mode: 0o600 });
        await writeFile(join(out, "intermediate.pem"), intermediate.record.pem, { mode: 0o644 });
        await writeFile(join(out, "ca.pem"), ca.trustBundlePem(), { mode: 0o644 });
        process.stdout.write(`\nWrote root and intermediate material to ${out}\n`);
      }
      return 0;
    }

    case "issue": {
      const ca = await CertificateAuthority.open({ dir });
      const role = requireFlag(args, "role") as CertRole;
      if (role === "root" || role === "intermediate") {
        throw new UsageError(`role ${role} is created by init/rotate-intermediate, not issue`);
      }
      const days = flag(args, "days");
      const issued = await ca.issue({
        role,
        commonName: requireFlag(args, "cn"),
        ...(args.flags.has("san") ? { sans: args.flags.get("san")! } : {}),
        ...(flag(args, "hardware-id") !== undefined
          ? { hardwareId: flag(args, "hardware-id")! }
          : {}),
        ...(days !== undefined ? { lifetimeDays: Number(days) } : {}),
      });
      process.stdout.write(
        `Issued ${role} certificate\n` +
          `  serial      ${issued.record.serial}\n` +
          `  subject     ${issued.record.subject}\n` +
          `  fingerprint ${issued.record.fingerprint}\n` +
          `  expires     ${issued.record.notAfter}\n`,
      );
      const out = flag(args, "out");
      if (out !== undefined) {
        await writeMaterial(out, issued, ca.trustBundlePem());
        process.stdout.write(`  written to  ${out} (cert.pem, key.pem, chain.pem, ca.pem)\n`);
      } else {
        process.stdout.write(`\n${issued.record.pem}${issued.privateKeyPem}`);
      }
      return 0;
    }

    case "rotate": {
      const ca = await CertificateAuthority.open({ dir });
      const days = flag(args, "days");
      const serial = requireFlag(args, "serial");
      const replacement = await ca.rotate(
        serial,
        days !== undefined ? Number(days) : undefined,
      );
      process.stdout.write(
        `Rotated ${serial}\n` +
          `  replacement serial ${replacement.record.serial}\n` +
          `  expires            ${replacement.record.notAfter}\n` +
          `  old certificate    revoked as superseded\n` +
          `\nPublish a fresh CRL (\`zw-ca crl\`) so peers stop accepting the old one.\n`,
      );
      const out = flag(args, "out");
      if (out !== undefined) {
        await writeMaterial(out, replacement, ca.trustBundlePem());
        process.stdout.write(`  written to         ${out}\n`);
      }
      return 0;
    }

    case "rotate-intermediate": {
      const ca = await CertificateAuthority.open({ dir });
      const keyPath = requireFlag(args, "root-key");
      const rootKeyPem = await (await import("node:fs/promises")).readFile(keyPath, "utf8");
      const issued = await ca.rotateIntermediate(rootKeyPem);
      process.stdout.write(
        `New issuing intermediate\n` +
          `  serial  ${issued.record.serial}\n` +
          `  expires ${issued.record.notAfter}\n` +
          `\nThe previous intermediate is NOT revoked: certificates it signed stay\n` +
          `valid until they expire. Revoke it explicitly if this is an incident.\n`,
      );
      const out = flag(args, "out");
      if (out !== undefined) {
        await writeMaterial(out, issued, ca.trustBundlePem());
        process.stdout.write(`  written to ${out}\n`);
      }
      return 0;
    }

    case "revoke": {
      const ca = await CertificateAuthority.open({ dir });
      const serial = requireFlag(args, "serial");
      const reason = (flag(args, "reason") ?? "unspecified") as RevocationReason;
      await ca.revoke(serial, reason);
      const record = ca.get(serial);
      process.stdout.write(
        `Revoked ${serial} (${record.commonName}) as ${reason}\n` +
          `\nRun \`zw-ca crl\` and distribute the CRL: revocation takes effect for\n` +
          `peers only once they load a CRL that lists this serial.\n`,
      );
      return 0;
    }

    case "crl": {
      const ca = await CertificateAuthority.open({ dir });
      const hours = flag(args, "hours");
      const pem = await ca.generateCrl(hours !== undefined ? Number(hours) : undefined);
      const revoked = ca.list().filter((c) => c.revoked).length;
      process.stdout.write(
        `Published CRL to ${join(dir, "crl.pem")}\n` +
          `  revoked certificates ${revoked}\n` +
          `  valid for            ${hours ?? 24}h\n`,
      );
      const out = flag(args, "out");
      if (out !== undefined) {
        await writeFile(out, pem, { mode: 0o644 });
        process.stdout.write(`  also written to      ${out}\n`);
      }
      return 0;
    }

    case "list": {
      const ca = await CertificateAuthority.open({ dir });
      const roleFlag = flag(args, "role");
      const certs = ca.list(roleFlag !== undefined ? { role: roleFlag as CertRole } : undefined);
      if (args.flags.has("json")) {
        process.stdout.write(JSON.stringify(certs, null, 2) + "\n");
        return 0;
      }
      if (certs.length === 0) {
        process.stdout.write("No certificates issued.\n");
        return 0;
      }
      for (const c of certs) {
        const status = c.revoked ? `REVOKED (${c.revoked.reason})` : "valid";
        process.stdout.write(
          `${c.serial}  ${c.role.padEnd(18)} ${c.commonName.padEnd(24)} ${c.notAfter}  ${status}\n`,
        );
      }
      return 0;
    }

    case "bundle": {
      const ca = await CertificateAuthority.open({ dir });
      process.stdout.write(ca.trustBundlePem());
      return 0;
    }

    default:
      throw new UsageError(`unknown command "${args.command}"`);
  }
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    if (err instanceof UsageError) {
      process.stderr.write(`zw-ca: ${err.message}\n\nRun \`zw-ca help\` for usage.\n`);
      process.exit(2);
    }
    if (err instanceof CaError) {
      process.stderr.write(`zw-ca: ${err.message}\n`);
      process.exit(1);
    }
    process.stderr.write(`zw-ca: unexpected error: ${(err as Error).message}\n`);
    process.exit(1);
  });
