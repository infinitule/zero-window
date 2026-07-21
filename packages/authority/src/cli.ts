#!/usr/bin/env node
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { VaultKeyProvider } from "@zw/kms-vault";
import { Logger } from "@zw/ops";
import { Authority } from "./authority.js";
import { encodeAdmitToken } from "./admit.js";
import { buildOfflineMedium, verifyOfflineMedium, type OfflineReleaseMedium } from "./release.js";
import type { Blueprint, ItemBank } from "./bank.js";
import { BankValidationError } from "./bank.js";

/**
 * zw-authority — operator CLI.
 *
 * Every command that changes custody state writes to the transparency log
 * before reporting success, and prints the next step so an operator working
 * from runbooks/key-ceremony.md is never left guessing.
 */

interface Args {
  _: string[];
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const _: string[] = [];
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) flags.set(a.slice(2, eq), a.slice(eq + 1));
      else {
        const next = argv[i + 1];
        if (next && !next.startsWith("--")) {
          flags.set(a.slice(2), next);
          i++;
        } else flags.set(a.slice(2), true);
      }
    } else _.push(a);
  }
  return { _, flags };
}

function req(args: Args, name: string): string {
  const v = args.flags.get(name);
  if (typeof v !== "string" || v.length === 0) {
    throw new UsageError(`missing required flag --${name}`);
  }
  return v;
}

function opt(args: Args, name: string): string | undefined {
  const v = args.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

class UsageError extends Error {}

const USAGE = `zw-authority — ZERO-WINDOW authority operations

USAGE
  zw-authority <command> [flags]

COMMANDS
  enrol-custodian   Register a custodian and their public key
  enrol-centre      Register an exam centre and its public key
  provision         Ingest an item bank, build+encrypt bundles, split the KEK
  distribute        Write a ciphertext bundle for a centre
  schedule          Sign and store the T-0 release schedule
  issue-admit       Issue Ed25519-signed admit tokens (QR payloads)
  release           Threshold release of a KEK (--offline for physical ceremony)
  verify-medium     Verify a signed offline release medium
  status            Show exams, bundles, custodians, centres and schedules
  checkpoint        Create a signed Merkle checkpoint of the log

COMMON FLAGS
  --dir <path>        Authority state directory (default ./authority-state)
  --passphrase <s>    Vault passphrase (else ZW_VAULT_PASSPHRASE or OS keyring)

Run 'zw-authority <command> --help' for command-specific flags.
`;

async function openAuthority(args: Args): Promise<Authority> {
  const dir = resolve(opt(args, "dir") ?? "./authority-state");
  await mkdir(dir, { recursive: true });
  const passphrase = opt(args, "passphrase") ?? process.env["ZW_VAULT_PASSPHRASE"];
  const provider = await VaultKeyProvider.open({
    keystorePath: join(dir, "keystore.json"),
    ...(passphrase ? { passphrase: Buffer.from(passphrase, "utf8") } : {}),
  });
  return Authority.open({
    statePath: join(dir, "authority.db"),
    logPath: join(dir, "log.db"),
    provider,
    logger: new Logger({ service: "zw-authority", level: "warn" }),
  });
}

async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  const cmd = args._[0];

  if (!cmd || args.flags.has("help") || cmd === "help") {
    process.stdout.write(USAGE);
    return cmd ? 0 : 1;
  }

  switch (cmd) {
    case "enrol-custodian": {
      const authority = await openAuthority(args);
      try {
        const custodianId = req(args, "id");
        const keyPath = opt(args, "public-key");
        const boxPublicKey = keyPath
          ? Buffer.from((await readFile(keyPath, "utf8")).trim(), "hex")
          : Buffer.from(req(args, "box-public-key"), "hex");
        authority.enrolCustodian({
          custodianId,
          name: opt(args, "name") ?? custodianId,
          boxPublicKey,
          certFingerprint: opt(args, "cert-fingerprint") ?? "",
        });
        process.stdout.write(`Enrolled custodian ${custodianId}\n`);
        return 0;
      } finally {
        await authority.close();
      }
    }

    case "enrol-centre": {
      const authority = await openAuthority(args);
      try {
        const centreId = req(args, "id");
        await authority.enrolCentre({
          centreId,
          boxPublicKey: Buffer.from(req(args, "box-public-key"), "hex"),
          certFingerprint: opt(args, "cert-fingerprint") ?? "",
          hardwareId: req(args, "hardware-id"),
        });
        process.stdout.write(`Enrolled centre ${centreId}\n`);
        return 0;
      } finally {
        await authority.close();
      }
    }

    case "provision": {
      const authority = await openAuthority(args);
      try {
        const bank = JSON.parse(await readFile(req(args, "bank"), "utf8")) as ItemBank;
        const blueprint = JSON.parse(
          await readFile(req(args, "blueprint"), "utf8"),
        ) as Blueprint;
        const threshold = Number(opt(args, "threshold") ?? 3);
        const result = await authority.provision({ bank, blueprint, threshold });
        process.stdout.write(
          `Provisioned ${result.examId}\n` +
            `  paper bundle    ${result.paper.bundleId}\n` +
            `    bundle hash   ${result.paper.bundleHash}\n` +
            `    KEK           ${result.paper.kekFingerprint}\n` +
            `  answers bundle  ${result.answers.bundleId}\n` +
            `    bundle hash   ${result.answers.bundleHash}\n` +
            `    KEK           ${result.answers.kekFingerprint}\n\n` +
            `The plaintext bank is no longer needed by this system and the KEKs\n` +
            `no longer exist: they were split to custodians and destroyed.\n` +
            `NEXT (runbooks/key-ceremony.md §5): deliver each custodian their\n` +
            `sealed share, then 'zw-authority distribute' to each centre.\n`,
        );
        return 0;
      } catch (err) {
        if (err instanceof BankValidationError) {
          process.stderr.write(`${err.message}\n`);
          for (const p of err.problems) process.stderr.write(`  - ${p}\n`);
          return 2;
        }
        throw err;
      } finally {
        await authority.close();
      }
    }

    case "distribute": {
      const authority = await openAuthority(args);
      try {
        const bundleId = req(args, "bundle");
        const centreId = req(args, "centre");
        await authority.distribute(bundleId, centreId);
        const bundle = authority.store.bundle(bundleId)!;
        const out = opt(args, "out");
        if (out) {
          await writeFile(out, bundle.ciphertext);
          process.stdout.write(`Wrote ciphertext bundle to ${out} (${bundle.ciphertext.length} bytes)\n`);
        }
        process.stdout.write(
          `Distributed ${bundleId} to ${centreId}\n  bundle hash ${bundle.bundleHash}\n` +
            `The centre must verify this hash against the log before accepting.\n`,
        );
        return 0;
      } finally {
        await authority.close();
      }
    }

    case "schedule": {
      const authority = await openAuthority(args);
      try {
        const bundleId = req(args, "bundle");
        const releaseAt = new Date(req(args, "at")).getTime();
        if (!Number.isFinite(releaseAt)) throw new UsageError(`--at is not a valid date`);
        const bundle = authority.store.bundle(bundleId);
        if (!bundle) throw new UsageError(`unknown bundle ${bundleId}`);
        await authority.scheduleRelease({ examId: bundle.examId, bundleId, releaseAt });
        process.stdout.write(
          `Scheduled release of ${bundleId} at ${new Date(releaseAt).toISOString()}\n` +
            `Release before this instant will be refused and logged as an\n` +
            `EARLY_RELEASE_ATTEMPT. Editing the schedule in the database will\n` +
            `invalidate its signature and block release entirely.\n`,
        );
        return 0;
      } finally {
        await authority.close();
      }
    }

    case "issue-admit": {
      const authority = await openAuthority(args);
      try {
        const examId = req(args, "exam");
        const centreId = req(args, "centre");
        const roster = JSON.parse(await readFile(req(args, "roster"), "utf8")) as Array<{
          registrationId: string;
          seat: string;
        }>;
        const saltPath = opt(args, "salt");
        const salt = saltPath
          ? Buffer.from((await readFile(saltPath, "utf8")).trim(), "hex")
          : Authority.newRegistrationSalt();
        const expiresAt = new Date(
          opt(args, "expires") ?? Date.now() + 30 * 24 * 3600 * 1000,
        ).getTime();

        const tokens = await authority.issueAdmitTokens({
          examId,
          centreId,
          salt,
          expiresAt,
          candidates: roster,
        });
        const out = opt(args, "out") ?? `admit-${examId}-${centreId}.jsonl`;
        await writeFile(
          out,
          tokens
            .map((t, i) =>
              JSON.stringify({ seat: roster[i]!.seat, qr: encodeAdmitToken(t), token: t }),
            )
            .join("\n") + "\n",
        );
        if (!saltPath) {
          const sp = `${out}.salt`;
          await writeFile(sp, salt.toString("hex"));
          process.stdout.write(`Registration salt written to ${sp} — this file is\n` +
            `sensitive: it links token hashes back to registration ids. Store it\n` +
            `with the registration system, NOT with the exam evidence.\n`);
        }
        process.stdout.write(`Issued ${tokens.length} admit token(s) to ${out}\n`);
        return 0;
      } finally {
        await authority.close();
      }
    }

    case "release": {
      const authority = await openAuthority(args);
      try {
        const bundleId = req(args, "bundle");
        const offline = args.flags.get("offline") === true;
        const sharePaths = (opt(args, "shares") ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        if (sharePaths.length === 0) {
          throw new UsageError(
            "--shares is required: a comma-separated list of custodian share files",
          );
        }
        const shares = await Promise.all(
          sharePaths.map(async (p) => {
            const parsed = JSON.parse(await readFile(p, "utf8")) as {
              custodianId: string;
              shareHex: string;
            };
            return {
              custodianId: parsed.custodianId,
              shareBlob: Buffer.from(parsed.shareHex, "hex"),
            };
          }),
        );

        const { outcome, medium } = offline
          ? await authority.releaseOffline({ bundleId, shares })
          : { outcome: await authority.release({ bundleId, shares }), medium: null };

        process.stdout.write(
          `Released ${bundleId}\n` +
            `  centres            ${outcome.wrapped.length}\n` +
            `  custodians         ${outcome.custodians.join(", ")}\n` +
            `  plaintext KEK life ${outcome.kekLifetimeMs.toFixed(1)}ms (budget 500ms)\n`,
        );

        if (medium) {
          const out = opt(args, "out") ?? `release-${bundleId.replace(/[:]/g, "_")}.json`;
          await writeFile(out, JSON.stringify(medium, null, 2));
          process.stdout.write(
            `\nOffline medium written to ${out}\n` +
              `Carry this to each centre. The centre verifies its signature before\n` +
              `unwrapping; a substituted medium will not verify.\n`,
          );
        }
        return 0;
      } finally {
        await authority.close();
      }
    }

    case "verify-medium": {
      const authority = await openAuthority(args);
      try {
        const medium = JSON.parse(
          await readFile(req(args, "file"), "utf8"),
        ) as OfflineReleaseMedium;
        const ok = verifyOfflineMedium(medium, authority.publicKey);
        process.stdout.write(
          ok
            ? `VALID: medium for ${medium.bundleId} verifies against this authority key\n`
            : `INVALID: signature does not verify — do not use this medium\n`,
        );
        return ok ? 0 : 1;
      } finally {
        await authority.close();
      }
    }

    case "status": {
      const authority = await openAuthority(args);
      try {
        const centres = authority.store.centres();
        const custodians = authority.store.custodians();
        const bundles = authority.store.bundles();
        process.stdout.write(`Authority public key ${authority.publicKey.toString("hex")}\n`);
        process.stdout.write(`Log entries          ${authority.log.size()}\n\n`);
        process.stdout.write(`CUSTODIANS (${custodians.length})\n`);
        for (const c of custodians) process.stdout.write(`  ${c.custodianId.padEnd(16)} ${c.name}\n`);
        process.stdout.write(`\nCENTRES (${centres.length})\n`);
        for (const c of centres) {
          process.stdout.write(`  ${c.centreId.padEnd(16)} hw:${c.hardwareId}\n`);
        }
        process.stdout.write(`\nBUNDLES (${bundles.length})\n`);
        for (const b of bundles) {
          const sched = authority.store.schedule(b.bundleId);
          const when = sched ? new Date(sched.releaseAt).toISOString() : "unscheduled";
          process.stdout.write(
            `  ${b.bundleId.padEnd(24)} ${b.kind.padEnd(8)} ${b.threshold}-of-${b.shareCount}  ${when}\n`,
          );
        }
        return 0;
      } finally {
        await authority.close();
      }
    }

    case "checkpoint": {
      const authority = await openAuthority(args);
      try {
        await authority.checkpoint();
        process.stdout.write(`Checkpoint created at size ${authority.log.size()}\n`);
        return 0;
      } finally {
        await authority.close();
      }
    }

    default:
      process.stderr.write(`unknown command '${cmd}'\n\n${USAGE}`);
      return 1;
  }
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    if (err instanceof UsageError) {
      process.stderr.write(`${err.message}\n\nRun 'zw-authority help' for usage.\n`);
      process.exit(1);
    }
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  });
