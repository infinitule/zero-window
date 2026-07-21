#!/usr/bin/env node
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { VaultKeyProvider } from "@zw/kms-vault";
import { Logger } from "@zw/ops";
import type { OfflineReleaseMedium } from "@zw/authority";
import { CentreNode, CentreError } from "./centre.js";
import type { PrinterTarget } from "./print.js";

/**
 * zw-centre — centre-node operator CLI.
 *
 * Exam-day commands are deliberately offline-safe: nothing here reaches the
 * authority. Bundle and key material arrive as files (over mTLS sync in the
 * daemon, or on signed media via `receive-medium` when the network is out).
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

class UsageError extends Error {}

function req(args: Args, name: string): string {
  const v = args.flags.get(name);
  if (typeof v !== "string" || v.length === 0) throw new UsageError(`missing required flag --${name}`);
  return v;
}

function opt(args: Args, name: string): string | undefined {
  const v = args.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

const USAGE = `zw-centre — ZERO-WINDOW centre node operations

USAGE
  zw-centre <command> [flags]

COMMANDS
  identity         Print this centre's box public key (for enrolment)
  receive-bundle   Take custody of a ciphertext bundle (verifies hash first)
  receive-medium   Accept a signed offline release medium (T-0 fallback)
  check-in         Verify an admit token QR payload and bind the seat
  run-t0           Generate and print papers for all checked-in candidates
  status           Custody, check-ins and paper state
  close-exam       Log EXAM_CLOSED and discard keys
  checkpoint       Create a signed Merkle checkpoint of the centre log

COMMON FLAGS
  --dir <path>       Centre state directory (default ./centre-state)
  --centre <id>      Centre id (required for most commands)
  --exam <id>        Exam id (required for most commands)
  --authority-key <hex|file>  Authority Ed25519 public key
  --printers <list>  Comma-separated id=url pairs (IPP endpoints)
  --spool-dir <path> Spool fallback directory
`;

async function readAuthorityKey(args: Args): Promise<Buffer> {
  const raw = req(args, "authority-key");
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, "hex");
  return Buffer.from((await readFile(raw, "utf8")).trim(), "hex");
}

function parsePrinters(args: Args): PrinterTarget[] {
  const raw = opt(args, "printers");
  if (!raw) return [];
  return raw.split(",").map((pair) => {
    const eq = pair.indexOf("=");
    if (eq === -1) throw new UsageError(`--printers entries must be id=url, got "${pair}"`);
    return { printerId: pair.slice(0, eq), url: pair.slice(eq + 1) };
  });
}

async function openCentre(args: Args): Promise<CentreNode> {
  const dir = resolve(opt(args, "dir") ?? "./centre-state");
  await mkdir(dir, { recursive: true });
  const passphrase = opt(args, "passphrase") ?? process.env["ZW_VAULT_PASSPHRASE"];
  const provider = await VaultKeyProvider.open({
    keystorePath: join(dir, "keystore.json"),
    ...(passphrase ? { passphrase: Buffer.from(passphrase, "utf8") } : {}),
  });
  const spoolDir = opt(args, "spool-dir");
  return CentreNode.open({
    centreId: req(args, "centre"),
    examId: req(args, "exam"),
    statePath: join(dir, "centre.db"),
    logPath: join(dir, "log.db"),
    provider,
    authorityPublicKey: await readAuthorityKey(args),
    printers: parsePrinters(args),
    ...(spoolDir ? { spoolDir } : {}),
    logger: new Logger({ service: "zw-centre", level: "warn" }),
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
    case "identity": {
      const dir = resolve(opt(args, "dir") ?? "./centre-state");
      await mkdir(dir, { recursive: true });
      const passphrase = opt(args, "passphrase") ?? process.env["ZW_VAULT_PASSPHRASE"];
      const provider = await VaultKeyProvider.open({
        keystorePath: join(dir, "keystore.json"),
        ...(passphrase ? { passphrase: Buffer.from(passphrase, "utf8") } : {}),
      });
      try {
        const pub = await provider.ensureBoxKey("centre-box");
        process.stdout.write(`${pub.toString("hex")}\n`);
        return 0;
      } finally {
        await provider.close();
      }
    }

    case "receive-bundle": {
      const centre = await openCentre(args);
      try {
        const envelope = await readFile(req(args, "file"));
        await centre.receiveBundle(envelope, {
          bundleId: req(args, "bundle"),
          examId: req(args, "exam"),
          kind: (opt(args, "kind") ?? "paper") as "paper" | "answers",
          bundleHash: req(args, "bundle-hash"),
          kekFingerprint: req(args, "kek-fingerprint"),
          threshold: Number(opt(args, "threshold") ?? 3),
        });
        process.stdout.write(
          `Custody accepted for ${req(args, "bundle")} (${envelope.length} bytes)\n` +
            `Hash verified against the distribution statement before storage.\n`,
        );
        return 0;
      } finally {
        await centre.close();
      }
    }

    case "receive-medium": {
      const centre = await openCentre(args);
      try {
        const medium = JSON.parse(
          await readFile(req(args, "file"), "utf8"),
        ) as OfflineReleaseMedium;
        await centre.receiveOfflineMedium(medium);
        process.stdout.write(
          `KEK accepted from offline medium for ${medium.bundleId}\n` +
            `This centre can now generate papers. The authority link is not needed.\n`,
        );
        return 0;
      } finally {
        await centre.close();
      }
    }

    case "check-in": {
      const centre = await openCentre(args);
      try {
        const qrFile = opt(args, "qr-file");
        const payloads: string[] = [];
        if (qrFile) {
          for (const line of (await readFile(qrFile, "utf8")).split("\n")) {
            const t = line.trim();
            if (t.length > 0) payloads.push(t);
          }
        } else if (opt(args, "qr")) {
          payloads.push(req(args, "qr"));
        } else {
          // Interactive: one QR payload per line on stdin (scanner-friendly).
          const rl = createInterface({ input: process.stdin });
          for await (const line of rl) {
            const t = line.trim();
            if (t.length > 0) payloads.push(t);
          }
        }
        let ok = 0;
        for (const p of payloads) {
          try {
            const r = await centre.checkIn(p);
            process.stdout.write(`CHECKED IN seat ${r.seat}\n`);
            ok++;
          } catch (err) {
            process.stdout.write(`REFUSED: ${(err as Error).message}\n`);
          }
        }
        process.stdout.write(`${ok}/${payloads.length} candidates checked in\n`);
        return ok === payloads.length ? 0 : 1;
      } finally {
        await centre.close();
      }
    }

    case "run-t0": {
      const centre = await openCentre(args);
      try {
        const { printed, failures } = await centre.runT0();
        process.stdout.write(`Printed ${printed} paper(s)\n`);
        for (const f of failures) process.stdout.write(`FAILED ${f.seat}: ${f.error}\n`);
        if (failures.length > 0) {
          process.stdout.write(
            `\n${failures.length} seat(s) failed. Consult runbooks/exam-day.md §printer-failure.\n`,
          );
        }
        return failures.length === 0 ? 0 : 1;
      } finally {
        await centre.close();
      }
    }

    case "status": {
      const centre = await openCentre(args);
      try {
        const bundle = centre.store.bundle(centre.paperBundleId());
        const checkins = centre.store.checkins();
        const papers = centre.store.papers();
        process.stdout.write(`Centre box key   ${centre.boxPublicKey.toString("hex")}\n`);
        process.stdout.write(
          `Bundle           ${bundle ? `${bundle.bundleId} (${bundle.ciphertext.length} bytes ciphertext)` : "none"}\n`,
        );
        process.stdout.write(`Check-ins        ${checkins.length}\n`);
        process.stdout.write(
          `Papers           ${papers.length} generated, ${papers.filter((p) => p.printedAt !== null).length} printed\n`,
        );
        process.stdout.write(`Log entries      ${centre.log.size()}\n`);
        return 0;
      } finally {
        await centre.close();
      }
    }

    case "close-exam": {
      const centre = await openCentre(args);
      try {
        await centre.closeExam();
        await centre.checkpoint();
        process.stdout.write(`Exam closed and checkpointed. Keys discarded from memory.\n`);
        return 0;
      } finally {
        await centre.close();
      }
    }

    case "checkpoint": {
      const centre = await openCentre(args);
      try {
        await centre.checkpoint();
        process.stdout.write(`Checkpoint created at size ${centre.log.size()}\n`);
        return 0;
      } finally {
        await centre.close();
      }
    }

    case "export-evidence": {
      const centre = await openCentre(args);
      try {
        const out = opt(args, "out") ?? "./evidence";
        await mkdir(out, { recursive: true });
        const { serializeEvidence } = await import("@zw/log");
        const bundle = centre.log.evidence(req(args, "exam"));
        const path = join(out, `centre-${req(args, "centre")}.evidence.jsonl`);
        await writeFile(path, serializeEvidence(bundle));
        process.stdout.write(`Evidence exported to ${path}\n`);
        return 0;
      } finally {
        await centre.close();
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
      process.stderr.write(`${err.message}\n\nRun 'zw-centre help' for usage.\n`);
      process.exit(1);
    }
    if (err instanceof CentreError) {
      process.stderr.write(`${err.code}: ${err.message}\n`);
      process.exit(1);
    }
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  });
