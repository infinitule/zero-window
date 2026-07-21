#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import {
  parseEvidence,
  Rfc3161AnchorBackend,
  PUBLIC_TSAS,
  type AnchorBackend,
  type EvidenceBundle,
} from "@zw/log";
import type { PaperBundleContent } from "@zw/authority";
import { audit, type AuditInput } from "./audit.js";
import { renderReport, signReport, verifyReport, type SignedAuditReport } from "./report.js";

/**
 * zw-verify — the independent auditor CLI.
 *
 * Run from a separate install, against evidence files alone. Nothing here
 * connects to any ZERO-WINDOW service: the inputs are files the auditor was
 * handed, plus (optionally) the public TSAs for anchor re-verification.
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

function opt(args: Args, name: string): string | undefined {
  const v = args.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

function req(args: Args, name: string): string {
  const v = opt(args, name);
  if (!v) throw new UsageError(`missing required flag --${name}`);
  return v;
}

const USAGE = `zw-verify — ZERO-WINDOW independent auditor

USAGE
  zw-verify audit [flags]      Full audit of an exam's evidence
  zw-verify report --file <signed-report.json>   Verify + display a report

AUDIT FLAGS
  --authority <file>        Authority evidence bundle (.jsonl)         [required]
  --centres <f1,f2,...>     Centre evidence bundles                    [required]
  --signers <file>          Out-of-band trusted signer keys JSON
                            {actor: hexEd25519} — WITHOUT this, signer
                            trust rests on the bundles themselves
  --paper-content <file>    Post-exam disclosure of the paper bundle
                            plaintext, enables byte-identical paper
                            re-derivation (T4)
  --tsa <names>             Anchor verification backends, comma-separated
                            (freetsa,digicert,sectigo). Default: all.
  --no-anchors              Skip TSA anchor verification
  --max-papers <n>          Cap papers to re-render (default: all)
  --out <file>              Write the signed report JSON here
                            (default audit-report.json)

The process exits 0 only when the overall verdict is PASS.
`;

async function loadEvidence(path: string): Promise<EvidenceBundle> {
  return parseEvidence(await readFile(path, "utf8"));
}

async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  const cmd = args._[0];
  if (!cmd || args.flags.has("help") || cmd === "help") {
    process.stdout.write(USAGE);
    return cmd ? 0 : 1;
  }

  switch (cmd) {
    case "audit": {
      const authority = await loadEvidence(req(args, "authority"));
      const centres = await Promise.all(
        req(args, "centres")
          .split(",")
          .map((f) => loadEvidence(f.trim())),
      );

      let anchorBackends: AnchorBackend[] | undefined;
      if (args.flags.get("no-anchors") !== true) {
        const names = (opt(args, "tsa") ?? Object.keys(PUBLIC_TSAS)).toString().split(",");
        anchorBackends = names
          .map((n) => n.trim())
          .filter((n) => n.length > 0)
          .map((n) => {
            const cfg = PUBLIC_TSAS[n];
            if (!cfg) throw new UsageError(`unknown TSA "${n}" (known: ${Object.keys(PUBLIC_TSAS).join(", ")})`);
            return new Rfc3161AnchorBackend(cfg);
          });
      }

      const input: AuditInput = {
        authority,
        centres,
        ...(anchorBackends ? { anchorBackends } : {}),
      };
      const signersPath = opt(args, "signers");
      if (signersPath) {
        input.trustedSigners = JSON.parse(await readFile(signersPath, "utf8")) as Record<
          string,
          string
        >;
      }
      const contentPath = opt(args, "paper-content");
      if (contentPath) {
        input.paperContent = JSON.parse(await readFile(contentPath, "utf8")) as PaperBundleContent;
      }
      const maxPapers = opt(args, "max-papers");
      if (maxPapers) input.maxPapersToRederive = Number(maxPapers);

      const body = await audit(input);
      const signed = signReport(body);
      const out = opt(args, "out") ?? "audit-report.json";
      await writeFile(out, JSON.stringify(signed, null, 2));
      process.stdout.write(renderReport(signed));
      process.stdout.write(`\nSigned report written to ${out}\n`);
      return body.overall === "PASS" ? 0 : 2;
    }

    case "report": {
      const signed = JSON.parse(await readFile(req(args, "file"), "utf8")) as SignedAuditReport;
      const ok = verifyReport(signed);
      process.stdout.write(renderReport(signed));
      process.stdout.write(ok ? "report signature: VALID\n" : "report signature: INVALID — do not rely on this report\n");
      return ok ? 0 : 1;
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
      process.stderr.write(`${err.message}\n\nRun 'zw-verify help' for usage.\n`);
      process.exit(1);
    }
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  });
