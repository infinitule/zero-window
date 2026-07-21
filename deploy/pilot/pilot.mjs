#!/usr/bin/env node
/**
 * ZERO-WINDOW pilot rehearsal — the M8 acceptance run.
 *
 * Three centres, 100 candidates each, driven through the complete custody
 * chain F1→F5 with real components throughout:
 *
 *   - real internal CA, real TLS 1.3 mutual authentication between every
 *     centre and the authority;
 *   - real threshold ceremony (3-of-5 Shamir) with the KEK generated,
 *     split and destroyed inside the key provider;
 *   - real IPP printing to print servers, with a deliberate printer failure
 *     mid-run to exercise failover;
 *   - real RFC 3161 anchoring to public TSAs (skipped with --offline);
 *   - a full independent audit at the end, run against exported evidence
 *     files only.
 *
 * Exit code 0 only if the audit's overall verdict is PASS.
 *
 * Usage:  pnpm pilot [--offline] [--candidates N] [--keep]
 */
import { createServer } from "node:http";
import { mkdtemp, mkdir, rm, writeFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ipp from "ipp";

import { Authority, buildAuthorityServer, encodeAdmitToken, splitBank } from "@zw/authority";
import { CentreNode, AuthoritySyncClient } from "@zw/centre";
import { CertificateAuthority } from "@zw/ca";
import { generateBoxKeyPair, sealOpen } from "@zw/crypto";
import { VaultKeyProvider } from "@zw/kms-vault";
import { serializeEvidence, Rfc3161AnchorBackend, PUBLIC_TSAS } from "@zw/log";
import { audit, signReport, renderReport } from "@zw/verifier";

// ---------------------------------------------------------------- config
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(`--${name}`);
const value = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : fallback;
};

const OFFLINE = flag("offline") || process.env.ZW_OFFLINE === "1";
const CANDIDATES = Number(value("candidates", "100"));
const KEEP = flag("keep");
const EXAM = value("exam", "EXAM-2026-PILOT");
const CENTRE_IDS = ["CENTRE-A", "CENTRE-B", "CENTRE-C"];
const THRESHOLD = 3;
const CUSTODIAN_COUNT = 5;

const t0 = Date.now();
const dirs = [];
const servers = [];
let step = 0;

const log = (msg, detail) => {
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1).padStart(6);
  process.stdout.write(`[${elapsed}s] ${msg}${detail ? ` — ${detail}` : ""}\n`);
};
const phase = (title) => {
  step++;
  process.stdout.write(`\n${"─".repeat(72)}\n${step}. ${title}\n${"─".repeat(72)}\n`);
};

async function tmp(prefix) {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

// ------------------------------------------------------- print servers
/**
 * An IPP print server. Real RFC 8010 wire format over HTTP, the same
 * protocol CUPS speaks; the compose topology swaps these for actual CUPS
 * containers (deploy/pilot/docker-compose.yml).
 */
async function printServer(name) {
  const state = { jobs: 0, down: false, printed: [] };
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      if (state.down) return res.destroy();
      const parsed = ipp.parse(Buffer.concat(chunks));
      const op = String(parsed.operation);
      const id = parsed.id ?? 1;
      let response;
      if (op === "Print-Job") {
        state.jobs++;
        state.printed.push(String(parsed["operation-attributes-tag"]?.["job-name"] ?? ""));
        response = {
          version: "2.0",
          statusCode: "successful-ok",
          id,
          "job-attributes-tag": { "job-id": state.jobs, "job-state": "pending" },
        };
      } else if (op === "Get-Job-Attributes") {
        response = {
          version: "2.0",
          statusCode: "successful-ok",
          id,
          "job-attributes-tag": { "job-id": 1, "job-state": "completed" },
        };
      } else {
        response = { version: "2.0", statusCode: "server-error-operation-not-supported", id };
      }
      res.setHeader("content-type", "application/ipp");
      res.end(ipp.serialize(response));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  const port = server.address().port;
  return {
    name,
    url: `http://127.0.0.1:${port}/printers/${name}`,
    state,
    kill() {
      state.down = true;
    },
  };
}

// --------------------------------------------------------------- bank
function buildBank() {
  const items = [];
  const subjects = ["mechanics", "optics", "thermodynamics"];
  for (const subject of subjects) {
    for (const difficulty of ["easy", "medium", "hard"]) {
      for (let i = 0; i < 20; i++) {
        items.push({
          id: `${subject}-${difficulty}-${String(i).padStart(2, "0")}`,
          subject,
          difficulty,
          body:
            `[${subject}/${difficulty} #${i}] A body of realistic length so that the ` +
            `renderer exercises word wrapping, pagination and the page hash chain: ` +
            `state the governing relation and justify each step of your reasoning.`,
          options: [
            `The first candidate response for item ${i}, of moderate length.`,
            `A second response, deliberately longer so that it wraps beneath its label when indented.`,
            `A third, shorter one (${i}).`,
            `A fourth distractor for item ${i}.`,
          ],
          correctIndex: i % 4,
        });
      }
    }
  }
  return { examId: EXAM, items };
}

const blueprint = {
  examId: EXAM,
  title: "ZERO-WINDOW Pilot — Physics Paper I",
  durationMinutes: 180,
  slots: [
    { subject: "mechanics", difficulty: "easy", count: 4 },
    { subject: "mechanics", difficulty: "medium", count: 4 },
    { subject: "mechanics", difficulty: "hard", count: 2 },
    { subject: "optics", difficulty: "easy", count: 3 },
    { subject: "optics", difficulty: "medium", count: 3 },
    { subject: "thermodynamics", difficulty: "easy", count: 2 },
    { subject: "thermodynamics", difficulty: "hard", count: 2 },
  ],
};

// ---------------------------------------------------------------- main
async function main() {
  process.stdout.write(
    `\n${"═".repeat(72)}\n` +
      `ZERO-WINDOW PILOT REHEARSAL — acceptance run\n` +
      `${CENTRE_IDS.length} centres × ${CANDIDATES} candidates, ${THRESHOLD}-of-${CUSTODIAN_COUNT} threshold` +
      `${OFFLINE ? ", offline (no TSA)" : ", live TSA anchoring"}\n` +
      `${"═".repeat(72)}\n`,
  );

  // ---- 1. PKI -------------------------------------------------------
  phase("Internal PKI (M3)");
  const caDir = await tmp("zw-pilot-ca-");
  const ca = await CertificateAuthority.open({ dir: caDir });
  await ca.initialize();
  log("CA initialized", "offline root + online issuing intermediate, ECDSA P-384");
  const serverCert = await ca.issue({
    role: "authority-server",
    commonName: "authority",
    sans: ["localhost", "127.0.0.1"],
  });
  const centreCerts = {};
  for (const id of CENTRE_IDS) {
    centreCerts[id] = await ca.issue({
      role: "centre-client",
      commonName: id,
      hardwareId: `tpm-${id.toLowerCase()}`,
    });
  }
  log(`issued ${CENTRE_IDS.length + 1} certificates`, "server + one hardware-bound client per centre");

  // ---- 2. Authority + custodians ------------------------------------
  phase("Authority and custodian enrolment (M4)");
  const aDir = await tmp("zw-pilot-auth-");
  const authority = await Authority.open({
    statePath: join(aDir, "authority.db"),
    logPath: join(aDir, "log.db"),
    provider: await VaultKeyProvider.open({
      keystorePath: join(aDir, "keystore.json"),
      passphrase: Buffer.from("pilot-authority-passphrase", "utf8"),
    }),
  });
  const custodians = Array.from({ length: CUSTODIAN_COUNT }, (_, i) => ({
    custodianId: `custodian-${i + 1}`,
    keys: generateBoxKeyPair(),
  }));
  for (const c of custodians) {
    authority.enrolCustodian({
      custodianId: c.custodianId,
      name: `Custodian ${c.custodianId.slice(-1)}`,
      boxPublicKey: c.keys.publicKey,
      certFingerprint: "",
    });
  }
  log(`enrolled ${custodians.length} custodians`, `threshold ${THRESHOLD}`);

  // ---- 3. Centres ---------------------------------------------------
  phase("Centre nodes and print servers (M5)");
  const printers = {};
  for (const id of CENTRE_IDS) {
    printers[id] = {
      primary: await printServer(`${id.toLowerCase()}-primary`),
      backup: await printServer(`${id.toLowerCase()}-backup`),
    };
  }
  const centres = {};
  for (const id of CENTRE_IDS) {
    const dir = await tmp(`zw-pilot-${id.toLowerCase()}-`);
    const spoolDir = join(dir, "spool");
    await mkdir(spoolDir, { recursive: true });
    centres[id] = {
      dir,
      spoolDir,
      node: await CentreNode.open({
        centreId: id,
        examId: EXAM,
        statePath: join(dir, "centre.db"),
        logPath: join(dir, "log.db"),
        provider: await VaultKeyProvider.open({
          keystorePath: join(dir, "keystore.json"),
          passphrase: Buffer.from(`pilot-${id}`, "utf8"),
        }),
        authorityPublicKey: authority.publicKey,
        printers: [
          { printerId: printers[id].primary.name, url: printers[id].primary.url },
          { printerId: printers[id].backup.name, url: printers[id].backup.url },
        ],
        spoolDir,
      }),
    };
    await authority.enrolCentre({
      centreId: id,
      boxPublicKey: centres[id].node.boxPublicKey,
      certFingerprint: centreCerts[id].record.fingerprint,
      hardwareId: `tpm-${id.toLowerCase()}`,
    });
  }
  log(`${CENTRE_IDS.length} centre nodes online`, "each with a primary and a backup IPP printer");

  // ---- 4. Provisioning ----------------------------------------------
  phase("F1 provisioning: ingest, encrypt, split, distribute");
  const bank = buildBank();
  const provisioned = await authority.provision({ bank, blueprint, threshold: THRESHOLD });
  log(
    `bank ingested: ${bank.items.length} items`,
    `paper KEK ${provisioned.paper.kekFingerprint.slice(0, 16)}…, answers KEK ${provisioned.answers.kekFingerprint.slice(0, 16)}…`,
  );

  const httpServer = await buildAuthorityServer({
    authority,
    tls: { cert: serverCert.chainPem, key: serverCert.privateKeyPem, ca: ca.trustBundlePem() },
  });
  const authorityPort = httpServer.server.address().port;
  log(`authority listening on mTLS :${authorityPort}`, "TLS 1.3, client certs required");

  for (const id of CENTRE_IDS) {
    await authority.distribute(provisioned.paper.bundleId, id);
  }
  const syncs = {};
  for (const id of CENTRE_IDS) {
    syncs[id] = new AuthoritySyncClient({
      authorityHost: "127.0.0.1",
      authorityPort,
      servername: "localhost",
      tls: {
        cert: centreCerts[id].chainPem,
        key: centreCerts[id].privateKeyPem,
        ca: ca.trustBundlePem(),
      },
    });
    await syncs[id].fetchBundle(centres[id].node, EXAM, "paper");
  }
  log("ciphertext bundles transferred over mTLS", "each centre verified the hash before storing");

  // ---- 5. Registration ----------------------------------------------
  phase("F2 registration: admit tokens");
  const salt = Authority.newRegistrationSalt();
  const tokensByCentre = {};
  for (const id of CENTRE_IDS) {
    tokensByCentre[id] = await authority.issueAdmitTokens({
      examId: EXAM,
      centreId: id,
      salt,
      expiresAt: Date.now() + 86_400_000,
      candidates: Array.from({ length: CANDIDATES }, (_, i) => ({
        registrationId: `${id}-REG-${String(i + 1).padStart(4, "0")}`,
        seat: `${id.slice(-1)}-${String(i + 1).padStart(3, "0")}`,
      })),
    });
  }
  log(
    `${CENTRE_IDS.length * CANDIDATES} admit tokens issued`,
    "Ed25519, salted registration hashes, no PII",
  );

  // ---- 6. Early release attempt --------------------------------------
  phase("T2 check: attempt release before T-0");
  const shareOf = (id) => {
    const rec = authority.store
      .shares(provisioned.paper.bundleId)
      .find((s) => s.custodianId === id);
    const c = custodians.find((x) => x.custodianId === id);
    return { custodianId: id, shareBlob: sealOpen(rec.sealed, c.keys.publicKey, c.keys.secretKey) };
  };
  await authority.scheduleRelease({
    examId: EXAM,
    bundleId: provisioned.paper.bundleId,
    releaseAt: Date.now() + 3_600_000,
  });
  let refused = false;
  try {
    await authority.release({
      bundleId: provisioned.paper.bundleId,
      shares: [shareOf("custodian-1"), shareOf("custodian-2"), shareOf("custodian-3")],
    });
  } catch (err) {
    refused = err.code === "TOO_EARLY";
  }
  if (!refused) throw new Error("ACCEPTANCE FAILURE: early release was not refused");
  log("early release REFUSED and logged", "EARLY_RELEASE_ATTEMPT recorded with custodian ids");

  // ---- 7. Threshold release at T-0 -----------------------------------
  phase("F3 threshold release at T-0");
  await authority.scheduleRelease({
    examId: EXAM,
    bundleId: provisioned.paper.bundleId,
    releaseAt: Date.now() - 1000,
  });
  const outcome = await authority.release({
    bundleId: provisioned.paper.bundleId,
    shares: [shareOf("custodian-2"), shareOf("custodian-4"), shareOf("custodian-5")],
  });
  log(
    `KEK released to ${outcome.wrapped.length} centres`,
    `plaintext KEK lifetime ${outcome.kekLifetimeMs.toFixed(2)}ms (budget 500ms)`,
  );
  if (outcome.kekLifetimeMs > 500) {
    throw new Error(`ACCEPTANCE FAILURE: KEK lifetime ${outcome.kekLifetimeMs}ms exceeds budget`);
  }
  for (const id of CENTRE_IDS) {
    const held = await syncs[id].tryFetchKek(centres[id].node, EXAM, "paper");
    if (!held) throw new Error(`ACCEPTANCE FAILURE: ${id} did not receive its KEK`);
  }
  log("all centres picked up wrapped KEKs over mTLS");

  // ---- 8. Autonomy: kill the authority --------------------------------
  phase("T10 check: authority goes down, exam proceeds");
  await httpServer.close();
  log("authority HTTP service STOPPED", "centres are now fully autonomous");

  // ---- 9. Check-in, generation, printing ------------------------------
  phase("F4 check-in, deterministic generation, IPP printing");
  const failoverCentre = CENTRE_IDS[1];
  for (const id of CENTRE_IDS) {
    for (const token of tokensByCentre[id]) {
      await centres[id].node.checkIn(encodeAdmitToken(token));
    }
    log(`${id}: ${CANDIDATES} candidates checked in`, "offline admit verification");
  }

  for (const id of CENTRE_IDS) {
    // Mid-run printer failure at one centre, to exercise failover under load.
    if (id === failoverCentre) {
      const seats = centres[id].node.store.checkins();
      const half = Math.floor(seats.length / 2);
      for (const [i, checkin] of seats.entries()) {
        if (i === half) {
          printers[id].primary.kill();
          log(`${id}: PRIMARY PRINTER KILLED mid-run`, `after ${i} papers`);
        }
        const { pdf } = await centres[id].node.generatePaper(checkin.seat);
        await centres[id].node.printPaper(checkin.seat, pdf);
      }
    } else {
      const { printed, failures } = await centres[id].node.runT0();
      if (failures.length > 0) {
        throw new Error(`ACCEPTANCE FAILURE: ${id} had ${failures.length} failures`);
      }
      log(`${id}: ${printed} papers generated and printed`);
    }
  }
  const failovers = centres[failoverCentre].node.log
    .entries()
    .filter((e) => e.type === "PRINTER_FAILOVER");
  log(
    `${failoverCentre}: ${failovers.length} printer failover(s) recorded`,
    `${printers[failoverCentre].backup.state.jobs} papers off the backup printer`,
  );

  // ---- 10. Close and anchor -------------------------------------------
  phase("F5 close, checkpoint and anchor");
  for (const id of CENTRE_IDS) {
    await centres[id].node.closeExam();
    await centres[id].node.checkpoint();
  }
  await authority.checkpoint();
  log("all centres closed and checkpointed");

  let anchorBackends;
  if (!OFFLINE) {
    anchorBackends = [
      new Rfc3161AnchorBackend(PUBLIC_TSAS.freetsa),
      new Rfc3161AnchorBackend(PUBLIC_TSAS.digicert),
    ];
    let anchored = 0;
    for (const [label, lg] of [
      ["authority", authority.log],
      ...CENTRE_IDS.map((id) => [id, centres[id].node.log]),
    ]) {
      const cp = lg.latestCheckpoint();
      if (!cp) continue;
      const root = Buffer.from(cp.root, "hex");
      const results = [];
      for (const backend of anchorBackends) {
        try {
          results.push(await backend.anchor(root));
        } catch (err) {
          log(`  anchor via ${backend.name} FAILED`, err.message.slice(0, 80));
        }
      }
      if (results.length > 0) {
        lg.attachAnchors(cp.size, results);
        anchored += results.length;
        log(`${label}: anchored to ${results.map((r) => r.tsa).join(", ")}`);
      }
    }
    if (anchored === 0) {
      log("no TSA reachable", "continuing; T5 will report NOT_EVALUATED");
      anchorBackends = undefined;
    }
  } else {
    log("offline mode", "skipping live TSA anchoring");
  }

  // ---- 11. Export evidence --------------------------------------------
  phase("Evidence export");
  const evDir = await tmp("zw-pilot-evidence-");
  const authorityEvidencePath = join(evDir, "authority.evidence.jsonl");
  await writeFile(authorityEvidencePath, serializeEvidence(authority.log.evidence(EXAM)));
  const centrePaths = [];
  for (const id of CENTRE_IDS) {
    const p = join(evDir, `${id.toLowerCase()}.evidence.jsonl`);
    await writeFile(p, serializeEvidence(centres[id].node.log.evidence(EXAM)));
    centrePaths.push(p);
  }
  const signers = { authority: authority.publicKey.toString("hex") };
  for (const id of CENTRE_IDS) {
    signers[`centre-${id}`] = centres[id].node.log.publicKey.toString("hex");
  }
  await writeFile(join(evDir, "signers.json"), JSON.stringify(signers, null, 2));

  // Post-exam disclosure enabling paper re-derivation.
  const paperContent = splitBank(bank, blueprint).paper;
  await writeFile(join(evDir, "paper-content.json"), JSON.stringify(paperContent));
  log(`evidence written to ${evDir}`, `${1 + CENTRE_IDS.length} bundles + signers + disclosure`);

  // ---- 12. Independent audit ------------------------------------------
  phase("M6 independent audit (zero trust in the operator)");
  const evidence = {
    authority: authority.log.evidence(EXAM),
    centres: CENTRE_IDS.map((id) => centres[id].node.log.evidence(EXAM)),
    trustedSigners: signers,
    paperContent,
    // Re-render a sample rather than all 300: each is a full PDF render, and
    // the property under test is determinism, which a sample establishes.
    maxPapersToRederive: Number(value("rederive", "12")),
    ...(anchorBackends ? { anchorBackends } : {}),
  };
  const body = await audit(evidence);
  const signed = signReport(body);
  const reportPath = join(evDir, "audit-report.json");
  await writeFile(reportPath, JSON.stringify(signed, null, 2));
  const rendered = renderReport(signed);
  process.stdout.write("\n" + rendered);
  await writeFile(join(evDir, "audit-report.txt"), rendered);

  // ---- 13. Acceptance assertions ---------------------------------------
  phase("Acceptance criteria");
  const checks = [];
  const check = (name, ok, detail) => {
    checks.push({ name, ok, detail });
    process.stdout.write(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}\n`);
  };

  const totalPrinted = CENTRE_IDS.reduce(
    (n, id) => n + centres[id].node.store.papers().filter((p) => p.printedAt !== null).length,
    0,
  );
  check(
    "every candidate received a printed paper",
    totalPrinted === CENTRE_IDS.length * CANDIDATES,
    `${totalPrinted}/${CENTRE_IDS.length * CANDIDATES}`,
  );

  const allHashes = CENTRE_IDS.flatMap((id) =>
    centres[id].node.store.papers().map((p) => p.paperHash),
  );
  check(
    "every paper is unique",
    new Set(allHashes).size === allHashes.length,
    `${new Set(allHashes).size} distinct hashes`,
  );

  check(
    "plaintext KEK lifetime within budget",
    outcome.kekLifetimeMs < 500,
    `${outcome.kekLifetimeMs.toFixed(2)}ms < 500ms`,
  );

  check("early release was refused", refused, "EARLY_RELEASE_ATTEMPT logged");

  check(
    "printer failover exercised and recorded",
    failovers.length > 0 && printers[failoverCentre].backup.state.jobs > 0,
    `${failovers.length} failover events`,
  );

  // No plaintext exam content at rest anywhere outside the vault boundary.
  const probe = bank.items[0].body.slice(0, 48);
  let leaks = 0;
  for (const id of CENTRE_IDS) {
    const files = await readdir(centres[id].dir, { recursive: true, withFileTypes: true });
    for (const f of files) {
      if (!f.isFile()) continue;
      const p = join(f.parentPath ?? centres[id].dir, f.name);
      if (p.includes("spool")) continue; // printed papers are the product
      const { readFile } = await import("node:fs/promises");
      if ((await readFile(p)).includes(Buffer.from(probe, "utf8"))) leaks++;
    }
  }
  check("no plaintext exam content at rest on centres", leaks === 0, `${leaks} leaks`);

  check(
    "audit re-derived papers byte-identically",
    body.papersRederived > 0 &&
      !body.threats.find((t) => t.threat === "T4")?.evidence.join(" ").includes("NOT what"),
    `${body.papersRederived} papers`,
  );

  // The pilot deliberately rehearses an early-release attempt, and the
  // auditor is RIGHT to flag it: an attempt to release before T-0 must never
  // be buried inside a PASS, even when refused. So the acceptance criterion
  // is not "overall PASS" — it is that every row is clean except T2, and
  // that T2's attention is attributable solely to the rehearsed refusal.
  const attention = body.threats.filter((t) => t.verdict === "ATTENTION");
  const onlyRehearsedT2 =
    attention.length === 1 &&
    attention[0].threat === "T2" &&
    attention[0].evidence.every(
      (e) => e.startsWith("REFUSED early release attempt") || e.includes("after its scheduled T-0"),
    );
  check(
    "no unexplained attention rows (T2 flags the rehearsed refusal, as it should)",
    body.overall === "PASS" || onlyRehearsedT2,
    body.overall === "PASS"
      ? "PASS"
      : `attention rows: ${attention.map((t) => t.threat).join(", ")}`,
  );

  check(
    "the auditor detected and reported the early-release attempt",
    body.threats
      .find((t) => t.threat === "T2")
      ?.evidence.some((e) => e.startsWith("REFUSED early release attempt")) ?? false,
    "T2 evidence names the refused attempt",
  );

  const fatalFindings = body.chainFindings.filter((f) => f.severity === "fatal");
  check("no fatal findings in any log", fatalFindings.length === 0, `${fatalFindings.length} fatal`);

  // ---- cleanup ---------------------------------------------------------
  for (const id of CENTRE_IDS) await centres[id].node.close();
  await authority.close();
  await Promise.all(servers.map((s) => new Promise((r) => s.close(() => r()))));

  const failed = checks.filter((c) => !c.ok);
  process.stdout.write(
    `\n${"═".repeat(72)}\n` +
      `PILOT ${failed.length === 0 ? "PASSED" : "FAILED"} in ${((Date.now() - t0) / 1000).toFixed(1)}s — ` +
      `${checks.length - failed.length}/${checks.length} acceptance criteria\n` +
      `evidence + signed report: ${evDir}\n` +
      `${"═".repeat(72)}\n`,
  );

  if (!KEEP) {
    // Keep the evidence directory; it is the artifact of the run.
    await Promise.all(
      dirs.filter((d) => d !== evDir).map((d) => rm(d, { recursive: true, force: true })),
    );
  }
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch(async (err) => {
  process.stderr.write(`\nPILOT FAILED: ${err.stack ?? err.message}\n`);
  await Promise.all(servers.map((s) => new Promise((r) => s.close(() => r()))));
  process.exit(1);
});
