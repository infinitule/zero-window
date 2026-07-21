# ZERO-WINDOW

Chain-of-custody platform for high-stakes paper examinations.

Exam papers leak in the window between creation and exam start, from inside
the custody chain. ZERO-WINDOW closes that window structurally rather than
procedurally:

1. **Question banks exist outside the authority vault only as ciphertext.**
2. **Decryption requires a 3-of-5 threshold ceremony** — no single person or
   machine can decrypt early, including whoever operates the system.
3. **Every candidate gets a different paper**, deterministically generated and
   printed at the centre at T-0. A leaked artifact identifies its source seat.
4. **Every custody event is committed to an append-only transparency log**
   whose Merkle roots are anchored to independently operated RFC 3161
   timestamping services. Anyone — including a hostile auditor — can verify
   the chain without trusting the operator.

---

## Quick start

Requires Node 20+ and pnpm 9.

```bash
pnpm install && pnpm build && pnpm test
pnpm pilot                    # full acceptance rehearsal, ~30s
pnpm pilot --offline          # same, without live TSA anchoring
```

`pnpm pilot` runs three centres × 100 candidates through the complete flow
with real components: real internal CA and TLS 1.3 mutual authentication,
real 3-of-5 Shamir ceremony, real IPP printing with a deliberate printer
failure, real anchoring to FreeTSA and DigiCert, and a full independent audit
at the end. It exits non-zero if any acceptance criterion fails.

---

## Acceptance run

Output of `pnpm pilot --candidates 100` on a clean checkout:

```
════════════════════════════════════════════════════════════════════════
ZERO-WINDOW PILOT REHEARSAL — acceptance run
3 centres × 100 candidates, 3-of-5 threshold, live TSA anchoring
════════════════════════════════════════════════════════════════════════
[   0.0s] CA initialized — offline root + online issuing intermediate, ECDSA P-384
[   0.1s] issued 4 certificates — server + one hardware-bound client per centre
[   0.5s] enrolled 5 custodians — threshold 3
[   2.0s] 3 centre nodes online — each with a primary and a backup IPP printer
[   2.0s] bank ingested: 180 items — paper KEK 891701e1f1f48b14…, answers KEK bf04c22981cc9525…
[   2.1s] authority listening on mTLS :51770 — TLS 1.3, client certs required
[   2.2s] ciphertext bundles transferred over mTLS — each centre verified the hash before storing
[   2.2s] 300 admit tokens issued — Ed25519, salted registration hashes, no PII
[   2.3s] early release REFUSED and logged — EARLY_RELEASE_ATTEMPT recorded with custodian ids
[   2.3s] KEK released to 3 centres — plaintext KEK lifetime 0.57ms (budget 500ms)
[   2.3s] all centres picked up wrapped KEKs over mTLS
[   2.3s] authority HTTP service STOPPED — centres are now fully autonomous
[   4.6s] CENTRE-B: PRIMARY PRINTER KILLED mid-run — after 50 papers
[  28.3s] authority: anchored to freetsa.org, digicert
[  30.2s] CENTRE-C: anchored to freetsa.org, digicert
```

The signed audit report produced by that run:

```
========================================================================
ZERO-WINDOW AUDIT REPORT — EXAM-2026-PILOT
overall: ATTENTION
========================================================================

LOGS
  authority               20 entries    1 checkpoints    2 anchors verified  OK
  centre-CENTRE-A        303 entries    1 checkpoints    2 anchors verified  OK
  centre-CENTRE-B        353 entries    1 checkpoints    2 anchors verified  OK
  centre-CENTRE-C        303 entries    1 checkpoints    2 anchors verified  OK

THREAT MODEL
  T1   PASS           Authority insider exfiltrates plaintext pre-T0
         · 2 bundle(s) committed at creation with 2 distinct KEK fingerprint(s)
         · plaintext-KEK lifetime at release: EXAM-2026-PILOT:paper=0.57ms
         · note: memory-handling guarantees (zeroization, no plaintext at rest)
           are enforced by the codebase's acceptance tests, which this auditor
           cannot re-run against the past; the log shows the commitments and
           timings that regime produces
  T2   ATTENTION      Centre decrypts early
         · EXAM-2026-PILOT:paper: released 1001ms after its scheduled T-0
         · REFUSED early release attempt on EXAM-2026-PILOT:paper (3599998ms
           before T-0, custodians: ["custodian-1","custodian-2","custodian-3"])
           — the schedule check held
  T3   PASS           Bundle tampering in transit or storage
         · EXAM-2026-PILOT:paper→CENTRE-A: distributed and received hashes agree
         · EXAM-2026-PILOT:paper→CENTRE-B: distributed and received hashes agree
         · EXAM-2026-PILOT:paper→CENTRE-C: distributed and received hashes agree
  T4   PASS           In-hall leak traceability (deterministic papers)
         · disclosed paper content matches the hash committed at provisioning
         · 12 paper(s) re-derived from log data byte-identically; all hashes unique
  T5   PASS           Fabricated early-leak evidence / backdating
         · [authority] final checkpoint anchored by: freetsa.org, digicert
         · [centre-CENTRE-A] final checkpoint anchored by: freetsa.org, digicert
         · [centre-CENTRE-B] final checkpoint anchored by: freetsa.org, digicert
         · [centre-CENTRE-C] final checkpoint anchored by: freetsa.org, digicert
  T6   PASS           Operator rewrites history
         · all 4 log(s) verified: hash chain intact, signatures valid,
           checkpoints consistent
         · signer keys checked against the auditor's out-of-band list
  T7   PASS           Impersonation
         · [centre-CENTRE-A] 100 paper(s) bound token→seat→paper_hash
         · [centre-CENTRE-B] 100 paper(s) bound token→seat→paper_hash
         · [centre-CENTRE-C] 100 paper(s) bound token→seat→paper_hash
  T8   PASS           Ledger as surveillance dataset
         · no PII-shaped field names in any log payload; identities appear
           only as salted hashes
  T9   PASS           Custodian collusion below threshold
         · EXAM-2026-PILOT:paper: 3 distinct enrolled custodians met threshold
           3; every approval logged before reconstruction
  T10  PASS           Denial of service at T-0
         · [centre CENTRE-B] printer centre-b-primary failed over: socket hang up  (×50)
         · 3/3 centre(s) reached EXAM_CLOSED; printed counts: 100, 100, 100

papers re-derived byte-identically: 12
report signature: 848620680eefe0393d7342511b5f3d01… (Ed25519, key da8bc307103eed79…)
========================================================================

  PASS  every candidate received a printed paper — 300/300
  PASS  every paper is unique — 300 distinct hashes
  PASS  plaintext KEK lifetime within budget — 0.57ms < 500ms
  PASS  early release was refused — EARLY_RELEASE_ATTEMPT logged
  PASS  printer failover exercised and recorded — 50 failover events
  PASS  no plaintext exam content at rest on centres — 0 leaks
  PASS  audit re-derived papers byte-identically — 12 papers
  PASS  no unexplained attention rows (T2 flags the rehearsed refusal, as it should)
  PASS  the auditor detected and reported the early-release attempt
  PASS  no fatal findings in any log — 0 fatal

PILOT PASSED in 30.2s — 10/10 acceptance criteria
```

**On the ATTENTION verdict.** The pilot deliberately attempts a release
before T-0 to exercise the control. The auditor refuses to bury that inside a
PASS, and it is right not to: somebody with valid custodian shares tried to
open the paper early. The acceptance criterion is therefore not "audit says
PASS" but "the only attention row is the rehearsed refusal, and the auditor
reported it" (DECISIONS.md D-41).

---

## Architecture

```
packages/
  crypto/        @zw/crypto     AEAD, BLAKE2b, Ed25519, Shamir GF(256), key-provider interface
  kms-pkcs11/    @zw/kms-pkcs11 PKCS#11 provider (SoftHSM2-tested; hardware documented)
  kms-vault/     @zw/kms-vault  encrypted file keystore + OS keyring
  log/           @zw/log        transparency log, Merkle checkpoints, multi-TSA RFC 3161
  ca/            @zw/ca         internal CA: issuance, rotation, revocation, mTLS
  ops/           @zw/ops        structured logging, metrics, health, graceful shutdown
  authority/     @zw/authority  ingestion, ceremony, admit tokens, threshold release
  centre/        @zw/centre     custody, check-in, deterministic papers, IPP printing
  verifier/      @zw/verifier   independent auditor CLI
deploy/          docker-compose pilot, Ansible, systemd units
runbooks/        key-ceremony, exam-day, incident-response, restore
```

### Critical flows

**F1 Provisioning** — ingest bank → validate against blueprint → split into
paper and answer-key bundles → encrypt each under its own fresh KEK inside
the key provider → Shamir-split 3-of-5 → seal each share to a custodian →
destroy the KEK → distribute ciphertext over mTLS. Logs `BUNDLE_CREATED`,
`SHARES_ISSUED`, `BUNDLE_DISTRIBUTED`.

**F2 Registration** — Ed25519-signed admit tokens binding a salted
registration hash to exam, centre and seat. Verified offline at the centre.

**F3 Threshold release** — at T-0, ≥3 custodians submit shares. The KEK is
reconstructed in locked memory, wrapped to each centre's public key, and
zeroized; total plaintext lifetime budgeted at 500 ms and measured (0.57 ms
in the pilot). Early attempts are refused, logged and alerted. An offline
path produces signed removable media for the network-down case.

**F4 Generation and printing** — the centre decrypts in memory, derives
`seed = BLAKE2b(examId ‖ centreId ‖ tokenHash)`, assembles per the blueprint,
renders a PDF with embedded fonts and fixed metadata, and prints via IPP with
completion polling and failover. Logs `PAPER_GENERATED` and `PAPER_PRINTED`.

**F5 Close and audit** — `EXAM_CLOSED` per centre, final checkpoint anchored
to both TSAs, answer keys released post-exam via the same threshold path,
`zw-verify audit` produces a signed report resolving every threat row.

---

## Verifying an exam as an auditor

The verifier needs evidence files and nothing else — no access to any
service, host or operator.

```bash
zw-verify audit \
  --authority authority.evidence.jsonl \
  --centres centre-a.evidence.jsonl,centre-b.evidence.jsonl,centre-c.evidence.jsonl \
  --signers signers.json \
  --paper-content paper-content.json \
  --tsa freetsa,digicert
```

`--signers` is the out-of-band list of public keys the auditor obtained at
enrolment. Without it the audit still runs but reports that signer trust
rests on the evidence's own claims. `--paper-content` is the post-exam
disclosure that enables byte-identical paper re-derivation; without it T4 is
reported NOT_EVALUATED rather than assumed to pass.

Exit codes: `0` PASS, `2` ATTENTION, `1` usage or I/O error.

---

## Documentation

| Document | Contents |
|---|---|
| [THREATS.md](THREATS.md) | Threat model with the test enforcing each row and residual risks |
| [SECURITY.md](SECURITY.md) | Cryptographic design, key hierarchy, invariants, reporting |
| [PRIVACY.md](PRIVACY.md) | What data exists where, DPIA outline, retention |
| [INTEGRATIONS.md](INTEGRATIONS.md) | What a deploying agency must provision: HSMs, TSAs, UIDAI |
| [DECISIONS.md](DECISIONS.md) | Every delegated design decision and its rationale |
| [ROADMAP.md](ROADMAP.md) | v1.1 plans |
| [runbooks/](runbooks/) | Key ceremony, exam day, incident response, restore |

---

## Engineering

- TypeScript, Node 20 LTS, strict mode, ESM, pnpm workspace.
- **356 tests** across nine packages. Coverage gates at 90% lines on the
  critical paths: crypto 94%, log 93%, authority 96% (release path 98%),
  centre 94%, verifier 94%.
- Named invariants in code (`I-KP-1`, `I-REL-2`, `I-GEN-3`, …) referenced from
  the tests that enforce them.
- No `any` in public signatures. Ambient typings for untyped native
  dependencies are hand-written and minimal.

```bash
pnpm build         # compile all packages
pnpm test          # unit, property, integration and drill tests
pnpm coverage      # with thresholds enforced
pnpm pilot         # end-to-end acceptance rehearsal
```

---

## Status

v1.0. All eight milestones complete. The pilot rehearsal passes 10/10
acceptance criteria with live TSA anchoring. Not yet run in a live
examination — see INTEGRATIONS.md for what a deploying agency must provision
first, and ROADMAP.md for what v1.1 adds.
