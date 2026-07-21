# Threat model

Each row states the threat, what structurally prevents it, and where that is
enforced by a test. Where a guarantee cannot be established by evidence
alone, the residual risk is stated rather than implied.

The audit CLI (`zw-verify audit`) resolves every row to PASS / ATTENTION /
NOT_EVALUATED against a real evidence set; see README for the pilot report.

---

## T1 — Authority insider exfiltrates plaintext before T-0

**Enforced by.** The item bank is encrypted at ingestion inside the vault
boundary. The KEK is generated inside the key provider, used once, split
3-of-5 and destroyed in adjacent calls — `provisionExam` never holds it
across an await that could be interrupted. Paper and answer-key bundles use
distinct KEKs. On the release path the reconstructed KEK lives in
`sodium_malloc` (mlocked, guarded) pages and is zeroized in a `finally`, on
the failure path too.

**Tests.**
- `packages/authority/test/provision.test.ts` — acceptance scan reads every
  byte the authority writes to disk and asserts no question body or option
  appears; asserts the stored bundle parses as a well-formed AEAD envelope.
- `packages/crypto/test/kek-engine.test.ts` — the KEK is unusable after
  `splitAndDestroyKek`.
- `packages/authority/test/release.test.ts` — plaintext-KEK lifetime measured
  and under budget with 20 recipients.

**Residual risk.** An attacker with kernel-level access to the authority host
*during the release call* could read the KEK from locked memory in that
window (measured: 0.57 ms in the pilot). No log can prove memory was
zeroized, so the audit reports this boundary explicitly rather than claiming
PASS on it. Mitigations are operational: hardened units, minimal host,
attended release window (see SECURITY.md).

---

## T2 — A centre decrypts early

**Enforced by.** Centres hold ciphertext only; the KEK arrives wrapped to the
centre's X25519 key and only after a threshold release. The release service
verifies the **signed** schedule on every attempt (I-REL-1), so editing the
schedule row in SQLite invalidates its signature and blocks release rather
than moving T-0. Early attempts are logged as `EARLY_RELEASE_ATTEMPT` and
counted before the refusal is thrown (I-REL-3).

**Tests.**
- `release.test.ts` — release before T-0 refused, event logged with custodian
  ids, no wrapped key stored, metric incremented.
- `release.test.ts` — a schedule modified directly in the store yields
  `SCHEDULE_TAMPERED`.
- `packages/centre/test/centre-flow.test.ts` — generation with the bundle in
  custody but no KEK fails `KEK_NOT_HELD`.
- Audit T2 cross-checks every `KEK_RELEASED` against its `RELEASE_SCHEDULED`.

---

## T3 — Bundle tampering in transit or storage

**Enforced by.** AEAD (XChaCha20-Poly1305) with associated data binding the
ciphertext to `{bundleId, kind, examId}`. The envelope hash is committed to
the log at distribution; the centre recomputes it **before** storing and
refuses on mismatch.

**Tests.**
- `centre-flow.test.ts` — a single flipped byte yields
  `BUNDLE_HASH_MISMATCH`.
- `packages/crypto/test/kat.test.ts` — AEAD rejects modified ciphertext and
  modified associated data.
- Audit T3 compares the authority's `BUNDLE_DISTRIBUTED` hash against each
  centre's independently written `BUNDLE_RECEIVED`.

---

## T4 — In-hall leak (a photographed paper)

**Enforced by.** Every candidate receives a different paper, deterministically
derived from `seed = BLAKE2b(examId ‖ centreId ‖ tokenHash)`. The printed QR
carries `{exam, centre, seat, content-hash prefix}`; page footers carry
`Page n of N` plus a hash chain across pages. `PAPER_GENERATED` binds seat →
paper hash. Given the post-exam disclosure, an auditor re-derives any
candidate's paper **byte-for-byte** and compares.

**Tests.**
- `packages/centre/test/determinism.test.ts` — byte-identical across repeated
  renders and across an independent re-derivation; independent of item
  storage order; 30 candidates produce 30 distinct papers.
- `packages/verifier/test/audit.test.ts` — a forged `paper_hash` fails
  re-derivation and is reported.
- Pilot: 300 candidates, 300 distinct paper hashes.

**Residual risk.** Determinism traces an artifact to a seat; it does not stop
a photograph being taken. The deterrent is attribution, and it works only if
the artifact retains the QR or a footer.

---

## T5 — Fabricated "early leak" evidence / backdating

**Enforced by.** Merkle checkpoints over the log, anchored via RFC 3161 to at
least two independently operated TSAs. The signed tokens are stored in the
evidence and re-verified by the auditor, who binds each token to the
checkpoint root it claims to cover.

**Tests.**
- `packages/log` tamper suite — TSA token substitution, checkpoint forgery,
  root mismatch all fail closed with diagnostics.
- Pilot: 8 live tokens from freetsa.org and DigiCert, re-verified by the
  auditor from evidence files alone.

**Residual risk.** Anchoring bounds timestamps from *below* (a root cannot be
older than its token). It cannot prove content was never disclosed by other
means, and it depends on the TSAs' own key security.

---

## T6 — The operator rewrites history

**Enforced by.** Hash-chained entries, each signed; SQLite triggers reject
`UPDATE` and `DELETE` on the log tables, so even direct database access
breaks the chain visibly. Checkpoints are signed and anchored. The auditor
verifies against signer keys supplied **out-of-band**, so re-signing history
with a fresh key is detected.

**Tests.**
- `packages/log` tamper suite — bit-flip, drop, reorder, checkpoint forgery.
- `audit.test.ts` — an edited entry is fatal; a signer key not on the
  auditor's list is caught even though its signatures are valid.

**Residual risk.** Without an out-of-band signer list the auditor can only
check internal consistency; the report states this explicitly rather than
downgrading silently.

---

## T7 — Impersonation

**Enforced by.** Ed25519-signed admit tokens verified **offline** at the
centre against the authority key alone. Check-in binds token hash → seat and
refuses duplicate tokens and occupied seats. Verification returns a specific
failure code so an invigilator is told what is wrong.

**Tests.**
- `packages/authority/test/admit.test.ts` — altered seat, altered expiry,
  foreign signing key, wrong centre, wrong exam, expired, malformed, and
  unsupported version each refused with the right code.
- `centre-flow.test.ts` — duplicate check-in and seat collision refused.
- Audit T7 — a paper generated for a token that never checked in is caught.

**Residual risk.** The token proves the *card* is authentic, not that the
bearer is the registered candidate. Physical identity checking remains the
invigilator's job; the system deliberately holds no biometric or PII to do it
(see T8 and INTEGRATIONS.md on UIDAI).

---

## T8 — The ledger becomes a surveillance dataset

**Enforced by.** Log payloads carry hashes, timestamps, seat ids and counts —
never registration ids, names or contact details. Registration ids are hashed
under a **per-exam salt**, so the same candidate is unlinkable across exams.
The `@zw/ops` redactor strips secret-shaped fields from logs and metric
labels.

**Tests.**
- `admit.test.ts` — no registration id appears anywhere in the log.
- `audit.test.ts` — PII-shaped field names in payloads are reported.
- `packages/ops/test/ops.test.ts` — redaction of secrets, buffers, nested
  structures.

See PRIVACY.md for the DPIA outline.

---

## T9 — Custodian collusion below threshold

**Enforced by.** Shamir 3-of-5 over GF(2⁸) with fresh CSPRNG coefficients per
byte; any 2 shares are information-theoretically independent of the KEK. Each
share is sealed to a custodian's personal key. Issuance is logged with the
hash of each sealed envelope. Duplicate submissions from one custodian are
refused.

**Tests.**
- `packages/crypto/test/shamir.test.ts` — every 3-subset of 5 reconstructs;
  2 shares fail closed; chi-square test on marginal share-byte distribution
  for maximally different secrets.
- `release.test.ts` — below threshold refused; one custodian submitting three
  times refused.
- Audit T9 — sub-threshold approvals and approvals from custodians never
  issued a share are both caught.

**Residual risk.** Three colluding custodians *can* release early — that is
the definition of the threshold. The controls against it are the signed
schedule (the attempt is refused and logged) and the evidence trail naming
who tried.

---

## T10 — Denial of service at T-0

**Enforced by.** Centre autonomy: after key receipt no exam-day path touches
the network (I-CTR-2). Ordered printer failover with completion polling, and
a spool-to-PDF fallback. Offline release onto signed media. Cold-spare
restore. `Restart=always` on centre units.

**Tests.**
- `packages/centre/test/autonomy.test.ts` — the authority is killed after key
  receipt over real mTLS; the exam completes.
- `packages/centre/test/drills.test.ts` — printer failover, total print
  failure → spool, cold-spare restore, offline release with a substituted
  medium refused.
- Pilot: primary printer killed mid-run at one centre; all 300 candidates
  still received papers.

**Residual risk.** A centre that never received its bundle before T-0 cannot
run the exam. This is checked at T-90 in the exam-day runbook because there
is no recovery path for it at T-0.
