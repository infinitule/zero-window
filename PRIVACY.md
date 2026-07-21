# Privacy

The transparency log is designed to be published, or at least handed to
adversarial auditors. That is only safe if it contains nothing worth
surveilling. This document states exactly what data exists, where, and for
how long.

---

## Data inventory

### In the transparency log (published to auditors)

| Field | Example | Why it is safe |
|---|---|---|
| Event type, sequence, timestamp | `PAPER_GENERATED`, seq 142 | Operational metadata |
| Exam and centre ids | `EXAM-2026-PHYS`, `CENTRE-A` | Institutional, not personal |
| Seat id | `A-014` | Identifies a chair, not a person, without the registration system |
| Admit token hash | 32 bytes | BLAKE2b over the token body; token contains a **salted** registration hash |
| Registration hash (inside a token) | 32 bytes | `BLAKE2b(per-exam salt ‖ registrationId)` |
| Bundle, paper, content hashes | 32 bytes | Content commitments |
| KEK fingerprints | 32 bytes | Commitment to a key, not the key |
| Custodian ids | `custodian-3` | Role identifiers, assigned by the agency |
| Counts, durations, printer ids | `100`, `570 µs` | Operational |

**Not in the log, ever:** registration ids, candidate names, addresses,
phone numbers, email, dates of birth, biometrics, photographs, marks, or
answer scripts.

### In centre state (local, not published)

Check-in records (token hash → seat → salted registration hash), paper
hashes, printed status. Deleted with the state directory at retention end.

### In authority state (local, not published)

Enrolment records, ciphertext bundles, sealed shares, schedules, admit-token
hashes. **The per-exam salt is not stored here** — it is written alongside
the roster at issuance and belongs with the registration system.

### Outside this system entirely

Candidate identities, contact details, registration records, marks. These
live in the agency's registration and results systems. ZERO-WINDOW never
receives them.

---

## Why the salt matters

Registration ids in national examinations are structured and low-entropy —
often a year, a centre code and a sequence number. An unsalted hash of such
an id is trivially reversed by enumeration.

The per-exam salt makes this infeasible **and** makes the same candidate
unlinkable across exams: `H(salt_A ‖ id) ≠ H(salt_B ‖ id)`. An adversary
holding two exams' evidence cannot build a longitudinal profile of a
candidate.

The salt is held by the registration system and the authority operator at
issuance time. It is never written to the log. Re-identification is therefore
possible **only** by a party holding both the salt and the registration
database — that is, the agency acting deliberately, which is the correct
place for that capability to sit.

**Operational consequence:** the salt is sensitive. `zw-authority
issue-admit` writes it to a separate `.salt` file and tells the operator to
store it with the registration system, not with the exam evidence.

---

## DPIA outline

Structured for GDPR Art. 35 / India DPDP Act 2023 assessment. An agency must
complete this against its own legal basis and retention policy; what follows
is the system-side input.

### 1. Nature of processing

Pseudonymised identifiers are processed to bind a candidate's admission to a
seat and to a uniquely generated examination paper, and to produce a
tamper-evident custody record.

### 2. Lawful basis (agency to confirm)

Typically public task / legal obligation for a statutory examination body.
Consent is not an appropriate basis: a candidate cannot meaningfully refuse
custody logging and still sit the exam.

### 3. Data minimisation

- The system receives a registration id **only** at token issuance, and
  retains only its salted hash.
- Seat ids are necessary: the entire integrity property (T4/T7) is the
  binding of paper → seat.
- No biometric, contact or demographic data is processed.

### 4. Retention

| Data | Suggested retention | Rationale |
|---|---|---|
| Transparency log and evidence bundles | Length of the challenge/appeal period + statutory audit period (typically 3–7 years) | It is the audit record; deleting it defeats the purpose |
| Per-exam salt | Same as the registration record | Needed to resolve a dispute back to a candidate |
| Centre operational state | Until evidence export is verified, then destroy | No ongoing purpose |
| Ciphertext bundles | Until the answer key is released and results published | No ongoing purpose |
| Generated PDFs | Not retained | Written to the printer or spool; never persisted by the node |

Retention is enforced by agency policy, not by this software. The system
provides no automatic deletion, deliberately: silently expiring an audit
record would be a T6 vector.

### 5. Rights of data subjects

- **Access.** A candidate can be told which seat they were bound to and that
  a paper of a given hash was generated for them. Resolution requires the
  salt, held by the agency.
- **Rectification.** The log is append-only by design. An erroneous entry is
  corrected by a subsequent entry, never by editing. This must be explained
  in the agency's privacy notice.
- **Erasure.** The log cannot be selectively erased without destroying its
  integrity property. Agencies should rely on the public-task exemption and
  on the fact that log contents are pseudonymised, not personal data in the
  ordinary sense. **Deleting the per-exam salt** renders the hashes
  permanently unlinkable — this is the appropriate erasure mechanism, and it
  is worth documenting as such.
- **Objection / automated decision-making.** No automated decisions are made
  about individuals. Paper assignment is deterministic pseudorandom
  selection, not profiling.

### 6. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Log used to track candidates across exams | Per-exam salt makes hashes unlinkable |
| Re-identification by brute force | Salt is 32 bytes from a CSPRNG |
| Salt leaks alongside evidence | Written to a separate file with an explicit warning; stored with the registration system |
| PII smuggled into a payload by future code | Redactor on all log fields (I-OPS-1); audit reports PII-shaped field names |
| Seat ids reveal hall layout | Accepted: operationally necessary, low sensitivity |

### 7. Residual risk

An agency holding both the salt and the registration database can
re-identify every entry. This is intended — dispute resolution requires it —
and is the reason the salt's storage location is a policy decision the
runbook forces the operator to make consciously.

---

## Verification

`zw-verify audit` scans every log payload for PII-shaped field names and
reports T8 ATTENTION if any appear. The test suite asserts that no
registration id reaches the log
(`packages/authority/test/admit.test.ts`).
