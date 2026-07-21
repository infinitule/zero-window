# Runbook — Incident response

**Scope:** suspected compromise, tampering, or leak affecting an examination
under ZERO-WINDOW custody.

**Principle:** the transparency log is evidence. Never delete, edit, or
"clean up" log files, state directories, or media during an incident — doing
so destroys the only thing that can establish what happened, and is itself
indistinguishable from an attack (T6). Copy, do not move; preserve, do not
repair.

**First action for every incident:** note the wall-clock time, capture a
checkpoint, and export evidence before changing anything.

```bash
zw-authority checkpoint --dir /var/lib/zero-window/authority
zw-centre export-evidence --dir /var/lib/zero-window/centre \
  --centre <ID> --exam <EXAM> --authority-key <key> --out /media/incident-$(date +%s)
```

---

## Severity and escalation

| Severity | Definition | Escalate to | Within |
|---|---|---|---|
| **SEV-1** | Exam content may be readable outside the vault before T-0 | Exam controller + board security officer | Immediately |
| **SEV-2** | Custody chain integrity in question; exam can still run | Exam controller | 15 minutes |
| **SEV-3** | Single-node or single-candidate issue with a working fallback | Centre supervisor | 1 hour |

---

## §early-release — an early release was attempted

**Signal:** `EARLY_RELEASE_ATTEMPT` in the authority log, or alert on
`zw_authority_early_release_attempts_total`.

**Severity:** SEV-2, or SEV-1 if repeated or by different custodian sets.

The release was **refused** — this is the control working, not a breach. But
somebody with valid custodian shares tried to open the paper early.

1. Identify who:
   ```bash
   zw-verify audit --authority authority.evidence.jsonl --centres ... | grep -A3 "T2"
   ```
   The evidence line names the custodians and how early the attempt was.
2. Contact each named custodian **separately**. Establish whether the attempt
   was a mistake (wrong bundle id, wrong clock) or deliberate.
3. If deliberate or unexplained: treat the shares as compromised. The exam
   content is still safe (below threshold), but the custodian set must be
   re-provisioned before T-0 — this means a new ceremony
   (key-ceremony.md) with a fresh KEK and different custodians.
4. Record the attempt and its resolution in the exam file. The audit report
   will show T2 ATTENTION; the board's file must explain it.

---

## §bundle-mismatch — a centre refused a bundle

**Signal:** `BUNDLE_HASH_MISMATCH` from `zw-centre receive-bundle`.

**Severity:** SEV-1.

The ciphertext delivered to the centre is not the ciphertext the authority
recorded. Either the transfer corrupted it or someone substituted it.

1. **Do not retry with a different `--bundle-hash`.** The hash comes from the
   authority's signed distribution record; changing it to match the file
   defeats the control.
2. Preserve the received file: `cp bundle.bin /media/incident-.../`.
3. Compare against the authority:
   ```bash
   zw-authority status --dir /var/lib/zero-window/authority
   sha256sum bundle.bin
   ```
4. Re-transfer over a different path (mTLS sync rather than media, or fresh
   media). If the second transfer verifies, the first was corrupted or
   tampered — preserve both and escalate.
5. If repeated transfers mismatch, the authority's copy or its records may
   have been altered. Run the verifier against the authority evidence before
   proceeding; a broken chain is conclusive.

---

## §media-substitution — an offline release medium failed to verify

**Signal:** `MEDIUM_INVALID` from `zw-centre receive-medium`.

**Severity:** SEV-1.

The medium's signature does not verify against the authority key. It was
altered, or it is not from this authority.

1. **Do not try another copy from the same courier.** Quarantine the medium.
2. Confirm the centre has the correct authority public key — compare against
   the value in the ceremony minutes (key-ceremony.md §0.1). A wrong key on
   the centre produces the same symptom and is the more common cause.
3. If the key is correct, the medium is not authentic. Dispatch a fresh
   medium by a different courier, and treat the original courier chain as
   compromised.
4. If T-0 is imminent and no valid medium can arrive in time, fall back to a
   fresh threshold release for this centre (exam-day.md §fallback).

---

## §impersonation — duplicate admit card presented

**Signal:** `already checked in` at check-in, or `seat ... already occupied`.

**Severity:** SEV-2.

Two people are presenting cards that resolve to the same token, or two cards
claim one seat.

1. Detain both admit cards (physically) and record both candidates' details
   by the centre's normal identity procedure. **The system deliberately holds
   no PII** — identity resolution is the registration system's job, not this
   node's.
2. Do not admit the second presenter on the disputed card.
3. The first check-in is already bound in the log with a timestamp; that
   binding is evidence.
4. Escalate to the exam controller for identity adjudication. The controller
   can look up the registration id from the card's registration hash **only**
   via the registration system, using the per-exam salt held there.

---

## §centre-compromise — a centre node is suspected compromised

**Severity:** SEV-1.

1. **Isolate:** disconnect the node from the network. Do not power it off if
   the exam is running and it is printing — losing volatile state is
   acceptable but stopping mid-candidate is not; finish the current paper.
2. **Preserve:** image the disk before any restore. The keystore, state
   database and log are all evidence.
3. **Assess what the attacker could obtain:**
   - *Before key release*: the bundle is ciphertext and the KEK does not
     exist at the centre. Exam content is **not** exposed.
   - *After key release*: the KEK is in the node's memory. A root-level
     attacker on a running node after T-0 can read the plaintext. The exam
     content is exposed **from T-0 onward** — which is after candidates have
     it anyway. Assess whether papers left the hall early.
4. **Continue the exam** on a cold spare (restore.md) — a compromised node
   must not keep printing, but candidates must still sit the exam.
5. The centre's client certificate must be revoked before the next exam:
   ```bash
   zw-ca revoke --dir /var/lib/zero-window/ca --serial <serial> --reason keyCompromise
   zw-ca crl --dir /var/lib/zero-window/ca --hours 24
   ```
   Distribute the new CRL to every service. Revocation takes effect only when
   peers load a CRL listing that serial.

---

## §authority-compromise — the authority host is suspected compromised

**Severity:** SEV-1. This is the most serious case.

1. Isolate the host. Preserve the disk image.
2. **Before T-0:** exam content is protected — the KEK does not exist on the
   host after provisioning (key-ceremony.md §2). An attacker gets ciphertext
   and the operational database. Papers are safe. The exam can proceed if
   centres already hold their bundles, using an offline release performed on
   a **different, clean host** with a restored keystore.
3. **During the release window:** the plaintext KEK exists for under 500 ms
   inside the release call. An attacker with kernel-level access at exactly
   that moment could capture it. If the compromise window overlaps the
   release, treat the paper as **leaked** and invoke the board's
   paper-cancellation procedure.
4. **After release:** the KEK is gone from the authority again. Exposure is
   limited to the release window.
5. Rotate the CA issuing intermediate and re-issue all certificates before
   the next exam:
   ```bash
   zw-ca rotate-intermediate --dir /var/lib/zero-window/ca
   ```

---

## §claimed-leak — someone publishes what they claim is the paper

**Severity:** SEV-1 until disproved.

This is what the deterministic-paper design exists for.

1. Obtain the highest-quality copy of the claimed leak available.
2. Read the **QR code** and the **page footer** from the artifact. The QR
   carries `{exam, centre, seat, content-hash prefix}`; the footer carries
   `Page n of N` and a page-chain prefix.
3. If the QR resolves to a real seat, the auditor re-derives that candidate's
   paper from the log and compares:
   ```bash
   zw-verify audit --authority ... --centres ... --paper-content ... 
   ```
   - **Matches:** the artifact is genuine and traceable to that seat.
     Investigate that centre and that seat. The `PAPER_PRINTED` entry names
     the printer and job.
   - **Does not match:** the artifact is not a paper this system produced —
     it is fabricated, or altered.
4. If the leak is claimed to predate T-0, check the anchored checkpoints. The
   RFC 3161 tokens from independent TSAs establish that the paper hashes were
   committed no earlier than the timestamps assert — this is what makes a
   backdating claim falsifiable by a third party (T5). Provide the auditor's
   signed report, which includes the anchor verification, to the board.
5. If a claimed leak carries no QR and no valid footer chain, say so plainly:
   the system produces neither.

---

## After any incident

- File the signed audit report with the incident record.
- Note in the exam file which threat rows the audit marked ATTENTION and why.
- If any control failed (as opposed to fired correctly), open a defect
  against this repository with the evidence bundle attached.
