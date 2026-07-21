# Runbook — Exam day

**When:** the day of the examination.
**Who:** release ceremony officer + three custodians (authority side); centre
supervisor + invigilators (each centre).
**Critical property:** the exam cannot be re-run. Every step below has a
rehearsed fallback. If something is not working, go to the fallback — do not
improvise, and do not delay past T-0 trying to fix the primary path.

Timings assume T-0 is the moment papers may be decrypted.

---

## T-90 minutes — centre readiness

At each centre:

```bash
zw-centre status --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <authority public key>
```

Expected:

```
Bundle           EXAM-2026-PHYS:paper (6591 bytes ciphertext)
Check-ins        0
Papers           0 generated, 0 printed
```

**If `Bundle none`:** the centre never took custody. Fetch it now — the
daemon retries automatically; if the network is down, obtain the bundle on
media and use `zw-centre receive-bundle` (key-ceremony.md §4). This must be
resolved before T-0; a centre without the bundle cannot run the exam even
with the key.

Check printers:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://<printer-host>:631/
```

Confirm **both** the primary and the backup respond. Confirm the spool
directory exists and has free space:

```bash
df -h /var/spool/zero-window
```

Rule of thumb: 250 KB per candidate. 500 candidates ≈ 125 MB; keep 1 GB free.

---

## T-45 — check-in opens

Invigilators scan admit-card QR codes. With a handheld scanner configured as
a keyboard, run the interactive form and scan continuously:

```bash
zw-centre check-in --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <authority public key>
```

Each scan prints `CHECKED IN seat B-014` or `REFUSED: <reason>`.

**Refusal reasons and what to do:**

| Message contains | Meaning | Action |
|---|---|---|
| `signature does not verify` | The card was not issued by this authority | Do not admit. Refer to the exam controller — this is a forgery attempt. |
| `token is for centre X` | Right exam, wrong centre | Do not admit here. Direct the candidate to their assigned centre. |
| `token is for exam X` | Card is for a different exam | Do not admit. |
| `expired at ...` | The card's validity window has passed | Do not admit without controller authorisation. |
| `already checked in` | This card has already been used | **Do not admit.** Two people are presenting the same card. Escalate immediately: incident-response.md §impersonation. |
| `seat ... is already occupied` | Another candidate is bound to that seat | Escalate; do not reassign seats manually. |

Check-in works with **no network**. It needs only the authority public key,
which is already on the node.

---

## T-0 — threshold release

### Primary path (network available)

Three custodians attend, each with their opened share on their own media.
The release officer runs:

```bash
zw-authority release \
  --dir /var/lib/zero-window/authority \
  --bundle EXAM-2026-PHYS:paper \
  --shares /media/c1/share.json,/media/c2/share.json,/media/c3/share.json
```

Expected:

```
Released EXAM-2026-PHYS:paper
  centres            3
  custodians         custodian-1, custodian-2, custodian-4
  plaintext KEK life 0.56ms (budget 500ms)
```

**Read the KEK lifetime aloud and record it.** If it exceeds 500 ms the
release fails deliberately and no key is distributed: the host is not fit for
release duty (memory pressure, contention, a debugger attached). Move to a
clean host and retry — the shares are unchanged and reusable.

Centres pick the key up automatically within `ZW_SYNC_INTERVAL_MS`
(default 5 s). Confirm at each centre:

```bash
curl -s http://127.0.0.1:9464/health/ready | jq .checks.kek
```

Expect `{"status":"pass"}`.

### Fallback: network down at T-0

The custodians are physically present at the authority; the centres are not
reachable. Produce signed media instead:

```bash
zw-authority release \
  --dir /var/lib/zero-window/authority \
  --bundle EXAM-2026-PHYS:paper \
  --offline \
  --shares /media/c1/share.json,/media/c2/share.json,/media/c3/share.json \
  --out /media/courier/release.json
```

Copy `release.json` to media for each centre and dispatch couriers. At each
centre:

```bash
zw-centre receive-medium --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <authority public key> \
  --file /media/courier/release.json
```

If this reports `MEDIUM_INVALID`, **stop**: the medium was altered or
substituted in transit. Do not retry with another copy from the same courier.
Escalate: incident-response.md §media-substitution.

### If a custodian does not arrive

The threshold is 3 of 5. Call the remaining custodians. Do **not** attempt to
proceed with two — it is cryptographically impossible, not a policy the
officer can waive.

---

## T+0 — generation and printing

```bash
zw-centre run-t0 --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <authority public key> \
  --printers hall-a=http://printer-a:631/printers/hall-a,hall-b=http://printer-b:631/printers/hall-b \
  --spool-dir /var/spool/zero-window
```

Papers are generated and printed one candidate at a time. Expect roughly
15–20 papers per second of generation; printing is bounded by the printer.

Expected final line: `Printed 100 paper(s)`.

### §printer-failure — a printer fails mid-run

**Nothing to do.** The node fails over to the next configured printer
automatically and records `PRINTER_FAILOVER` in the log. Papers already
queued on the failed printer are reprinted on the backup.

Confirm which printer papers came off:

```bash
curl -s http://127.0.0.1:9464/metrics | grep zw_centre_papers_printed_total
```

If **all** printers fail, papers are written to `--spool-dir` as PDFs. The
run still reports success. The print room then prints them manually:

```bash
ls /var/spool/zero-window/
lp -d <working-printer> /var/spool/zero-window/*.pdf
```

Each spooled PDF is a complete, correctly-numbered paper for one seat; the
seat is in the filename and on every page footer.

### A seat fails

`run-t0` continues past individual failures and lists them at the end:

```
FAILED B-042: no candidate checked in at seat B-042
```

Re-run the single seat after fixing the cause:

```bash
zw-centre run-t0 ...    # already-printed seats are skipped automatically
```

A seat whose paper was already generated will report `ALREADY_GENERATED` —
that is correct and protects against duplicate papers reaching one candidate.

### The centre node dies mid-exam

Go to **restore.md**. Do not start a second node against a copy of the state
while the first may still be running.

---

## Exam close

At each centre, when the last paper is collected:

```bash
zw-centre close-exam --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <authority public key>
```

This logs `EXAM_CLOSED`, checkpoints the log, and discards the key from
memory. After this the node cannot generate papers again.

---

## §post-exam — answer keys

Only after **every** centre has closed:

```bash
zw-authority schedule --dir /var/lib/zero-window/authority \
  --bundle EXAM-2026-PHYS:answers --at <now, UTC>

zw-authority release --dir /var/lib/zero-window/authority \
  --bundle EXAM-2026-PHYS:answers \
  --shares /media/c1/answers-share.json,...
```

The answer-key bundle has its own KEK and its own custodian shares; releasing
the paper at T-0 did not release it.

---

## Evidence export and audit

At the authority and at each centre:

```bash
zw-authority checkpoint --dir /var/lib/zero-window/authority
zw-centre export-evidence --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <key> --out /media/evidence
```

Hand the evidence files, the signer list, and (for dispute resolution) the
post-exam paper-content disclosure to the auditor. They run:

```bash
zw-verify audit --authority authority.evidence.jsonl \
  --centres centre-a.evidence.jsonl,centre-b.evidence.jsonl \
  --signers signers.json --paper-content paper-content.json
```

Exit code 0 means the overall verdict is PASS.

---

## Quick reference — what breaks the exam, and what does not

| Event | Exam continues? |
|---|---|
| Authority host dies after key release | **Yes** — centres are autonomous |
| Network to the authority drops after key release | **Yes** |
| Network drops before T-0 | Yes, via offline release media |
| Primary printer fails | **Yes** — automatic failover |
| All printers fail | **Yes** — spool to PDF, print manually |
| Centre node dies | Yes — cold-spare restore (restore.md) |
| Fewer than 3 custodians present | **No** — cryptographically impossible |
| Centre never received the bundle | **No** — must be fixed before T-0 |
