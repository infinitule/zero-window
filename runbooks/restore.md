# Runbook — Centre node restore from cold spare

**When:** a centre node fails during or shortly before an exam.
**Who:** centre supervisor + one technician.
**Time to restore:** 10–15 minutes if the spare is pre-staged.
**Rehearsed by:** `packages/centre/test/drills.test.ts` — DRILL 2.

---

## 0. Decide whether to restore

| Symptom | Action |
|---|---|
| Process crashed, host healthy | systemd restarts it automatically (`Restart=always`). Wait 30 s and check `zw-centre status`. Do **not** restore. |
| Host unresponsive, disk intact | Move the disk to the spare, or restore from backup (§2). |
| Disk lost or corrupt | Restore from backup (§2). Papers already printed stay printed. |
| Node compromised (suspected intrusion) | **Stop.** incident-response.md §centre-compromise. Do not restore onto the same host. |

**Critical:** never run two nodes against the same centre state at once. Two
nodes would both believe they own the seat bindings and could print duplicate
papers for the same candidate. Physically power off the failed node, or
disconnect it from the network, **before** starting the spare.

---

## 1. What is and is not in the backup

| In the backup | Not in the backup |
|---|---|
| Ciphertext bundle (unreadable alone) | **The KEK** — memory-only, never written to disk |
| Check-in records (token hash → seat) | Plaintext exam content |
| Paper hashes, printed status per seat | Generated PDFs |
| The transparency log, hash-chained and signed | |
| The node's keystore (box + signing keys) | |

That the KEK is absent is deliberate and load-bearing: a stolen backup
cannot decrypt the paper. It also means **the restore must re-obtain the
key** (§3).

---

## 2. Restore the state

Pre-staged spare, with the same centre id and the same client certificate:

```bash
# on the spare, as root
systemctl stop zw-centre

rsync -a --delete /media/backup/centre-state/ /var/lib/zero-window/centre/
chown -R zerowindow:zerowindow /var/lib/zero-window/centre
```

If backups are taken with `zw-centre export-evidence`, the log is portable
but the operational state is not — restore from the filesystem backup of
`/var/lib/zero-window/centre`, which is what the nightly job copies.

Verify the restored log is intact before proceeding:

```bash
sudo -u zerowindow zw-centre status \
  --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <authority public key>
```

Expected: the bundle is present, and check-in/paper counts match what the
hall reports. If the counts are lower than the hall's tally, the backup is
stale — see §5.

---

## 3. Re-obtain the key

### If the authority is reachable

Start the node; the sync loop fetches the wrapped KEK automatically:

```bash
systemctl start zw-centre
journalctl -u zw-centre -f
```

Wait for `KEK received; sync loop stopping — the node is now autonomous`.

### If the authority is not reachable

Use the offline medium produced at T-0 (exam-day.md §fallback). It is still
valid — it is sealed to this centre's key, and the spare has the same
keystore:

```bash
sudo -u zerowindow zw-centre receive-medium \
  --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <authority public key> \
  --file /media/courier/release.json
```

### If neither is available

The key cannot be recovered at the centre. Call the release officer: three
custodians can perform another offline release for this centre
(exam-day.md §fallback). This is why custodian shares are retained until
every centre has closed.

---

## 4. Resume the exam

```bash
sudo -u zerowindow zw-centre run-t0 \
  --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <authority public key> \
  --printers <same as before> --spool-dir /var/spool/zero-window
```

Seats already served are skipped automatically (`ALREADY_GENERATED`), so this
is safe to run: it prints only the outstanding candidates. Do not delete
paper records to "force a reprint" — see §5.

Close normally when the exam ends:

```bash
sudo -u zerowindow zw-centre close-exam --dir /var/lib/zero-window/centre ...
```

---

## 5. Stale backup: seats served after the last backup

If candidates were served between the last backup and the failure, the
restored node does not know it. Symptoms: a candidate's seat shows no paper,
but the hall says they received one.

**Do not reprint blindly.** Two different papers for one seat is worse than
none — it breaks the seat↔paper binding an auditor relies on (T4/T7).

1. Take the invigilator's physical tally as the source of truth for who
   holds a paper.
2. For each disputed seat, read the **page footer** on the candidate's paper:
   it carries `Page n of N`, the page-chain prefix, and the seat.
3. Give the seat, and that footer prefix, to the auditor. After the exam the
   verifier re-derives that candidate's paper from the log and confirms
   whether the printed artifact matches:
   ```bash
   zw-verify audit --authority ... --centres ... --paper-content ...
   ```
4. Only reprint for a candidate who demonstrably has **no** paper, and record
   the decision in the incident log. The reprint appears in the evidence as a
   second `PAPER_GENERATED` for that seat, which is correct: the audit will
   surface it, and the incident record explains it.

Reduce this window by backing up more often during the exam:

```bash
# suggested: every 5 minutes during the exam window
*/5 * * * * rsync -a /var/lib/zero-window/centre/ /media/backup/centre-state/
```

---

## 6. After the exam

Export evidence from the **spare** (it holds the continuing log):

```bash
sudo -u zerowindow zw-centre export-evidence \
  --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <key> --out /media/evidence
```

Record in the incident log: time of failure, time of restore, which seats
were served before and after, and whether the offline medium was used. The
auditor will see a continuous, valid hash chain across the restore — the
chain does not break — so the human record is what explains the gap in wall
time.
