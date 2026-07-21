# Runbook — Key ceremony (provisioning an examination)

**When:** once per examination, days-to-weeks before the exam date.
**Who:** ceremony officer (runs the commands), five custodians (hold shares),
one witness who is not the ceremony officer.
**Duration:** 60–90 minutes including custodian attendance.
**Preconditions:** authority host provisioned, internal CA initialised, every
centre enrolled.

This ceremony is the moment the exam content stops being readable. After
step 5, no person and no machine — including the ceremony officer and the
operator of this system — can decrypt the paper until three of five
custodians act together at T-0. Do not deviate from these steps. If a step
fails, stop and consult §Troubleshooting rather than improvising.

---

## 0. Before the custodians arrive

**0.1** Confirm the authority host is the intended machine:

```bash
zw-authority status --dir /var/lib/zero-window/authority
```

Record the printed **authority public key** in the ceremony minutes. Every
centre and every auditor will check signatures against this value; if it
differs from the value distributed at enrolment, **stop** — you are on the
wrong host or the keystore has been replaced.

**0.2** Confirm the item bank and blueprint files are the ones approved by
the examination board, by hash:

```bash
sha256sum bank.json blueprint.json
```

Read both hashes aloud to the witness and record them. The bank is plaintext
exam content: it must reach this host on encrypted removable media, and the
media must be destroyed or re-encrypted at step 6.

**0.3** Confirm every centre that will sit this exam is enrolled:

```bash
zw-authority status --dir /var/lib/zero-window/authority
```

A centre missing here **cannot receive a key at T-0**, and there is no
recovery path on exam day. Enrol it now (§Enrolling a centre).

---

## 1. Enrol the custodians

Each custodian brings their own hardware token or centre-issued client
certificate and their **box public key** — a 64-character hex string they
generate on their own device:

```bash
# run by the custodian, on the custodian's machine
zw-centre identity --dir ~/custodian-state
```

The ceremony officer enrols each one:

```bash
zw-authority enrol-custodian \
  --dir /var/lib/zero-window/authority \
  --id custodian-1 \
  --name "Full Name" \
  --box-public-key <64-hex-characters>
```

Repeat for all five. Read each key back to its custodian and have them
confirm it character-by-character before continuing. A wrong key means that
custodian's share is unrecoverable, and if two are wrong the exam cannot be
released.

---

## 2. Ingest and encrypt

```bash
zw-authority provision \
  --dir /var/lib/zero-window/authority \
  --bank bank.json \
  --blueprint blueprint.json \
  --threshold 3
```

Expected output names two bundles and two key fingerprints:

```
Provisioned EXAM-2026-PHYS
  paper bundle    EXAM-2026-PHYS:paper
    bundle hash   67d76530e0623b2d…
    KEK           6017e981d8078...
  answers bundle  EXAM-2026-PHYS:answers
    ...
```

**Record all four values in the minutes.** The bundle hashes are what each
centre will verify on receipt; the KEK fingerprints are what the release
proves it reconstructed.

If this command reports validation problems instead, the bank cannot satisfy
the blueprint. It prints one line per problem. Fix the bank with the
examination board — **do not** edit the blueprint to fit a deficient bank
without board approval.

> At the moment this command returns, both KEKs have been split and
> destroyed. The paper cannot be decrypted by this host.

---

## 3. Issue custodian shares

Each custodian's share is already sealed to their public key. Export them one
per custodian, to the custodian's own removable media:

```bash
zw-authority export-share \
  --dir /var/lib/zero-window/authority \
  --bundle EXAM-2026-PHYS:paper \
  --custodian custodian-1 \
  --out /media/custodian-1/share.json
```

The custodian verifies they can open it **before leaving the room**:

```bash
# run by the custodian
zw-centre open-share --dir ~/custodian-state --file /media/custodian-1/share.json
```

Expected: `share opened successfully for custodian-1`. If it fails, the
public key recorded at step 1 is wrong for this custodian — re-run step 1
with the correct key and repeat step 2 (the whole provisioning must be
redone, because shares are bound to the split).

Have each custodian sign the minutes acknowledging receipt.

---

## 4. Distribute ciphertext to centres

For each enrolled centre:

```bash
zw-authority distribute \
  --dir /var/lib/zero-window/authority \
  --bundle EXAM-2026-PHYS:paper \
  --centre CENTRE-A \
  --out /tmp/bundle-CENTRE-A.bin
```

Centres normally pull this themselves over mTLS when their daemon runs; the
`--out` file is for air-gapped centres receiving it on media.

The centre confirms custody:

```bash
zw-centre receive-bundle --dir /var/lib/zero-window/centre \
  --centre CENTRE-A --exam EXAM-2026-PHYS \
  --authority-key <authority public key from step 0.1> \
  --file /tmp/bundle-CENTRE-A.bin \
  --bundle EXAM-2026-PHYS:paper \
  --bundle-hash <hash from step 2> \
  --kek-fingerprint <fingerprint from step 2> \
  --threshold 3
```

The centre recomputes the hash and refuses the bundle if it disagrees. A
refusal here means the file was altered in transit — **do not retry with a
different hash**; investigate as a security incident
(runbooks/incident-response.md).

---

## 5. Schedule T-0

```bash
zw-authority schedule \
  --dir /var/lib/zero-window/authority \
  --bundle EXAM-2026-PHYS:paper \
  --at 2026-09-14T09:30:00Z
```

Use UTC. This schedule is signed; editing the database afterwards invalidates
the signature and **blocks the release entirely** rather than moving it.
Changing T-0 legitimately means re-running this command, which re-signs.

Do **not** schedule the answers bundle now. It is released after the exam
closes (runbooks/exam-day.md §post-exam).

---

## 6. Close the ceremony

```bash
zw-authority checkpoint --dir /var/lib/zero-window/authority
```

Then:

- destroy or re-encrypt the plaintext `bank.json` media, witnessed;
- confirm each custodian has departed with exactly one share;
- file the minutes with: authority public key, both bundle hashes, both KEK
  fingerprints, T-0 in UTC, custodian names and their key fingerprints.

---

## Enrolling a centre

Run on the centre node to obtain its box public key:

```bash
zw-centre identity --dir /var/lib/zero-window/centre
```

Then on the authority:

```bash
zw-authority enrol-centre \
  --dir /var/lib/zero-window/authority \
  --id CENTRE-A \
  --box-public-key <64-hex> \
  --hardware-id tpm-centre-a-001
```

The hardware id must match the one in the centre's client certificate
(`zw-ca list`), or the centre will be refused at the mTLS layer.

---

## Troubleshooting

**`item bank failed validation`** — the bank cannot fill the blueprint. Each
problem line names the slot and the shortfall. The bank needs more items in
that (subject, difficulty) pair.

**`custodian X is not enrolled`** — step 1 was skipped or the id is
misspelled. Ids are case-sensitive.

**`fewer custodians than threshold`** — you asked for a threshold larger than
the number of custodians enrolled. Never lower the threshold below 3 without
board approval; enrol more custodians instead.

**A custodian cannot open their share** — their public key was recorded
wrongly. The entire provisioning must be redone (step 2 onward) because
shares are bound to one split. This is why step 3 verifies before the
custodians leave.

**The authority public key does not match the enrolment record** — stop. Do
not provision. Either you are on the wrong host or the keystore has been
replaced. Escalate per incident-response.md.
