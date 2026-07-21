# Integrations — what a deploying agency must provision

This document is deliberately blunt about the boundary between what this
codebase does and what an agency must obtain, configure or contract for. Where
an external dependency is real, the code integrates the real interface; where
credentials or hardware can only come from the agency, that is stated plainly
rather than stubbed.

---

## 1. Key storage

Two production providers ship. Both implement the same `KeyProvider`
interface; no component outside that boundary touches raw key bytes.

### `@zw/kms-vault` — encrypted file keystore (no HSM budget)

Argon2id-derived file key, XChaCha20-Poly1305 at rest, OS keyring integration
for the passphrase (macOS Keychain, libsecret on Linux). Suitable for pilots.

**Agency must provide:** a passphrase delivery mechanism. In production this
is systemd's encrypted credential store (see `deploy/systemd/`), not an
environment variable in a unit file.

**Understand the limit:** a root-level attacker on the authority host can
read the keystore and its passphrase from process memory. The file vault
protects against disk theft and backup exfiltration, not host compromise.

### `@zw/kms-pkcs11` — PKCS#11 (HSM)

Tested in CI against **SoftHSM2 2.6+**, which is itself a real PKCS#11
provider — not a mock.

**Validated hardware.** The following are supported by the PKCS#11 mechanisms
this provider uses (AES-256-GCM key wrap, ECDSA/EdDSA signing, on-token key
generation):

| Device | Module path (typical) | Notes |
|---|---|---|
| YubiHSM 2 | `/usr/lib/pkcs11/yubihsm_pkcs11.so` | Requires `yubihsm-connector` running. Adequate for a single authority; ~doubles release latency vs. software, still well inside the 500 ms budget. |
| Thales Luna 7 | `/usr/lib/libCryptoki2_64.so` | Network-attached HSM. Configure the client and confirm partition login before the ceremony. |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` | Cluster must be initialised and the crypto user created. Adds network latency to every operation — measure against the release budget before committing. |

**Agency must provide:** the HSM itself, its PKCS#11 module, slot/token
configuration, and the PIN — delivered the same way as the vault passphrase.
Set `ZW_KEY_PROVIDER=pkcs11`, `ZW_PKCS11_MODULE`, `ZW_PKCS11_SLOT`.

**Agency must decide:** whether Shamir splitting happens inside the HSM
(vendor-specific, not portable across the table above) or in host memory
using key material extracted under wrap. This implementation does the latter
in locked, zeroized pages, because it is portable and auditable. An agency
requiring split-inside-HSM must extend the provider for its specific device.

---

## 2. Time-stamping authorities (RFC 3161)

Anchoring is what makes a backdating claim falsifiable by a third party (T5).
The client is real RFC 3161 over HTTP with full token parsing and
verification.

**Configured public TSAs:**

| Name | Endpoint | Notes |
|---|---|---|
| `freetsa` | `https://freetsa.org/tsr` | Free, community-operated. No SLA. Rate-limited; polite use only. |
| `digicert` | `http://timestamp.digicert.com` | Free for timestamping. Commercially operated. |
| `sectigo` | `http://timestamp.sectigo.com` | Free for timestamping. Third independent operator. |

**Agency must decide and arrange:**

- **Whether free public TSAs are acceptable.** They have no SLA and no
  contractual commitment to you. For a national examination, contract at
  least one commercial TSA with a defined availability guarantee, and keep a
  free one as the independent second anchor. The point of multiple anchors is
  that no single operator's cooperation can move a timestamp — so they must
  be *independently operated*, not merely two endpoints.
- **Rate limits.** One checkpoint per log per exam is a handful of requests;
  a national rollout with hundreds of centres checkpointing frequently is
  not. Measure your checkpoint cadence against the TSA's limits.
- **Network egress.** Centres normally have no internet access. Either
  centres anchor via the authority after evidence collection, or accept that
  centre logs are anchored at collection time rather than at exam close.
- **TSA outage.** `Rfc3161AnchorBackend` fails loudly; the checkpoint is
  still created and can be anchored later. The audit reports how many
  distinct TSAs covered the final checkpoint and flags ATTENTION below the
  policy minimum (default 2).

---

## 3. Printing

Primary path is IPP (RFC 8011) to networked printers, integration-tested
against real CUPS in the compose topology.

**Agency must provide:**

- Printers reachable over IPP from each centre node. Any IPP 2.0 printer or
  CUPS queue works; PostScript/PDF-capable devices are assumed (papers are
  PDF).
- **A backup printer per centre on a different failure domain** — different
  circuit, different switch. Automatic failover is worthless if the backup
  shares whatever killed the primary (DECISIONS.md D-44).
- Sufficient paper and toner for the full candidate count plus contingency.
  A centre that runs out mid-exam has no software fallback.

**Fallback:** `--spool-dir` writes finished PDFs for print-room workflows.
This is a genuine fallback path, exercised by a drill, not a placeholder.

---

## 4. Identity — Aadhaar / UIDAI

**What ships:** a complete, production identity path — Ed25519-signed admit
tokens issued by the authority at registration and verified **offline** at the
centre. This requires no external service and works with no connectivity.

**What does not ship:** Aadhaar authentication.

Aadhaar/UIDAI is a licensed government API. Access requires the deploying
agency to be registered as an **AUA (Authentication User Agency)** or **KUA
(KYC User Agency)** with UIDAI, holding:

- a signed AUA/KUA licence agreement with UIDAI;
- an ASA (Authentication Service Agency) connection, or accreditation as one;
- a licence key and an AUA code issued by UIDAI;
- a UIDAI-issued digital signature certificate for signing auth requests;
- deployment of registered biometric devices meeting UIDAI's L1 registered-
  device specification, if biometric authentication is used;
- compliance with UIDAI's audit, data-retention and privacy obligations.

**None of these can be obtained by this project, and none can be simulated.**
An implementation that pretended to authenticate against Aadhaar would be
worse than useless: it would create the appearance of identity assurance
where there is none.

What this codebase provides instead is the **integration point**: identity
verification at check-in is reached through a single call site
(`CentreNode.checkIn` → `verifyAdmitToken`) whose contract is
"given a presented credential, return a verdict and a stable token hash". An
agency with UIDAI credentials implements an adapter satisfying that contract
and wires it there. The seat binding, logging and paper derivation downstream
are unchanged, because they depend only on the token hash.

**Privacy note.** If Aadhaar authentication is added, the Aadhaar number must
**not** enter the transparency log. The log's contract (T8) is hashes and
seat ids only; an adapter must hash under the per-exam salt exactly as the
shipped provider does. See PRIVACY.md.

---

## 5. Public key infrastructure

`@zw/ca` is a complete internal CA: two-tier, ECDSA P-384, issuance,
rotation, revocation, CRL publication readable by OpenSSL.

**Agency must decide:**

- **Where the root key lives.** `zw-ca init` prints its path and instructs
  removal to offline media. This is not automated because "offline" is a
  physical property — a safe, an HSM in a vault, an air-gapped machine — that
  software cannot assert.
- **CRL distribution.** Revocation fails closed: a missing or stale CRL is a
  hard error (I-CA-3). An agency must therefore have a mechanism to get
  fresh CRLs to every node before the current one expires (default 24 h), or
  services will refuse connections. This is deliberate.
- **Hardware identifiers.** Centre and custodian certificates must carry one
  (I-CA-2). Use a TPM EK hash, a device serial, or an inventory id — but use
  something the agency can independently verify against its asset register.

---

## 6. Operational dependencies

| Requirement | Why |
|---|---|
| Node 20 LTS or newer | Runtime; also part of the byte-reproducibility surface for paper rendering |
| Time synchronisation (NTP/chrony) on all hosts | The signed schedule and T-0 comparison depend on host clocks. A centre with a badly skewed clock can misjudge admit-token expiry. |
| `LimitMEMLOCK=infinity` | Key material is mlocked; without this a KEK could be written to swap |
| Backup target reachable from centre nodes | Bounds seat loss on node failure (runbooks/restore.md §5) |
| Prometheus scraper (optional) | `/metrics` on the centre admin port; alert on `zw_authority_early_release_attempts_total` |

---

## 7. What is deliberately absent

- **No message broker.** Exam-day topology is hub-and-spoke and must work
  with degraded connectivity.
- **No cloud dependency.** Every component runs on hardware the agency
  controls. TSAs are the only external calls, and they are optional per run.
- **No telemetry.** Nothing phones home.
- **No candidate PII in this system.** Names, contact details and
  registration ids stay in the agency's registration system. This system
  holds salted hashes and seat ids.
