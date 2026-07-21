# Security design

## Cryptographic primitives

All primitives come from libsodium via `sodium-native`. No hand-rolled
cryptography; the only primitive implemented in this codebase is Shamir
secret sharing over GF(2⁸), which libsodium does not provide, and it is
covered by known-answer tests and property tests.

| Purpose | Primitive | Notes |
|---|---|---|
| Bundle encryption | XChaCha20-Poly1305 (IETF) | 24-byte random nonces — safe at any realistic volume |
| Hashing | BLAKE2b-256 | Domain-separated everywhere (`I-HASH-1`) |
| Signatures | Ed25519, detached | Domain-separated (`I-SIG-1`) |
| Key wrapping | X25519 sealed boxes | Anonymous; authenticity from the signed containing message |
| Threshold | Shamir 3-of-5 over GF(2⁸) | Fresh CSPRNG coefficients per byte |
| Password KDF | Argon2id (moderate) | File-vault keystore only |
| Transport | TLS 1.3 only, mutual | ECDSA P-384 certificates |
| Anchoring | RFC 3161, SHA-256 | ≥2 independently operated TSAs |

KATs: XChaCha20-Poly1305 against draft-irtf-cfrg-xchacha-03 §A.3.1, BLAKE2b
against RFC 7693 Appendix A, Ed25519 against RFC 8032 §7.1. GF(2⁸)
multiplication is cross-checked against a table-free reference for all 65 536
input pairs.

---

## Key hierarchy

```
Authority signing key (Ed25519, long-lived, in key provider)
├── signs log entries, checkpoints, admit tokens, release schedules,
│   offline release media
│
Per-bundle KEK (XChaCha20 key, ephemeral, never persisted)
├── generated inside the key provider
├── encrypts exactly one bundle
├── Shamir-split 3-of-5 → sealed to custodian X25519 keys
└── DESTROYED — exists again only inside reconstructWrapRelease at T-0
│
Custodian keys (X25519, custodian-controlled hardware)
└── each opens exactly one share per bundle
│
Centre keys (X25519, per centre node)
└── receive the wrapped KEK at release; held in memory only
│
PKI (ECDSA P-384)
├── offline root → online issuing intermediate → leaves
└── serverAuth OR clientAuth, never both; hardware-bound client certs
```

Paper and answer-key bundles have **distinct** KEKs, so releasing the paper
at T-0 cannot release the answers.

---

## Named invariants

Invariants are named in code and referenced from the tests enforcing them.

| Invariant | Statement |
|---|---|
| `I-SEC-1` | Every buffer holding raw key material is `sodium_malloc`'d and zeroized |
| `I-HASH-1` | Every protocol hash is domain-separated |
| `I-SIG-1` | Every signature is domain-separated |
| `I-SSS-1` | Shamir coefficients are fresh CSPRNG output per byte per split |
| `I-KP-1` | Raw private/secret key bytes never cross the key-provider boundary |
| `I-KP-2` | A plaintext KEK is never persisted in any form |
| `I-LOG-2` | The log is append-only at the storage layer (SQLite triggers) |
| `I-LOG-3` | `entry[n].prevHash == entry[n-1].hash`; entry 0 is all zeroes |
| `I-BANK-1` | Committed hashes are over canonical JSON (sorted keys, integers only) |
| `I-ADMIT-1` | Admit tokens carry a per-exam salted hash, never a registration id |
| `I-CA-1` | Server certs carry serverAuth only; client certs clientAuth only |
| `I-CA-2` | Centre and custodian certs bind a hardware identifier |
| `I-CA-3` | A missing or stale CRL is a hard failure, never a silent pass |
| `I-REL-1` | The release schedule's signature is verified on every attempt |
| `I-REL-2` | The plaintext KEK exists only inside one call, zeroized on all paths |
| `I-REL-3` | Early release attempts are logged before being refused |
| `I-CTR-1` | Centre state holds exam content only as ciphertext; KEKs are memory-only |
| `I-CTR-2` | The exam-day path takes no network dependency |
| `I-GEN-1` | Generation depends only on (seed, draw sequence) |
| `I-GEN-2` | Assembly is a pure function of (content, exam, centre, token hash) |
| `I-GEN-3` | Rendering is a pure function of the assembled paper |
| `I-OPS-1` | Log fields pass through a redactor |
| `I-OPS-2` | Metric labels pass through the same redactor |
| `I-SRV-1` | Authorization uses the verified client certificate CN, never a parameter |
| `I-VER-1` | Audit conclusions derive from evidence and auditor-supplied trust only |

---

## The 500 ms budget

The reconstructed plaintext KEK exists only inside
`KeyProvider.reconstructWrapRelease`: reconstruct → verify fingerprint →
seal to every recipient → zeroize in a `finally`. Its lifetime is measured in
microseconds and returned.

A run exceeding 500 ms **fails the release** rather than warning (D-24). The
KEK is zeroized either way. A host that cannot complete this in half a second
is under memory pressure, CPU contention, or has a debugger attached — none
of which should be true of a machine performing a threshold release. The
release is retryable on a clean host with the same shares.

Measured: **0.57 ms** with 3 centres, **under 1 ms** with 20.

---

## Security properties by phase

**Before provisioning** — plaintext bank exists on encrypted media and inside
the vault host only. Destroyed after ingestion (ceremony step 6).

**Between provisioning and T-0** — no plaintext KEK exists anywhere on Earth.
The bank exists as ciphertext at the authority and at every centre.
Reconstruction requires 3 of 5 custodians. This is the window the system is
named for, and it is closed structurally, not by policy.

**At T-0** — the KEK exists for sub-millisecond intervals inside the release
call on the authority host, and thereafter in centre memory until the exam
closes.

**After close** — centres discard KEKs from memory. Answer keys are released
by a second threshold ceremony.

---

## What this system does not defend against

Stated plainly, because a security document that claims completeness is
lying.

- **Kernel-level compromise of the authority during the release window.** A
  0.57 ms window, but not zero. Mitigation is operational: hardened units,
  minimal host, attended release.
- **Three colluding custodians.** That is what a 3-of-5 threshold means. The
  controls are the signed schedule (an early attempt is refused and logged
  naming them) and the evidence trail.
- **A photograph of a paper legitimately in a candidate's hands.**
  Determinism provides attribution, not prevention.
- **Coercion of a TSA operator.** Mitigated by requiring anchors from
  independently operated TSAs.
- **Malicious hardware or firmware** on authority or centre hosts.
- **An invigilator admitting someone whose card does not verify.** The system
  refuses the card and says why; a human can still wave someone through.

---

## Reporting a vulnerability

Do not open a public issue for a security defect in the custody chain.

Contact the deploying agency's security officer, and the maintainers, with:
the affected version or commit, a description of the impact in terms of the
threat table (THREATS.md), reproduction steps, and — if the defect concerns
evidence integrity — an evidence bundle demonstrating it.

If a defect allows exam content to be read before T-0, or allows the
transparency log to be rewritten without detection, treat it as SEV-1 and
follow runbooks/incident-response.md for any exam currently in custody.
