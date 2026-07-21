# DECISIONS

Delegated and unspecified choices, with rationale. Each entry states what was
decided, why, and what would make us revisit it.

---

## D-1 — Shamir over GF(2^8), byte-parallel, implemented in-tree

**Decision.** `@zw/crypto/shamir` implements Shamir secret sharing over
GF(2^8) with the AES reduction polynomial, one independent random polynomial
per secret byte.

**Why.** libsodium has no threshold primitive. The credible alternatives were
an npm Shamir package or an in-tree implementation. Every widely used Node
Shamir package we assessed is either unmaintained, ships no known-answer
tests, or leaks the secret through non-uniform coefficient generation. This
implementation is ~130 lines, is verified against a table-free reference
implementation of GF multiply for all 65 536 input pairs, has a KAT with a
pinned digest, and has a statistical-independence property test at t−1
shares. Auditability of a small in-tree implementation beat a dependency we
could not vouch for.

**Revisit if.** A audited threshold library with published KATs becomes
available for Node, or the scheme moves to verifiable secret sharing (see
ROADMAP v1.1 — VSS would let a custodian prove their share is well-formed
before T-0 rather than discovering corruption at release).

## D-2 — Share checksum is a checksum, not a MAC

**Decision.** The 16-byte trailer on a serialized share is an unkeyed
BLAKE2b checksum.

**Why.** It exists to catch corruption and share mix-ups (wrong exam, wrong
custodian, damaged removable media on the offline path) with a precise
diagnostic. Authenticity is not its job: shares travel inside a sealed box
addressed to the custodian's personal key, and the ceremony record that
issues them is signed and logged. A keyed MAC here would need a key that
every custodian holds, which adds a secret without adding a security property
the sealed envelope does not already provide.

**Revisit if.** Shares ever travel outside a sealed, signed envelope.

## D-3 — `file-vault` is a first-class provider, not a test double

**Decision.** `@zw/kms-vault` is a supported production tier: Argon2id-derived
file key, XChaCha20-Poly1305 per entry, passphrase in the OS keyring.

**Why.** The brief requires a real option for pilots without HSM budget.
Making this "the test provider" would mean the pilot runs code the production
deployment does not, which is exactly the class of gap this project exists to
close. Both providers pass the same conformance suite exported from
`@zw/crypto`.

**Security posture.** An attacker with root on the host while the service is
running can read derived key material from process memory. An attacker with
the keystore file alone gets nothing. This is stated in SECURITY.md and is
the reason `pkcs11` is the recommended tier for live high-stakes exams.

## D-4 — PKCS#11 provider uses a non-extractable AES master key wrapping seeds

**Decision.** `@zw/kms-pkcs11` generates one AES-256 key inside the token with
`CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, `CKA_TOKEN=true`, and stores all
ZERO-WINDOW key seeds as AES-GCM ciphertext under it. Seeds are decrypted by
the HSM into mlocked secure buffers for exactly one operation.

**Why.** ZERO-WINDOW's evidence format is libsodium end-to-end — Ed25519
signatures and X25519 sealed boxes — so that any third party can verify a
pilot log with stock libsodium and no HSM. PKCS#11 defines no mechanism
matching `crypto_box_seal`, and EdDSA support is uneven across tokens
(SoftHSM2 requires a `--with-eddsa` build; the Homebrew build used in local
development does not have it). Wrapping seeds under a non-extractable token
key gives the property that matters most at rest: key material is
cryptographically bound to the HSM, and stealing the seed-store file yields
nothing without the token and its PIN.

**What it does not give.** Protection against live root on the host during an
operation. `Pkcs11KeyProvider.capabilities()` reports `nativeEdDSA` so a
deployment knows what its token supports; INTEGRATIONS.md carries the
validated-hardware matrix.

**Revisit if.** The signing path moves to native token EdDSA on hardware that
supports it (YubiHSM 2, Thales Luna) — the provider interface does not change,
only the internals of `sign()`.

## D-5 — PKCS#11 modules are refcounted per process

**Decision.** `Pkcs11Session` keeps a module registry keyed by library path;
`C_Initialize` runs on first acquire and `C_Finalize` only when the last
session closes. `CKR_USER_ALREADY_LOGGED_IN` is treated as success.

**Why.** Both are PKCS#11 semantics that bite in production, not test
artifacts: `C_Initialize` is per-process (a second call returns
`CKR_CRYPTOKI_ALREADY_INITIALIZED`), and login state is per-token
per-application, not per-session. A deployment that opens a second provider —
the pilot harness running authority and centre in one process, or any
reconnect after an error — would otherwise fail on a code path never
exercised until the day it matters.

## D-6 — libsodium reached through a single import point

**Decision.** Only `@zw/crypto/sodium.ts` imports `sodium-native`. Everything
else, including the KDF used by the vault keystore, goes through `@zw/crypto`.

**Why.** The native dependency surface stays auditable in one file, and the
hand-written ambient typings (`sodium-native.d.ts`) declare exactly the
functions in use — anything outside that set is a compile error rather than a
silent `any`.

## D-7 — GF(256) table lookups are not constant-time (accepted residual risk)

**Decision.** Shamir arithmetic uses exp/log tables.

**Why and scope.** Table lookups can leak through cache timing on some
micro-architectures. Shamir arithmetic in ZERO-WINDOW runs only in the
ceremony and release paths, on operator-controlled hardware, never in a
network-facing handler processing attacker-controlled secrets. The realistic
attacker for T1/T9 is an insider with credentials, not a co-resident cache
observer. Accepted and recorded rather than silently ignored; a constant-time
implementation is ~4× slower and buys nothing against the actual threat model.

**Revisit if.** The release service ever runs on shared/multi-tenant compute.

## D-8 — Test entropy is injectable; production entropy is not

**Decision.** `shamirSplit` accepts an optional `entropy` callback used only
by KATs and the statistical-independence test. Production callers omit it and
get the CSPRNG; the PKCS#11 provider supplies the HSM's `C_GenerateRandom`.

**Why.** A pinned KAT for a randomized algorithm requires deterministic
entropy. The alternative — no KAT — leaves the splitter unverified against
regression. The parameter is documented as test-only and the property tests
run against real CSPRNG output as well.

## D-9 — Coverage gate on `@zw/crypto` excludes the conformance suite

**Decision.** `src/conformance.ts` is excluded from `@zw/crypto`'s own
coverage measurement.

**Why.** It is a test suite that ships as source so provider packages can run
it against their own backends. It is fully executed — by
`@zw/kms-vault` and `@zw/kms-pkcs11` — just not by `@zw/crypto`'s own run,
where counting it would measure the wrong thing.

## D-10 — In-tree DER/ASN.1 and CMS verification rather than a library

**Decision.** `@zw/log` implements the DER encoding, RFC 3161 parsing, and
CMS SignedData signature verification it needs (`asn1.ts`, `rfc3161.ts`,
`cms.ts`) instead of depending on a general ASN.1 or PKI library.

**Why.** The verifier is the component a hostile auditor runs to check the
operator's claims. Every byte it parses should be readable in this repository
without following a dependency chain whose parsing behaviour can change
between minor versions. The required surface is small — one request type, one
response type, one CMS profile — and is deliberately narrow: anything outside
the RFC 3161 profile is rejected rather than tolerated. Verified against
tokens from three independently operated public TSAs (FreeTSA, DigiCert,
Sectigo), which exercise different signature algorithms and certificate
layouts.

**Revisit if.** Support is needed for TSAs using mechanisms outside this
profile, at which point the narrow implementation should be extended
deliberately rather than replaced with a permissive parser.

## D-11 — Anchors verify the CMS signature; chain validation belongs to the auditor

**Decision.** `parseTimeStampToken` verifies the TSA's SignerInfo signature
over the token content by default. Certificate CHAIN validation to a trust
anchor, and revocation, are performed by `@zw/verifier` against roots the
deploying agency configures.

**Why.** These are different questions. "Did the holder of this certificate's
key sign our root at the asserted time?" is a cryptographic fact this package
can settle. "Is that certificate a TSA I trust?" is policy, and hard-coding a
trust store into the anchoring client would make the operator's opinion of
trustworthiness part of the evidence. The split keeps the auditor's decision
explicit. SECURITY.md §"What a TSA token proves" states the boundary.

**Not checked, deliberately:** corruption confined to redundant chain
certificates or the informational `digestAlgorithms` hint does not invalidate
a token, because neither is covered by the signature. Tested explicitly.

## D-12 — Merkle inclusion proofs do not pin tree size; checkpoints do

**Decision.** `verifyInclusion` is the standard RFC 6962 algorithm, which
does not by itself authenticate the tree size — for some (index, size) pairs
the path shape coincides, so one proof can verify at more than one size.

**Why it is safe here.** `size` is never taken from the party presenting a
proof. It is covered by the checkpoint's Ed25519 signature and by the
TSA-anchored root, so an operator cannot restate the size of a tree they have
already published. This is asserted by a test so the property is documented
and pinned rather than latent.

## D-13 — Canonical JSON rejects floats and undefined instead of coercing

**Decision.** The canonical encoder throws on non-integer numbers, `undefined`
properties, bigints, and raw binary.

**Why.** Every rejected case is a way two encoders could disagree about what
bytes were signed. A float that round-trips differently, or a property
silently dropped because it was `undefined`, would make a valid log look
forged (or, worse, let a forged one look valid). Timestamps are integer
milliseconds and everything else numeric is a count, so the restriction costs
nothing. Binary must be explicitly base64/hex encoded by the caller so the
encoding is visible in the evidence file.

## D-14 — The log is append-only in the storage engine, not only in the API

**Decision.** SQLite triggers `RAISE(ABORT)` on UPDATE or DELETE of `entries`,
and on DELETE of `checkpoints`.

**Why.** T6 is an operator who rewrites history; that operator has shell
access to the database file. The hash chain already makes rewrites
*detectable*, but making them fail at the storage layer means the honest
operator cannot corrupt the log by accident and the dishonest one must work
visibly harder. Anchors accumulate and are never replaced, so a later TSA
cannot displace an earlier inconvenient timestamp.

## D-15 — TSA fixtures recorded from real services; live tests are opt-in

**Decision.** CI verifies real, recorded RFC 3161 tokens offline. The live
network path runs under `ZW_TSA_MODE=live` (nightly and on demand), and
`scripts/record-tsa-fixtures.mjs` regenerates the fixtures.

**Why.** A public TSA being unreachable must never fail a build or block a
release — the same T10 reasoning that puts a fallback on every exam-day path.
Recording real tokens rather than synthesising them keeps the parser honest
against three independent implementations; the fixture script refuses to write
unless at least two TSAs responded.

## D-16 — ECDSA P-384 for the PKI, not Ed25519 or RSA

**Decision.** All CA and leaf keys are ECDSA P-384 with SHA-384.

**Why.** Ed25519 would be the better primitive on merit and is what the rest
of the stack uses for application signatures, but TLS support for Ed25519
certificates is still uneven across stacks and middleboxes likely to sit
between an authority and a few hundred centres. RSA-4096 costs materially
more per handshake on modest centre-node hardware. P-384 is universally
supported, gives margin over P-256 for certificates that must stay valid
across a multi-year exam cycle, and keeps handshakes cheap.

**Note.** This is a transport-layer choice only. Evidence — log entries,
checkpoints, admit tokens — is Ed25519 throughout, so no auditor needs a
TLS stack to verify it.

## D-17 — Two-tier CA with the root held offline

**Decision.** A root that signs only intermediates (pathLen 1) and an online
issuing intermediate that signs leaves (pathLen 0). `zw-ca init` prints the
path of the root key and instructs the operator to move it to offline media.

**Why.** Compromise of the online issuing key is then recoverable by rotating
one intermediate, rather than re-provisioning every centre in the country.
`rotate-intermediate` deliberately does NOT revoke the previous intermediate:
certificates it signed stay valid until they expire, so a routine rotation
cannot accidentally strand a fleet. Revoking it is a separate, explicit act
for incident response.

## D-18 — One EKU per role, and a hardware binding on client certificates

**Decision.** Server certificates carry serverAuth only; client certificates
carry clientAuth only (I-CA-1). Centre and custodian certificates must carry
a hardware identifier, bound both in the subject (`OU=hw:<id>`) and as a URI
SAN (I-CA-2); issuance refuses without one.

**Why.** A stolen centre client certificate must not be usable to stand up a
server impersonating the authority, and vice versa — the split EKU makes that
structural rather than a matter of configuration. The hardware binding means
a copied key pair presenting from a different machine is detectable at
connection time, which is the realistic form of T7 inside a custody chain.

## D-19 — Revocation fails closed: a missing or stale CRL is an error

**Decision.** `RevocationList.load` throws when the CRL file is absent, and
`assertFresh` throws once `nextUpdate` has passed (I-CA-3). CRLs default to a
24-hour validity window.

**Why.** Revocation that can be disabled by deleting a file, or by simply not
republishing, is not revocation. Making staleness a hard failure means an
operator who stops publishing CRLs takes the fleet down loudly instead of
silently disabling the check — the failure mode you want when the alternative
is accepting a compromised centre certificate at T-0.

## D-20 — CRLs are published with the RFC 7468 label

**Decision.** `generateCrl` rewrites the PEM label from `BEGIN CRL` to
`BEGIN X509 CRL`; the parser accepts both.

**Why.** @peculiar/x509 emits the bare label, which OpenSSL and other standard
tooling refuse to parse — verified by running `openssl crl` against a
published file, which failed before this fix and is now pinned by a test. An
operator following the incident-response runbook must be able to inspect a
published CRL with standard tools.

## D-21 — TLS 1.3 only, and "connected" is not "authenticated"

**Decision.** Both server and client options set `minVersion: TLSv1.3`.
Services treat their own connection handler firing — not the client's connect
callback — as the authentication signal.

**Why.** The deployment is entirely first-party, so there is no legacy peer to
accommodate and no reason to keep TLS 1.2 cipher negotiation in the attack
surface. The second half matters more: in TLS 1.3 the client's connect
callback fires once it has verified the SERVER, before the server has
validated the client certificate, so a rejected client observes a successful
connect and learns it was refused only on a later read. A service that treated
connect as authentication would be wrong in exactly the case that matters.
Asserted by handshake tests that count server-side accepts.

## D-22 — Per-bundle KEKs: the answer key is a separate cryptographic object

**Decision.** Provisioning builds two bundles per exam — paper and answers —
each encrypted under its own freshly generated KEK, each split to the same
custodian set, each with its own release schedule.

**Why.** The answer key must stay sealed at T-0 when the paper KEK is
released, and become available only after the exam closes. Sharing one KEK
would make that a matter of access control on the same secret; separate KEKs
make it structural. Releasing the paper cannot release the answers, and the
test asserts the answers bundle has no schedule and refuses release at T-0.

## D-23 — The release schedule is signed, and verified on every attempt

**Decision.** `scheduleRelease` signs `{v, examId, bundleId, releaseAt}` with
the authority key. `performRelease` re-verifies that signature before
comparing the clock (I-REL-1).

**Why.** Without this, the T-0 check is only as strong as write access to a
SQLite row — an operator could move T-0 earlier and release legitimately. With
it, editing the row invalidates the signature and the release refuses
outright rather than proceeding early. Tested by writing a modified schedule
directly to the store and asserting `SCHEDULE_TAMPERED`.

## D-24 — Blowing the KEK-lifetime budget fails the release

**Decision.** If the measured plaintext-KEK lifetime exceeds 500ms, the
release is failed with `BUDGET_EXCEEDED` even though the wrapping succeeded.
The KEK is zeroized either way.

**Why.** The budget exists to bound the window in which a plaintext KEK is
resident. A run that overshoots it indicates the host is not fit for release
duty — paging, CPU contention, a debugger attached. Treating that as a
warning would normalize exactly the condition the budget is meant to detect.
Failing means an operator investigates before T-0 rather than after a leak.
The alternative — release anyway and alert — was rejected because the release
can simply be retried on a healthy host, so the cost of failing closed is low.

## D-25 — Early release attempts are logged before they are refused

**Decision.** `EARLY_RELEASE_ATTEMPT` is appended to the transparency log,
and a counter incremented, before the error is thrown (I-REL-3). Custodian
approvals are likewise logged before reconstruction is attempted.

**Why.** A custodian attempting to release early is the single most valuable
signal this system can produce, and it must survive the refusal. Logging
after the throw would lose it; logging approvals only on success would erase
the evidence of who authorised a release that then failed.

## D-26 — Registration IDs are salted per exam before hashing

**Decision.** Admit tokens carry `BLAKE2b(salt ‖ registrationId)` under a
per-exam salt (I-ADMIT-1). The salt is written alongside the roster, and the
CLI tells the operator to store it with the registration system rather than
with the exam evidence.

**Why.** T8 asks that the ledger not become a surveillance dataset. An
unsalted hash of a structured national ID is trivially brute-forced, and a
single global salt would let anyone holding two exams' evidence link the same
candidate across them. A per-exam salt makes tokens unlinkable across exams
while keeping them deterministic within one, which is what the centre needs.

## D-27 — Durations are logged as integer microseconds

**Decision.** The KEK lifetime is recorded as `kek_lifetime_us`, an integer,
not as fractional milliseconds.

**Why.** The log's canonical JSON admits integers only, so that an evidence
bundle re-encodes byte-identically on any platform — a float would not, and
the verifier's byte-comparison would fail on a different machine. Recording
microseconds keeps full resolution without floats.

## D-28 — Certificate serials never begin with a zero nibble

**Decision.** `newSerial` forces the top nibble non-zero as well as clearing
the sign bit, and every serial comparison normalizes case and leading zeros.

**Why.** X.509 encoders drop leading zeros when rendering a serial to hex, so
a serial beginning `0x0…` was recorded one way at issuance and reported
another way by Node's TLS stack — the enrolment lookup then failed. This hit
roughly one certificate in sixteen, intermittently, which is the worst way to
discover a fault in a system that runs once a year. Found by a full-workspace
run rather than by the CA's own suite; now pinned by a test that issues 40
certificates and round-trips each serial through Node's parser.
