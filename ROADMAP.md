# Roadmap — v1.1

v1.0 is complete and passes its acceptance run. This is what v1.1 adds, why,
and what each item costs. Items are ordered by the strength of the argument
for them, not by ease.

---

## 1. OpenTimestamps anchor backend

**Why.** Today's anchors depend on TSAs that are organisations: they can be
compelled, can go out of business, and can have their keys compromised.
OpenTimestamps anchors into the Bitcoin blockchain, which is a different
trust model entirely — no operator to compel. Having both means a backdating
claim must defeat two unlike systems.

**Design.** `AnchorBackend` already abstracts this; the interface needs no
change. `OpenTimestampsBackend` submits the checkpoint root to calendar
servers, stores the incomplete `.ots` proof immediately, and upgrades it to a
Bitcoin-attested proof once confirmed (typically hours). Verification walks
the proof to a block header.

**Complication worth naming.** Unlike RFC 3161, an OTS proof is not
immediately complete. The evidence format must carry a proof that upgrades
after the fact, and the verifier must distinguish "pending" from "attested"
rather than treating an un-upgraded proof as a failure. This is the main
design work, not the protocol integration.

**Effort.** ~2 weeks including evidence-format versioning.

---

## 2. Hardware admit cards (NFC)

**Why.** A printed QR can be photographed and reprinted. The card itself is
not currently unforgeable — only its *contents* are signed, so a copied card
verifies exactly like the original. The duplicate-check-in control catches
the second presenter, which means the honest candidate may be the one turned
away if the impostor arrives first.

**Design.** NTAG 424 DNA cards (or equivalent) storing the same signed token,
plus a per-tap challenge-response using the card's secure element. The
verification interface (`verifyAdmitToken`) already returns a verdict plus a
stable token hash, so the seat binding, logging and paper derivation
downstream need no change — the adapter shape proven by the UIDAI integration
point applies here too.

**Complication.** Cost per candidate, reader provisioning at every hall, and
a fallback for a failed reader that does not reintroduce the copyable path.
The fallback probably has to be "printed QR plus manual identity check",
which is where we are today — so this raises the ceiling without raising the
floor.

**Effort.** ~3 weeks plus hardware procurement lead time.

---

## 3. Multi-authority federation

**Why.** A single authority is a single point of both failure and trust. A
state-level board running exams for several districts may want each district
to hold custody of its own bundles while sharing one evidence chain and one
auditor workflow.

**Design.** Authorities become peers, each with its own signing key and log,
cross-anchoring each other's checkpoints so a rewrite by one is detectable by
the others. `EvidenceBundle` gains a federation manifest; the verifier's
`trustedSigners` map already accommodates multiple actors.

**Complication.** Cross-anchoring is a consensus problem in disguise. The
design must avoid requiring liveness between authorities at T-0 — the whole
point of T10 is that the system survives partition. The likely shape is
asynchronous cross-anchoring after the fact, not synchronous agreement.

**Effort.** ~4–6 weeks. This is the largest item and needs a design review
before implementation.

---

## 4. Split-inside-HSM threshold operations

**Why.** Today Shamir splitting happens in locked host memory using key
material from the provider. That is portable across every HSM in
INTEGRATIONS.md, but it means the KEK is briefly in host RAM rather than
never leaving the token. An agency with a uniform HSM estate can do better.

**Design.** Extend `@zw/kms-pkcs11` with a vendor-specific path where the
device supports on-token key splitting or M-of-N activation (Luna's M-of-N,
CloudHSM quorum). Falls back to the portable path when unavailable.

**Complication.** Every vendor spells this differently, and the fallback must
remain the tested default. Risks becoming vendor-lock disguised as a feature.

**Effort.** ~2 weeks per vendor, and it should only be built against hardware
an agency has actually committed to.

---

## 5. Signed audit reports under an auditor's own key

**Why.** `signReport` currently mints an ephemeral key per report (D-39). The
report is tamper-evident but not attributable to a named auditing body.

**Design.** `zw-verify audit --signing-key <pkcs11-uri|file>` to sign with the
auditor's own credential, and `zw-verify report --expect-signer <hex>` to
check attribution. Deliberately kept out of v1.0 so that no ZERO-WINDOW
install ever mints something claiming to be an auditor identity.

**Effort.** ~3 days.

---

## 6. Load testing at national scale

**Why.** The pilot is 3 centres × 100 candidates. A national examination is
thousands of centres. The release endpoint is the concentration point: every
centre fetches its wrapped KEK within the same minute.

**What to measure.** Wrapped-KEK fan-out at 1 000 and 5 000 centres (the
current implementation wraps serially inside the release call — at 5 000
recipients this may itself threaten the 500 ms budget and likely needs
batching or parallel sealing); TSA rate limits at that checkpoint volume;
mTLS handshake cost at the authority under a synchronised thundering herd.

**Honest expectation.** The 500 ms KEK budget will need re-examination at
that scale. It may become "500 ms per batch" with recipients sealed in
parallel — which is a change to a security-relevant constant and therefore
needs its own decision record.

**Effort.** ~2 weeks including harness.

---

## Not planned, and why

- **Online exam delivery.** A different system with a different threat model.
  This one is about paper.
- **Automatic marking.** Out of scope; the answer-key bundle exists to be
  handed to whatever marking system the agency uses.
- **Cloud-hosted authority.** The trust model assumes the agency controls the
  hardware. A managed offering would reintroduce exactly the operator-trust
  problem the design removes.
- **Automatic retention deletion.** Silently expiring audit records is a T6
  vector. Retention stays an agency policy decision with a human in it.
