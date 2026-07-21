# Impact analysis — India's examination paper leaks

## Purpose of this document

ZERO-WINDOW was built in response to a specific, documented failure: exam
papers leak from inside the custody chain between creation and exam start.
This document sets out what is actually documented about that problem in
India, and — row by row — which of those failures this architecture would
have prevented, which it would not, and why.

It deliberately does not claim the problem is solved. A system that has never
run a live examination has not solved anything. What follows is the case for
a pilot, stated at the strength the evidence supports.

---

## 1. The documented record

### Scale

| Finding | Source |
|---|---|
| 50+ paper-leak cases in government recruitment exams since 2015, across 8 states, affecting **1.4 crore+ aspirants** | [Tribune India](https://www.tribuneindia.com/news/india/50-cases-of-public-exam-paper-leak-since-2015-588102) |
| 48 leak instances across 16 states in 5 years, touching **1.51 crore applicants** for ~1.2 lakh posts | Indian Express investigation, as reported in the above |
| ~89 papers leaked over the decade, leading to **48 re-examinations** | [Legal Service India](https://www.legalserviceindia.com/Legal-Articles/india-examination-crisis-paper-leaks-exam-cancellations-accountability/) |

The ratio deserves attention: roughly **1.5 crore candidates competing for
about 1.2 lakh posts**. Each cancellation displaces on the order of a hundred
applicants per available position.

### Major incidents

| Year | Examination | Candidates affected | Outcome |
|---|---|---|---|
| 2021 | UP Teacher Eligibility Test (UPTET) | ~21 lakh | Cancelled; 23 arrested |
| 2022 | UKSSSC graduate-level (Uttarakhand) | — | Cancelled, re-conducted within 3 months |
| 2024 | UP Police Constable recruitment | ~48 lakh | Cancelled 24 Feb; 300+ arrested |
| 2024 | UGC-NET | 9.08 lakh | Cancelled — paper surfaced on the darknet |
| 2024 | NEET-UG | 24 lakh sat; 1,563 results cancelled | Paper sold ~₹30–32 lakh/candidate, leaked ~24h before |
| 2024 | Rajasthan (RPSC) | — | ED attached assets of an ex-RPSC member in a money-laundering probe |

Sources: [Careers360 NEET timeline](https://news.careers360.com/neet-ug-paper-leak-2024-arrests-investigations-bihar-gujarat-solver-gang-cheating-cases-demands-for-re-exam-justice-story-so-far), [Careers360 UGC-NET](https://news.careers360.com/ugc-net-2024-cancelled-lax-system-paper-leak-government-opposition-targets-bjp-education-minister), [Deccan Herald UPTET](https://www.deccanherald.com/amp/story/india%2Fup-tet-2021-question-paper-leaked-exam-cancelled-1055389.html), [Deccan Herald RPSC](https://www.deccanherald.com/amp/story/india%2Frajasthan%2Frajasthan-paper-leak-ed-attaches-assets-of-ex-rpsc-member-agents-in-money-laundering-probe-2655403), [Wikipedia](https://en.wikipedia.org/wiki/Paper_leak_in_India).

### Legislative response

The **Public Examinations (Prevention of Unfair Means) Act, 2024** received
assent on 25 February 2024 and came into force 21 June 2024. It covers UPSC,
SSC, RRB, NTA, IBPS and central government departments, with 3–5 years'
imprisonment and fines to ₹10 lakh for individuals, and up to **₹1 crore**
for organised crime.
([PRS](https://prsindia.org/billtrack/the-public-examinations-prevention-of-unfair-means-bill-2024),
[India Code](https://www.indiacode.nic.in/handle/123456789/20100?view_type=browse))

The Act punishes leaks after they occur. It does not change whether a leak is
*possible*. That gap is what this architecture addresses.

---

## 2. On the economic cost

**There is no credible published figure for the cumulative economic cost of
paper leaks in India, and this document will not invent one.**

I searched for one. What exists is fragmentary:

- Coaching-market size in adjacent categories — e.g. a Tamil Nadu government
  committee estimated NEET-specific coaching in that state alone at
  **₹5,750 crore** ([Deccan Herald](https://www.deccanherald.com/india/neet-related-coaching-centres-business-in-tamil-nadu-is-rs-5750-crore-report-1032854)) —
  but coaching spend is not leak-caused loss.
- Per-candidate leak prices in prosecutions: **₹8–10 lakh** in some cases,
  **₹30–32 lakh** in the NEET-UG 2024 Bihar case. These are bribe prices, not
  economic cost.
- Re-examination costs, candidate travel and accommodation, and delayed
  recruitment are all described qualitatively in the literature; none is
  quantified nationally.

A defensible cost model would need: direct re-examination expenditure per
exam, candidate-side costs (fees, travel, lost wages, extra coaching for a
delayed cycle), the cost of posts left vacant during litigation, and a value
for reduced trust. Those inputs are not publicly available in a consistent
form.

**What can be said honestly:** the affected population is documented at
**1.4–1.5 crore candidates**, and 48+ re-examinations have occurred. Any
per-candidate cost an agency can defend from its own records multiplies into
a very large number. That multiplication is the agency's to perform with its
own figures — not something to assert here.

Publishing an invented total would be the fastest way to lose a technical
audience that can check it.

---

## 3. Which leak vectors this architecture actually closes

The design targets the window between bundle creation and T-0. Not every
documented Indian leak occurs in that window.

### Closed by design

| Vector | Mechanism | Threat row |
|---|---|---|
| **Strongroom / treasury storage leak** — papers sit in physical custody for days | Centres hold ciphertext only. There is no readable paper to steal before T-0. | T2, T3 |
| **Transport interception** | AEAD ciphertext with the envelope hash committed to the log; a centre refuses a bundle whose hash disagrees. | T3 |
| **Printing-press insider** — the classic central-press leak | There is no central press. Papers are generated and printed at the centre at T-0. | T1, T2 |
| **Single-official early opening** | Decryption needs 3-of-5 custodians. No individual — including the system operator — can decrypt early. | T2, T9 |
| **Operator backdating the record** to conceal a leak | Hash-chained log with Merkle checkpoints anchored to independently operated RFC 3161 TSAs. | T5, T6 |
| **Untraceable circulated paper** | Every candidate's paper is unique and re-derivable byte-for-byte from log data. A photograph traces to a seat. | T4 |
| **Fabricated "leak" claims** used to force a cancellation | An artifact either re-derives from the log or it is not a paper this system produced. | T4, T5 |

The NEET-UG 2024 pattern specifically — a paper obtained roughly 24 hours
before the exam and sold — is the case this architecture is built against.
Twenty-four hours before T-0, no plaintext paper exists anywhere: not at the
authority, not at the centre, not in any custodian's possession.

### **Not** closed — stated plainly

| Vector | Why the architecture does not help |
|---|---|
| **Question-setter or paper-setting agency collusion** | Content leaked at authorship is outside the vault boundary. The system encrypts what it is given; it cannot protect a paper that left before ingestion. |
| **Solver gangs operating during the exam** | Once candidates hold papers, the custody chain has done its job. In-hall electronic cheating is a different control set. |
| **Impersonation with complicit officials** ("dummy candidates") | Signed admit tokens prove the *card* is authentic, not that the bearer is the registered candidate. A bribed invigilator can still admit someone. |
| **Post-exam OMR/answer-sheet tampering** | Out of scope. This system's custody ends at printing; marking integrity is a separate problem. |
| **Coercion of three or more custodians** | That is what a 3-of-5 threshold means. The controls are that the attempt is refused, logged and attributable — not that it is impossible. |
| **Compromised hardware or a kernel-level attacker on the authority during the ~0.6 ms release window** | Measured at 0.57 ms in the pilot, but not zero. Mitigation is operational. |

An honest reading: this architecture removes the **custody window** as a leak
vector. It does not remove human corruption at authorship or in the hall. It
does make every remaining vector *attributable* — which is a real change,
because most of the documented cases were detected only after candidates
started talking, not by any control.

---

## 4. Why there is no AI in the trust path — deliberately

There is no machine learning, no anomaly detection and no analytics in any
security-relevant path of this system, and adding some would make it weaker.

The guarantees here are of two kinds:

1. **Information-theoretic** — any 2 of 5 Shamir shares are *provably*
   independent of the key. Not "hard to break": mathematically independent,
   verified by a chi-square test in the suite.
2. **Computational, with standard primitives** — XChaCha20-Poly1305, Ed25519,
   BLAKE2b, all with published known-answer tests.

Both are *checkable*. An auditor re-runs the verifier and gets a deterministic
answer. A model that scores an event as 0.94-suspicious gives an auditor
nothing to check, has false positives and false negatives, and can be evaded
by anyone who understands its features. Putting one in the release path would
replace a proof with a guess and become the weakest link.

Where analytics genuinely belongs is **outside** the trust boundary: the
system already emits structured JSON logs and Prometheus metrics, and an
agency can run whatever detection it likes over
`zw_authority_early_release_attempts_total` or the anchored evidence stream.
That is monitoring built on top of proofs, which is the right order. Doing it
the other way round — proofs justified by monitoring — is how systems end up
looking secure and not being secure.

Likewise, this system is **not bulletproof**, and
[SECURITY.md](SECURITY.md#what-this-system-does-not-defend-against) says so in
a dedicated section. That section is not a weakness in the pitch; it is the
reason the rest of the claims are worth believing.

---

## 5. What would have to be true to claim this "solves" the problem

Current status: v1.0 passes a 10/10 acceptance rehearsal — 3 centres, 300
candidates, live TSA anchoring, independent audit. **It has never run a live
examination.**

To make a defensible claim of impact, in order:

1. **An adversarial audit** by a party with no stake in the outcome — ideally
   commissioned by a body that would prefer it to fail.
2. **A single-centre live pilot** on a low-stakes examination, with the full
   ceremony and a published audit report.
3. **A multi-centre pilot** at district scale, including a deliberate failure
   drill on exam day.
4. **Load validation at national scale.** The release path currently seals to
   recipients serially; at 5,000 centres this may itself threaten the 500 ms
   budget ([ROADMAP.md](ROADMAP.md) item 6). This is unproven above 20.
5. **HSM-backed keys and contracted TSAs**, per
   [INTEGRATIONS.md](INTEGRATIONS.md).
6. **Legal and procedural integration** — the Public Examinations Act 2024
   assumes a leak is investigated after the fact; this architecture produces
   evidence a court has not yet been asked to weigh.

Only after (2) can anyone honestly say a paper leak was prevented rather than
made structurally harder.

---

## 6. The case, stated at its true strength

India cancels examinations affecting crores of candidates because papers
become readable to people who should not be able to read them, and because
after the fact nobody can prove what happened. The 2024 Act raised the
penalty for getting caught. It did not reduce the number of people who *can*
leak a paper.

This architecture reduces that number to zero for the custody window: between
provisioning and T-0, decrypting a paper requires three of five custodians
acting together, and every custody event is committed to a log anchored to
timestamping services no exam board controls. When something does go wrong,
an auditor with no access to the operator's systems can establish what
happened from evidence files alone.

That is a narrower claim than "solved". It is also one that survives contact
with a hostile reviewer — which, given the subject matter, is the only kind
of claim worth making.
