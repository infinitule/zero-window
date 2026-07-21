import {
  domainHash,
  serializeAead,
  type CustodianRecipient,
  type KeyProvider,
} from "@zw/crypto";
import type { TransparencyLog } from "@zw/log";
import {
  canonicalJson,
  contentHash,
  splitBank,
  validateBank,
  type Blueprint,
  type ItemBank,
} from "./bank.js";
import type { AuthorityStore } from "./store.js";

/**
 * F1 provisioning: ingest → build → encrypt → split → issue shares.
 *
 * The whole flow runs inside the authority vault boundary. Plaintext exists
 * only as a local variable during `provisionExam`; nothing plaintext is ever
 * written to the store (I-AUTH-1), and the KEK is destroyed inside the
 * provider the moment it has been split (I-KP-2).
 */

export interface ProvisionOptions {
  bank: ItemBank;
  blueprint: Blueprint;
  /** Custodians who will hold shares. Default policy is 3-of-5 (D-3). */
  custodians: Array<{ custodianId: string; boxPublicKey: Buffer }>;
  threshold: number;
  /** Injected for deterministic tests; defaults to Date.now. */
  now?: () => number;
}

export interface ProvisionedBundle {
  bundleId: string;
  kind: "paper" | "answers";
  bundleHash: string;
  contentHash: string;
  kekFingerprint: string;
}

export interface ProvisionResult {
  examId: string;
  paper: ProvisionedBundle;
  answers: ProvisionedBundle;
}

export function bundleId(examId: string, kind: "paper" | "answers"): string {
  return `${examId}:${kind}`;
}

/** AEAD associated data binds a ciphertext to its bundle identity (T3). */
export function bundleAssociatedData(id: string, kind: string, examId: string): Buffer {
  return canonicalJson({ bundleId: id, kind, examId, v: 1 });
}

export async function provisionExam(
  opts: ProvisionOptions,
  deps: { provider: KeyProvider; store: AuthorityStore; log: TransparencyLog },
): Promise<ProvisionResult> {
  const now = opts.now ?? Date.now;
  const { provider, store, log } = deps;

  validateBank(opts.bank, opts.blueprint);

  if (opts.threshold < 2) throw new Error("threshold must be at least 2");
  if (opts.custodians.length < opts.threshold) {
    throw new Error(
      `${opts.custodians.length} custodian(s) for a threshold of ${opts.threshold}: ` +
        "cannot issue a share set that could ever be reconstructed",
    );
  }
  for (const c of opts.custodians) {
    if (!store.custodian(c.custodianId)) {
      throw new Error(`custodian ${c.custodianId} is not enrolled`);
    }
  }

  const { paper, answers } = splitBank(opts.bank, opts.blueprint);
  const recipients: CustodianRecipient[] = opts.custodians.map((c) => ({
    custodianId: c.custodianId,
    boxPublicKey: c.boxPublicKey,
  }));

  const results: Record<"paper" | "answers", ProvisionedBundle> = {
    paper: await buildBundle("paper", opts.bank.examId, paper),
    answers: await buildBundle("answers", opts.bank.examId, answers),
  };

  return { examId: opts.bank.examId, paper: results.paper, answers: results.answers };

  async function buildBundle(
    kind: "paper" | "answers",
    examId: string,
    content: unknown,
  ): Promise<ProvisionedBundle> {
    const id = bundleId(examId, kind);
    const kekId = `kek:${id}`;

    // T1: the KEK is generated INSIDE the provider and never leaves it.
    // Distinct KEKs per bundle: the answer-key bundle must remain sealed
    // when the paper KEK is released at T-0 (F1).
    const kekFingerprint = await provider.generateKek(kekId);

    const plaintext = canonicalJson(content);
    const chash = contentHash(content);
    const ad = bundleAssociatedData(id, kind, examId);
    const envelope = serializeAead(await provider.aeadEncryptWithKek(kekId, plaintext, ad));
    plaintext.fill(0); // plaintext exam content does not linger in this process

    const bundleHash = domainHash("bundle-envelope", envelope);

    // Split immediately: the window in which a plaintext KEK exists anywhere
    // is bounded by these two adjacent calls (T1).
    const encShares = await provider.splitAndDestroyKek(kekId, {
      threshold: opts.threshold,
      custodians: recipients,
    });

    const createdAt = now();
    store.putBundle({
      bundleId: id,
      examId,
      kind,
      bundleHash: bundleHash.toString("hex"),
      contentHash: chash.toString("hex"),
      kekFingerprint: kekFingerprint.toString("hex"),
      threshold: opts.threshold,
      shareCount: encShares.length,
      createdAt,
      ciphertext: envelope,
    });

    await log.append({
      type: "BUNDLE_CREATED",
      payload: {
        bundle_id: id,
        exam_id: examId,
        kind,
        bundle_hash: bundleHash.toString("hex"),
        content_hash: chash.toString("hex"),
        kek_fingerprint: kekFingerprint.toString("hex"),
        threshold: opts.threshold,
        share_count: encShares.length,
        item_count: kind === "paper" ? opts.bank.items.length : opts.bank.items.length,
      },
      ts: createdAt,
    });

    for (const s of encShares) {
      store.putShare({
        bundleId: id,
        custodianId: s.custodianId,
        x: s.x,
        sealed: s.sealed,
        issuedAt: createdAt,
      });
    }

    // T9: share issuance is itself evidence. The log records WHO holds a
    // share and the hash of the sealed envelope they received — enough for an
    // auditor to prove a custodian was issued a share, without revealing it.
    await log.append({
      type: "SHARES_ISSUED",
      payload: {
        bundle_id: id,
        exam_id: examId,
        threshold: opts.threshold,
        custodians: encShares.map((s) => ({
          custodian_id: s.custodianId,
          x: s.x,
          sealed_hash: domainHash("sealed-share", s.sealed).toString("hex"),
        })),
      },
      ts: createdAt,
    });

    return {
      bundleId: id,
      kind,
      bundleHash: bundleHash.toString("hex"),
      contentHash: chash.toString("hex"),
      kekFingerprint: kekFingerprint.toString("hex"),
    };
  }
}

/**
 * Record distribution of a ciphertext bundle to a centre. The bundle hash
 * goes in the log at this point so a centre that later receives a mismatched
 * bundle can prove the mismatch against the log rather than against the
 * authority's word (T3).
 */
export async function recordDistribution(
  bundleIdValue: string,
  centreId: string,
  deps: { store: AuthorityStore; log: TransparencyLog },
  now = Date.now(),
): Promise<void> {
  const bundle = deps.store.bundle(bundleIdValue);
  if (!bundle) throw new Error(`unknown bundle ${bundleIdValue}`);
  if (!deps.store.centre(centreId)) throw new Error(`centre ${centreId} is not enrolled`);

  deps.store.recordDistribution(bundleIdValue, centreId, now);
  await deps.log.append({
    type: "BUNDLE_DISTRIBUTED",
    payload: {
      bundle_id: bundleIdValue,
      exam_id: bundle.examId,
      centre_id: centreId,
      bundle_hash: bundle.bundleHash,
      bytes: bundle.ciphertext.length,
    },
    ts: now,
  });
}
