import { domainHash } from "@zw/crypto";

/**
 * Item bank schema and canonical serialization.
 *
 * The bank is the plaintext exam content. It exists in the clear only inside
 * the authority vault boundary, and only during ingestion (T1).
 */

export type Difficulty = "easy" | "medium" | "hard";

export interface Item {
  id: string;
  subject: string;
  difficulty: Difficulty;
  body: string;
  /** Answer options in presentation order as authored. */
  options: string[];
  /** Index into `options`. Lives in the answer-key bundle, never the paper bundle. */
  correctIndex: number;
}

export interface ItemBank {
  examId: string;
  items: Item[];
}

/** Blueprint: how many items of each (subject, difficulty) a paper contains. */
export interface BlueprintSlot {
  subject: string;
  difficulty: Difficulty;
  count: number;
}

export interface Blueprint {
  examId: string;
  title: string;
  durationMinutes: number;
  slots: BlueprintSlot[];
}

export class BankValidationError extends Error {
  constructor(
    message: string,
    readonly problems: string[],
  ) {
    super(message);
    this.name = "BankValidationError";
  }
}

const DIFFICULTIES: readonly Difficulty[] = ["easy", "medium", "hard"];

/**
 * Validate a bank against a blueprint. Runs at ingestion so that a bank which
 * cannot satisfy the blueprint is rejected while a human is still present —
 * discovering it at T-0 is not recoverable.
 */
export function validateBank(bank: ItemBank, blueprint: Blueprint): void {
  const problems: string[] = [];

  if (bank.examId !== blueprint.examId) {
    problems.push(`bank examId ${bank.examId} does not match blueprint ${blueprint.examId}`);
  }
  if (bank.items.length === 0) problems.push("bank contains no items");

  const seen = new Set<string>();
  for (const [i, item] of bank.items.entries()) {
    const where = `item[${i}]${item.id ? ` (${item.id})` : ""}`;
    if (!item.id || typeof item.id !== "string") problems.push(`${where}: missing id`);
    else if (seen.has(item.id)) problems.push(`${where}: duplicate id`);
    else seen.add(item.id);

    if (!item.subject) problems.push(`${where}: missing subject`);
    if (!DIFFICULTIES.includes(item.difficulty)) {
      problems.push(`${where}: difficulty must be one of ${DIFFICULTIES.join("|")}`);
    }
    if (!item.body?.trim()) problems.push(`${where}: empty body`);
    if (!Array.isArray(item.options) || item.options.length < 2) {
      problems.push(`${where}: needs at least 2 options`);
    } else if (item.options.some((o) => !o?.trim())) {
      problems.push(`${where}: contains an empty option`);
    }
    if (
      !Number.isInteger(item.correctIndex) ||
      item.correctIndex < 0 ||
      item.correctIndex >= (item.options?.length ?? 0)
    ) {
      problems.push(`${where}: correctIndex out of range`);
    }
  }

  // The blueprint must be satisfiable, with margin: a paper is drawn from the
  // pool per slot, so a pool equal to the slot size would make every paper
  // identical in content and defeat per-candidate uniqueness (T4).
  for (const slot of blueprint.slots) {
    const pool = bank.items.filter(
      (it) => it.subject === slot.subject && it.difficulty === slot.difficulty,
    );
    if (slot.count <= 0) {
      problems.push(`blueprint slot ${slot.subject}/${slot.difficulty}: count must be positive`);
    }
    if (pool.length < slot.count) {
      problems.push(
        `blueprint slot ${slot.subject}/${slot.difficulty} needs ${slot.count} items, ` +
          `bank has ${pool.length}`,
      );
    }
  }
  if (blueprint.slots.length === 0) problems.push("blueprint has no slots");

  if (problems.length > 0) {
    throw new BankValidationError(
      `item bank failed validation (${problems.length} problem(s))`,
      problems,
    );
  }
}

/**
 * Canonical JSON: sorted keys, no insignificant whitespace, UTF-8. Every hash
 * committed to the transparency log is taken over this encoding, so the same
 * logical content always produces the same hash on any machine
 * (INVARIANT I-BANK-1).
 */
export function canonicalJson(value: unknown): Buffer {
  return Buffer.from(canonicalStringify(value), "utf8");
}

function canonicalStringify(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("cannot canonicalize non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalStringify(v)}`).join(",")}}`;
  }
  throw new Error(`cannot canonicalize ${typeof value}`);
}

/** The paper bundle: everything a centre needs to render papers, minus answers. */
export interface PaperBundleContent {
  examId: string;
  blueprint: Blueprint;
  items: Array<Omit<Item, "correctIndex">>;
}

/** The answer-key bundle: released only after the exam closes. */
export interface AnswerBundleContent {
  examId: string;
  answers: Array<{ id: string; correctIndex: number }>;
}

export function splitBank(
  bank: ItemBank,
  blueprint: Blueprint,
): { paper: PaperBundleContent; answers: AnswerBundleContent } {
  return {
    paper: {
      examId: bank.examId,
      blueprint,
      items: bank.items.map(({ correctIndex: _drop, ...rest }) => rest),
    },
    answers: {
      examId: bank.examId,
      answers: bank.items.map((it) => ({ id: it.id, correctIndex: it.correctIndex })),
    },
  };
}

export function contentHash(content: unknown): Buffer {
  return domainHash("bundle-content", canonicalJson(content));
}
