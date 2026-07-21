import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseAead } from "@zw/crypto";
import { BankValidationError, canonicalJson, validateBank } from "../src/bank.js";
import { cleanupDirs, newAuthority, sampleBank, sampleBlueprint } from "./helpers.js";

afterEach(async () => {
  await cleanupDirs();
});

describe("item bank validation", () => {
  it("accepts a bank that satisfies its blueprint", () => {
    expect(() => validateBank(sampleBank(), sampleBlueprint())).not.toThrow();
  });

  it("rejects a bank that cannot fill a blueprint slot, naming the slot", () => {
    const bank = sampleBank();
    const blueprint = sampleBlueprint();
    blueprint.slots.push({ subject: "chemistry", difficulty: "hard", count: 5 });
    try {
      validateBank(bank, blueprint);
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(BankValidationError);
      expect((err as BankValidationError).problems.join("\n")).toContain(
        "chemistry/hard needs 5 items, bank has 0",
      );
    }
  });

  it("catches malformed items with per-item diagnostics", () => {
    const bank = sampleBank();
    bank.items[0]!.options = ["only one"];
    bank.items[1]!.correctIndex = 99;
    bank.items[2]!.body = "   ";
    bank.items[3]!.id = bank.items[4]!.id;
    try {
      validateBank(bank, sampleBlueprint());
      expect.unreachable("should have thrown");
    } catch (err) {
      const problems = (err as BankValidationError).problems.join("\n");
      expect(problems).toContain("needs at least 2 options");
      expect(problems).toContain("correctIndex out of range");
      expect(problems).toContain("empty body");
      expect(problems).toContain("duplicate id");
    }
  });

  it("rejects a bank whose examId disagrees with the blueprint", () => {
    try {
      validateBank(sampleBank("A"), sampleBlueprint("B"));
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(BankValidationError);
      expect((err as BankValidationError).problems.join("\n")).toContain(
        "bank examId A does not match blueprint B",
      );
    }
  });
});

describe("canonical JSON (I-BANK-1)", () => {
  it("is key-order independent", () => {
    const a = canonicalJson({ b: 1, a: 2, c: { z: 1, y: 2 } });
    const b = canonicalJson({ c: { y: 2, z: 1 }, a: 2, b: 1 });
    expect(a.equals(b)).toBe(true);
  });

  it("drops undefined and preserves array order", () => {
    expect(canonicalJson({ a: undefined, b: [3, 1, 2] }).toString()).toBe('{"b":[3,1,2]}');
  });

  it("refuses values that cannot be canonicalized", () => {
    expect(() => canonicalJson({ n: Number.NaN })).toThrow(/non-finite/);
  });
});

describe("F1 provisioning", () => {
  it("builds two independently-keyed bundles and logs the flow", async () => {
    const h = await newAuthority();
    const result = await h.authority.provision({
      bank: sampleBank(),
      blueprint: sampleBlueprint(),
      threshold: 3,
    });

    expect(result.paper.kekFingerprint).not.toBe(result.answers.kekFingerprint);

    const types = h.authority.log.entries().map((e) => e.type);
    expect(types.filter((t) => t === "BUNDLE_CREATED")).toHaveLength(2);
    expect(types.filter((t) => t === "SHARES_ISSUED")).toHaveLength(2);

    // T9: share issuance is evidence — who got a share, and the hash of what
    // they got, without revealing the share.
    const issued = h.authority.log.entries().find((e) => e.type === "SHARES_ISSUED")!;
    const custodians = issued.payload["custodians"] as Array<Record<string, unknown>>;
    expect(custodians).toHaveLength(5);
    expect(custodians[0]!["sealed_hash"]).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(issued.payload)).not.toContain("shareHex");
    await h.close();
  });

  it("T4: the paper bundle contains no answer keys", async () => {
    const h = await newAuthority();
    const bank = sampleBank();
    const result = await h.authority.provision({
      bank,
      blueprint: sampleBlueprint(),
      threshold: 3,
    });
    const paper = h.authority.store.bundle(result.paper.bundleId)!;
    // The ciphertext obviously does not contain them; assert on the plaintext
    // structure that was committed, via the content hash of a re-derivation.
    const { splitBank } = await import("../src/bank.js");
    const { paper: content } = splitBank(bank, sampleBlueprint());
    expect(JSON.stringify(content)).not.toContain("correctIndex");
    const { contentHash } = await import("../src/bank.js");
    expect(contentHash(content).toString("hex")).toBe(paper.contentHash);
    await h.close();
  });

  it("refuses to provision with fewer custodians than the threshold", async () => {
    const h = await newAuthority({ custodians: 2 });
    await expect(
      h.authority.provision({ bank: sampleBank(), blueprint: sampleBlueprint(), threshold: 3 }),
    ).rejects.toThrow(/cannot issue a share set/);
    await h.close();
  });

  it("refuses a custodian who is not enrolled", async () => {
    const h = await newAuthority();
    await expect(
      h.authority.provision({
        bank: sampleBank(),
        blueprint: sampleBlueprint(),
        threshold: 2,
        custodians: [
          { custodianId: "ghost", boxPublicKey: h.custodians[0]!.keys.publicKey },
          { custodianId: "cust-1", boxPublicKey: h.custodians[0]!.keys.publicKey },
        ],
      }),
    ).rejects.toThrow(/ghost is not enrolled/);
    await h.close();
  });

  it("T3: distribution records the bundle hash a centre must check", async () => {
    const h = await newAuthority();
    const r = await h.authority.provision({
      bank: sampleBank(),
      blueprint: sampleBlueprint(),
      threshold: 3,
    });
    await h.authority.distribute(r.paper.bundleId, "CENTRE-A");
    const dist = h.authority.log.entries().find((e) => e.type === "BUNDLE_DISTRIBUTED")!;
    expect(dist.payload["bundle_hash"]).toBe(r.paper.bundleHash);
    expect(dist.payload["centre_id"]).toBe("CENTRE-A");
    await h.close();
  });

  it("refuses distribution to an unenrolled centre", async () => {
    const h = await newAuthority();
    const r = await h.authority.provision({
      bank: sampleBank(),
      blueprint: sampleBlueprint(),
      threshold: 3,
    });
    await expect(h.authority.distribute(r.paper.bundleId, "CENTRE-ZZ")).rejects.toThrow(
      /not enrolled/,
    );
    await h.close();
  });
});

describe("ACCEPTANCE: no plaintext exam content at rest before T-0 (T1)", () => {
  it("no state file contains any question body, option or answer", async () => {
    const h = await newAuthority();
    const bank = sampleBank();
    const result = await h.authority.provision({
      bank,
      blueprint: sampleBlueprint(),
      threshold: 3,
    });
    for (const c of h.centres) await h.authority.distribute(result.paper.bundleId, c.centreId);
    await h.authority.scheduleRelease({
      examId: result.examId,
      bundleId: result.paper.bundleId,
      releaseAt: Date.now() + 3_600_000,
    });
    await h.authority.checkpoint();

    // Scan every byte the authority has written to disk.
    const files = await readdir(h.dir, { recursive: true, withFileTypes: true });
    const scanned: string[] = [];
    for (const f of files) {
      if (!f.isFile()) continue;
      const path = join(f.parentPath ?? h.dir, f.name);
      scanned.push(path);
      const bytes = await readFile(path);

      for (const item of bank.items) {
        expect(bytes.includes(Buffer.from(item.body, "utf8")), `${path} leaked a question body`).toBe(
          false,
        );
        for (const opt of item.options) {
          expect(bytes.includes(Buffer.from(opt, "utf8")), `${path} leaked an option`).toBe(false);
        }
      }
    }
    expect(scanned.length).toBeGreaterThan(0);

    // And the stored bundle really is a well-formed AEAD envelope, not
    // plaintext that merely happens not to match.
    const stored = h.authority.store.bundle(result.paper.bundleId)!;
    const env = parseAead(stored.ciphertext);
    expect(env.suite).toBe("xchacha20poly1305-ietf");
    expect(env.nonce).toHaveLength(24);
    await h.close();
  });

  it("no raw key material appears in the transparency log", async () => {
    const h = await newAuthority();
    const r = await h.authority.provision({
      bank: sampleBank(),
      blueprint: sampleBlueprint(),
      threshold: 3,
    });
    await h.authority.distribute(r.paper.bundleId, "CENTRE-A");
    await h.authority.scheduleRelease({
      examId: r.examId,
      bundleId: r.paper.bundleId,
      releaseAt: Date.now() - 1000,
    });
    await h.authority.release({
      bundleId: r.paper.bundleId,
      shares: ["cust-1", "cust-2", "cust-3"].map((custodianId) => ({
        custodianId,
        shareBlob: h.openShare(r.paper.bundleId, custodianId),
      })),
    });

    const serialized = JSON.stringify(h.authority.log.entries());
    // Every custodian's actual share bytes must be absent from the log.
    for (const c of h.custodians) {
      const share = h.openShare(r.paper.bundleId, c.custodianId);
      expect(serialized).not.toContain(share.toString("hex"));
      // Also check a distinctive interior slice, in case of any re-encoding.
      expect(serialized).not.toContain(share.subarray(16, 40).toString("hex"));
    }
    // Nor any custodian secret key.
    for (const c of h.custodians) {
      expect(serialized).not.toContain(c.keys.secretKey.toString("hex"));
    }
    await h.close();
  });
});
