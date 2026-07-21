import { afterEach, describe, expect, it } from "vitest";
import { generateSigningKeyPair } from "@zw/crypto";
import {
  admitTokenHash,
  decodeAdmitToken,
  encodeAdmitToken,
  registrationHash,
  verifyAdmitToken,
} from "../src/admit.js";
import { Authority } from "../src/authority.js";
import { cleanupDirs, newAuthority } from "./helpers.js";

afterEach(async () => {
  await cleanupDirs();
});

const ROSTER = [
  { registrationId: "REG-0001", seat: "A-01" },
  { registrationId: "REG-0002", seat: "A-02" },
  { registrationId: "REG-0003", seat: "A-03" },
];

async function issued(opts: { expiresAt?: number } = {}) {
  const h = await newAuthority();
  const salt = Authority.newRegistrationSalt();
  const tokens = await h.authority.issueAdmitTokens({
    examId: "EXAM-2026-PHYS",
    centreId: "CENTRE-A",
    salt,
    expiresAt: opts.expiresAt ?? Date.now() + 86_400_000,
    candidates: ROSTER,
  });
  return { h, salt, tokens };
}

describe("F2 admit tokens", () => {
  it("verify offline against the authority public key alone", async () => {
    const { h, tokens } = await issued();
    for (const t of tokens) {
      const verdict = verifyAdmitToken(t, h.authority.publicKey, {
        examId: "EXAM-2026-PHYS",
        centreId: "CENTRE-A",
      });
      expect(verdict.ok).toBe(true);
    }
    await h.close();
  });

  it("T7: a forged or altered token is refused with a precise reason", async () => {
    const { h, tokens } = await issued();
    const good = tokens[0]!;
    const pk = h.authority.publicKey;
    const expect_ = { examId: "EXAM-2026-PHYS", centreId: "CENTRE-A" };

    // Altered seat — signature no longer covers the body.
    expect(verifyAdmitToken({ ...good, seat: "A-99" }, pk, expect_)).toMatchObject({
      ok: false,
      code: "BAD_SIGNATURE",
    });

    // Altered expiry, to extend admissibility.
    expect(
      verifyAdmitToken({ ...good, expiresAt: good.expiresAt + 86_400_000 }, pk, expect_),
    ).toMatchObject({ ok: false, code: "BAD_SIGNATURE" });

    // Signed by a different key entirely.
    const impostor = generateSigningKeyPair();
    expect(verifyAdmitToken(good, impostor.publicKey, expect_)).toMatchObject({
      ok: false,
      code: "BAD_SIGNATURE",
    });
    await h.close();
  });

  it("refuses a token issued for another centre or another exam", async () => {
    const { h, tokens } = await issued();
    expect(
      verifyAdmitToken(tokens[0]!, h.authority.publicKey, {
        examId: "EXAM-2026-PHYS",
        centreId: "CENTRE-B",
      }),
    ).toMatchObject({ ok: false, code: "WRONG_CENTRE" });
    expect(
      verifyAdmitToken(tokens[0]!, h.authority.publicKey, {
        examId: "EXAM-OTHER",
        centreId: "CENTRE-A",
      }),
    ).toMatchObject({ ok: false, code: "WRONG_EXAM" });
    await h.close();
  });

  it("refuses an expired token", async () => {
    const { h, tokens } = await issued({ expiresAt: Date.now() - 1000 });
    const v = verifyAdmitToken(tokens[0]!, h.authority.publicKey, {
      examId: "EXAM-2026-PHYS",
      centreId: "CENTRE-A",
    });
    expect(v).toMatchObject({ ok: false, code: "EXPIRED" });
    await h.close();
  });

  it("refuses malformed and unsupported-version tokens without throwing", async () => {
    const { h, tokens } = await issued();
    const pk = h.authority.publicKey;
    const e = { examId: "EXAM-2026-PHYS", centreId: "CENTRE-A" };
    expect(
      verifyAdmitToken({ ...tokens[0]!, signature: undefined as never }, pk, e),
    ).toMatchObject({ ok: false, code: "MALFORMED" });
    expect(verifyAdmitToken({ ...tokens[0]!, v: 99 }, pk, e)).toMatchObject({
      ok: false,
      code: "UNSUPPORTED_VERSION",
    });
    await h.close();
  });

  it("survives the QR round trip", async () => {
    const { h, tokens } = await issued();
    for (const t of tokens) {
      const qr = encodeAdmitToken(t);
      // Comfortably inside QR capacity at high error correction.
      expect(qr.length).toBeLessThan(700);
      expect(qr).toMatch(/^[A-Za-z0-9_-]+$/);
      const back = decodeAdmitToken(qr);
      expect(
        verifyAdmitToken(back, h.authority.publicKey, {
          examId: "EXAM-2026-PHYS",
          centreId: "CENTRE-A",
        }).ok,
      ).toBe(true);
    }
    expect(() => decodeAdmitToken("not-a-token")).toThrow(/base64url|JSON|object/);
    await h.close();
  });
});

describe("T8: the ledger is not a surveillance dataset", () => {
  it("no registration id or seat-linkable PII enters the log", async () => {
    const { h } = await issued();
    const serialized = JSON.stringify(h.authority.log.entries());
    for (const c of ROSTER) {
      expect(serialized).not.toContain(c.registrationId);
    }
    // The log carries the count and token hashes, nothing more.
    const entry = h.authority.log.entries().find((e) => e.type === "ADMIT_TOKENS_ISSUED")!;
    expect(entry.payload["count"]).toBe(3);
    expect((entry.payload["token_hashes"] as string[])[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(entry.payload)).not.toContain("REG-");
    await h.close();
  });

  it("I-ADMIT-1: the same candidate is unlinkable across exams", async () => {
    const saltA = Authority.newRegistrationSalt();
    const saltB = Authority.newRegistrationSalt();
    const id = "REG-0001";
    expect(registrationHash(saltA, id).equals(registrationHash(saltB, id))).toBe(false);
    // Deterministic under a fixed salt, so a centre can still match a
    // candidate to their token when the registration system supplies the salt.
    expect(registrationHash(saltA, id).equals(registrationHash(saltA, id))).toBe(true);
  });

  it("token hash is a stable identity for seat binding", async () => {
    const { h, tokens } = await issued();
    const { signature: _s, ...body } = tokens[0]!;
    const hash = admitTokenHash(body);
    expect(hash).toHaveLength(32);
    // Stable across encode/decode — the centre computes the same binding key
    // the authority recorded.
    const back = decodeAdmitToken(encodeAdmitToken(tokens[0]!));
    const { signature: _s2, ...backBody } = back;
    expect(admitTokenHash(backBody).equals(hash)).toBe(true);
    await h.close();
  });
});
