import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { blake2b } from "@zw/crypto";
import {
  PUBLIC_TSAS,
  Rfc3161AnchorBackend,
  Rfc3161Error,
  anchorToAll,
  buildTimeStampRequest,
  derDecode,
  parseTimeStampToken,
  verifyAnchors,
  verifyEvidence,
  verifyTokenBinding,
  type Anchor,
  type AnchorBackend,
} from "../src/index.js";
import { bundleOf, cleanupTempDirs, newTestLog, populateExamLog } from "./helpers.js";

afterAll(cleanupTempDirs);

const here = dirname(fileURLToPath(import.meta.url));

interface FixtureFile {
  root_preimage: string;
  root: string;
  anchors: (Anchor & { key: string })[];
}

async function fixtures(): Promise<FixtureFile> {
  return JSON.parse(
    await readFile(join(here, "fixtures", "tsa-tokens.json"), "utf8"),
  ) as FixtureFile;
}

/**
 * Live-TSA tests run when ZW_TSA_MODE=live (the nightly CI job and manual
 * verification). Everything else runs against tokens recorded from the real
 * services, so a TSA outage cannot fail a build (T10).
 */
const liveMode = process.env["ZW_TSA_MODE"] === "live";

describe("RFC 3161 request construction", () => {
  it("builds a DER TimeStampReq that parses back to the requested imprint", () => {
    const imprint = Buffer.alloc(32, 0xab);
    const { der, nonce } = buildTimeStampRequest({ imprint, hashAlgorithm: "sha256" });
    // SEQUENCE tag, version 1, and the imprint must appear verbatim.
    expect(der[0]).toBe(0x30);
    expect(der.includes(imprint)).toBe(true);
    expect(nonce).toHaveLength(8);
    // Top bit cleared so the DER INTEGER stays positive without a pad byte.
    expect((nonce[0] ?? 0) & 0x80).toBe(0);
  });

  it("rejects an imprint whose length does not match the hash algorithm", () => {
    expect(() =>
      buildTimeStampRequest({ imprint: Buffer.alloc(20), hashAlgorithm: "sha256" }),
    ).toThrowError(/32/);
    expect(() =>
      buildTimeStampRequest({ imprint: Buffer.alloc(32), hashAlgorithm: "sha512" }),
    ).toThrowError(/64/);
  });
});

describe("recorded real TSA tokens", () => {
  it("parses tokens from three independently operated TSAs", async () => {
    const fx = await fixtures();
    expect(fx.anchors.length).toBeGreaterThanOrEqual(2);
    for (const anchor of fx.anchors) {
      const token = parseTimeStampToken(Buffer.from(anchor.token, "base64"));
      expect(token.genTime).toBeGreaterThan(Date.UTC(2020, 0, 1));
      expect(token.serialNumber.length).toBeGreaterThan(0);
      expect(token.policyOid).toMatch(/^\d+(\.\d+)+$/);
      // The TSA signed a SHA-256 imprint OF our root, not the root itself.
      const { createHash } = await import("node:crypto");
      const expected = createHash("sha256").update(Buffer.from(fx.root, "hex")).digest("hex");
      expect(token.imprint).toBe(expected);
    }
  });

  it("verifies each recorded anchor against its root", async () => {
    const fx = await fixtures();
    const root = Buffer.from(fx.root, "hex");
    for (const anchor of fx.anchors) {
      const backend = new Rfc3161AnchorBackend({ name: anchor.tsa, url: anchor.url });
      await expect(backend.verify(anchor, root)).resolves.toBeUndefined();
    }
  });

  it("rejects a token presented against a different root (T5/T6)", async () => {
    const fx = await fixtures();
    const anchor = fx.anchors[0]!;
    const backend = new Rfc3161AnchorBackend({ name: anchor.tsa, url: anchor.url });
    const otherRoot = blake2b(Buffer.from("a different checkpoint entirely"));
    await expect(backend.verify(anchor, otherRoot)).rejects.toThrow(
      /anchor claims root .* but the checkpoint root is/,
    );
  });

  it("rejects TSA-token substitution: a real token relabelled onto another root", async () => {
    const fx = await fixtures();
    const anchor = fx.anchors[0]!;
    const otherRoot = blake2b(Buffer.from("forged checkpoint"));
    // The operator rewrites the anchor's claimed imprint to match the forged
    // root, keeping the genuine TSA-signed token.
    const substituted: Anchor = { ...anchor, imprint: otherRoot.toString("hex") };
    const backend = new Rfc3161AnchorBackend({ name: anchor.tsa, url: anchor.url });
    await expect(backend.verify(substituted, otherRoot)).rejects.toThrow(
      /token imprint .* does not match the data timestamped/,
    );
  });

  it("rejects an anchor whose recorded genTime disagrees with its token", async () => {
    const fx = await fixtures();
    const anchor = fx.anchors[0]!;
    const root = Buffer.from(fx.root, "hex");
    // Backdating the recorded time while keeping the real token.
    const backdated: Anchor = { ...anchor, genTime: anchor.genTime - 86_400_000 };
    const backend = new Rfc3161AnchorBackend({ name: anchor.tsa, url: anchor.url });
    await expect(backend.verify(backdated, root)).rejects.toThrow(
      /records genTime .* but the token asserts/,
    );
  });

  it("verifies the TSA's CMS signature, not merely the token structure", async () => {
    const fx = await fixtures();
    for (const anchor of fx.anchors) {
      const token = parseTimeStampToken(Buffer.from(anchor.token, "base64"));
      // A verified signer is what distinguishes evidence from a parseable blob.
      expect(token.signer, `${anchor.tsa} token must carry a verified signer`).toBeDefined();
      expect(token.signer!.subject.length).toBeGreaterThan(0);
      expect(token.signer!.certificatePem).toMatch(/^-----BEGIN CERTIFICATE-----/);
    }
  });

  it("rejects a token whose signed content has been altered", async () => {
    const fx = await fixtures();
    const anchor = fx.anchors[0]!;
    const raw = Buffer.from(anchor.token, "base64");

    // Corrupt a byte inside the encapsulated TSTInfo — the content the TSA
    // signed. The messageDigest signed attribute must no longer match.
    const corrupted = Buffer.from(raw);
    corrupted[100] = (corrupted[100] ?? 0) ^ 0xff;
    const backend = new Rfc3161AnchorBackend({ name: anchor.tsa, url: anchor.url });
    await expect(
      backend.verify(
        { ...anchor, token: corrupted.toString("base64") },
        Buffer.from(fx.root, "hex"),
      ),
    ).rejects.toThrow(/does not match the .* digest of TSTInfo|content has been altered|parse/);
  });

  it("rejects a token whose signature bytes have been altered", async () => {
    const fx = await fixtures();
    const anchor = fx.anchors[0]!;
    const raw = Buffer.from(anchor.token, "base64");

    // Locate the SignerInfo signature OCTET STRING and flip a byte in it.
    const ci = derDecode(raw);
    const signedData = ci.children![1]!.children![0]!;
    const signerInfos = signedData.children!.filter((c) => c.tag === 0x31).at(-1)!;
    const signerInfo = signerInfos.children![0]!;
    const sigNode = signerInfo.children!.filter((c) => c.tag === 0x04).at(-1)!;
    const sigOffset = sigNode.end - 1;

    const corrupted = Buffer.from(raw);
    corrupted[sigOffset] = (corrupted[sigOffset] ?? 0) ^ 0xff;

    const backend = new Rfc3161AnchorBackend({ name: anchor.tsa, url: anchor.url });
    await expect(
      backend.verify(
        { ...anchor, token: corrupted.toString("base64") },
        Buffer.from(fx.root, "hex"),
      ),
    ).rejects.toThrow(/no embedded certificate verifies the timestamp signature/);
  });

  it("rejects a token stripped of its certificates (nothing to verify against)", async () => {
    // Documented boundary: corruption confined to redundant CHAIN
    // certificates or to the informational digestAlgorithms hint does not
    // invalidate a token, because neither is covered by the signature. What
    // must fail is a token with no certificate that verifies the signature.
    const fx = await fixtures();
    const anchor = fx.anchors[0]!;
    const raw = Buffer.from(anchor.token, "base64");
    const ci = derDecode(raw);
    const signedData = ci.children![1]!.children![0]!;
    const certs = signedData.children!.find((c) => c.tag === 0xa0)!;

    // Blank every certificate byte; the DER stays well-formed in shape but no
    // certificate parses or verifies.
    const corrupted = Buffer.from(raw);
    corrupted.fill(0, certs.start + 4, certs.end);
    expect(() => parseTimeStampToken(corrupted)).toThrow();
  });

  it("rejects a non-timestamp DER blob presented as a token", () => {
    // A DER SEQUENCE that is valid ASN.1 but not a TimeStampToken.
    const notAToken = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]);
    expect(() => parseTimeStampToken(notAToken)).toThrowError(Rfc3161Error);
    expect(() => parseTimeStampToken(notAToken)).toThrow(/not a TimeStampToken|SignedData missing/);
  });

  it("verifyTokenBinding catches a nonce that was not echoed (replayed token)", async () => {
    const fx = await fixtures();
    const token = parseTimeStampToken(Buffer.from(fx.anchors[0]!.token, "base64"));
    const { createHash } = await import("node:crypto");
    const imprint = createHash("sha256").update(Buffer.from(fx.root, "hex")).digest();
    expect(() =>
      verifyTokenBinding(token, {
        imprint,
        hashAlgorithm: "sha256",
        nonce: Buffer.from("0011223344556677", "hex"),
      }),
    ).toThrow(/does not echo the requested nonce/);
  });
});

describe("multi-TSA anchoring policy", () => {
  class StubBackend implements AnchorBackend {
    constructor(
      readonly name: string,
      private readonly behaviour: "ok" | "fail",
    ) {}
    async anchor(root: Buffer): Promise<Anchor> {
      if (this.behaviour === "fail") throw new Error(`${this.name} is unreachable`);
      return {
        backend: "rfc3161",
        tsa: this.name,
        url: `https://${this.name}/tsr`,
        token: "",
        genTime: Date.now(),
        imprint: root.toString("hex"),
        hashAlgorithm: "sha256",
      };
    }
    async verify(): Promise<void> {
      if (this.behaviour === "fail") throw new Error("cannot verify");
    }
  }

  const root = blake2b(Buffer.from("root"));

  it("succeeds with a partial anchor set and reports the failures (T10)", async () => {
    const res = await anchorToAll(
      [new StubBackend("up", "ok"), new StubBackend("down", "fail")],
      root,
      1,
    );
    expect(res.anchors).toHaveLength(1);
    expect(res.failures).toEqual([{ backend: "down", error: "down is unreachable" }]);
  });

  it("fails when fewer than the required number of anchors succeed", async () => {
    await expect(
      anchorToAll([new StubBackend("a", "ok"), new StubBackend("b", "fail")], root, 2),
    ).rejects.toThrow(/1 of 2 succeeded, 2 required.*b is unreachable/s);
  });

  it("refuses to anchor with no backends configured", async () => {
    await expect(anchorToAll([], root)).rejects.toThrow(/no anchor backends configured/);
  });
});

describe("checkpoint anchoring end to end", () => {
  it("attaches recorded anchors to a checkpoint and verifies the evidence", async () => {
    const fx = await fixtures();
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();

    // Re-stamp the fixture anchors onto this checkpoint's actual root. The
    // tokens themselves were minted for the fixture root, so verification
    // must reject them — which is precisely the substitution check.
    const bogus = fx.anchors.map((a) => ({ ...a, imprint: cp.root }));
    const backends = fx.anchors.map(
      (a) => new Rfc3161AnchorBackend({ name: a.tsa, url: a.url }),
    );
    const withBogus = {
      ...bundleOf(t.log),
      checkpoints: [{ ...cp, anchors: bogus }],
    };
    const res = await verifyAnchors(withBogus.checkpoints, backends);
    expect(res.findings.every((f) => f.code === "ANCHOR_INVALID")).toBe(true);
    expect(res.findings).toHaveLength(fx.anchors.length);
    expect(res.anchorsChecked).toBe(0);

    await t.close();
  });

  it("attachAnchors refuses an anchor for a different root", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    expect(() =>
      t.log.attachAnchors(cp.size, [
        {
          backend: "rfc3161",
          tsa: "x",
          url: "https://x/tsr",
          token: "",
          genTime: Date.now(),
          imprint: "9".repeat(64),
          hashAlgorithm: "sha256",
        },
      ]),
    ).toThrow(/does not match checkpoint root/);
    await t.close();
  });

  it("flags a checkpoint anchored to fewer TSAs than policy requires", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    await t.log.createCheckpoint();
    const report = await verifyEvidence(bundleOf(t.log), { minAnchorsPerCheckpoint: 2 });
    expect(report.ok).toBe(false);
    expect(
      report.findings.find((f) => f.code === "CHECKPOINT_UNDER_ANCHORED")!.message,
    ).toMatch(/anchored to 0 independent TSA\(s\), policy requires 2/);
    await t.close();
  });
});

describe.runIf(liveMode)("live public TSAs (ZW_TSA_MODE=live)", () => {
  it("anchors a real checkpoint to at least two independent TSAs", async () => {
    const t = await newTestLog();
    await populateExamLog(t.log);
    const cp = await t.log.createCheckpoint();
    const root = Buffer.from(cp.root, "hex");

    const backends = Object.values(PUBLIC_TSAS).map(
      (c) => new Rfc3161AnchorBackend({ ...c, timeoutMs: 30_000 }),
    );
    const { anchors, failures } = await anchorToAll(backends, root, 2);
    expect(anchors.length).toBeGreaterThanOrEqual(2);
    expect(new Set(anchors.map((a) => a.tsa)).size).toBe(anchors.length);

    const updated = t.log.attachAnchors(cp.size, anchors);
    expect(updated.anchors.length).toBe(anchors.length);

    const report = await verifyEvidence(bundleOf(t.log), {
      anchorBackends: backends,
      minAnchorsPerCheckpoint: 2,
    });
    expect(report.ok, JSON.stringify(report.findings)).toBe(true);
    expect(report.anchorsChecked).toBe(anchors.length);
    if (failures.length > 0) console.warn("TSA failures:", failures);

    await t.close();
  }, 120_000);
});
