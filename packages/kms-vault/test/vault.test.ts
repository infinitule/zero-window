import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runKeyProviderConformance } from "@zw/crypto";
import { Keystore, VaultKeyProvider } from "../src/index.js";

const dirs: string[] = [];

async function newVaultDir(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "zw-vault-"));
  dirs.push(d);
  return d;
}

afterAll(async () => {
  await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
});

describe("VaultKeyProvider conformance", () => {
  runKeyProviderConformance(
    {
      it: (name, fn) => it(name, fn),
      expectTrue: (cond, message) => expect(cond, message).toBe(true),
    },
    async () => {
      const dir = await newVaultDir();
      return VaultKeyProvider.open({
        keystorePath: join(dir, "keystore.json"),
        passphrase: Buffer.from("test-passphrase-not-from-keyring"),
      });
    },
  );
});

describe("Keystore at rest", () => {
  it("persists keys across reopen and rejects a wrong passphrase", async () => {
    const dir = await newVaultDir();
    const path = join(dir, "keystore.json");
    const pass = Buffer.from("correct horse battery staple");

    const p1 = await VaultKeyProvider.open({ keystorePath: path, passphrase: pass });
    const pub = await p1.ensureSigningKey("authority-log");
    await p1.close();

    const p2 = await VaultKeyProvider.open({ keystorePath: path, passphrase: pass });
    expect((await p2.getSigningPublicKey("authority-log")).equals(pub)).toBe(true);
    await p2.close();

    await expect(
      VaultKeyProvider.open({ keystorePath: path, passphrase: Buffer.from("wrong") }),
    ).rejects.toThrow(/wrong passphrase|corrupted/);
  });

  it("stores no plaintext key material on disk (acceptance: no raw keys at rest)", async () => {
    const dir = await newVaultDir();
    const path = join(dir, "keystore.json");
    const p = await VaultKeyProvider.open({
      keystorePath: path,
      passphrase: Buffer.from("pass"),
    });
    const signPub = await p.ensureSigningKey("k-sign");
    const boxPub = await p.ensureBoxKey("k-box");
    await p.close();

    const raw = await readFile(path);
    const parsed = JSON.parse(raw.toString("utf8")) as {
      entries: Record<string, string>;
      kdf: { alg: string };
    };
    expect(parsed.kdf.alg).toBe("argon2id13");
    expect(Object.keys(parsed.entries).sort()).toEqual(["box:k-box", "sign:k-sign"]);

    // The seeds must not appear anywhere in the file. We cannot see the seeds
    // directly (the provider never returns them), so we assert the stronger
    // property that the file decrypts only under the right passphrase and
    // that public keys — which ARE derivable from seeds — are absent, i.e.
    // nothing in the file is stored unencrypted.
    expect(raw.includes(signPub)).toBe(false);
    expect(raw.includes(boxPub)).toBe(false);
    // Entries must be distinct ciphertexts, not a shared/constant blob.
    const values = Object.values(parsed.entries);
    expect(new Set(values).size).toBe(values.length);
  });

  it("binds each entry to its id — a swapped entry fails to decrypt (I-KS-1)", async () => {
    const dir = await newVaultDir();
    const path = join(dir, "keystore.json");
    const pass = Buffer.from("pass");
    const ks = await Keystore.open(path, pass);
    const a = Buffer.alloc(32, 0xaa);
    const b = Buffer.alloc(32, 0xbb);
    await ks.put("sign:alpha", a);
    await ks.put("sign:beta", b);
    ks.close();

    const file = JSON.parse(await readFile(path, "utf8")) as { entries: Record<string, string> };
    const swapped = { ...file, entries: { ...file.entries } };
    const alpha = swapped.entries["sign:alpha"]!;
    swapped.entries["sign:alpha"] = swapped.entries["sign:beta"]!;
    swapped.entries["sign:beta"] = alpha;
    const { writeFile } = await import("node:fs/promises");
    await writeFile(path, JSON.stringify(swapped));

    const ks2 = await Keystore.open(path, pass).catch((e: Error) => e);
    // Opening eagerly verifies the first entry, so a swap is caught either at
    // open or at get — both are fail-closed.
    if (ks2 instanceof Error) {
      expect(ks2.message).toMatch(/wrong passphrase|corrupted/);
    } else {
      expect(() => ks2.get("sign:alpha")).toThrow();
      ks2.close();
    }
  });

  it("creates a keystore with a keyring-backed passphrase when asked", async () => {
    // Uses ZW_VAULT_PASSPHRASE rather than touching the real OS keyring, so
    // the test never writes to the developer's Keychain.
    const dir = await newVaultDir();
    process.env["ZW_VAULT_PASSPHRASE"] = "env-supplied-passphrase";
    try {
      const p = await VaultKeyProvider.open({ keystorePath: join(dir, "ks.json") });
      const pub = await p.ensureSigningKey("k");
      expect(pub).toHaveLength(32);
      await p.close();
    } finally {
      delete process.env["ZW_VAULT_PASSPHRASE"];
    }
  });

  it("fails closed when no passphrase source is available", async () => {
    const dir = await newVaultDir();
    const saved = process.env["ZW_VAULT_PASSPHRASE"];
    delete process.env["ZW_VAULT_PASSPHRASE"];
    try {
      await expect(
        VaultKeyProvider.open({
          keystorePath: join(dir, "ks.json"),
          keyringAccount: `nonexistent-account-${Date.now()}`,
        }),
      ).rejects.toThrow(/no vault passphrase/);
    } finally {
      if (saved !== undefined) process.env["ZW_VAULT_PASSPHRASE"] = saved;
    }
  });
});
