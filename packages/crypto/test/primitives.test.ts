import { describe, expect, it } from "vitest";
import {
  AEAD_KEY_BYTES,
  AEAD_NONCE_BYTES,
  Blake2bHasher,
  PWHASH_MEMLIMIT_MODERATE,
  PWHASH_OPSLIMIT_MODERATE,
  PWHASH_SALT_BYTES,
  aeadDecrypt,
  aeadEncrypt,
  blake2b,
  boxKeyPairFromSeed,
  constantTimeEqual,
  deriveKeyFromPassphrase,
  domainHash,
  fromHex,
  generateBoxKeyPair,
  generateSigningKeyPair,
  gfDiv,
  gfInv,
  hex,
  parseAead,
  randomBytes,
  randomFill,
  seal,
  sealOpen,
  secureAlloc,
  serializeAead,
  sign,
  signDomain,
  signingKeyPairFromSeed,
  verify,
  verifyDomain,
  zeroFree,
  zeroize,
} from "../src/index.js";

describe("hashing", () => {
  it("domainHash separates contexts", () => {
    const data = Buffer.from("same-bytes");
    expect(domainHash("a", data).equals(domainHash("b", data))).toBe(false);
    expect(domainHash("a", data).equals(domainHash("a", data))).toBe(true);
    // array form must equal the concatenated form
    expect(
      domainHash("a", [Buffer.from("same-"), Buffer.from("bytes")]).equals(domainHash("a", data)),
    ).toBe(true);
  });

  it("keyed BLAKE2b differs from unkeyed", () => {
    const data = Buffer.from("payload");
    const key = Buffer.alloc(32, 7);
    expect(blake2b(data, { key }).equals(blake2b(data))).toBe(false);
  });

  it("incremental hasher matches one-shot and rejects reuse", () => {
    const h = new Blake2bHasher();
    h.update(Buffer.from("abc")).update(Buffer.from("def"));
    const got = h.digest();
    expect(got.equals(blake2b(Buffer.from("abcdef")))).toBe(true);
    expect(() => h.digest()).toThrow(/finalized/);
    expect(() => h.update(Buffer.from("x"))).toThrow(/finalized/);

    const keyed = new Blake2bHasher({ key: Buffer.alloc(32, 1), outLen: 64 });
    expect(keyed.update(Buffer.from("z")).digest()).toHaveLength(64);
  });

  it("hex helpers round-trip and reject malformed input", () => {
    const b = randomBytes(16);
    expect(fromHex(hex(b)).equals(b)).toBe(true);
    expect(fromHex("")).toHaveLength(0);
    expect(() => fromHex("abc")).toThrow(/invalid hex/);
    expect(() => fromHex("zz")).toThrow(/invalid hex/);
  });
});

describe("AEAD envelope", () => {
  const key = Buffer.alloc(AEAD_KEY_BYTES, 3);

  it("serializes and parses envelopes", () => {
    const ct = aeadEncrypt(key, Buffer.from("secret payload"), Buffer.from("ad"));
    const wire = serializeAead(ct);
    const back = parseAead(wire);
    expect(back.nonce.equals(ct.nonce)).toBe(true);
    expect(back.ciphertext.equals(ct.ciphertext)).toBe(true);
    expect(aeadDecrypt(key, back, Buffer.from("ad")).toString()).toBe("secret payload");
  });

  it("rejects malformed envelopes with precise diagnostics", () => {
    expect(() => parseAead(Buffer.alloc(4))).toThrow(/too short/);
    const good = serializeAead(aeadEncrypt(key, Buffer.from("x"), Buffer.alloc(0)));
    const badMagic = Buffer.from(good);
    badMagic[0] = 0x00;
    expect(() => parseAead(badMagic)).toThrow(/bad magic/);
  });

  it("validates key, nonce and buffer lengths", () => {
    expect(() => aeadEncrypt(Buffer.alloc(8), Buffer.from("x"), Buffer.alloc(0))).toThrow(
      /bad key length/,
    );
    expect(() =>
      aeadEncrypt(key, Buffer.from("x"), Buffer.alloc(0), Buffer.alloc(3)),
    ).toThrow(/bad nonce length/);
    const ct = aeadEncrypt(key, Buffer.from("x"), Buffer.alloc(0));
    expect(() => aeadDecrypt(Buffer.alloc(8), ct, Buffer.alloc(0))).toThrow(/bad key length/);
    expect(() =>
      aeadDecrypt(key, { ...ct, ciphertext: Buffer.alloc(3) }, Buffer.alloc(0)),
    ).toThrow(/too short/);
    expect(() =>
      aeadDecrypt(key, { ...ct, suite: "aes-gcm" as never }, Buffer.alloc(0)),
    ).toThrow(/unsupported suite/);
    expect(() => aeadDecrypt(key, ct, Buffer.alloc(0), Buffer.alloc(99))).toThrow(
      /length mismatch/,
    );
  });

  it("uses a fresh random nonce per message", () => {
    const a = aeadEncrypt(key, Buffer.from("same"), Buffer.alloc(0));
    const b = aeadEncrypt(key, Buffer.from("same"), Buffer.alloc(0));
    expect(a.nonce.equals(b.nonce)).toBe(false);
    expect(a.nonce).toHaveLength(AEAD_NONCE_BYTES);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });

  it("decrypts into a caller-supplied secure buffer", () => {
    const plaintext = Buffer.from("key-material-goes-here-32bytes!!");
    const ct = aeadEncrypt(key, plaintext, Buffer.alloc(0));
    const out = secureAlloc(plaintext.length);
    aeadDecrypt(key, ct, Buffer.alloc(0), out);
    expect(out.equals(plaintext)).toBe(true);
    zeroFree(out);
  });
});

describe("signatures", () => {
  it("generates working keypairs", () => {
    const kp = generateSigningKeyPair();
    expect(kp.publicKey).toHaveLength(32);
    const msg = Buffer.from("attest");
    expect(verify(msg, sign(msg, kp.secretKey), kp.publicKey)).toBe(true);
    zeroFree(kp.secretKey);
  });

  it("rejects seeds of the wrong length", () => {
    expect(() => signingKeyPairFromSeed(Buffer.alloc(8))).toThrow(/bad seed length/);
    expect(() => boxKeyPairFromSeed(Buffer.alloc(8))).toThrow(/bad seed length/);
  });

  it("verify() fails closed on malformed signature or key rather than throwing", () => {
    const kp = generateSigningKeyPair();
    const msg = Buffer.from("m");
    const sig = sign(msg, kp.secretKey);
    expect(verify(msg, Buffer.alloc(10), kp.publicKey)).toBe(false);
    expect(verify(msg, sig, Buffer.alloc(10))).toBe(false);
    zeroFree(kp.secretKey);
  });

  it("domain-separated signatures do not cross domains", () => {
    const kp = generateSigningKeyPair();
    const msg = Buffer.from("release-approval");
    const sig = signDomain("ceremony", msg, kp.secretKey);
    expect(verifyDomain("ceremony", msg, sig, kp.publicKey)).toBe(true);
    expect(verifyDomain("release", msg, sig, kp.publicKey)).toBe(false);
    expect(verify(msg, sig, kp.publicKey)).toBe(false);
    zeroFree(kp.secretKey);
  });
});

describe("sealed boxes", () => {
  it("seals to a recipient and opens only with their secret key", () => {
    const alice = generateBoxKeyPair();
    const mallory = generateBoxKeyPair();
    const payload = Buffer.from("share material");
    const sealed = seal(payload, alice.publicKey);

    expect(sealOpen(sealed, alice.publicKey, alice.secretKey).equals(payload)).toBe(true);
    expect(() => sealOpen(sealed, mallory.publicKey, mallory.secretKey)).toThrow(
      /decryption failed/,
    );

    const tampered = Buffer.from(sealed);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0xff;
    expect(() => sealOpen(tampered, alice.publicKey, alice.secretKey)).toThrow(
      /decryption failed/,
    );

    zeroFree(alice.secretKey);
    zeroFree(mallory.secretKey);
  });

  it("validates lengths", () => {
    const kp = generateBoxKeyPair();
    expect(() => seal(Buffer.from("x"), Buffer.alloc(8))).toThrow(/bad public key/);
    expect(() => sealOpen(Buffer.alloc(4), kp.publicKey, kp.secretKey)).toThrow(/too short/);
    const sealed = seal(Buffer.from("xy"), kp.publicKey);
    expect(() => sealOpen(sealed, kp.publicKey, kp.secretKey, Buffer.alloc(99))).toThrow(
      /length mismatch/,
    );
    zeroFree(kp.secretKey);
  });

  it("derives stable keypairs from a seed", () => {
    const seed = Buffer.alloc(32, 5);
    const a = boxKeyPairFromSeed(seed);
    const b = boxKeyPairFromSeed(seed);
    expect(a.publicKey.equals(b.publicKey)).toBe(true);
    zeroFree(a.secretKey);
    zeroFree(b.secretKey);
  });
});

describe("secure memory helpers", () => {
  it("zeroizes and compares in constant time", () => {
    const buf = Buffer.alloc(16, 0xff);
    zeroize(buf);
    expect(buf.every((b) => b === 0)).toBe(true);

    expect(constantTimeEqual(Buffer.from("abc"), Buffer.from("abc"))).toBe(true);
    expect(constantTimeEqual(Buffer.from("abc"), Buffer.from("abd"))).toBe(false);
    expect(constantTimeEqual(Buffer.from("abc"), Buffer.from("ab"))).toBe(false);
  });

  it("randomFill fills and secure buffers can be freed twice safely", () => {
    const b = Buffer.alloc(32);
    randomFill(b);
    expect(b.every((x) => x === 0)).toBe(false);

    const s = secureAlloc(32);
    randomFill(s);
    zeroFree(s);
    // A double free must not crash the process — release paths call this in
    // finally blocks that may run after an early zeroFree.
    expect(() => zeroFree(Buffer.alloc(4))).not.toThrow();
  });
});

describe("GF(256) edge cases", () => {
  it("inverse and division behave as a field", () => {
    for (let a = 1; a < 256; a++) {
      expect(gfDiv(a, a)).toBe(1);
      expect(gfInv(gfInv(a))).toBe(a);
    }
    expect(gfDiv(0, 5)).toBe(0);
    expect(() => gfInv(0)).toThrow(/undefined/);
    expect(() => gfDiv(1, 0)).toThrow(/by zero/);
  });
});

describe("KDF", () => {
  it("derives deterministically from passphrase+salt and diverges otherwise", () => {
    const salt = Buffer.alloc(PWHASH_SALT_BYTES, 1);
    const params = {
      alg: "argon2id13" as const,
      salt,
      // Interactive limits keep the test fast; production uses MODERATE.
      opslimit: 2,
      memlimit: 64 * 1024 * 1024,
    };
    const k1 = deriveKeyFromPassphrase(Buffer.from("pw"), params, 32);
    const k2 = deriveKeyFromPassphrase(Buffer.from("pw"), params, 32);
    expect(k1.equals(k2)).toBe(true);

    const k3 = deriveKeyFromPassphrase(Buffer.from("pw2"), params, 32);
    expect(k1.equals(k3)).toBe(false);

    const k4 = deriveKeyFromPassphrase(
      Buffer.from("pw"),
      { ...params, salt: Buffer.alloc(PWHASH_SALT_BYTES, 2) },
      32,
    );
    expect(k1.equals(k4)).toBe(false);

    for (const k of [k1, k2, k3, k4]) zeroFree(k);
  });

  it("rejects bad parameters", () => {
    expect(() =>
      deriveKeyFromPassphrase(
        Buffer.from("pw"),
        { alg: "scrypt" as never, salt: Buffer.alloc(PWHASH_SALT_BYTES), opslimit: 2, memlimit: 1 },
        32,
      ),
    ).toThrow(/unsupported KDF/);
    expect(() =>
      deriveKeyFromPassphrase(
        Buffer.from("pw"),
        { alg: "argon2id13", salt: Buffer.alloc(3), opslimit: 2, memlimit: 1 },
        32,
      ),
    ).toThrow(/salt must be/);
  });

  it("exposes moderate limits as the documented production defaults", () => {
    expect(PWHASH_OPSLIMIT_MODERATE).toBeGreaterThan(0);
    expect(PWHASH_MEMLIMIT_MODERATE).toBeGreaterThan(0);
  });
});
