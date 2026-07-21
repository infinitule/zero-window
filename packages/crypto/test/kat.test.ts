import { describe, expect, it } from "vitest";
import {
  aeadDecrypt,
  aeadEncrypt,
  blake2b,
  fromHex,
  sign,
  signingKeyPairFromSeed,
  verify,
} from "../src/index.js";

/**
 * Known-answer tests against published vectors:
 *  - XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 §A.3.1
 *  - BLAKE2b-512: RFC 7693 Appendix A ("abc")
 *  - Ed25519: RFC 8032 §7.1 test vectors 1 & 2
 */

describe("XChaCha20-Poly1305 KAT (draft-irtf-cfrg-xchacha-03 A.3.1)", () => {
  const plaintext = Buffer.from(
    "Ladies and Gentlemen of the class of '99: If I could offer you " +
      "only one tip for the future, sunscreen would be it.",
    "ascii",
  );
  const aad = fromHex("50515253c0c1c2c3c4c5c6c7");
  const key = fromHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  const nonce = fromHex("404142434445464748494a4b4c4d4e4f5051525354555657");
  const expectedCiphertext = fromHex(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
      "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
      "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
      "21f9664c97637da9768812f615c68b13b52e",
  );
  const expectedTag = fromHex("c0875924c1c7987947deafd8780acf49");

  it("encrypts to the published ciphertext and tag", () => {
    const ct = aeadEncrypt(key, plaintext, aad, nonce);
    expect(ct.ciphertext.subarray(0, plaintext.length).equals(expectedCiphertext)).toBe(true);
    expect(ct.ciphertext.subarray(plaintext.length).equals(expectedTag)).toBe(true);
  });

  it("round-trips and authenticates AAD", () => {
    const ct = aeadEncrypt(key, plaintext, aad, nonce);
    expect(aeadDecrypt(key, ct, aad).equals(plaintext)).toBe(true);
    expect(() => aeadDecrypt(key, ct, Buffer.from("tampered-ad"))).toThrow();
    const flipped = { ...ct, ciphertext: Buffer.from(ct.ciphertext) };
    flipped.ciphertext[0]! ^= 0x01;
    expect(() => aeadDecrypt(key, flipped, aad)).toThrow();
  });
});

describe("BLAKE2b KAT (RFC 7693 Appendix A)", () => {
  it("hashes 'abc' to the published BLAKE2b-512 digest", () => {
    const expected = fromHex(
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    );
    expect(blake2b(Buffer.from("abc", "ascii"), { outLen: 64 }).equals(expected)).toBe(true);
  });
});

describe("Ed25519 KAT (RFC 8032 §7.1)", () => {
  it("vector 1: empty message", () => {
    const seed = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const kp = signingKeyPairFromSeed(seed);
    expect(
      kp.publicKey.equals(
        fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
      ),
    ).toBe(true);
    const sig = sign(Buffer.alloc(0), kp.secretKey);
    expect(
      sig.equals(
        fromHex(
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
      ),
    ).toBe(true);
    expect(verify(Buffer.alloc(0), sig, kp.publicKey)).toBe(true);
  });

  it("vector 2: one-byte message 0x72", () => {
    const seed = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    const kp = signingKeyPairFromSeed(seed);
    expect(
      kp.publicKey.equals(
        fromHex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
      ),
    ).toBe(true);
    const msg = fromHex("72");
    const sig = sign(msg, kp.secretKey);
    expect(
      sig.equals(
        fromHex(
          "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
      ),
    ).toBe(true);
    expect(verify(msg, sig, kp.publicKey)).toBe(true);
    expect(verify(fromHex("73"), sig, kp.publicKey)).toBe(false);
  });
});
