import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";
import { afterAll, describe, expect, it } from "vitest";
import { blake2b } from "@zw/crypto";
import {
  Rfc3161AnchorBackend,
  Rfc3161Error,
  buildTimeStampRequest,
  derEncode,
  derInteger,
  derSequence,
  parseTimeStampResponse,
} from "../src/index.js";

/**
 * TSA failure modes. Exam day cannot be re-run, so every way a TSA can
 * misbehave — down, slow, HTTP error, protocol-level rejection, garbage
 * response — must surface as an actionable error rather than a hang or a
 * silently accepted non-anchor (T10).
 */

const servers: Server[] = [];

afterAll(async () => {
  await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
});

async function startServer(
  handler: (req: unknown, res: { statusCode: number; end: (b?: Buffer) => void; setHeader(k: string, v: string): void }) => void,
): Promise<string> {
  const server = createServer(handler as never);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}/tsr`;
}

const root = blake2b(Buffer.from("checkpoint-root"));

describe("TSA failure handling", () => {
  it("reports an HTTP error status with the TSA name", async () => {
    const url = await startServer((_req, res) => {
      res.statusCode = 503;
      res.end();
    });
    const backend = new Rfc3161AnchorBackend({ name: "flaky-tsa", url });
    await expect(backend.anchor(root)).rejects.toThrow(/flaky-tsa returned HTTP 503/);
  });

  it("times out rather than hanging the release path", async () => {
    const url = await startServer(() => {
      /* never responds */
    });
    const backend = new Rfc3161AnchorBackend({ name: "slow-tsa", url, timeoutMs: 300 });
    await expect(backend.anchor(root)).rejects.toThrow(/slow-tsa timed out after 300ms/);
  });

  it("reports a connection failure", async () => {
    // Port 1 is reserved and never listening.
    const backend = new Rfc3161AnchorBackend({
      name: "dead-tsa",
      url: "http://127.0.0.1:1/tsr",
      timeoutMs: 2000,
    });
    await expect(backend.anchor(root)).rejects.toThrow(/dead-tsa request failed/);
  });

  it("rejects a garbage (non-DER) response", async () => {
    const url = await startServer((_req, res) => {
      res.statusCode = 200;
      res.end(Buffer.from("this is not DER at all"));
    });
    const backend = new Rfc3161AnchorBackend({ name: "garbage-tsa", url });
    await expect(backend.anchor(root)).rejects.toThrowError(Rfc3161Error);
  });

  it("surfaces a protocol-level rejection with the PKIStatus", async () => {
    // TimeStampResp with status 2 (rejection).
    const rejection = derSequence(derSequence(derInteger(2)));
    const url = await startServer((_req, res) => {
      res.statusCode = 200;
      res.setHeader("content-type", "application/timestamp-reply");
      res.end(rejection);
    });
    const backend = new Rfc3161AnchorBackend({ name: "refusing-tsa", url });
    await expect(backend.anchor(root)).rejects.toThrow(/TSA rejected the request: PKIStatus=2/);
  });

  it("rejects a granted response that carries no token", async () => {
    const granted = derSequence(derSequence(derInteger(0)));
    expect(() => parseTimeStampResponse(granted)).toThrow(/granted but no TimeStampToken/);
  });

  it("rejects a response that is not a TimeStampResp sequence", () => {
    expect(() => parseTimeStampResponse(derInteger(1))).toThrow(/not a TimeStampResp SEQUENCE/);
    expect(() => parseTimeStampResponse(derSequence(derInteger(0), derInteger(0)))).toThrow();
    expect(() => parseTimeStampResponse(Buffer.from([0x30, 0x00]))).toThrow(
      /not a TimeStampResp SEQUENCE/,
    );
  });

  it("rejects a malformed PKIStatusInfo", () => {
    const bad = derSequence(derInteger(0));
    expect(() => parseTimeStampResponse(bad)).toThrow(/PKIStatusInfo missing or malformed/);
  });

  it("sends the correct content type and a well-formed request body", async () => {
    let seenContentType = "";
    let seenBody = Buffer.alloc(0);
    const url = await startServer((req, res) => {
      const r = req as { headers: Record<string, string>; on(e: string, cb: (c?: Buffer) => void): void };
      seenContentType = r.headers["content-type"] ?? "";
      const chunks: Buffer[] = [];
      r.on("data", (c) => chunks.push(c as Buffer));
      r.on("end", () => {
        seenBody = Buffer.concat(chunks);
        res.statusCode = 500;
        res.end();
      });
    });
    const backend = new Rfc3161AnchorBackend({ name: "inspect", url });
    await expect(backend.anchor(root)).rejects.toThrow();
    expect(seenContentType).toBe("application/timestamp-query");
    // Body must be the DER request containing the SHA-256 imprint of the root.
    const { createHash } = await import("node:crypto");
    const imprint = createHash("sha256").update(root).digest();
    expect(seenBody.includes(imprint)).toBe(true);
    expect(seenBody[0]).toBe(0x30);
  });

  it("verify() refuses an anchor from a different backend kind", async () => {
    const backend = new Rfc3161AnchorBackend({ name: "x", url: "http://x/tsr" });
    await expect(
      backend.verify(
        {
          backend: "opentimestamps",
          tsa: "x",
          url: "http://x",
          token: "",
          genTime: 0,
          imprint: root.toString("hex"),
          hashAlgorithm: "sha256",
        },
        root,
      ),
    ).rejects.toThrow(/cannot be verified by the RFC 3161 backend/);
  });

  it("supports basic auth for commercial TSAs", async () => {
    let seenAuth = "";
    const url = await startServer((req, res) => {
      seenAuth = (req as { headers: Record<string, string> }).headers["authorization"] ?? "";
      res.statusCode = 500;
      res.end();
    });
    const backend = new Rfc3161AnchorBackend({
      name: "paid-tsa",
      url,
      auth: { username: "user", password: "pass" },
    });
    await expect(backend.anchor(root)).rejects.toThrow();
    expect(seenAuth).toBe(`Basic ${Buffer.from("user:pass").toString("base64")}`);
  });

  it("honours an explicit nonce and the sha512 profile", () => {
    const nonce = Buffer.from("1122334455667788", "hex");
    const { der, nonce: used } = buildTimeStampRequest({
      imprint: Buffer.alloc(64, 1),
      hashAlgorithm: "sha512",
      nonce,
      certReq: false,
    });
    expect(used.equals(nonce)).toBe(true);
    // certReq:false omits the BOOLEAN
    expect(der.includes(Buffer.from([0x01, 0x01, 0xff]))).toBe(false);
    expect(der.includes(derEncode(0x04, Buffer.alloc(64, 1)))).toBe(true);
  });
});
