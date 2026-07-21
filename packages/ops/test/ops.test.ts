import { describe, expect, it, vi } from "vitest";
import {
  Counter,
  GracefulShutdown,
  HealthRegistry,
  Histogram,
  Logger,
  MetricsRegistry,
  redact,
} from "../src/index.js";

describe("redaction (I-OPS-1)", () => {
  it("redacts secret-looking field names", () => {
    const out = redact({
      secret: "s3cr3t",
      private_key: "PRIVATE",
      passphrase: "hunter2",
      share: "abcd",
      kek: "raw",
      pin: "1234",
      apiToken: "t",
    }) as Record<string, unknown>;
    for (const v of Object.values(out)) expect(v).toBe("[redacted]");
  });

  it("keeps safe identifiers that merely resemble secrets", () => {
    const out = redact({
      key_id: "kek-exam-1",
      publicKey: "abc",
      kek_fingerprint: "ff00",
      token_hash: "9911",
      threshold: 3,
      share_count: 5,
    }) as Record<string, unknown>;
    expect(out["key_id"]).toBe("kek-exam-1");
    expect(out["kek_fingerprint"]).toBe("ff00");
    expect(out["threshold"]).toBe(3);
    expect(out["share_count"]).toBe(5);
  });

  it("never emits raw bytes for Buffers", () => {
    const secret = Buffer.alloc(32, 0xab);
    const out = redact({ blob: secret }) as Record<string, string>;
    expect(out["blob"]).toMatch(/^\[bytes len=32 sha-prefix=abababab…\]$/);
    expect(out["blob"]).not.toContain("abababababababab");
  });

  it("truncates long strings that could carry encoded key material", () => {
    const long = "a".repeat(400);
    expect(redact({ note: long })["note" as never]).toContain("truncated");
  });

  it("redacts recursively through nested objects and arrays", () => {
    const out = redact({
      ceremony: { custodians: [{ id: "c1", share: "SECRET" }] },
    }) as { ceremony: { custodians: Array<Record<string, unknown>> } };
    expect(out.ceremony.custodians[0]!["id"]).toBe("c1");
    expect(out.ceremony.custodians[0]!["share"]).toBe("[redacted]");
  });
});

describe("Logger", () => {
  it("emits one JSON object per line with required fields", () => {
    const lines: string[] = [];
    const log = new Logger({ service: "authority", write: (l) => lines.push(l) });
    log.info("bundle created", { exam_id: "EX-1" });
    expect(lines).toHaveLength(1);
    const rec = JSON.parse(lines[0]!) as Record<string, unknown>;
    expect(rec["level"]).toBe("info");
    expect(rec["service"]).toBe("authority");
    expect(rec["msg"]).toBe("bundle created");
    expect(rec["exam_id"]).toBe("EX-1");
    expect(typeof rec["ts"]).toBe("string");
  });

  it("redacts secrets passed as log fields", () => {
    const lines: string[] = [];
    new Logger({ service: "s", write: (l) => lines.push(l) }).info("release", {
      kek: Buffer.alloc(32, 1),
      shares: ["a", "b"],
    });
    expect(lines[0]).not.toContain("01010101");
    expect(lines[0]).toContain("[redacted]");
  });

  it("respects level thresholds and child bindings", () => {
    const lines: string[] = [];
    const log = new Logger({ service: "s", level: "warn", write: (l) => lines.push(l) });
    log.debug("noise");
    log.info("noise");
    log.warn("real", {});
    expect(lines).toHaveLength(1);

    const child = new Logger({ service: "s", write: (l) => lines.push(l) }).child({
      centre_id: "C-A",
    });
    child.info("hello");
    expect(JSON.parse(lines[1]!)["centre_id"]).toBe("C-A");
  });

  it("survives circular fields instead of overflowing the stack", () => {
    const lines: string[] = [];
    const circular: Record<string, unknown> = { name: "ceremony" };
    circular["self"] = circular;
    new Logger({ service: "s", write: (l) => lines.push(l) }).error("bad", { circular });
    expect(lines).toHaveLength(1);
    const rec = JSON.parse(lines[0]!) as { circular: Record<string, unknown> };
    expect(rec.circular["name"]).toBe("ceremony");
    expect(rec.circular["self"]).toBe("[circular]");
  });

  it("caps pathological nesting depth", () => {
    const lines: string[] = [];
    let deep: Record<string, unknown> = { end: true };
    for (let i = 0; i < 50; i++) deep = { nested: deep };
    new Logger({ service: "s", write: (l) => lines.push(l) }).info("deep", { deep });
    expect(lines[0]).toContain("[max depth exceeded]");
  });

  it("does not mistake repeated sibling references for cycles", () => {
    const lines: string[] = [];
    const shared = { id: "centre-A" };
    new Logger({ service: "s", write: (l) => lines.push(l) }).info("two", {
      first: shared,
      second: shared,
    });
    const rec = JSON.parse(lines[0]!) as Record<string, { id: string }>;
    expect(rec["first"]!.id).toBe("centre-A");
    expect(rec["second"]!.id).toBe("centre-A");
  });
});

describe("metrics", () => {
  it("exposes counters in Prometheus text format", () => {
    const reg = new MetricsRegistry();
    const c = reg.counter("zw_releases_total", "releases performed");
    c.inc({ exam_id: "EX-1" });
    c.inc({ exam_id: "EX-1" });
    c.inc({ exam_id: "EX-2" }, 3);
    const out = reg.expose();
    expect(out).toContain("# TYPE zw_releases_total counter");
    expect(out).toContain('zw_releases_total{exam_id="EX-1"} 2');
    expect(out).toContain('zw_releases_total{exam_id="EX-2"} 3');
    expect(c.get({ exam_id: "EX-1" })).toBe(2);
  });

  it("refuses to decrease a counter and rejects bad names", () => {
    const reg = new MetricsRegistry();
    expect(() => reg.counter("zw_x", "h").inc({}, -1)).toThrow(/cannot decrease/);
    expect(() => reg.counter("1bad-name", "h")).toThrow(/invalid metric name/);
  });

  it("histograms produce cumulative buckets, sum and count", () => {
    const h = new Histogram("zw_kek_lifetime_ms", "plaintext KEK lifetime", [10, 100, 500]);
    h.observe(5);
    h.observe(50);
    h.observe(400);
    h.observe(900);
    const out = h.expose().join("\n");
    expect(out).toContain('zw_kek_lifetime_ms_bucket{le="10"} 1');
    expect(out).toContain('zw_kek_lifetime_ms_bucket{le="100"} 2');
    expect(out).toContain('zw_kek_lifetime_ms_bucket{le="500"} 3');
    expect(out).toContain('zw_kek_lifetime_ms_bucket{le="+Inf"} 4');
    expect(out).toContain("zw_kek_lifetime_ms_count 4");
    expect(h.count()).toBe(4);
  });

  it("rejects non-ascending histogram buckets", () => {
    expect(() => new Histogram("h", "h", [10, 5])).toThrow(/ascending/);
  });

  it("redacts label values so metrics cannot leak key material (I-OPS-2)", () => {
    const reg = new MetricsRegistry();
    reg.counter("zw_test_total", "t").inc({ share: "RAWSHARE", exam_id: "EX-1" });
    const out = reg.expose();
    expect(out).not.toContain("RAWSHARE");
    expect(out).toContain("[redacted]");
    expect(out).toContain('exam_id="EX-1"');
  });

  it("gauges go up and down and re-registration returns the same metric", () => {
    const reg = new MetricsRegistry();
    const g = reg.gauge("zw_centres_enrolled", "enrolled centres");
    g.set(3);
    g.inc();
    g.dec({}, 2);
    expect(g.get()).toBe(2);
    expect(reg.gauge("zw_centres_enrolled", "enrolled centres")).toBe(g);
    expect(() => reg.counter("zw_centres_enrolled", "x")).toThrow(/already registered as gauge/);
  });

  it("escapes label values that would corrupt the exposition format", () => {
    const reg = new MetricsRegistry();
    reg.counter("zw_e", "h").inc({ detail: 'a"b\nc\\d' });
    const line = reg.expose().split("\n").find((l) => l.startsWith("zw_e{"))!;
    expect(line).toContain('detail="a\\"b\\nc\\\\d"');
    expect(line.split("\n")).toHaveLength(1);
  });

  it("empty metrics still expose a zero series", () => {
    const reg = new MetricsRegistry();
    reg.counter("zw_empty_total", "h");
    reg.histogram("zw_empty_hist", "h", [1]);
    const out = reg.expose();
    expect(out).toContain("zw_empty_total 0");
    expect(out).toContain("zw_empty_hist_count 0");
  });
});

describe("health", () => {
  it("aggregates to the worst status", async () => {
    const h = new HealthRegistry("centre", "1.0.0");
    h.addReadiness("db", () => ({ status: "pass" }));
    h.addReadiness("authority", () => ({ status: "warn", detail: "offline" }));
    let r = await h.ready();
    expect(r.status).toBe("warn");
    h.addReadiness("printer", () => ({ status: "fail", detail: "no printers" }));
    r = await h.ready();
    expect(r.status).toBe("fail");
    expect(r.checks["printer"]!.detail).toBe("no printers");
    expect(r.service).toBe("centre");
  });

  it("treats a throwing check as a failure, not a crash", async () => {
    const h = new HealthRegistry("s", "1");
    h.addLiveness("boom", () => {
      throw new Error("disk gone");
    });
    const r = await h.live();
    expect(r.status).toBe("fail");
    expect(r.checks["boom"]!.detail).toBe("disk gone");
  });

  it("liveness and readiness are independent (autonomy mode stays live)", async () => {
    const h = new HealthRegistry("centre", "1");
    h.addLiveness("process", () => ({ status: "pass" }));
    h.addReadiness("authority_link", () => ({ status: "fail", detail: "link down" }));
    expect((await h.live()).status).toBe("pass");
    expect((await h.ready()).status).toBe("fail");
  });
});

describe("graceful shutdown", () => {
  it("runs hooks in reverse order and exits zero", async () => {
    const order: string[] = [];
    const exit = vi.fn();
    const gs = new GracefulShutdown({ exit });
    gs.register("first", () => {
      order.push("first");
    });
    gs.register("second", async () => {
      order.push("second");
    });
    const code = await gs.shutdown("SIGTERM");
    expect(order).toEqual(["second", "first"]);
    expect(code).toBe(0);
    expect(exit).toHaveBeenCalledWith(0);
  });

  it("continues past a failing hook and reports it", async () => {
    const events: string[] = [];
    const gs = new GracefulShutdown({ onEvent: (e) => events.push(e) });
    gs.register("ok", () => {});
    gs.register("bad", () => {
      throw new Error("nope");
    });
    expect(await gs.shutdown("test")).toBe(0);
    expect(events).toContain("shutdown_hook_failed");
    expect(events).toContain("shutdown_hook_complete");
  });

  it("exits non-zero when a hook exceeds the deadline", async () => {
    const gs = new GracefulShutdown({ timeoutMs: 20 });
    gs.register("hang", () => new Promise<void>(() => {}));
    expect(await gs.shutdown("test")).toBe(1);
  });

  it("is idempotent", async () => {
    let runs = 0;
    const gs = new GracefulShutdown({});
    gs.register("h", () => {
      runs++;
    });
    await gs.shutdown("a");
    await gs.shutdown("b");
    expect(runs).toBe(1);
    expect(gs.inProgress).toBe(true);
  });

  it("installs and uninstalls signal handlers", async () => {
    const before = process.listenerCount("SIGTERM");
    const gs = new GracefulShutdown({});
    const uninstall = gs.install();
    expect(process.listenerCount("SIGTERM")).toBe(before + 1);
    uninstall();
    expect(process.listenerCount("SIGTERM")).toBe(before);
  });
});
