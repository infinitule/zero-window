import { redact } from "./logging.js";

/**
 * Prometheus text-format metrics registry.
 *
 * Deliberately small and dependency-free: services expose a handful of
 * counters, gauges and histograms, and the exposition format is stable and
 * simple enough that pulling in a client library would add supply-chain
 * surface for no benefit on an air-gap-capable deployment.
 *
 * INVARIANT I-OPS-2: label values are redacted the same way log fields are,
 * so a metric can never become an exfiltration channel for key material
 * (acceptance criterion: no raw key material in metrics).
 */

export type Labels = Record<string, string | number>;

function escapeLabelValue(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

function labelKey(labels: Labels): string {
  const entries = Object.entries(labels).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) return "";
  return entries
    .map(([k, v]) => {
      const safe = redact(String(v), k);
      return `${k}="${escapeLabelValue(String(safe))}"`;
    })
    .join(",");
}

function validateName(name: string): void {
  if (!/^[a-zA-Z_:][a-zA-Z0-9_:]*$/.test(name)) {
    throw new Error(`invalid metric name: ${name}`);
  }
}

abstract class Metric {
  constructor(
    readonly name: string,
    readonly help: string,
  ) {
    validateName(name);
  }
  abstract type: string;
  abstract expose(): string[];

  protected header(): string[] {
    return [`# HELP ${this.name} ${this.help.replace(/\n/g, " ")}`, `# TYPE ${this.name} ${this.type}`];
  }
}

export class Counter extends Metric {
  readonly type = "counter";
  private readonly values = new Map<string, number>();

  inc(labels: Labels = {}, delta = 1): void {
    if (delta < 0) throw new Error("counter cannot decrease");
    const k = labelKey(labels);
    this.values.set(k, (this.values.get(k) ?? 0) + delta);
  }

  get(labels: Labels = {}): number {
    return this.values.get(labelKey(labels)) ?? 0;
  }

  expose(): string[] {
    if (this.values.size === 0) return [...this.header(), `${this.name} 0`];
    return [
      ...this.header(),
      ...[...this.values.entries()].map(([k, v]) =>
        k ? `${this.name}{${k}} ${v}` : `${this.name} ${v}`,
      ),
    ];
  }
}

export class Gauge extends Metric {
  readonly type = "gauge";
  private readonly values = new Map<string, number>();

  set(value: number, labels: Labels = {}): void {
    this.values.set(labelKey(labels), value);
  }

  inc(labels: Labels = {}, delta = 1): void {
    const k = labelKey(labels);
    this.values.set(k, (this.values.get(k) ?? 0) + delta);
  }

  dec(labels: Labels = {}, delta = 1): void {
    this.inc(labels, -delta);
  }

  get(labels: Labels = {}): number {
    return this.values.get(labelKey(labels)) ?? 0;
  }

  expose(): string[] {
    if (this.values.size === 0) return [...this.header(), `${this.name} 0`];
    return [
      ...this.header(),
      ...[...this.values.entries()].map(([k, v]) =>
        k ? `${this.name}{${k}} ${v}` : `${this.name} ${v}`,
      ),
    ];
  }
}

interface HistogramSeries {
  counts: number[];
  sum: number;
  count: number;
}

export class Histogram extends Metric {
  readonly type = "histogram";
  private readonly series = new Map<string, HistogramSeries>();

  constructor(
    name: string,
    help: string,
    readonly buckets: number[],
  ) {
    super(name, help);
    if (buckets.length === 0) throw new Error("histogram needs at least one bucket");
    for (let i = 1; i < buckets.length; i++) {
      if (buckets[i]! <= buckets[i - 1]!) throw new Error("histogram buckets must be ascending");
    }
  }

  observe(value: number, labels: Labels = {}): void {
    const k = labelKey(labels);
    let s = this.series.get(k);
    if (!s) {
      s = { counts: new Array<number>(this.buckets.length).fill(0), sum: 0, count: 0 };
      this.series.set(k, s);
    }
    for (let i = 0; i < this.buckets.length; i++) {
      if (value <= this.buckets[i]!) s.counts[i]!++;
    }
    s.sum += value;
    s.count++;
  }

  /** Total observations, for assertions and health logic. */
  count(labels: Labels = {}): number {
    return this.series.get(labelKey(labels))?.count ?? 0;
  }

  /** Highest observed value is not retained; sum/count give the mean. */
  mean(labels: Labels = {}): number {
    const s = this.series.get(labelKey(labels));
    return s && s.count > 0 ? s.sum / s.count : 0;
  }

  expose(): string[] {
    const lines = this.header();
    for (const [k, s] of this.series.entries()) {
      const withLe = (le: string) => (k ? `${k},le="${le}"` : `le="${le}"`);
      for (let i = 0; i < this.buckets.length; i++) {
        lines.push(`${this.name}_bucket{${withLe(String(this.buckets[i]))}} ${s.counts[i]}`);
      }
      lines.push(`${this.name}_bucket{${withLe("+Inf")}} ${s.count}`);
      lines.push(k ? `${this.name}_sum{${k}} ${s.sum}` : `${this.name}_sum ${s.sum}`);
      lines.push(k ? `${this.name}_count{${k}} ${s.count}` : `${this.name}_count ${s.count}`);
    }
    if (this.series.size === 0) {
      for (const b of this.buckets) lines.push(`${this.name}_bucket{le="${b}"} 0`);
      lines.push(`${this.name}_bucket{le="+Inf"} 0`);
      lines.push(`${this.name}_sum 0`);
      lines.push(`${this.name}_count 0`);
    }
    return lines;
  }
}

export class MetricsRegistry {
  private readonly metrics = new Map<string, Metric>();

  counter(name: string, help: string): Counter {
    return this.register(new Counter(name, help));
  }

  gauge(name: string, help: string): Gauge {
    return this.register(new Gauge(name, help));
  }

  histogram(name: string, help: string, buckets: number[]): Histogram {
    return this.register(new Histogram(name, help, buckets));
  }

  private register<T extends Metric>(metric: T): T {
    const existing = this.metrics.get(metric.name);
    if (existing) {
      if (existing.type !== metric.type) {
        throw new Error(`metric ${metric.name} already registered as ${existing.type}`);
      }
      return existing as T;
    }
    this.metrics.set(metric.name, metric);
    return metric;
  }

  /** Prometheus text exposition format (version 0.0.4). */
  expose(): string {
    const lines: string[] = [];
    for (const m of [...this.metrics.values()].sort((a, b) => a.name.localeCompare(b.name))) {
      lines.push(...m.expose());
    }
    return lines.join("\n") + "\n";
  }

  static readonly CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";
}
