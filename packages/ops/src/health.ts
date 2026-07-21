/**
 * Health checks and graceful shutdown.
 *
 * Liveness vs readiness is a real operational distinction here: a centre node
 * that has lost authority connectivity after key receipt is still healthy and
 * must keep printing (autonomy mode, T10). It is NOT ready to accept new
 * distribution, but restarting it would be actively harmful. So connectivity
 * checks are readiness-only and never liveness.
 */

export type HealthStatus = "pass" | "warn" | "fail";

export interface CheckResult {
  status: HealthStatus;
  detail?: string;
}

export type HealthCheck = () => Promise<CheckResult> | CheckResult;

export interface HealthReport {
  status: HealthStatus;
  service: string;
  version: string;
  uptimeSeconds: number;
  checks: Record<string, CheckResult>;
}

export class HealthRegistry {
  private readonly liveness = new Map<string, HealthCheck>();
  private readonly readiness = new Map<string, HealthCheck>();
  private readonly startedAt = Date.now();

  constructor(
    private readonly service: string,
    private readonly version: string,
  ) {}

  /** A failing liveness check means the process is unrecoverable: restart it. */
  addLiveness(name: string, check: HealthCheck): void {
    this.liveness.set(name, check);
  }

  /** A failing readiness check means "do not send me work"; not a restart. */
  addReadiness(name: string, check: HealthCheck): void {
    this.readiness.set(name, check);
  }

  async live(): Promise<HealthReport> {
    return this.run(this.liveness);
  }

  async ready(): Promise<HealthReport> {
    return this.run(this.readiness);
  }

  private async run(checks: Map<string, HealthCheck>): Promise<HealthReport> {
    const results: Record<string, CheckResult> = {};
    let worst: HealthStatus = "pass";
    for (const [name, check] of checks) {
      let result: CheckResult;
      try {
        result = await check();
      } catch (err) {
        result = { status: "fail", detail: (err as Error).message };
      }
      results[name] = result;
      if (result.status === "fail") worst = "fail";
      else if (result.status === "warn" && worst === "pass") worst = "warn";
    }
    return {
      status: worst,
      service: this.service,
      version: this.version,
      uptimeSeconds: Math.floor((Date.now() - this.startedAt) / 1000),
      checks: results,
    };
  }
}

export type ShutdownHook = () => Promise<void> | void;

/**
 * Graceful shutdown. Hooks run in reverse registration order (so resources
 * are torn down in the opposite order they were created) with a hard deadline
 * — a shutdown that hangs must not leave a centre node half-alive at T-0.
 */
export class GracefulShutdown {
  private readonly hooks: Array<{ name: string; hook: ShutdownHook }> = [];
  private shuttingDown = false;
  private readonly signalHandlers: Array<[NodeJS.Signals, () => void]> = [];

  constructor(
    private readonly opts: {
      timeoutMs?: number;
      onEvent?: (event: string, fields: Record<string, unknown>) => void;
      exit?: (code: number) => void;
    } = {},
  ) {}

  register(name: string, hook: ShutdownHook): void {
    this.hooks.push({ name, hook });
  }

  /** Install SIGTERM/SIGINT handlers. Returns a function to uninstall them. */
  install(): () => void {
    const handle = (signal: NodeJS.Signals) => () => {
      void this.shutdown(signal);
    };
    for (const signal of ["SIGTERM", "SIGINT"] as const) {
      const h = handle(signal);
      process.on(signal, h);
      this.signalHandlers.push([signal, h]);
    }
    return () => this.uninstall();
  }

  uninstall(): void {
    for (const [signal, h] of this.signalHandlers) process.off(signal, h);
    this.signalHandlers.length = 0;
  }

  get inProgress(): boolean {
    return this.shuttingDown;
  }

  async shutdown(reason: string): Promise<number> {
    if (this.shuttingDown) return 0;
    this.shuttingDown = true;
    const emit = this.opts.onEvent ?? (() => {});
    emit("shutdown_started", { reason, hooks: this.hooks.length });

    const timeoutMs = this.opts.timeoutMs ?? 15_000;
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), timeoutMs);
      timer.unref();
    });

    const runAll = (async () => {
      for (const { name, hook } of [...this.hooks].reverse()) {
        try {
          await hook();
          emit("shutdown_hook_complete", { hook: name });
        } catch (err) {
          emit("shutdown_hook_failed", { hook: name, error: (err as Error).message });
        }
      }
      return "done" as const;
    })();

    const outcome = await Promise.race([runAll, deadline]);
    if (timer) clearTimeout(timer);
    const code = outcome === "timeout" ? 1 : 0;
    emit("shutdown_complete", { outcome, exit_code: code });
    this.uninstall();
    this.opts.exit?.(code);
    return code;
  }
}
