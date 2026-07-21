import pkcs11js from "pkcs11js";
import { KeyProviderError } from "@zw/crypto";

/**
 * Thin, typed wrapper over pkcs11js: module load, slot/token selection,
 * login, and object helpers. Every PKCS#11 error is translated into a
 * KeyProviderError carrying the CKR_* name so operator diagnostics are
 * precise (runbooks/incident-response.md refers to these).
 */

export interface Pkcs11Config {
  /** Path to the PKCS#11 shared library (e.g. libsofthsm2.so, libyubihsm_pkcs11). */
  modulePath: string;
  /** Token label to select. Preferred over slot index — stable across reboots. */
  tokenLabel?: string;
  /** Slot index fallback when no label is given. */
  slotIndex?: number;
  /** User PIN. Supplied via systemd LoadCredential / keyring in production. */
  pin: string;
}

function ckrName(err: unknown): string {
  const e = err as { code?: number; message?: string };
  if (typeof e.code !== "number") return e.message ?? String(err);
  for (const [name, value] of Object.entries(pkcs11js as unknown as Record<string, unknown>)) {
    if (name.startsWith("CKR_") && value === e.code) return name;
  }
  return `CKR_UNKNOWN(0x${e.code.toString(16)})`;
}

export function wrapP11<T>(what: string, fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    throw new KeyProviderError(`${what}: ${ckrName(err)}`, "BACKEND_FAILURE");
  }
}

/**
 * PKCS#11 modules are initialized ONCE PER PROCESS: C_Initialize returns
 * CKR_CRYPTOKI_ALREADY_INITIALIZED on a second call, and C_Finalize tears the
 * module down for every session in the process. A deployment legitimately
 * opens several providers in one process (authority + centre in the pilot
 * harness; reconnect after an error), so the loaded module is a refcounted
 * singleton keyed by module path. C_Finalize runs only when the last session
 * against that module closes.
 */
interface LoadedModule {
  pkcs11: pkcs11js.PKCS11;
  refs: number;
}

const loadedModules = new Map<string, LoadedModule>();

function acquireModule(modulePath: string): pkcs11js.PKCS11 {
  const existing = loadedModules.get(modulePath);
  if (existing) {
    existing.refs++;
    return existing.pkcs11;
  }
  const pkcs11 = new pkcs11js.PKCS11();
  wrapP11("C_Load", () => pkcs11.load(modulePath));
  wrapP11("C_Initialize", () => pkcs11.C_Initialize());
  loadedModules.set(modulePath, { pkcs11, refs: 1 });
  return pkcs11;
}

function releaseModule(modulePath: string): void {
  const entry = loadedModules.get(modulePath);
  if (!entry) return;
  entry.refs--;
  if (entry.refs > 0) return;
  loadedModules.delete(modulePath);
  try {
    entry.pkcs11.C_Finalize();
  } catch {
    /* best effort — process is tearing this module down anyway */
  }
}

export class Pkcs11Session {
  private closed = false;

  private constructor(
    private readonly pkcs11: pkcs11js.PKCS11,
    readonly session: Buffer,
    readonly slot: Buffer,
    private readonly modulePath: string,
  ) {}

  static open(config: Pkcs11Config): Pkcs11Session {
    const pkcs11 = acquireModule(config.modulePath);

    let slot: Buffer;
    try {
      const slots = wrapP11("C_GetSlotList", () => pkcs11.C_GetSlotList(true));
      if (slots.length === 0) {
        throw new KeyProviderError(
          `PKCS#11 module ${config.modulePath} reports no token-present slots`,
          "BACKEND_FAILURE",
        );
      }
      if (config.tokenLabel !== undefined) {
        const match = slots.find((s) => {
          const info = wrapP11("C_GetTokenInfo", () => pkcs11.C_GetTokenInfo(s));
          return info.label.trim() === config.tokenLabel;
        });
        if (!match) {
          const labels = slots.map((s) =>
            wrapP11("C_GetTokenInfo", () => pkcs11.C_GetTokenInfo(s)).label.trim(),
          );
          throw new KeyProviderError(
            `no token labelled "${config.tokenLabel}"; present tokens: ${labels.join(", ")}`,
            "BACKEND_FAILURE",
          );
        }
        slot = match;
      } else {
        const idx = config.slotIndex ?? 0;
        const chosen = slots[idx];
        if (!chosen) {
          throw new KeyProviderError(
            `slot index ${idx} out of range (${slots.length} slots)`,
            "BACKEND_FAILURE",
          );
        }
        slot = chosen;
      }

      const session = wrapP11("C_OpenSession", () =>
        pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION),
      );
      try {
        // PKCS#11 login state is per-token per-application, NOT per-session:
        // a second session on a token this process already authenticated to
        // returns CKR_USER_ALREADY_LOGGED_IN. That is success, not failure —
        // the session inherits the token's logged-in state.
        try {
          pkcs11.C_Login(session, pkcs11js.CKU_USER, config.pin);
        } catch (err) {
          if ((err as { code?: number }).code !== pkcs11js.CKR_USER_ALREADY_LOGGED_IN) {
            throw err;
          }
        }
      } catch (err) {
        try {
          pkcs11.C_CloseSession(session);
        } catch {
          /* best effort */
        }
        throw new KeyProviderError(
          `C_Login: ${ckrName(err)}`,
          "BACKEND_FAILURE",
        );
      }
      return new Pkcs11Session(pkcs11, session, slot, config.modulePath);
    } catch (err) {
      releaseModule(config.modulePath);
      throw err;
    }
  }

  get p11(): pkcs11js.PKCS11 {
    return this.pkcs11;
  }

  /** Hardware RNG — used for all key material generated by this provider. */
  randomFill(buf: Buffer): void {
    wrapP11("C_GenerateRandom", () => this.pkcs11.C_GenerateRandom(this.session, buf));
  }

  findObjects(template: pkcs11js.Template): Buffer[] {
    return wrapP11("C_FindObjects", () => {
      this.pkcs11.C_FindObjectsInit(this.session, template);
      const found: Buffer[] = [];
      for (;;) {
        const objs = this.pkcs11.C_FindObjects(this.session, 16);
        if (!objs || (Array.isArray(objs) && objs.length === 0)) break;
        const arr = Array.isArray(objs) ? objs : [objs];
        found.push(...arr);
        if (arr.length < 16) break;
      }
      this.pkcs11.C_FindObjectsFinal(this.session);
      return found;
    });
  }

  findOne(template: pkcs11js.Template): Buffer | null {
    const objs = this.findObjects(template);
    return objs[0] ?? null;
  }

  getAttribute(obj: Buffer, type: number): Buffer {
    const [attr] = wrapP11("C_GetAttributeValue", () =>
      this.pkcs11.C_GetAttributeValue(this.session, obj, [{ type }]),
    );
    const value = attr?.value;
    if (!Buffer.isBuffer(value)) {
      throw new KeyProviderError(`attribute 0x${type.toString(16)} unreadable`, "BACKEND_FAILURE");
    }
    return value;
  }

  tokenInfo(): pkcs11js.TokenInfo {
    return wrapP11("C_GetTokenInfo", () => this.pkcs11.C_GetTokenInfo(this.slot));
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.pkcs11.C_Logout(this.session);
    } catch {
      /* session may already be gone */
    }
    try {
      this.pkcs11.C_CloseSession(this.session);
    } catch {
      /* ditto */
    }
    releaseModule(this.modulePath);
  }
}
