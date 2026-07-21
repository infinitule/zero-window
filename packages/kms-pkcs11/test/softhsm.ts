import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);

/**
 * Provision a real SoftHSM2 token for the test run. SoftHSM2 is itself a real
 * PKCS#11 provider — these are not mocked tests.
 *
 * The module path and softhsm2-util location are discovered from the
 * environment first (ZW_PKCS11_MODULE / ZW_SOFTHSM2_UTIL, set by CI), then
 * from the standard install locations on Linux and macOS/Homebrew.
 */

const MODULE_CANDIDATES = [
  process.env["ZW_PKCS11_MODULE"],
  "/usr/lib/softhsm/libsofthsm2.so",
  "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
  "/usr/lib64/pkcs11/libsofthsm2.so",
  "/usr/local/lib/softhsm/libsofthsm2.so",
  "/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so",
  "/opt/homebrew/lib/softhsm/libsofthsm2.so",
].filter((p): p is string => typeof p === "string");

const UTIL_CANDIDATES = [
  process.env["ZW_SOFTHSM2_UTIL"],
  "/usr/bin/softhsm2-util",
  "/usr/local/bin/softhsm2-util",
  "/usr/local/opt/softhsm/bin/softhsm2-util",
  "/opt/homebrew/bin/softhsm2-util",
].filter((p): p is string => typeof p === "string");

export interface SoftHsmToken {
  modulePath: string;
  tokenLabel: string;
  pin: string;
  dir: string;
  confPath: string;
}

export function findSoftHsmModule(): string | null {
  return MODULE_CANDIDATES.find((p) => existsSync(p)) ?? null;
}

function findSoftHsmUtil(): string | null {
  return UTIL_CANDIDATES.find((p) => existsSync(p)) ?? null;
}

/**
 * Initialize a fresh, isolated SoftHSM2 token in a temp directory. Returns
 * null when SoftHSM2 is not installed, so the suite can skip rather than
 * fail on a developer machine without it (CI always has it — the SoftHSM2
 * job asserts it is present).
 */
export async function provisionSoftHsmToken(
  label: string,
  /**
   * Reuse an existing token store. SoftHSM2 reads SOFTHSM2_CONF once, at
   * C_Initialize time, and the module is a per-process singleton — so a
   * second token that must be visible to an already-initialized module has
   * to be created in the SAME store, not a new temp directory.
   */
  existing?: SoftHsmToken,
): Promise<SoftHsmToken | null> {
  const modulePath = findSoftHsmModule();
  const util = findSoftHsmUtil();
  if (!modulePath || !util) return null;

  if (existing) {
    const pin = "1234";
    await exec(
      util,
      ["--init-token", "--free", "--label", label, "--so-pin", "5678", "--pin", pin],
      { env: { ...process.env, SOFTHSM2_CONF: existing.confPath } },
    );
    return { modulePath, tokenLabel: label, pin, dir: existing.dir, confPath: existing.confPath };
  }

  const dir = await mkdtemp(join(tmpdir(), "zw-softhsm-"));
  const tokenDir = join(dir, "tokens");
  await import("node:fs/promises").then((fs) => fs.mkdir(tokenDir, { recursive: true }));
  const confPath = join(dir, "softhsm2.conf");
  await writeFile(
    confPath,
    [
      `directories.tokendir = ${tokenDir}`,
      "objectstore.backend = file",
      "log.level = ERROR",
      "slots.removable = false",
      "",
    ].join("\n"),
  );

  const pin = "1234";
  await exec(
    util,
    ["--init-token", "--free", "--label", label, "--so-pin", "5678", "--pin", pin],
    { env: { ...process.env, SOFTHSM2_CONF: confPath } },
  );

  // The provider reads SOFTHSM2_CONF from the process environment when it
  // loads the module, so point it at this isolated token store.
  process.env["SOFTHSM2_CONF"] = confPath;

  return { modulePath, tokenLabel: label, pin, dir, confPath };
}
