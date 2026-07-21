import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

/**
 * OS keyring integration for the vault passphrase. The passphrase never
 * touches disk; it is stored in the platform secret store and fetched at
 * unlock time.
 *
 *   macOS  — security(1) / Keychain
 *   Linux  — secret-tool(1) / libsecret (GNOME Keyring, KWallet via
 *            libsecret backend)
 *
 * If no keyring is available the caller must supply the passphrase by another
 * means (ZW_VAULT_PASSPHRASE env var for systemd LoadCredential, or an
 * interactive prompt). See runbooks/key-ceremony.md.
 */

export interface Keyring {
  readonly backend: "macos-keychain" | "libsecret" | "unavailable";
  get(service: string, account: string): Promise<Buffer | null>;
  set(service: string, account: string, secret: Buffer): Promise<void>;
  delete(service: string, account: string): Promise<void>;
}

class MacOsKeychain implements Keyring {
  readonly backend = "macos-keychain" as const;

  async get(service: string, account: string): Promise<Buffer | null> {
    try {
      // -w prints only the password; we request hex to survive binary secrets.
      const { stdout } = await exec("security", [
        "find-generic-password",
        "-s",
        service,
        "-a",
        account,
        "-w",
      ]);
      return Buffer.from(stdout.trim(), "hex");
    } catch {
      return null;
    }
  }

  async set(service: string, account: string, secret: Buffer): Promise<void> {
    await exec("security", [
      "add-generic-password",
      "-s",
      service,
      "-a",
      account,
      "-w",
      secret.toString("hex"),
      "-U",
    ]);
  }

  async delete(service: string, account: string): Promise<void> {
    try {
      await exec("security", ["delete-generic-password", "-s", service, "-a", account]);
    } catch {
      // absent is success
    }
  }
}

class LibSecretKeyring implements Keyring {
  readonly backend = "libsecret" as const;

  async get(service: string, account: string): Promise<Buffer | null> {
    try {
      const { stdout } = await exec("secret-tool", [
        "lookup",
        "service",
        service,
        "account",
        account,
      ]);
      const trimmed = stdout.trim();
      return trimmed.length > 0 ? Buffer.from(trimmed, "hex") : null;
    } catch {
      return null;
    }
  }

  async set(service: string, account: string, secret: Buffer): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const child = execFile(
        "secret-tool",
        ["store", "--label", `${service}:${account}`, "service", service, "account", account],
        (err) => (err ? reject(err) : resolve()),
      );
      child.stdin?.end(secret.toString("hex"));
    });
  }

  async delete(service: string, account: string): Promise<void> {
    try {
      await exec("secret-tool", ["clear", "service", service, "account", account]);
    } catch {
      // absent is success
    }
  }
}

class UnavailableKeyring implements Keyring {
  readonly backend = "unavailable" as const;
  async get(): Promise<Buffer | null> {
    return null;
  }
  async set(): Promise<void> {
    throw new Error(
      "no OS keyring available: install libsecret-tools (Linux) or run on macOS, " +
        "or supply the passphrase via ZW_VAULT_PASSPHRASE",
    );
  }
  async delete(): Promise<void> {
    /* nothing to delete */
  }
}

let cached: Keyring | undefined;

export async function detectKeyring(): Promise<Keyring> {
  if (cached) return cached;
  const probe = async (cmd: string, args: string[]): Promise<boolean> => {
    try {
      await exec(cmd, args);
      return true;
    } catch {
      return false;
    }
  };
  if (process.platform === "darwin" && (await probe("security", ["help"]))) {
    cached = new MacOsKeychain();
  } else if (await probe("secret-tool", ["--help"])) {
    cached = new LibSecretKeyring();
  } else {
    cached = new UnavailableKeyring();
  }
  return cached;
}
