import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { ASSETS } from "../entries.ts";
import { herdrMayListen, ping } from "../herdr/client.ts";

export type UserBridge = { name: string; stateDir: string; socket: string; env: Record<string, string> };

export function userBridge(root: string, name: string, env: NodeJS.ProcessEnv): UserBridge {
  if (!/^ovis-u-[a-f0-9]{32}$/.test(name)) throw new Error("Invalid stored Herdr session name");
  const dir = join(root, "users", Buffer.from(name.slice(7), "hex").toString("base64url"));
  const home = join(dir, "home");
  const config = join(home, ".config");
  const sockets = join(dir, "socket");
  if (Buffer.byteLength(join(sockets, "herdr-client.sock")) >= 108) throw new Error("OVIS_STATE_DIR is too long for Herdr sockets");
  const socket = join(sockets, "herdr.sock");
  const stateDir = join(dir, "ovis");
  mkdirSync(home, { recursive: true, mode: 0o700 });
  mkdirSync(sockets, { recursive: true, mode: 0o700 });
  // Start from a small environment. Process-wide OAuth, web sessions and legacy Ovis/Herdr
  // configuration must never be inherited by agents or by a worker's bridge.
  const shared = Object.fromEntries(
    ["PATH", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "TERM", "TZ", "OVIS_HERDR_BIN", "OVIS_PTY_SIDECAR_BIN"].flatMap((key) => env[key] === undefined ? [] : [[key, env[key]!]]),
  );
  return { name, stateDir, socket, env: {
    ...shared, HOME: home, XDG_CONFIG_HOME: config, XDG_DATA_HOME: join(home, ".local/share"),
    XDG_STATE_HOME: join(home, ".local/state"), XDG_CACHE_HOME: join(home, ".cache"),
    OVIS_ASSETS: ASSETS, OVIS_STATE_DIR: stateDir, OVIS_RUNTIME: "herdr", HERDR_SOCKET: socket,
    HERDR_SESSION: name, HERDR_SOCKET_PATH: socket,
  } };
}

export async function ensureHerdr(bridge: UserBridge): Promise<void> {
  const check = async () => {
    const info = await ping(bridge.socket, 1000).catch(() => null);
    if (info && info.protocol < 22) throw new Error("Herdr 0.9 or newer is required");
    return info !== null;
  };
  if (await check()) return;
  if (!await herdrMayListen(bridge.socket)) {
    const binary = bridge.env["OVIS_HERDR_BIN"] ?? "herdr";
    mkdirSync(bridge.stateDir, { recursive: true, mode: 0o700 });
    const log = Bun.file(join(bridge.stateDir, "herdr.log"));
    Bun.spawn([binary, "server"], {
      env: bridge.env, cwd: bridge.env["HOME"], stdin: "ignore", stdout: log, stderr: log,
    }).unref();
  }
  // Herdr serializes daemon startup with its own file lock. The listener never removes sockets.
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (await check()) return;
    await Bun.sleep(150);
  }
  throw new Error("Herdr session did not become ready");
}
