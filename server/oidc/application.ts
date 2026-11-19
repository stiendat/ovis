import { MessageChannel, Worker, type MessagePort } from "node:worker_threads";
import type { Server, ServerWebSocket } from "bun";
import { COMPILED } from "../entries.ts";
import { jsonResponse } from "../http.ts";
import { LARGE_REPLY_BYTES } from "../herdr/client.ts";
import { nonCanonicalPath } from "../machine-api.ts";
import { OUTPUT_HARD_BYTES } from "../output-window.ts";
import { serveStatic } from "../static.ts";
import { CALLBACK, forgetLogin, forgetSession, OidcAuth, oidcSettings, type OidcSettings, type WebSession } from "./auth.ts";
import type { BridgeRequest, FromBridge, ToBridge } from "./channel.ts";
import { ensureHerdr, userBridge } from "./herdr.ts";

const NO_STORE = { "cache-control": "no-store", "referrer-policy": "no-referrer" };
const PAGE_HEADER = "x-ovis-page";
const PAGE_PARAM = "_ovis_page";
const SESSION_ENDED = 4401;
const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);

// Keep host administration, legacy ingress, remote machines and runtime selection
// outside this mode. Only the local machine alias is routed to a user bridge.
const ROUTES = /^\/api\/(?:session|health|runtime|herdr-ui|preferences|seen|agents|agent-catalog|agent\/(?:rename|commands)|integrations|layout\/ratio|sessions\/(?:history|resume)|pane\/.+|workspace\/.+|worktree\/.+|tab\/.+|fs\/.+|tasks\/.+|plan\/.+|fonts(?:\/.+)?)$/;

function routed(path: string, method: string): boolean {
  if (nonCanonicalPath(path)) return false;
  if (path === "/ws") return method === "GET";
  if (path === "/api/machines" || path === "/api/machines/events") return method === "GET";
  return ROUTES.test(path.replace(/^\/api\/machines\/local\//, "/api/"));
}

function failure(status: number, code: string, message: string, headers: Record<string, string> = {}): Response {
  return jsonResponse({ error: { code, message } }, status, { ...NO_STORE, ...headers });
}

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ ...NO_STORE, location });
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return new Response(null, { status: 303, headers });
}

function signedOut(): Response {
  return new Response('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Ovis</title><h1>Signed out of Ovis</h1><a href="/auth/login">Sign in with Pocket ID</a></html>', {
    headers: { ...NO_STORE, "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; frame-ancestors 'none'" },
  });
}

type Socket = { key: string; port: MessagePort; stop: () => void; opened: (ws: ServerWebSocket<Socket>) => void };
type Listener = Server<Socket>;

export function createOidcServer(
  settings: OidcSettings,
  { port, env = process.env, provision = ensureHerdr, fetchProvider }: {
    port: number;
    env?: NodeJS.ProcessEnv;
    provision?: typeof ensureHerdr;
    fetchProvider?: ConstructorParameters<typeof OidcAuth>[1];
  },
) {
  const auth = new OidcAuth(settings, fetchProvider);
  const workers = new Map<string, Promise<Worker>>();
  const checking = new Map<string, Promise<ReturnType<typeof userBridge>>>();
  const sessions = new Map<string, { timer: ReturnType<typeof setTimeout>; stops: Set<() => void> }>();
  let stopped = false;

  function end(key: string): void {
    const entry = sessions.get(key);
    if (!entry) return;
    sessions.delete(key);
    clearTimeout(entry.timer);
    for (const stop of entry.stops) stop();
  }

  function watch(session: WebSession, stop: () => void): () => void {
    let entry = sessions.get(session.key);
    if (!entry) {
      entry = { timer: setTimeout(() => end(session.key), Math.max(0, session.expires - Date.now())), stops: new Set() };
      sessions.set(session.key, entry);
    }
    entry.stops.add(stop);
    return () => {
      entry.stops.delete(stop);
      if (entry.stops.size === 0 && sessions.get(session.key) === entry) end(session.key);
    };
  }

  function checkHerdr(name: string): Promise<ReturnType<typeof userBridge>> {
    const existing = checking.get(name);
    if (existing) return existing;
    const check = (async () => {
      const bridge = userBridge(settings.stateDir, name, env);
      await provision(bridge);
      return bridge;
    })().finally(() => { checking.delete(name); });
    checking.set(name, check);
    return check;
  }

  function worker(name: string, recheck = false): Promise<Worker> {
    const existing = workers.get(name);
    if (existing) return recheck ? Promise.all([existing, checkHerdr(name)]).then(([thread]) => thread) : existing;
    const opening = (async () => {
      const bridge = await checkHerdr(name);
      if (stopped) throw new Error("Ovis is stopping");
      const thread = new Worker(new URL("./worker.ts", import.meta.url), { env: { ...bridge.env, OVIS_AUTH_WORKER: "1" }, workerData: { socket: bridge.socket, stateDir: bridge.stateDir } });
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => { void thread.terminate(); reject(new Error("User bridge startup timed out")); }, 20_000);
        thread.once("message", () => { clearTimeout(timeout); resolve(); });
        thread.on("error", () => { clearTimeout(timeout); reject(new Error("User bridge failed")); });
        thread.once("exit", () => {
          clearTimeout(timeout);
          if (workers.get(name) === opening) workers.delete(name);
          reject(new Error("User bridge entered an unavailable state"));
        });
      });
      return thread;
    })();
    workers.set(name, opening);
    void opening.catch(() => { if (workers.get(name) === opening) workers.delete(name); });
    return opening;
  }

  const forward = async (request: Request, listener: Listener, url: URL, session: WebSession): Promise<Response | undefined> => {
    listener.timeout(request, 60);
    const thread = await worker(session.name, url.pathname === "/ws" || url.pathname === "/api/health");
    if (!auth.valid(session.key) || request.signal.aborted) return failure(401, "oidc_required", "Sign in again");
    const headers = new Headers();
    // Build a request from the configured public origin and a short header allowlist.
    // The worker never receives the OIDC cookie, client authorization or proxy assertions.
    for (const key of ["accept", "accept-encoding", "content-type", "range", "if-range", "if-none-match", "if-modified-since", "origin", "sec-fetch-site", "x-request-id", "x-herdr-machine"]) {
      const value = request.headers.get(key);
      if (value !== null) headers.set(key, value);
    }
    headers.set("host", url.host);
    const body = request.body === null ? undefined : await request.arrayBuffer();
    if (!auth.valid(session.key) || request.signal.aborted) return failure(401, "oidc_required", "Sign in again");

    const { port1, port2 } = new MessageChannel();
    const post = (message: ToBridge) => port1.postMessage(message);
    const packet: BridgeRequest = { url: url.href, method: request.method, headers: [...headers], body, websocket: url.pathname === "/ws" };
    return new Promise((resolve) => {
      let socket: ServerWebSocket<Socket> | undefined;
      let stream: ReadableStreamDefaultController<Uint8Array> | undefined;
      let complete = false;
      let pulled: (() => void) | undefined;
      const finish = () => {
        if (complete) return;
        complete = true;
        pulled?.();
        removeWatch();
        request.signal.removeEventListener("abort", disconnected);
        port1.close();
      };
      const fail = () => {
        if (complete) return;
        socket?.close(1011, "Bridge unavailable");
        stream?.error(new Error("Bridge unavailable"));
        resolve(failure(503, "bridge_unavailable", "The personal Herdr bridge is unavailable"));
        finish();
      };
      const abort = () => { post({ type: "cancel" }); finish(); };
      const removeWatch = watch(session, () => {
        if (socket) socket.close(SESSION_ENDED, "Sign in again");
        else {
          stream?.error(new Error("Signed out"));
          resolve(failure(401, "oidc_required", "Sign in again"));
          abort();
        }
      });
      const disconnected = () => { if (!socket) abort(); };
      request.signal.addEventListener("abort", disconnected, { once: true });
      port1.on("close", fail);
      port1.on("message", (message: FromBridge) => {
        if (complete) return;
        switch (message.type) {
          case "timeout": listener.timeout(request, message.seconds); break;
          case "response": {
            const headers = new Headers(message.headers);
            headers.delete("set-cookie");
            headers.set("cache-control", "no-store");
            headers.set("referrer-policy", "no-referrer");
            const body = message.body ? new ReadableStream<Uint8Array>({
              start: (controller) => { stream = controller; },
              pull: () => new Promise<void>((resolvePull) => { pulled = resolvePull; post({ type: "pull" }); }),
              cancel: abort,
            }, { highWaterMark: 0 }) : null;
            resolve(new Response(body, { status: message.status, headers }));
            if (!body) finish();
            break;
          }
          case "upgrade": {
            const ok = auth.valid(session.key) && listener.upgrade(request, {
              data: { key: session.key, port: port1, stop: finish, opened: (ws) => { socket = ws; } },
            });
            if (ok) {
              resolve(undefined);
            } else {
              resolve(failure(426, "upgrade_required", "WebSocket upgrade required"));
              abort();
            }
            break;
          }
          case "chunk": stream?.enqueue(message.bytes); pulled?.(); pulled = undefined; break;
          case "end": stream?.close(); finish(); break;
          case "error": fail(); break;
          case "send": {
            if (!socket) break;
            if (!auth.valid(session.key)) { end(session.key); break; }
            if (socket.send(message.text) === 0) { socket.close(1011, "Terminal output stalled"); break; }
            post({ type: "buffer", sent: message.bytes, queued: socket.getBufferedAmount() });
            break;
          }
          case "close": socket?.close(message.code, message.reason); break;
        }
      });
      try { thread.postMessage({ request: packet, port: port2 }, body ? [port2, body] : [port2]); }
      catch { port2.close(); fail(); }
    });
  };

  const listener = Bun.serve<Socket>({
    hostname: "127.0.0.1", port, maxRequestBodySize: 64 * 1024 * 1024,
    async fetch(request, listener) {
      const input = new URL(request.url);
      const path = input.pathname;
      if (path === "/healthz" && request.method === "GET") return jsonResponse({ ok: true }, 200, NO_STORE);
      const base = new URL(settings.origin);
      if (listener.requestIP(request)?.address !== "127.0.0.1" ||
          request.headers.get("host") !== base.host || request.headers.get("x-forwarded-proto") !== "https") {
        return failure(421, "unexpected_ingress", "Use the configured HTTPS address");
      }
      const url = new URL(base.origin + path + input.search);
      const site = request.headers.get("sec-fetch-site");
      if ((!SAFE.has(request.method) || path === "/ws") &&
          (request.headers.get("origin") !== settings.origin || site === "cross-site")) {
        return failure(403, "invalid_origin", "Use controls from this app");
      }
      try {
        const session = auth.session(request);
        if (path === CALLBACK && request.method === "GET") {
          const identity = await auth.identity(request, url.search).catch(() => null);
          if (!identity) return failure(401, "oidc_callback_failed", "Pocket ID login failed. Open Ovis to try again.", { "set-cookie": forgetLogin() });
          const name = auth.allocate(identity);
          await worker(name, true);
          if (session) { auth.revoke(session.key); end(session.key); }
          return redirect("/", [forgetLogin(), auth.issue(name)]);
        }
        if (path === "/auth/signed-out" && request.method === "GET") return signedOut();
        if (path === "/auth/login" && request.method === "GET") {
          const login = await auth.login();
          return redirect(login.url.href, [login.cookie]);
        }
        if (path === "/api/auth" && request.method === "DELETE") {
          if (!session || request.headers.get(PAGE_HEADER) !== session.binding) return failure(401, "oidc_required", "Sign in again");
          auth.revoke(session.key);
          end(session.key);
          return new Response(null, { status: 204, headers: { ...NO_STORE, "set-cookie": forgetSession() } });
        }
        if (path.startsWith("/auth/")) return failure(404, "not_found", "Not found");
        if (path.startsWith("/api/") || path === "/ws") {
          if (!session) return failure(401, "oidc_required", "Sign in again");
          if (!routed(path, request.method)) return failure(404, "not_found", "Not available in this deployment");
          const binding = request.headers.get(PAGE_HEADER) ?? (SAFE.has(request.method) ? url.searchParams.get(PAGE_PARAM) : null);
          if (binding !== session.binding) return failure(401, "oidc_required", "Reload Ovis to continue");
          url.searchParams.delete(PAGE_PARAM);
          return await forward(request, listener, url, session);
        }
        if (!SAFE.has(request.method)) return failure(405, "method_not_allowed", "Use GET");
        if (path.startsWith("/assets/") || path.startsWith("/icons/") || ["/sw.js", "/manifest.webmanifest", "/favicon.ico"].includes(path)) {
          return serveStatic(path, request.headers.get("accept-encoding"), settings.origin);
        }
        if (!session) {
          const login = await auth.login();
          return redirect(login.url.href, [login.cookie]);
        }
        const html = await serveStatic("/index.html", null, settings.origin);
        const headers = new Headers(html.headers);
        for (const [header, value] of Object.entries(NO_STORE)) headers.set(header, value);
        const content = (await html.text()).replace(/<head>/i,
          `<head><meta name="ovis-oidc-page" content="${session.binding}"><meta name="ovis-oidc-account" content="${session.account}">`);
        return new Response(content, { status: html.status, headers });
      } catch (error) {
        console.warn("Ovis OIDC could not complete a request", error instanceof Error ? error.name : "UnknownError");
        return failure(503, "ovis_unavailable", "Pocket ID or the personal Herdr session is unavailable. Open Ovis to try again.");
      }
    },
    websocket: {
      backpressureLimit: OUTPUT_HARD_BYTES + LARGE_REPLY_BYTES,
      closeOnBackpressureLimit: true,
      open(ws) {
        ws.data.opened(ws);
        if (!auth.valid(ws.data.key)) { ws.close(SESSION_ENDED, "Sign in again"); return; }
        ws.data.port.postMessage({ type: "open" } satisfies ToBridge);
      },
      message(ws, data) {
        if (!auth.valid(ws.data.key)) { end(ws.data.key); return; }
        ws.data.port.postMessage({ type: "message", text: String(data) } satisfies ToBridge);
      },
      drain(ws) { ws.data.port.postMessage({ type: "drain" } satisfies ToBridge); },
      close(ws, code, reason) {
        ws.data.port.postMessage({ type: "close", code, reason } satisfies ToBridge);
        ws.data.stop();
      },
    },
  });
  return {
    port: listener.port!,
    async stop() {
      stopped = true;
      for (const key of sessions.keys()) end(key);
      listener.stop(true);
      await Promise.allSettled([...workers.values()].map(async (opening) => {
        const thread = await opening;
        await new Promise<void>((resolve) => {
          const timeout = setTimeout(resolve, 3000);
          const done = () => { clearTimeout(timeout); resolve(); };
          thread.once("message", done);
          thread.once("exit", done);
          thread.postMessage("stop");
        });
        await thread.terminate();
      }));
      auth.close();
    },
  };
}

export async function serveOidc(): Promise<void> {
  if (COMPILED || process.platform !== "linux") throw new Error("Run OIDC from the Ovis checkout with Bun on Linux");
  if (process.env["HOST"] && process.env["HOST"] !== "127.0.0.1") throw new Error("OIDC requires a loopback listener");
  const port = Number(process.env["PORT"] ?? 7317);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Set PORT to a valid TCP port");
  const app = createOidcServer(oidcSettings(process.env), { port });
  console.log(`Ovis OIDC listening on 127.0.0.1:${app.port}`);
  const stop = () => { void app.stop().finally(() => process.exit()); };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
}
