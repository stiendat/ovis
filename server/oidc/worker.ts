import { parentPort, workerData, type MessagePort } from "node:worker_threads";
import type { BridgeRequest, FromBridge, ToBridge } from "./channel.ts";
import type { UserBridge } from "./herdr.ts";

const bridge = workerData as Pick<UserBridge, "socket" | "stateDir">;
if (!parentPort || process.env["HERDR_SOCKET"] !== bridge.socket || process.env["OVIS_STATE_DIR"] !== bridge.stateDir) {
  throw new Error("User bridge requires a separate worker environment");
}

// These modules load after the worker's environment is set. Several agents cache
// their store roots and pane IDs at module scope.
const { createServer } = await import("../index.ts");
const { handleRequest } = await import("../dispatch.ts");
const { checkHerdrSockets } = await import("../herdr/client.ts");
checkHerdrSockets((socket) => {
  if (socket !== bridge.socket) throw new Error("Unexpected Herdr socket for user bridge");
  return socket;
});
const app = createServer({ listenerless: true, stateDir: bridge.stateDir, token: "", tailscaleOwner: null, system: null });
const sockets = app.context.services.core.socketHandlers;
type Client = Parameters<typeof sockets.open>[0];

const parent = parentPort;
parent.on("message", (message: "stop" | { request: BridgeRequest; port: MessagePort }) => {
  if (message === "stop") {
    app.stop();
    parent.postMessage("stopped");
    return;
  }
  const { request, port } = message;
  void serve(request, port).catch(() => { port.postMessage({ type: "error" } satisfies FromBridge); port.close(); });
});
parentPort.postMessage("ready");

async function serve(packet: BridgeRequest, port: MessagePort): Promise<void> {
  const post = (message: FromBridge) => port.postMessage(message);
  const abort = new AbortController();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let client: Client | undefined;
  let pending = 0;
  let queued = 0;
  let live = false;
  let disconnected = false;
  const close = (code: number, reason: string) => {
    if (disconnected) return;
    disconnected = true;
    live = false;
    abort.abort();
    if (client) sockets.close(client, code, reason);
    void reader?.cancel().catch(() => {});
    port.close();
  };
  port.on("close", () => close(1006, ""));
  port.on("message", (message: ToBridge) => {
    switch (message.type) {
      case "cancel": close(1006, ""); break;
      case "pull":
        void reader?.read().then((result) => {
          if (disconnected) return;
          if (result.done) { post({ type: "end" }); close(1000, ""); }
          else post({ type: "chunk", bytes: result.value });
        }).catch(() => { post({ type: "error" }); close(1011, ""); });
        break;
      case "open": if (client && !disconnected) { live = true; void sockets.open(client); } break;
      case "message": if (client && live) void sockets.message(client, message.text); break;
      case "drain": if (client && live) { queued = 0; sockets.drain(client); } break;
      case "buffer": pending -= message.sent; queued = message.queued; break;
      case "close": close(message.code, message.reason); break;
    }
  });
  const request = new Request(packet.url, { method: packet.method, headers: packet.headers, body: packet.body, signal: abort.signal });
  const response = await handleRequest(request, {
    ...app.context,
    oidc: true,
    requestIP: () => ({ address: "127.0.0.1" }),
    timeout: (_, seconds) => post({ type: "timeout", seconds }),
    upgrade: (_, { data }) => {
      if (!packet.websocket || disconnected) return false;
      client = {
        data,
        get readyState() { return live ? 1 : 3; },
        send(text) {
          if (!live) return 0;
          const bytes = Buffer.byteLength(text);
          pending += bytes;
          post({ type: "send", text, bytes });
          return bytes;
        },
        getBufferedAmount: () => pending + queued,
        close(code, reason) {
          live = false;
          post({ type: "close", code, reason });
        },
      };
      post({ type: "upgrade" });
      return true;
    },
  });
  if (disconnected || response === undefined) return;
  if (packet.method !== "HEAD") reader = response.body?.getReader();
  post({ type: "response", status: response.status, headers: [...response.headers], body: reader !== undefined });
  if (!reader) close(1000, "");
}
