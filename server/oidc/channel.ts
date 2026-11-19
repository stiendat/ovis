export type BridgeRequest = {
  url: string;
  method: string;
  headers: [string, string][];
  body?: ArrayBuffer;
  websocket: boolean;
};

export type ToBridge =
  | { type: "pull" | "cancel" | "open" | "drain" }
  | { type: "message"; text: string }
  | { type: "buffer"; sent: number; queued: number }
  | { type: "close"; code: number; reason: string };

export type FromBridge =
  | { type: "upgrade" | "end" | "error" }
  | { type: "timeout"; seconds: number }
  | { type: "response"; status: number; headers: [string, string][]; body: boolean }
  | { type: "chunk"; bytes: Uint8Array }
  | { type: "send"; text: string; bytes: number }
  | { type: "close"; code?: number; reason?: string };
