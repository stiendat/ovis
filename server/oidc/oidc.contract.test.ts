import { afterEach, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CustomFetch } from "openid-client";
import { createOidcServer } from "./application.ts";
import { CALLBACK, OidcAuth, type OidcSettings } from "./auth.ts";
import { ensureHerdr, type UserBridge } from "./herdr.ts";

const ISSUER = "https://pocket-id.example";
const ORIGIN = "https://ovis.example";
const CLIENT = "ovis-dev";
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const wrongKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
const cleanups: (() => void | Promise<void>)[] = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function settings(): OidcSettings {
  const stateDir = mkdtempSync(join(tmpdir(), "ovis-id-"));
  cleanups.push(() => rmSync(stateDir, { recursive: true, force: true }));
  return {
    origin: ORIGIN, issuer: new URL(ISSUER), stateDir,
    redirect: ORIGIN + CALLBACK, clientId: CLIENT,
    clientSecret: "oidc-test-client-secret", secret: "oidc-test-session-secret-with-32-bytes",
  };
}

type Claim = { subject: string; nonce: string; challenge: string; fault?: "expired" | "audience" | "issuer" | "nonce" | "signature" };

function provider() {
  const codes = new Map<string, Claim>();
  const fetchProvider: CustomFetch = async (url, options) => {
    const path = new URL(url).pathname;
    if (path === "/.well-known/openid-configuration") return Response.json({
      issuer: ISSUER, authorization_endpoint: ISSUER + "/authorize", token_endpoint: ISSUER + "/token", jwks_uri: ISSUER + "/jwks",
      response_types_supported: ["code"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["client_secret_basic"],
      id_token_signing_alg_values_supported: ["RS256"], subject_types_supported: ["public"],
    });
    if (path === "/jwks") return Response.json({ keys: [{ ...pair.publicKey.export({ format: "jwk" }), kid: "test", alg: "RS256", use: "sig" }] });
    if (path !== "/token") return new Response(null, { status: 404 });
    const authorization = new Headers(options?.headers).get("authorization") ?? "";
    expect(authorization.startsWith("Basic ")).toBe(true);
    expect(decodeURIComponent(Buffer.from(authorization.slice(6), "base64").toString())).toBe(CLIENT + ":oidc-test-client-secret");
    const body = new URLSearchParams(String(options?.body));
    const code = body.get("code") ?? "";
    const claim = codes.get(code);
    codes.delete(code);
    if (!claim || body.get("redirect_uri") !== ORIGIN + CALLBACK ||
        createHash("sha256").update(body.get("code_verifier") ?? "").digest("base64url") !== claim.challenge) {
      return Response.json({ error: "invalid_grant" }, { status: 400 });
    }
    const now = Math.floor(Date.now() / 1000);
    const jwt = JSON.stringify({
      iss: claim.fault === "issuer" ? "https://someone-else.example" : ISSUER,
      aud: claim.fault === "audience" ? "different-client" : CLIENT, sub: claim.subject,
      nonce: claim.fault === "nonce" ? "unexpected" : claim.nonce,
      iat: now - 20, exp: now + (claim.fault === "expired" ? -10 : 600),
      email: "same-email@example.com",
    });
    const encoded = Buffer.from('{"alg":"RS256","kid":"test"}').toString("base64url") + "." + Buffer.from(jwt).toString("base64url");
    return Response.json({
      access_token: "not-retained", token_type: "Bearer",
      id_token: encoded + "." + sign("sha256", Buffer.from(encoded), claim.fault === "signature" ? wrongKey : pair.privateKey).toString("base64url"),
    });
  };
  return { codes, fetchProvider };
}

const cookiePair = (value: string) => value.split(";")[0]!;

test("issuer and subject own exactly one persistent Herdr name, independent of web sessions", () => {
  const config = settings();
  const alice = { issuer: ISSUER, subject: "alice" };
  const first = new OidcAuth(config);
  const name = first.allocate(alice);
  expect(first.allocate({ ...alice, issuer: "https://other.example" })).not.toBe(name);
  const cookie = first.issue(name);
  first.close();
  const restarted = new OidcAuth(config);
  try {
    expect(restarted.allocate(alice)).toBe(name);
    expect(restarted.allocate({ ...alice, subject: "bob" })).not.toBe(name);
    const session = restarted.session(new Request(ORIGIN, { headers: { cookie: cookiePair(cookie) } }));
    expect(session?.name).toBe(name);
    restarted.revoke(session!.key);
    expect(restarted.valid(session!.key)).toBe(false);
  } finally { restarted.close(); }
});

test("OIDC binds PKCE, state and nonce and validates signatures, claims and expiration", async () => {
  const mock = provider();
  const auth = new OidcAuth(settings(), mock.fetchProvider);
  cleanups.push(() => auth.close());
  async function authorize(fault?: Claim["fault"]) {
    const login = await auth.login();
    const state = login.url.searchParams.get("state")!;
    const code = crypto.randomUUID();
    expect(login.url.origin).toBe(ISSUER);
    expect(login.url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(login.cookie).toMatch(/; Secure; HttpOnly; SameSite=Lax$/);
    mock.codes.set(code, { subject: "alice", nonce: login.url.searchParams.get("nonce")!, challenge: login.url.searchParams.get("code_challenge")!, fault });
    const search = "?" + new URLSearchParams({ state, code });
    const request = new Request(ORIGIN + CALLBACK + search, { headers: { cookie: cookiePair(login.cookie) } });
    return { request, search };
  }
  const good = await authorize();
  expect(await auth.identity(good.request, good.search)).toEqual({ issuer: ISSUER, subject: "alice" });
  expect(await auth.identity(good.request, good.search)).toBeNull();
  const wrongState = await authorize();
  expect(await auth.identity(new Request(ORIGIN + CALLBACK), wrongState.search)).toBeNull();
  await expect(auth.identity(wrongState.request, wrongState.search.replace(/state=[^&]+/, "state=unexpected"))).rejects.toThrow();
  for (const fault of ["audience", "issuer", "nonce", "signature"] as const) {
    const bad = await authorize(fault);
    await expect(auth.identity(bad.request, bad.search)).rejects.toThrow();
  }
  const expired = await authorize("expired");
  expect(await auth.identity(expired.request, expired.search).catch(() => null)).toBeNull();
});

const herdr = process.env["OVIS_OIDC_TEST_HERDR"] ?? Bun.which("herdr");

test.skipIf(!herdr)("one listener routes multiple devices to their own real Herdr sessions and closes revoked sockets", async () => {
  const config = settings();
  const mock = provider();
  const bridges = new Map<string, UserBridge>();
  const env = { ...process.env, OVIS_HERDR_BIN: herdr ?? undefined };
  const start = () => createOidcServer(config, {
    port: 0, env, fetchProvider: mock.fetchProvider,
    provision: async (bridge) => { bridges.set(bridge.name, bridge); await ensureHerdr(bridge); },
  });
  let app = start();
  cleanups.push(async () => {
    await app.stop();
    for (const bridge of bridges.values()) {
      await Bun.spawn([herdr!, "server", "stop"], { env: bridge.env, stdout: "ignore", stderr: "ignore" }).exited;
    }
  });
  const read = (path: string, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    headers.set("Host", new URL(ORIGIN).host);
    headers.set("X-Forwarded-Proto", "https");
    return fetch(`http://127.0.0.1:${app.port}${path}`, { ...init, headers, redirect: "manual" });
  };
  const database = new OidcAuth(config);
  cleanups.push(() => database.close());
  async function login(subject: string) {
    const login = await read("/");
    expect(login.status).toBe(303);
    const auth = new URL(login.headers.get("location")!);
    const code = crypto.randomUUID();
    mock.codes.set(code, { subject, nonce: auth.searchParams.get("nonce")!, challenge: auth.searchParams.get("code_challenge")! });
    const callback = await read(CALLBACK + "?" + new URLSearchParams({ state: auth.searchParams.get("state")!, code }), {
      headers: { cookie: cookiePair(login.headers.get("set-cookie")!) },
    });
    if (callback.status !== 303) throw new Error(`Login returned ${callback.status}: ${await callback.text()}`);
    const cookie = cookiePair(callback.headers.getSetCookie().find((value) => value.startsWith("__Host-ovis-session="))!);
    const session = database.session(new Request(ORIGIN, { headers: { cookie } }))!;
    return { cookie, "x-ovis-page": session.binding };
  }
  expect((await read("/api/session", { headers: { authorization: "Bearer legacy", "tailscale-user-login": "alice" } })).status).toBe(401);
  const [alice, alicePhone, bob] = await Promise.all([login("alice"), login("alice"), login("bob")]);
  expect(bridges.size).toBe(2);
  expect(alice.cookie).not.toBe(alicePhone.cookie);

  const create = (headers: HeadersInit, label: string) => read("/api/workspace/create", {
    method: "POST", headers: { ...headers, origin: ORIGIN, "content-type": "application/json" },
    body: JSON.stringify({ label }),
  });
  const results = await Promise.all([create(alice, "Alice workspace"), create(bob, "Bob workspace")]);
  for (const result of results) if (result.status !== 200 && result.status !== 201) throw new Error(await result.text());
  const snapshot = async (headers: HeadersInit) => {
    const response = await read("/api/session?" + new URLSearchParams({ session: [...bridges.keys()].at(-1)! }), { headers });
    if (response.status !== 200) throw new Error(await response.text());
    return await response.json() as { snapshot: { workspaces: { workspace_id: string; label: string }[]; panes: { workspace_id: string; pane_id: string }[] } };
  };
  const [aliceState, bobState] = await Promise.all([snapshot(alicePhone), snapshot(bob)]);
  expect(JSON.stringify(aliceState)).toContain("Alice workspace");
  expect(JSON.stringify(aliceState)).not.toContain("Bob workspace");
  expect(JSON.stringify(bobState)).toContain("Bob workspace");
  expect(JSON.stringify(bobState)).not.toContain("Alice workspace");
  expect((await read("/api/session", { headers: { ...alice, "x-ovis-page": bob["x-ovis-page"] } })).status).toBe(401);
  expect((await create(bob, "Bob only")).ok).toBe(true);
  const bobExtra = (await snapshot(bob)).snapshot;
  const extraWorkspace = bobExtra.workspaces.find((item) => item.label === "Bob only")!;
  const bobPane = bobExtra.panes.find((item) => item.workspace_id === extraWorkspace.workspace_id)!.pane_id;
  const paneQuery = "?" + new URLSearchParams({ pane_id: bobPane });
  const send = (headers: HeadersInit) => read("/api/pane/input", {
    method: "POST", headers: { ...headers, origin: ORIGIN, "content-type": "application/json" },
    body: JSON.stringify({ pane_id: bobPane, text: "test marker" }),
  });
  expect((await send(alice)).status).toBe(404);
  expect((await send(bob)).status).toBe(200);
  expect((await read("/api/pane/read" + paneQuery, { headers: alice })).status).toBe(404);
  expect(await (await read("/api/pane/conversation" + paneQuery, { headers: alice })).text()).not.toContain("test marker");
  expect((await read("/api/workspace/create", { method: "POST", headers: { ...alice, origin: "https://other.example" } })).status).toBe(403);
  expect((await read("/api/machines/remote/session", { headers: alice })).status).toBe(404);
  expect((await read("/api/bridge", { headers: alice })).status).toBe(404);

  const Socket = WebSocket as unknown as new (url: string, options: { headers: Record<string, string> }) => WebSocket;
  const ws = new Socket(`ws://127.0.0.1:${app.port}/ws?_ovis_page=${alice["x-ovis-page"]}`, {
    headers: { host: new URL(ORIGIN).host, "x-forwarded-proto": "https", origin: ORIGIN, cookie: alice.cookie },
  });
  const closed = new Promise<number>((resolve) => ws.addEventListener("close", (event) => resolve(event.code), { once: true }));
  const wsSnapshot = await new Promise<string>((resolve, reject) => {
    ws.addEventListener("message", (event) => { if (JSON.parse(String(event.data)).type === "snapshot") resolve(String(event.data)); });
    ws.addEventListener("error", () => reject(new Error("Personal WebSocket failed")), { once: true });
  });
  expect(wsSnapshot).toContain("Alice workspace");
  expect(wsSnapshot).not.toContain("Bob workspace");
  expect((await read("/api/auth", { method: "DELETE", headers: { ...alice, origin: ORIGIN } })).status).toBe(204);
  expect(await closed).toBe(4401);
  expect((await read("/api/session", { headers: alice })).status).toBe(401);
  await app.stop();
  app = start();
  expect(JSON.stringify(await snapshot(alicePhone))).toContain("Alice workspace");
  expect(JSON.stringify(await snapshot(bob))).toContain("Bob workspace");
  expect(bridges.size).toBe(2);
}, 45_000);
