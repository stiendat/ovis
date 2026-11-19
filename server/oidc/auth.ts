import { Database } from "bun:sqlite";
import { createHmac, randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import * as oidc from "openid-client";
import { parseCookies } from "../auth.ts";

export const CALLBACK = "/auth/oidc/callback";
const SESSION_COOKIE = "__Host-ovis-session";
const LOGIN_COOKIE = "__Host-ovis-login";
const LOGIN_SECONDS = 600;
const SESSION_SECONDS = 12 * 60 * 60;

export interface OidcSettings {
  origin: string;
  issuer: URL;
  backchannel?: URL;
  clientId: string;
  clientSecret: string;
  redirect: string;
  secret: string;
  stateDir: string;
}

export function oidcSettings(env: NodeJS.ProcessEnv): OidcSettings {
  const read = (key: string): string => {
    const value = env[key];
    if (!value?.trim()) throw new Error(`Set ${key} for OIDC`);
    return value;
  };
  const https = (key: string): URL => {
    const value = new URL(read(key));
    if (value.protocol !== "https:" || value.username || value.password || value.search || value.hash) throw new Error(`${key} must be an HTTPS URL`);
    return value;
  };
  const base = https("APP_BASE_URL");
  if (base.pathname !== "/") throw new Error("APP_BASE_URL must be an origin");
  const redirect = env["OIDC_REDIRECT_URI"] ?? base.origin + CALLBACK;
  if (redirect !== base.origin + CALLBACK) throw new Error("OIDC_REDIRECT_URI must be APP_BASE_URL plus " + CALLBACK);
  const secret = read("SESSION_SECRET");
  if (Buffer.byteLength(secret) < 32) throw new Error("SESSION_SECRET needs at least 32 bytes of random data");
  const stateDir = read("OVIS_STATE_DIR");
  if (!isAbsolute(stateDir)) throw new Error("OVIS_STATE_DIR must be an absolute path");
  const rawBackchannel = env["OIDC_LOOPBACK_URL"];
  const backchannel = rawBackchannel ? new URL(rawBackchannel) : undefined;
  if (backchannel && (backchannel.hostname !== "127.0.0.1" || backchannel.protocol !== "http:" ||
      backchannel.pathname !== "/" || backchannel.search || backchannel.hash || backchannel.username || backchannel.password)) {
    throw new Error("OIDC_LOOPBACK_URL must be an HTTP origin on 127.0.0.1");
  }
  return { backchannel, origin: base.origin, redirect, secret, stateDir, issuer: https("OIDC_ISSUER_URL"), clientId: read("OIDC_CLIENT_ID"), clientSecret: read("OIDC_CLIENT_SECRET") };
}

type Identity = { issuer: string; subject: string };
type Login = { state: string; nonce: string; verifier: string };
export type WebSession = { key: string; name: string; expires: number; binding: string; account: string };

const random = () => randomBytes(32).toString("base64url");

function cookie(name: string, value: string, age: number): string {
  return `${name}=${value}; Max-Age=${age}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

export const forgetSession = () => cookie(SESSION_COOKIE, "", 0);
export const forgetLogin = () => cookie(LOGIN_COOKIE, "", 0);

export class OidcAuth {
  private readonly db: Database;
  private discovery?: Promise<oidc.Configuration>;

  constructor(readonly settings: OidcSettings, private readonly fetchProvider?: oidc.CustomFetch) {
    mkdirSync(settings.stateDir, { recursive: true, mode: 0o700 });
    this.db = new Database(join(settings.stateDir, "identities.sqlite"), { create: true, strict: true });
    this.db.exec(`
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS users (
        issuer TEXT NOT NULL, subject TEXT NOT NULL, name TEXT NOT NULL UNIQUE,
        PRIMARY KEY (issuer, subject)
      );
      CREATE TABLE IF NOT EXISTS web_sessions (
        key TEXT PRIMARY KEY, name TEXT NOT NULL REFERENCES users(name), expires INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oidc_logins (
        key TEXT PRIMARY KEY, state TEXT NOT NULL, nonce TEXT NOT NULL, verifier TEXT NOT NULL, expires INTEGER NOT NULL
      );
    `);
  }

  private hash(purpose: string, value: string): string {
    return createHmac("sha256", this.settings.secret).update(purpose + "\0" + value).digest("base64url");
  }

  private readKey(request: Request, name: string): string | undefined {
    const value = parseCookies(request.headers.get("cookie")).get(name);
    if (value && /^[\w-]{43}$/.test(value)) return this.hash(name, value);
  }

  private loopbackFetch(): oidc.CustomFetch | undefined {
    const target = this.settings.backchannel;
    if (!target) return undefined;
    return (input, init) => {
      const url = new URL(input);
      if (url.origin !== this.settings.issuer.origin) throw new Error("Pocket ID advertised an unexpected backchannel origin");
      const headers = new Headers(init.headers);
      headers.set("host", url.host);
      headers.set("x-forwarded-proto", "https");
      const body = init.body instanceof Uint8Array ? Uint8Array.from(init.body) : init.body;
      return fetch(new URL(target.origin + url.pathname + url.search), { ...init, headers, body, redirect: "manual" });
    };
  }

  private provider(): Promise<oidc.Configuration> {
    return this.discovery ??= oidc.discovery(
      this.settings.issuer, this.settings.clientId,
      { id_token_signed_response_alg: "RS256" },
      oidc.ClientSecretBasic(this.settings.clientSecret),
      { execute: [oidc.enableNonRepudiationChecks], timeout: 10, [oidc.customFetch]: this.fetchProvider ?? this.loopbackFetch() },
    ).catch((error: unknown) => { this.discovery = undefined; throw error; });
  }

  async login(): Promise<{ url: URL; cookie: string }> {
    const provider = await this.provider();
    const token = random();
    const state = random();
    const nonce = random();
    const verifier = oidc.randomPKCECodeVerifier();
    const challenge = await oidc.calculatePKCECodeChallenge(verifier);
    this.db.run("DELETE FROM oidc_logins WHERE expires <= ?", [Date.now()]);
    this.db.run("INSERT INTO oidc_logins VALUES (?, ?, ?, ?, ?)", [this.hash(LOGIN_COOKIE, token), state, nonce, verifier, Date.now() + LOGIN_SECONDS * 1000]);
    return {
      url: oidc.buildAuthorizationUrl(provider, {
        redirect_uri: this.settings.redirect, scope: "openid profile email", response_type: "code",
        state, nonce, code_challenge: challenge, code_challenge_method: "S256",
      }),
      cookie: cookie(LOGIN_COOKIE, token, LOGIN_SECONDS),
    };
  }

  async identity(request: Request, search: string): Promise<Identity | null> {
    const key = this.readKey(request, LOGIN_COOKIE);
    if (!key) return null;
    const flow = this.db.query<Login, [string, number]>("DELETE FROM oidc_logins WHERE key = ? AND expires > ? RETURNING state, nonce, verifier").get(key, Date.now());
    if (!flow) return null;
    const tokens = await oidc.authorizationCodeGrant(await this.provider(), new URL(this.settings.redirect + search), {
      pkceCodeVerifier: flow.verifier, expectedState: flow.state, expectedNonce: flow.nonce, idTokenExpected: true,
    });
    const claims = tokens.claims();
    if (!claims || typeof claims.sub !== "string" || !claims.sub || !Number.isFinite(claims.exp) || claims.exp * 1000 <= Date.now()) return null;
    return { issuer: claims.iss, subject: claims.sub };
  }

  allocate({ issuer, subject }: Identity): string {
    // A conflict on the generated name fails closed. A second login for this identity
    // gets the row that won the insert, even across processes and restarts.
    return this.db.query<{ name: string }, [string, string, string]>(
      "INSERT INTO users VALUES (?, ?, ?) ON CONFLICT(issuer, subject) DO UPDATE SET subject = excluded.subject RETURNING name",
    ).get(issuer, subject, "ovis-u-" + randomBytes(16).toString("hex"))!.name;
  }

  issue(name: string): string {
    const token = random();
    this.db.run("DELETE FROM web_sessions WHERE expires <= ?", [Date.now()]);
    this.db.run("INSERT INTO web_sessions VALUES (?, ?, ?)", [this.hash(SESSION_COOKIE, token), name, Date.now() + SESSION_SECONDS * 1000]);
    return cookie(SESSION_COOKIE, token, SESSION_SECONDS);
  }

  session(request: Request): WebSession | null {
    const key = this.readKey(request, SESSION_COOKIE);
    if (!key) return null;
    const row = this.db.query<{ name: string; expires: number }, [string, number]>(
      "SELECT name, expires FROM web_sessions WHERE key = ? AND expires > ?",
    ).get(key, Date.now());
    return row && { ...row, key, binding: this.hash("page", key), account: this.hash("browser-account", row.name) };
  }

  valid(key: string): boolean {
    return this.db.query("SELECT 1 FROM web_sessions WHERE key = ? AND expires > ?").get(key, Date.now()) !== null;
  }

  revoke(key: string): void { this.db.run("DELETE FROM web_sessions WHERE key = ?", [key]); }
  close(): void { this.db.close(); }
}
