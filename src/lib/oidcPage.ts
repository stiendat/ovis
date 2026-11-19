import { clearOvisStorage } from "./legacyStorage.ts";

const meta = (name: string) => typeof document === "undefined" ? null : document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`)?.content ?? null;
export const oidcPage = meta("ovis-oidc-page");
const account = meta("ovis-oidc-account");
const ACCOUNT_KEY = "ovis:oidc-account";
let leaving = false;
let signingOut = false;

export function setOidcSigningOut(value: boolean): void { signingOut = value; }

export function leaveOidcPage(path = location.pathname + location.search): void {
  if (leaving || signingOut) return;
  leaving = true;
  document.getElementById("root")?.replaceChildren();
  location.replace(path);
}

export function signedOutOfOidc(): void {
  signingOut = false;
  try {
    clearOvisStorage(window.localStorage);
    clearOvisStorage(window.sessionStorage);
  } catch { }
  leaveOidcPage("/auth/signed-out");
}

if (account !== null) {
  try {
    if (localStorage.getItem(ACCOUNT_KEY) !== account) {
      clearOvisStorage(localStorage);
      clearOvisStorage(sessionStorage);
      localStorage.setItem(ACCOUNT_KEY, account);
    }
    if (sessionStorage.getItem(ACCOUNT_KEY) !== account) {
      clearOvisStorage(sessionStorage);
      sessionStorage.setItem(ACCOUNT_KEY, account);
    }
  } catch { }
  window.addEventListener("storage", (event) => {
    if (event.key === ACCOUNT_KEY && event.newValue !== account) {
      leaveOidcPage(event.newValue === null ? "/auth/signed-out" : "/");
    }
  });
  window.addEventListener("pageshow", (event) => { if (event.persisted) leaveOidcPage(); });
}

export function oidcResource(path: string): string {
  if (oidcPage === null) return path;
  const url = new URL(path, location.href);
  if (url.host !== location.host || (!url.pathname.startsWith("/api/") && url.pathname !== "/ws")) return path;
  url.searchParams.set("_ovis_page", oidcPage);
  return url.href;
}
