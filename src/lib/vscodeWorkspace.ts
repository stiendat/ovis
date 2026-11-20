export function vscodeWorkspaceUrl(base: string | undefined, folder: string | null | undefined): string | null {
  if (!base || !folder?.startsWith("/")) return null;
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return null;
  url.searchParams.set("folder", folder);
  return url.href;
}
