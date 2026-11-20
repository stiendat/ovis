import { expect, test } from "bun:test";

import { vscodeWorkspaceUrl } from "./vscodeWorkspace.ts";

test("opens the worktree folder at the configured editor endpoint", () => {
  const folder = "/home/user/worktrees/review #1 & follow-up";
  const url = new URL(vscodeWorkspaceUrl("https://editor.example.com/workbench/", folder)!);
  expect(url.origin).toBe("https://editor.example.com");
  expect(url.pathname).toBe("/workbench/");
  expect(url.searchParams.get("folder")).toBe(folder);
});

test("requires a folder and a clean HTTPS editor endpoint", () => {
  const folder = "/worktree";
  for (const base of [undefined, "", "editor.example.com", "http://editor.example.com", "https://user:pass@editor.example.com", "https://editor.example.com/?token=secret", "https://editor.example.com/#secret"]) {
    expect(vscodeWorkspaceUrl(base, folder)).toBeNull();
  }
  expect(vscodeWorkspaceUrl("https://editor.example.com", "relative/worktree")).toBeNull();
  expect(vscodeWorkspaceUrl("https://editor.example.com", null)).toBeNull();
});
