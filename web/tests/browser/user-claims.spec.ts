import { test, expect } from "@playwright/test";
import { editUser, mockApi } from "./fixtures";

test("cancelling a slow user load cannot overwrite another user's claims", async ({ page }) => {
  await mockApi(page);
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  let started!: () => void;
  const pending = new Promise<void>(resolve => { started = resolve; });
  await page.route("**/api/admin/users/*/claims", async route => {
    const alice = route.request().url().includes("/alice/");
    if (alice) { started(); await gate; }
    await route.fulfill({ json: [{ claim_name: "department", claim_value: alice ? "alice-team" : "bob-team", required_scope: null }] });
  });
  await page.goto("/admin/clients/users");
  await editUser(page, "alice");
  await pending;
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await editUser(page, "bob");
  await expect(page.locator("textarea")).toHaveValue('"bob-team"');
  const completed = page.waitForResponse("**/api/admin/users/alice/claims");
  release();
  await completed;
  const saved = page.waitForRequest(request => request.method() === "PUT" && request.url().endsWith("/bob/claims"));
  await page.getByRole("button", { name: "Save custom claims" }).click();
  expect((await saved).postDataJSON()).toEqual({ claims: [{ claim_name: "department", claim_value: "bob-team", required_scope: null }] });
});
