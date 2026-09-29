import { test, expect } from "@playwright/test";
import { mockApi } from "./fixtures";

test("bootstrap checks the code before allowing profile customization", async ({ page }) => {
  await mockApi(page, false);
  await page.route("**/api/setup-status", route => route.fulfill({ json: { initialized: false, bootstrap_enabled: true } }));
  let calls = 0;
  await page.route("**/api/bootstrap", route => {
    calls++;
    return route.request().postDataJSON().token === "correct-code"
      ? route.fulfill({ json: { ok: true, setup_only: true } })
      : route.fulfill({ status: 401, json: { error: "unauthorized" } });
  });
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Continue", exact: true })).toBeDisabled();
  await page.locator('input[type="password"]').fill("wrong-code");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("setup code was not accepted");
  await expect(page.getByRole("heading", { name: "Enter setup code" })).toBeVisible();
  await page.locator('input[type="password"]').fill("correct-code");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByRole("heading", { name: "OIDC information" })).toBeVisible();
  expect(calls).toBe(2);
});
