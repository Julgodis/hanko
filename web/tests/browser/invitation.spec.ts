import { test, expect } from "@playwright/test";
import { mockApi } from "./fixtures";

test("an invitation survives reload before a setup session exists", async ({ page }) => {
  await mockApi(page, false);
  await page.goto("/?enroll=invitation-token");
  await expect(page.getByRole("heading", { name: "Set up your account" })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("heading", { name: "Set up your account" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Continue", exact: true })).toBeEnabled();
  await expect(page).toHaveURL(/enroll=invitation-token/);
});
