import { test, expect } from "@playwright/test";
import { mockApi } from "./fixtures";

test("an authenticated visitor on an unknown route reaches account settings", async ({ page }) => {
  await mockApi(page);
  await page.goto("/unknown-route");
  await expect(page).toHaveURL(/\/account\/profile$/);
  await expect(page.getByRole("heading", { name: "Your profile", exact: true })).toBeVisible();
});
