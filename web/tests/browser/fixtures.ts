import { expect, type Page } from "@playwright/test";

export const users = ["alice", "bob"].map(id => ({
  id, username: id, display_name: id, email: null, invitation_label: null,
  is_admin: false, disabled: false, created_at: 1, groups: [],
}));

export async function mockApi(page: Page, authenticated = true) {
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    let data: unknown;
    if (path === "/api/session") data = { authenticated, is_admin: authenticated, setup_only: false };
    else if (path === "/api/setup-status") data = { initialized: true, bootstrap_enabled: false };
    else if (path === "/api/admin/users") data = users;
    else if (path === "/api/invitations/validate") data = { valid: true, in_progress: false };
    else data = [];
    await route.fulfill({ json: data });
  });
}

export async function editUser(page: Page, name: string) {
  await page.locator("tr").filter({ hasText: name }).getByRole("button", { name: "Edit user" }).click();
  await expect(page.getByRole("heading", { name: "Edit user", exact: true })).toBeVisible();
}
