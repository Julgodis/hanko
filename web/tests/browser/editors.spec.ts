import { test, expect } from "@playwright/test";
import { mockApi } from "./fixtures";

const client = {
  client_id: "one", name: "First client", client_type: "public", token_endpoint_auth_method: "none",
  pkce_policy: "required", enabled: true, redirect_uris: ["https://app.example/callback"],
  post_logout_redirect_uris: [], scopes: ["openid"], allowed_groups: [], claims: [], user_count: 0,
};

test("client drafts reset when leaving an editor and creation submits its own data", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/admin/clients", route => route.fulfill({ json: route.request().method() === "POST" ? { ...client, client_id: "new", name: "New client", client_secret: "shown-once" } : [client] }));
  await page.goto("/admin/clients/clients/one/edit");
  await expect(page.getByLabel("Application name", { exact: true })).toHaveValue("First client");
  await page.getByLabel("Application name", { exact: true }).fill("Unsaved edit");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("button", { name: "Add a client" }).click();
  await expect(page.getByLabel("Application name", { exact: true })).toBeEmpty();
  await page.getByLabel("Application name", { exact: true }).fill("New client");
  await page.locator('textarea').first().fill("https://new.example/callback");
  const saved = page.waitForRequest(request => request.method() === "POST" && request.url().endsWith("/api/admin/clients"));
  await page.getByRole("button", { name: "Create OIDC client" }).click();
  expect((await saved).postDataJSON()).toMatchObject({ name: "New client", redirect_uris: ["https://new.example/callback"] });
  await expect(page.getByRole("heading", { name: "Client created" })).toBeVisible();
  await expect(page.locator('input[value="shown-once"]')).toBeVisible();
});

test("group membership drafts survive a visit to a member's claim editor", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/admin/groups", route => route.fulfill({ json: [{ id: "team", name: "team", display_name: "Team", member_count: 0, claims: [] }] }));
  await page.goto("/admin/clients/groups/team/edit");
  await page.getByRole("checkbox", { name: "Toggle bob in Team" }).check();
  await page.getByLabel("Display name", { exact: true }).fill("Team draft");
  await page.locator("tr").filter({ hasText: "bob" }).getByRole("button", { name: "Edit claims" }).click();
  await expect(page.getByRole("heading", { name: "Edit user", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Back to group" }).click();
  await expect(page.getByRole("checkbox", { name: "Toggle bob in Team draft" })).toBeChecked();
  const saved = page.waitForRequest(request => request.method() === "PUT" && request.url().endsWith("/team/members"));
  await page.getByRole("button", { name: "Save members" }).click();
  expect((await saved).postDataJSON()).toEqual({ users: ["bob"] });
});

test("invitation creation shows the returned link and can start a fresh draft", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/admin/invitations", route => route.fulfill({ json: route.request().method() === "POST" ? { id: "invite", enrollment_url: "https://id.example/?enroll=one", expires_at: 2000000000 } : [] }));
  await page.goto("/admin/clients/users/invite");
  await page.getByLabel("Admin-only user label", { exact: false }).fill("Team invite");
  await page.getByRole("button", { name: "Create invite link" }).click();
  await expect(page.getByRole("heading", { name: "Invite link ready" })).toBeVisible();
  await expect(page.locator('input[value="https://id.example/?enroll=one"]')).toBeVisible();
  await page.getByRole("button", { name: "Create another invite" }).click();
  await expect(page.getByLabel("Admin-only user label", { exact: false })).toBeEmpty();
});
