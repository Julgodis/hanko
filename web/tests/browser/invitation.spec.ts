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

test("a completed one-use invitation recovers after refresh fails without re-registering", async ({ page, context }) => {
  test.setTimeout(90_000);
  const authenticator = await context.newCDPSession(page);
  await authenticator.send("WebAuthn.enable");
  await authenticator.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });

  await page.goto("/");
  await page.locator('input[type="password"]').fill("browser-test-bootstrap");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByRole("heading", { name: "OIDC information" })).toBeVisible();
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Create your Hanko" })).toBeVisible();
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Register passkey", exact: true }).click();
  await expect(page).toHaveURL(/\/account/);

  const csrf = (await context.cookies()).find(cookie => cookie.name === "hanko_csrf")!.value;
  async function createInvite(label: string) {
    const response = await context.request.post("/api/admin/invitations", {
      headers: { Origin: "http://localhost:5179", "X-CSRF-Token": csrf },
      data: { label, max_uses: 1, expires_in: 1, expires_unit: "days", groups: [] },
    });
    expect(response.ok()).toBeTruthy();
    return await response.json() as { enrollment_url: string };
  }
  const completedInvite = await createInvite("one-use recovery invite");
  const otherInvite = await createInvite("second valid invite");

  let failSetupStatus = false;
  let registrationVerifications = 0;
  await page.route("**/api/setup-status", async route => {
    if (failSetupStatus) {
      failSetupStatus = false;
      await route.fulfill({ status: 503, json: { error: "temporarily unavailable" } });
      return;
    }
    await route.continue();
  });
  await page.route("**/api/passkeys/register/verify", async route => {
    registrationVerifications++;
    failSetupStatus = true;
    await route.continue();
  });

  await page.goto(completedInvite.enrollment_url);
  await expect(page.getByRole("heading", { name: "Set up your account" })).toBeVisible();
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Create your Hanko" })).toBeVisible();
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Register passkey", exact: true }).click();

  await expect(page.getByRole("heading", { name: "Your account is ready" })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("Your passkey is registered");
  await expect(page).not.toHaveURL(/enroll=/);
  expect(registrationVerifications).toBe(1);
  const identity = await (await context.request.get("/api/session")).json();
  expect(identity.authenticated).toBe(true);
  expect(identity.setup_only).toBe(false);
  const passkeys = await (await context.request.get("/api/passkeys")).json();
  expect(passkeys).toHaveLength(1);

  await page.getByRole("button", { name: "Continue to account", exact: true }).click();
  await expect(page).toHaveURL(/\/account/);
  await expect(page.getByRole("heading", { name: "Your profile" })).toBeVisible();
  expect(registrationVerifications).toBe(1);

  await page.reload();
  await expect(page.getByRole("heading", { name: "Your profile" })).toBeVisible();

  await page.goto(otherInvite.enrollment_url);
  await expect(page.getByRole("heading", { name: "Set up your account" })).toBeVisible();
});
