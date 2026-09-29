import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";

test("two sign-in tabs complete and a cross-origin client exchanges a PKCE code", async ({ page, context }) => {
  test.setTimeout(60_000);
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
  await expect(page).toHaveURL(/\/account\/profile$/);

  const csrf = (await context.cookies()).find(cookie => cookie.name === "hanko_csrf")!.value;
  const callback = "http://127.0.0.1:5179/tests/browser/client.html";
  const clientResponse = await context.request.post("/api/admin/clients", {
    headers: { Origin: "http://localhost:5179", "X-CSRF-Token": csrf },
    data: {
      name: "Browser test client", client_type: "public", token_endpoint_auth_method: "none", pkce_policy: "required",
      redirect_uris: [callback], post_logout_redirect_uris: [], scopes: ["openid", "profile"], allowed_groups: [], claims: [],
    },
  });
  expect(clientResponse.ok()).toBeTruthy();
  const client = await clientResponse.json();
  const verifier = "test-verifier-with-enough-entropy-for-pkce-validation";
  const query = new URLSearchParams({
    response_type: "code", client_id: client.client_id, redirect_uri: callback, scope: "openid profile",
    state: "first-tab", code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256", prompt: "consent",
  });
  await page.goto(`/authorize?${query}`);
  await expect(page.getByRole("button", { name: "Allow", exact: true })).toBeVisible();
  const second = await context.newPage();
  query.set("state", "second-tab");
  await second.goto(`/authorize?${query}`);
  await expect(second.getByRole("button", { name: "Allow", exact: true })).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: "Allow", exact: true }).click();
  await expect(page).toHaveURL(/127\.0\.0\.1:5179\/tests\/browser\/client.html\?.*code=/);
  expect(new URL(page.url()).searchParams.get("state")).toBe("first-tab");
  const code = new URL(page.url()).searchParams.get("code")!;
  await second.getByRole("button", { name: "Allow", exact: true }).click();
  await expect(second).toHaveURL(/127\.0\.0\.1:5179\/tests\/browser\/client.html\?.*code=/);
  expect(new URL(second.url()).searchParams.get("state")).toBe("second-tab");

  // Real fetches from the application's distinct origin exercise browser CORS,
  // including the Authorization-header preflight for userinfo.
  const result = await page.evaluate(async ({ code, verifier, clientId, callback }) => {
    // Bypass Vite so its development CORS headers cannot mask a server bug.
    const origin = "http://localhost:38127";
    const endpoint = (url: string) => `${origin}${new URL(url).pathname}`;
    const discovery = await (await fetch(`${origin}/.well-known/openid-configuration`)).json();
    const keys = await (await fetch(endpoint(discovery.jwks_uri))).json();
    const tokenResponse = await fetch(endpoint(discovery.token_endpoint), {
      method: "POST", body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier, redirect_uri: callback }),
    });
    const tokens = await tokenResponse.json();
    const infoResponse = await fetch(endpoint(discovery.userinfo_endpoint), { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    return { tokenStatus: tokenResponse.status, infoStatus: infoResponse.status, info: await infoResponse.json(), keyCount: keys.keys.length };
  }, { code, verifier, clientId: client.client_id, callback });
  expect(result.tokenStatus).toBe(200);
  expect(result.infoStatus).toBe(200);
  expect(result.info.sub).toBeTruthy();
  expect(result.keyCount).toBeGreaterThan(0);
});
