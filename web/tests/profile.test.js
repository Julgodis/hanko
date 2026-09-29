import assert from "node:assert/strict";
import test from "node:test";
import { buildProfilePayload, createProfileDraft, missingProfileClaims } from "../src/lib/profile.ts";
import { canEditConfiguredUserClaim } from "../src/lib/userClaims.ts";

test("profile submission omits hidden fields without erasing stored values", () => {
  const draft = createProfileDraft({ username: " alice ", pictureUrl: "https://example.test/private.png", address: { country: "Sweden", locality: "Stockholm" }, profileClaims: { nickname: "Private" } });
  const payload = buildProfilePayload(draft, [], new Set(["picture", "country", "nickname"]));
  assert.equal(payload.username, "alice");
  assert.equal(payload.display_name, null);
  assert.ok(!("picture" in payload));
  assert.ok(!("country" in payload.address));
  assert.ok(!("nickname" in payload.profile_claims));
  assert.equal(payload.address.locality, "Stockholm");
});

test("required address fields remain editable and are included despite hidden configuration", () => {
  const hidden = new Set(["address", "country"]);
  const draft = createProfileDraft();
  assert.deepEqual(missingProfileClaims(draft, ["country", "name"]), ["country", "name"]);
  assert.equal(canEditConfiguredUserClaim("address", ["country"], hidden), true);
  draft.address.country = "Sweden";
  draft.displayName = "Alice";
  assert.deepEqual(missingProfileClaims(draft, ["country", "name"]), []);
  assert.equal(buildProfilePayload(draft, ["country"], hidden).address.country, "Sweden");
  assert.deepEqual(missingProfileClaims(draft, ["address"]), []);
});

test("self-service drafts never submit administrator-managed application roles", () => {
  const draft = createProfileDraft({ profileClaims: { nickname: "Alice", app_roles: { app: ["admin"] } } });
  assert.ok(!("app_roles" in draft.profileClaims));
  const payload = buildProfilePayload(draft, []);
  assert.ok(!("app_roles" in payload.profile_claims));
  assert.equal(payload.profile_claims.nickname, "Alice");
});

test("independent profile drafts do not share editable address state", () => {
  const first = createProfileDraft();
  first.address.country = "Sweden";
  assert.equal(createProfileDraft().address.country, "");
});
