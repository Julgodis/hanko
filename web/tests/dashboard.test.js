import assert from "node:assert/strict";
import test from "node:test";
import { loadDashboardTab } from "../src/lib/dashboard.ts";

test("personal account sections work without calling unavailable admin endpoints", async () => {
  const requested = [];
  const load = async path => {
    requested.push(path);
    assert.ok(!path.startsWith("/api/admin/"));
    return [];
  };
  assert.deepEqual(await loadDashboardTab("hanko", true, load), {});
  await loadDashboardTab("passkeys", true, load);
  await loadDashboardTab("consents", true, load);
  assert.deepEqual(requested, ["/api/passkeys", "/api/account/consents"]);
});

test("non-administrators never request admin resources", async () => {
  for (const tab of ["clients", "users", "groups", "keys"]) {
    assert.deepEqual(await loadDashboardTab(tab, false, async () => assert.fail("unexpected request")), {});
  }
});

test("invitation and client editors receive groups alongside their section data", async () => {
  const load = async path => [path];
  const users = await loadDashboardTab("users", true, load);
  assert.deepEqual(users.groups, ["/api/admin/groups"]);
  assert.deepEqual(users.invitations, ["/api/admin/invitations"]);
  const clients = await loadDashboardTab("clients", true, load);
  assert.deepEqual(clients.groups, ["/api/admin/groups"]);
  assert.deepEqual(clients.clients, ["/api/admin/clients"]);
});

test("failed section requests reject instead of presenting partial results as complete", async () => {
  await assert.rejects(loadDashboardTab("clients", true, async path => {
    if (path.endsWith("groups")) throw new Error("offline");
    return [];
  }), /offline/);
});
