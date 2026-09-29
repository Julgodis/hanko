export type DashboardTab = "clients" | "users" | "groups" | "keys" | "hanko" | "passkeys" | "consents";
type Resource = "clients" | "groups" | "users" | "invitations" | "keys" | "passkeys" | "consents";
const endpoints: Record<Resource, string> = {
  clients: "/api/admin/clients", groups: "/api/admin/groups", users: "/api/admin/users",
  invitations: "/api/admin/invitations", keys: "/api/admin/signing-keys",
  passkeys: "/api/passkeys", consents: "/api/account/consents",
};
const tabResources: Record<DashboardTab, Resource[]> = {
  clients: ["clients", "groups"], users: ["users", "invitations", "groups"],
  groups: ["users", "groups"], keys: ["keys"], hanko: [], passkeys: ["passkeys"], consents: ["consents"],
};

export async function loadDashboardTab<T>(tab: DashboardTab, isAdmin: boolean, load: (path: string) => Promise<T>): Promise<Partial<Record<Resource, T>>> {
  if (!isAdmin && ["clients", "users", "groups", "keys"].includes(tab)) return {};
  const entries = await Promise.all(tabResources[tab].map(async resource => [resource, await load(endpoints[resource])] as const));
  return Object.fromEntries(entries);
}
