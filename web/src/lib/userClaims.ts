const hiddenUserClaims = new Set(
  (import.meta.env.VITE_HIDDEN_USER_CLAIMS ?? "")
    .split(",")
    .map((claim) => claim.trim())
    .filter(Boolean),
);

export type OidcProfileClaims = {
  profile?: string;
  given_name?: string;
  family_name?: string;
  nickname?: string;
  website?: string;
  locale?: string;
  zoneinfo?: string;
  app_roles?: Record<string, string[]>;
};

export function canEditUserClaim(claim: string) {
  return !hiddenUserClaims.has(claim);
}

export function formatAppRoles(appRoles?: Record<string, string[]>) {
  return Object.entries(appRoles ?? {})
    .flatMap(([clientId, roles]) => roles.map((role) => `${clientId}: ${role}`))
    .join("\n");
}

export function parseAppRoles(value: string): Record<string, string[]> {
  const appRoles: Record<string, string[]> = {};
  for (const [index, line] of value.split(/\r?\n/).entries()) {
    const entry = line.trim();
    if (!entry) continue;
    const separator = entry.indexOf(":");
    if (separator <= 0 || separator === entry.length - 1) {
      throw new Error(`App role line ${index + 1} must use client-id: role format.`);
    }
    const clientId = entry.slice(0, separator).trim();
    const role = entry.slice(separator + 1).trim();
    if (!clientId || !role) {
      throw new Error(`App role line ${index + 1} must include a client ID and role.`);
    }
    (appRoles[clientId] ??= []).push(role);
  }
  return appRoles;
}
