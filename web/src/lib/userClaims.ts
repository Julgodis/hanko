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
