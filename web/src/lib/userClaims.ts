import userClaimDefinitions from "../../../shared/user_claims.json";

export const SUPPORTED_USER_CLAIMS = userClaimDefinitions.supported_user_claims;

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

export function canEditConfiguredUserClaim(claim: string, requiredUserClaims: string[]) {
  const requiresAddressField = requiredUserClaims.some((requiredClaim) => userClaimDefinitions.address_user_claims.includes(requiredClaim));
  return requiredUserClaims.includes(claim)
    || (requiresAddressField && userClaimDefinitions.address_user_claims.includes(claim))
    || canEditUserClaim(claim);
}

export function isRequiredUserClaim(claim: string, requiredUserClaims: string[]) {
  return SUPPORTED_USER_CLAIMS.includes(claim) && requiredUserClaims.includes(claim);
}

export function missingRequiredUserClaims(requiredUserClaims: string[], values: Record<string, unknown>) {
  return requiredUserClaims.filter((claim) => {
    if (!SUPPORTED_USER_CLAIMS.includes(claim)) return false;
    const value = values[claim];
    if (claim === "address") {
      return !value || typeof value !== "object" || !Object.values(value).some(hasUserValue);
    }
    return !hasUserValue(value);
  });
}

function hasUserValue(value: unknown): boolean {
  if (typeof value === "string") return value.trim().length > 0;
  if (Array.isArray(value)) return value.some(hasUserValue);
  if (value && typeof value === "object") return Object.values(value).some(hasUserValue);
  return false;
}
