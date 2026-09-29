import { canEditConfiguredUserClaim, missingRequiredUserClaims, type OidcProfileClaims } from "./userClaims.ts";

export type OidcAddress = { street_address: string; locality: string; region: string; postal_code: string; country: string };
export type ProfileDraft = {
  username: string;
  displayName: string;
  pictureUrl: string;
  phoneNumber: string;
  address: OidcAddress;
  profileClaims: Required<Omit<OidcProfileClaims, "app_roles">>;
};
export type InitialProfile = Partial<Omit<ProfileDraft, "address" | "profileClaims">> & {
  address?: Partial<OidcAddress>;
  profileClaims?: OidcProfileClaims;
};
export type SavedProfile = {
  sessions_revoked: boolean;
  username: string | null;
  display_name: string | null;
  picture: string | null;
  phone_number: string | null;
  address: Partial<OidcAddress> | null;
  profile_claims: OidcProfileClaims;
};

const PROFILE_CLAIMS = ["profile", "given_name", "family_name", "nickname", "website", "locale", "zoneinfo"] as const;

export function createProfileDraft(initial: InitialProfile = {}): ProfileDraft {
  return {
    username: initial.username ?? "",
    displayName: initial.displayName ?? "",
    pictureUrl: initial.pictureUrl ?? "",
    phoneNumber: initial.phoneNumber ?? "",
    address: { street_address: "", locality: "", region: "", postal_code: "", country: "", ...initial.address },
    // Do not copy admin-managed claims into a self-service draft.
    profileClaims: Object.fromEntries(PROFILE_CLAIMS.map(claim => [claim, initial.profileClaims?.[claim] ?? ""])) as ProfileDraft["profileClaims"],
  };
}

export function missingProfileClaims(draft: ProfileDraft, required: string[]) {
  return missingRequiredUserClaims(required, {
    preferred_username: draft.username, name: draft.displayName,
    picture: draft.pictureUrl, phone_number: draft.phoneNumber,
    address: draft.address, ...draft.address, ...draft.profileClaims,
  });
}

export function buildProfilePayload(draft: ProfileDraft, required: string[], hidden?: ReadonlySet<string>) {
  const canEdit = (claim: string) => canEditConfiguredUserClaim(claim, required, hidden);
  const body: Record<string, unknown> = {
    username: draft.username.trim() || null,
    display_name: draft.displayName.trim() || null,
  };
  if (canEdit("picture")) body.picture = draft.pictureUrl.trim();
  if (canEdit("phone_number")) body.phone_number = draft.phoneNumber.trim();
  if (canEdit("address")) body.address = Object.fromEntries(Object.entries(draft.address).filter(([claim]) => canEdit(claim)));
  const claims = Object.fromEntries(PROFILE_CLAIMS.filter(canEdit).map(claim => [claim, draft.profileClaims[claim]]));
  if (Object.keys(claims).length) body.profile_claims = claims;
  return body;
}
