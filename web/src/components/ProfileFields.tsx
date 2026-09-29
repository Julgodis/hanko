import type { ProfileDraft } from "../lib/profile";
import { canEditConfiguredUserClaim, isRequiredUserClaim } from "../lib/userClaims";

type Props = { value: ProfileDraft; onChange: (value: ProfileDraft) => void; requiredUserClaims: string[] };

export function ProfileFields({ value, onChange, requiredUserClaims }: Props) {
  const { username, displayName, pictureUrl, phoneNumber, address, profileClaims } = value;
  const canEditUserClaim = (claim: string) => canEditConfiguredUserClaim(claim, requiredUserClaims);
  const fieldRequirement = (claim: string) => isRequiredUserClaim(claim, requiredUserClaims) ? "Required" : "Optional";
  const update = <K extends keyof ProfileDraft>(key: K, next: ProfileDraft[K]) => onChange({ ...value, [key]: next });
  return <>
        {canEditUserClaim("preferred_username") && <label className="admin-field">
          <span>Username <em>{fieldRequirement("preferred_username")}</em></span>
          <input autoComplete="username" autoCapitalize="none" maxLength={64} pattern={"[A-Za-z0-9._\\-]+"} value={username} onChange={(event) => update("username", event.target.value.toLowerCase())} placeholder="Used as preferred_username" required={isRequiredUserClaim("preferred_username", requiredUserClaims)} />
          <small>Leave blank to keep your username private.</small>
        </label>}
        {canEditUserClaim("name") && <label className="admin-field">
          <span>Name <em>{fieldRequirement("name")}</em></span>
          <input autoComplete="name" maxLength={120} value={displayName} onChange={(event) => update("displayName", event.target.value)} placeholder="How apps should know you" required={isRequiredUserClaim("name", requiredUserClaims)} />
          <small>Shared as the OIDC name claim when provided.</small>
        </label>}
        {canEditUserClaim("picture") && <label className="admin-field">
          <span>Picture URL <em>{fieldRequirement("picture")}</em></span>
          <input type="url" maxLength={2048} value={pictureUrl} onChange={(event) => update("pictureUrl", event.target.value)} placeholder="Generated from your Hanko stamp" required={isRequiredUserClaim("picture", requiredUserClaims)} />
          <small>Leave blank to use a generated image matching your Hanko stamp. A custom HTTPS image URL overrides it.</small>
        </label>}
        {canEditUserClaim("phone_number") && <label className="admin-field">
          <span>Phone number <em>{fieldRequirement("phone_number")}</em></span>
          <input type="tel" autoComplete="tel" maxLength={64} value={phoneNumber} onChange={(event) => update("phoneNumber", event.target.value)} placeholder="+1 555 123 4567" required={isRequiredUserClaim("phone_number", requiredUserClaims)} />
          <small>Shared with apps that request the phone scope. Hanko does not verify phone ownership.</small>
        </label>}
        {canEditUserClaim("address") && canEditUserClaim("street_address") && <label className="admin-field">
          <span>Street address <em>{isRequiredUserClaim("address", requiredUserClaims) ? "Address required" : fieldRequirement("street_address")}</em></span>
          <textarea autoComplete="street-address" maxLength={500} rows={2} value={address.street_address} onChange={(event) => update("address", { ...address, street_address: event.target.value })} placeholder="Street, apartment or floor" required={isRequiredUserClaim("street_address", requiredUserClaims)} />
          <small>Apartment and floor details can go here. Shared with apps that request the address scope.</small>
        </label>}
        {canEditUserClaim("locality") && canEditUserClaim("address") && <label className="admin-field"><span>City or locality <em>{fieldRequirement("locality")}</em></span><input autoComplete="address-level2" maxLength={500} value={address.locality} onChange={(event) => update("address", { ...address, locality: event.target.value })} required={isRequiredUserClaim("locality", requiredUserClaims)} /></label>}
        {canEditUserClaim("region") && canEditUserClaim("address") && <label className="admin-field"><span>Region or state <em>{fieldRequirement("region")}</em></span><input autoComplete="address-level1" maxLength={500} value={address.region} onChange={(event) => update("address", { ...address, region: event.target.value })} required={isRequiredUserClaim("region", requiredUserClaims)} /></label>}
        {canEditUserClaim("postal_code") && canEditUserClaim("address") && <label className="admin-field"><span>Postal code <em>{fieldRequirement("postal_code")}</em></span><input autoComplete="postal-code" maxLength={500} value={address.postal_code} onChange={(event) => update("address", { ...address, postal_code: event.target.value })} required={isRequiredUserClaim("postal_code", requiredUserClaims)} /></label>}
        {canEditUserClaim("country") && canEditUserClaim("address") && <label className="admin-field"><span>Country <em>{fieldRequirement("country")}</em></span><input autoComplete="country-name" maxLength={500} value={address.country} onChange={(event) => update("address", { ...address, country: event.target.value })} required={isRequiredUserClaim("country", requiredUserClaims)} /></label>}
        {canEditUserClaim("profile") && <label className="admin-field"><span>Profile URL <em>{fieldRequirement("profile")}</em></span><input type="url" maxLength={2048} value={profileClaims.profile} onChange={(event) => update("profileClaims", { ...profileClaims, profile: event.target.value })} placeholder="https://example.com/about" required={isRequiredUserClaim("profile", requiredUserClaims)} /></label>}
        {canEditUserClaim("given_name") && <label className="admin-field"><span>Given name <em>{fieldRequirement("given_name")}</em></span><input autoComplete="given-name" maxLength={120} value={profileClaims.given_name} onChange={(event) => update("profileClaims", { ...profileClaims, given_name: event.target.value })} required={isRequiredUserClaim("given_name", requiredUserClaims)} /></label>}
        {canEditUserClaim("family_name") && <label className="admin-field"><span>Family name <em>{fieldRequirement("family_name")}</em></span><input autoComplete="family-name" maxLength={120} value={profileClaims.family_name} onChange={(event) => update("profileClaims", { ...profileClaims, family_name: event.target.value })} required={isRequiredUserClaim("family_name", requiredUserClaims)} /></label>}
        {canEditUserClaim("nickname") && <label className="admin-field"><span>Nickname <em>{fieldRequirement("nickname")}</em></span><input autoComplete="nickname" maxLength={120} value={profileClaims.nickname} onChange={(event) => update("profileClaims", { ...profileClaims, nickname: event.target.value })} required={isRequiredUserClaim("nickname", requiredUserClaims)} /></label>}
        {canEditUserClaim("website") && <label className="admin-field"><span>Website <em>{fieldRequirement("website")}</em></span><input type="url" maxLength={2048} value={profileClaims.website} onChange={(event) => update("profileClaims", { ...profileClaims, website: event.target.value })} placeholder="https://example.com" required={isRequiredUserClaim("website", requiredUserClaims)} /></label>}
        {canEditUserClaim("locale") && <label className="admin-field"><span>Locale <em>{fieldRequirement("locale")}</em></span><input maxLength={128} value={profileClaims.locale} onChange={(event) => update("profileClaims", { ...profileClaims, locale: event.target.value })} placeholder="en-US" required={isRequiredUserClaim("locale", requiredUserClaims)} /></label>}
        {canEditUserClaim("zoneinfo") && <label className="admin-field"><span>Time zone <em>{fieldRequirement("zoneinfo")}</em></span><input maxLength={128} value={profileClaims.zoneinfo} onChange={(event) => update("profileClaims", { ...profileClaims, zoneinfo: event.target.value })} placeholder="Europe/Stockholm" required={isRequiredUserClaim("zoneinfo", requiredUserClaims)} /></label>}
  </>;
}
