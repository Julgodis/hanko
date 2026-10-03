import type { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type { Scope } from "./scopes";
import type { OidcProfileClaims } from "./userClaims";

export type TokenEndpointAuthMethod = "none" | "client_secret_basic" | "client_secret_post";

export type PkcePolicy = "required" | "optional";

export type Client = {
  client_id: string;
  name: string;
  client_type: "public" | "confidential";
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  pkce_policy: PkcePolicy;
  enabled: boolean;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  scopes: Scope[];
  allowed_groups: string[];
  claims: { claim_name: string; user_attribute_path: string; required_scope: string | null }[];
  user_count: number;
};

export type GroupClaimMapping = { claim_name: string; claim_value: unknown; required_scope: Scope };

export type Group = { id: string; name: string; display_name: string; member_count: number; claims?: GroupClaimMapping[] };

export type AdminUser = { id: string; username: string; display_name: string; email: string | null; invitation_label: string | null; is_admin: boolean; disabled: boolean; created_at: number; groups: string[] };

export type UserClaim = { claim_name: string; claim_value: unknown; required_scope: string | null };

export type Invitation = { id: string; label: string; email: string | null; max_uses: number; use_count: number; created_at: number; expires_at: number; revoked: boolean };

export type CreatedInvitation = { id: string; label: string; email: string | null; enrollment_url: string; expires_at: number };

export type SigningKey = { kid: string; algorithm: string; status: string; created_at: number; retire_after: number | null };

export type AccountPasskey = { id: string; label: string; created_at: number; last_used_at: number | null };

export type ConsentGrant = { client_id: string; client_name: string; scopes: string[]; granted_at: number; expires_at: number | null };

export type CreatedClient = {
  client_id: string;
  client_secret: string | null;
  name: string;
  client_type: "public" | "confidential";
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  pkce_policy: PkcePolicy;
  scopes: Scope[];
};

export type RegistrationStart = {
  ceremony_id: string;
  publicKey: Parameters<typeof startRegistration>[0]["optionsJSON"];
};

export type AuthenticationStart = {
  ceremony_id: string;
  publicKey: Parameters<typeof startAuthentication>[0]["optionsJSON"];
};

export type CredentialChangeApproval = { approval_token: string };

export type Session = {
  authenticated: boolean;
  setup_only: boolean;
  is_admin: boolean;
  username?: string | null;
  hanko_color?: string | null;
  hanko_seed?: string | null;
  oidc_username?: string | null;
  oidc_name?: string | null;
  oidc_picture?: string | null;
  oidc_phone?: string | null;
  oidc_address?: { street_address?: string; locality?: string; region?: string; postal_code?: string; country?: string } | null;
  oidc_profile_claims?: OidcProfileClaims | null;
  required_user_claims?: string[];
  allow_multiple_passkeys_per_authenticator?: boolean;
  server?: { version: string; commit: string; build_date: string } | null;
};

export type SetupStatus = { initialized: boolean; bootstrap_enabled: boolean };

export type AuthorizationRequest = {
  client_name: string;
  scopes: string[];
  requires_fresh_authentication: boolean;
  consent_required: boolean;
  claims?: Record<string, unknown> | null;
};
