import { Check, Copy, Fingerprint, KeyRound, Mail, Pencil, Plus, Shield, Users, UserRound, Stamp, Trash2 } from "lucide-react";
import { Fragment, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { HankoSeal } from "./components/HankoSeal";
import { PrivateValue } from "./components/PrivacyMode";
import { SealCustomizer } from "./components/SealCustomizer";
import { ORIGINAL_HANKO_GRADIENT } from "./components/generateHankoPath";
import { api, defaultPasskeyLabel, json } from "./lib/utils";
import { canEditUserClaim, type OidcProfileClaims } from "./lib/userClaims";

const AVAILABLE_SCOPES = ["profile", "email", "address", "phone", "picture", "groups", "offline_access"] as const;
const EXPIRY_UNIT_SECONDS = { seconds: 1, minutes: 60, hours: 60 * 60, days: 24 * 60 * 60, years: 365 * 24 * 60 * 60 } as const;
type ExpiryUnit = keyof typeof EXPIRY_UNIT_SECONDS;

type Scope = "openid" | (typeof AVAILABLE_SCOPES)[number];
type TokenEndpointAuthMethod = "none" | "client_secret_basic" | "client_secret_post";
type PkcePolicy = "required" | "optional";
type Client = {
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
type GroupClaimMapping = { claim_name: string; claim_value: unknown; required_scope: Scope };
type Group = { id: string; name: string; display_name: string; member_count: number; claims?: GroupClaimMapping[] };
type AdminUser = { id: string; username: string; display_name: string; email: string | null; invitation_label: string | null; is_admin: boolean; disabled: boolean; created_at: number; groups: string[] };
type MembershipEditor = { kind: "group"; id: string };
type UserClaim = { claim_name: string; claim_value: unknown; required_scope: string | null };
type UserClaimDraft = { claim_name: string; claim_value: string; required_scope: string };
type Invitation = { id: string; label: string; email: string | null; max_uses: number; use_count: number; created_at: number; expires_at: number; revoked: boolean };
type CreatedInvitation = { id: string; label: string; email: string | null; enrollment_url: string; expires_at: number };
type SigningKey = { kid: string; algorithm: string; status: string; created_at: number; retire_after: number | null };
type AccountPasskey = { id: string; label: string; created_at: number; last_used_at: number | null };
type OidcAddress = { street_address: string; locality: string; region: string; postal_code: string; country: string };
const EMPTY_OIDC_ADDRESS: OidcAddress = { street_address: "", locality: "", region: "", postal_code: "", country: "" };
type OidcProfileDraft = Required<Omit<OidcProfileClaims, "app_roles">>;
const EMPTY_OIDC_PROFILE: OidcProfileDraft = { profile: "", given_name: "", family_name: "", nickname: "", website: "", locale: "", zoneinfo: "" };
type Tab = "clients" | "users" | "groups" | "keys" | "hanko" | "passkeys";
type ClaimDraft = { claim_name: string; user_attribute_path: string; required_scope: string };
type GroupClaimDraft = { claim_name: string; claim_value: string; required_scope: Scope };
type CreatedClient = {
  client_id: string;
  client_secret: string | null;
  name: string;
  client_type: "public" | "confidential";
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  pkce_policy: PkcePolicy;
  scopes: Scope[];
};
type RegistrationStart = {
  ceremony_id: string;
  publicKey: Parameters<typeof startRegistration>[0]["optionsJSON"];
};
type AuthenticationStart = {
  ceremony_id: string;
  publicKey: Parameters<typeof startAuthentication>[0]["optionsJSON"];
};
type CredentialChangeApproval = { approval_token: string };

function splitLines(value: string) {
  return [...new Set(value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))];
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "The request could not be completed.";
}

function invitationEmailHref(invitation: CreatedInvitation) {
  const subject = `Your Hanko invite: ${invitation.label}`;
  const expiry = new Date(invitation.expires_at * 1000).toLocaleString();
  const body = `You have been invited to set up a Hanko account.\n\nUse this link before ${expiry}:\n${invitation.enrollment_url}`;
  return `mailto:${encodeURIComponent(invitation.email ?? "")}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

function invitationStatus(invitation: Invitation) {
  if (invitation.revoked) return "Revoked";
  if (invitation.expires_at <= Date.now() / 1000) return "Expired";
  if (invitation.use_count >= invitation.max_uses) return "Limit reached";
  return "Active";
}

export default function ClientAdmin({ isAdmin = true }: { isAdmin?: boolean }) {
  const previewScreen = import.meta.env.DEV && new URLSearchParams(window.location.search).get("ui-preview") === "1"
    ? new URLSearchParams(window.location.search).get("screen")
    : null;
  const previewTab = (): Tab => {
    if (previewScreen === "users" || previewScreen === "invite" || previewScreen === "invite-ready") return "users";
    if (previewScreen === "groups") return "groups";
    if (previewScreen === "keys") return "keys";
    if (previewScreen === "passkeys") return "passkeys";
    if (previewScreen === "hanko") return "hanko";
    return isAdmin ? "clients" : "hanko";
  };
  const [activeTab, setActiveTab] = useState<Tab>(previewTab);
  const [clients, setClients] = useState<Client[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [signingKeys, setSigningKeys] = useState<SigningKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [name, setName] = useState("");
  const [tokenAuthMethod, setTokenAuthMethod] = useState<TokenEndpointAuthMethod>("none");
  const [pkcePolicy, setPkcePolicy] = useState<PkcePolicy>("required");
  const [clientEnabled, setClientEnabled] = useState(true);
  const [redirectUris, setRedirectUris] = useState("");
  const [logoutUris, setLogoutUris] = useState("");
  const [scopes, setScopes] = useState<Scope[]>(["openid", "profile", "email"]);
  const [allowedGroups, setAllowedGroups] = useState<string[]>([]);
  const [claims, setClaims] = useState<ClaimDraft[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [clientFormMode, setClientFormMode] = useState<"create" | "edit" | null>(previewScreen === "client-form" ? "create" : null);
  const [credentialsUpdated, setCredentialsUpdated] = useState(false);
  const [userFormOpen, setUserFormOpen] = useState(previewScreen === "invite" || previewScreen === "invite-ready");
  const [groupFormOpen, setGroupFormOpen] = useState(false);
  const [editingGroupId, setEditingGroupId] = useState("");
  const [editingClientId, setEditingClientId] = useState("");
  const [deletingClientId, setDeletingClientId] = useState("");
  const [created, setCreated] = useState<CreatedClient | null>(null);
  const [copied, setCopied] = useState("");
  const [addingPasskey, setAddingPasskey] = useState(false);
  const [passkeyError, setPasskeyError] = useState("");
  const [passkeyMessage, setPasskeyMessage] = useState("");
  const [passkeys, setPasskeys] = useState<AccountPasskey[]>([]);
  const [passkeyDrafts, setPasskeyDrafts] = useState<Record<string, string>>({});
  const [passkeysLoading, setPasskeysLoading] = useState(false);
  const [passkeyActionId, setPasskeyActionId] = useState("");
  const [removeTarget, setRemoveTarget] = useState<AccountPasskey | null>(null);
  const [removalConfirmation, setRemovalConfirmation] = useState("");
  const [hankoColor, setHankoColor] = useState(ORIGINAL_HANKO_GRADIENT);
  const [hankoSeed, setHankoSeed] = useState("hanko");
  const [savingHanko, setSavingHanko] = useState(false);
  const [hankoMessage, setHankoMessage] = useState("");
  const [oidcUsername, setOidcUsername] = useState("");
  const [oidcName, setOidcName] = useState("");
  const [oidcPicture, setOidcPicture] = useState("");
  const [oidcPhone, setOidcPhone] = useState("");
  const [oidcAddress, setOidcAddress] = useState<OidcAddress>(EMPTY_OIDC_ADDRESS);
  const [oidcProfileClaims, setOidcProfileClaims] = useState<OidcProfileDraft>(EMPTY_OIDC_PROFILE);
  const [savingOidcProfile, setSavingOidcProfile] = useState(false);
  const [oidcProfileMessage, setOidcProfileMessage] = useState("");
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [invitationLabel, setInvitationLabel] = useState("");
  const [invitationEmail, setInvitationEmail] = useState("");
  const [invitationMaxUses, setInvitationMaxUses] = useState("10");
  const [invitationExpiry, setInvitationExpiry] = useState("7");
  const [invitationExpiryUnit, setInvitationExpiryUnit] = useState<ExpiryUnit>("days");
  const [userGroups, setUserGroups] = useState<string[]>([]);
  const [createdInvitation, setCreatedInvitation] = useState<CreatedInvitation | null>(previewScreen === "invite-ready" ? {
    id: "inv_preview_ready",
    label: "Studio team",
    email: "person@example.com",
    enrollment_url: "https://id.example.com/enroll/sample-invite-token",
    expires_at: 1_793_109_600,
  } : null);
  const [groupName, setGroupName] = useState("");
  const [groupDisplayName, setGroupDisplayName] = useState("");
  const [groupClaims, setGroupClaims] = useState<GroupClaimDraft[]>([]);
  const [deletingGroupId, setDeletingGroupId] = useState("");
  const [adminActionBusy, setAdminActionBusy] = useState(false);
  const [adminActionMessage, setAdminActionMessage] = useState("");
  const [membershipEditor, setMembershipEditor] = useState<MembershipEditor | null>(null);
  const [membershipSelection, setMembershipSelection] = useState<string[]>([]);
  const [membershipBusy, setMembershipBusy] = useState(false);
  const [membershipLoading, setMembershipLoading] = useState(false);
  const [membershipReady, setMembershipReady] = useState(false);
  const [membershipError, setMembershipError] = useState("");
  const [editingUser, setEditingUser] = useState<AdminUser | null>(null);
  const [userClaimDrafts, setUserClaimDrafts] = useState<UserClaimDraft[]>([]);
  const [userClaimsLoading, setUserClaimsLoading] = useState(false);
  const [userClaimsReady, setUserClaimsReady] = useState(false);
  const [userClaimsBusy, setUserClaimsBusy] = useState(false);
  const [userEditorError, setUserEditorError] = useState("");
  const [userEditorMessage, setUserEditorMessage] = useState("");

  async function refreshClients() {
    setClients(await api<Client[]>("/api/admin/clients"));
  }

  async function refreshPasskeys() {
    const records = await api<AccountPasskey[]>("/api/passkeys");
    setPasskeys(records);
    setPasskeyDrafts(Object.fromEntries(records.map((passkey) => [passkey.id, passkey.label])));
  }

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const sessionPromise = api<{ hanko_color?: string; hanko_seed?: string; oidc_username?: string | null; oidc_name?: string | null; oidc_picture?: string | null; oidc_phone?: string | null; oidc_address?: Partial<OidcAddress> | null; oidc_profile_claims?: OidcProfileClaims | null }>("/api/session");
        const [session, clientList, groupList] = isAdmin
          ? await Promise.all([sessionPromise, api<Client[]>("/api/admin/clients"), api<Group[]>("/api/admin/groups")])
          : [await sessionPromise, [], []];
        if (active) {
          setClients(clientList);
          setGroups(groupList);
          if (session.hanko_color) setHankoColor(session.hanko_color === "#d64135" ? ORIGINAL_HANKO_GRADIENT : session.hanko_color);
          if (session.hanko_seed) setHankoSeed(session.hanko_seed);
          setOidcUsername(session.oidc_username ?? "");
          setOidcName(session.oidc_name ?? "");
          setOidcPicture(session.oidc_picture ?? "");
          setOidcPhone(session.oidc_phone ?? "");
          setOidcAddress({ ...EMPTY_OIDC_ADDRESS, ...(session.oidc_address ?? {}) });
          setOidcProfileClaims({
            ...EMPTY_OIDC_PROFILE,
            ...(session.oidc_profile_claims ?? {}),
          });
        }
      } catch (loadError) {
        if (active) setLoadError(errorMessage(loadError));
      } finally {
        if (active) setLoading(false);
      }
    }
    void load();
    return () => { active = false; };
  }, [isAdmin]);

  useEffect(() => {
    let active = true;
    async function loadTabData() {
      try {
        if (activeTab === "users" && isAdmin) {
          const [userList, invitationList] = await Promise.all([
            api<AdminUser[]>("/api/admin/users"),
            api<Invitation[]>("/api/admin/invitations"),
          ]);
          setUsers(userList);
          setInvitations(invitationList);
        }
        if (activeTab === "groups" && isAdmin) setUsers(await api<AdminUser[]>("/api/admin/users"));
        if (activeTab === "keys" && isAdmin) setSigningKeys(await api<SigningKey[]>("/api/admin/signing-keys"));
        if (activeTab === "passkeys") {
          setPasskeysLoading(true);
          const records = await api<AccountPasskey[]>("/api/passkeys");
          if (active) {
            setPasskeys(records);
            setPasskeyDrafts(Object.fromEntries(records.map((passkey) => [passkey.id, passkey.label])));
          }
        }
      } catch (tabError) {
        if (active) setLoadError(errorMessage(tabError));
      } finally {
        if (active && activeTab === "passkeys") setPasskeysLoading(false);
      }
    }
    void loadTabData();
    return () => { active = false; };
  }, [activeTab, isAdmin]);

  useEffect(() => {
    if (clientFormMode !== null || userFormOpen || groupFormOpen || editingUser) {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }, [clientFormMode, userFormOpen, groupFormOpen, editingUser]);

  function toggleScope(scope: (typeof AVAILABLE_SCOPES)[number]) {
    setScopes((current) => current.includes(scope)
      ? current.filter((item) => item !== scope)
      : [...current, scope]);
  }

  function toggleGroup(groupName: string) {
    setAllowedGroups((current) => current.includes(groupName)
      ? current.filter((item) => item !== groupName)
      : [...current, groupName]);
  }

  function updateClaim(index: number, key: keyof ClaimDraft, value: string) {
    setClaims((current) => current.map((claim, claimIndex) =>
      claimIndex === index ? { ...claim, [key]: value } : claim));
  }

  function updateGroupClaim(index: number, key: keyof GroupClaimDraft, value: string) {
    setGroupClaims((current) => current.map((claim, claimIndex) =>
      claimIndex !== index
        ? claim
        : key === "required_scope"
          ? { ...claim, required_scope: value as Scope }
          : { ...claim, [key]: value }));
  }

  function openCreateClient() {
    setName("");
    setTokenAuthMethod("none");
    setPkcePolicy("required");
    setClientEnabled(true);
    setRedirectUris("");
    setLogoutUris("");
    setScopes(["openid", "profile", "email"]);
    setAllowedGroups([]);
    setClaims([]);
    setEditingClientId("");
    setCreated(null);
    setCredentialsUpdated(false);
    setError("");
    setClientFormMode("create");
  }

  function openEditClient(client: Client) {
    setName(client.name);
    setTokenAuthMethod(client.token_endpoint_auth_method);
    setPkcePolicy(client.pkce_policy);
    setClientEnabled(client.enabled);
    setRedirectUris(client.redirect_uris.join("\n"));
    setLogoutUris(client.post_logout_redirect_uris.join("\n"));
    setScopes(client.scopes);
    setAllowedGroups(client.allowed_groups);
    setClaims(client.claims.map((claim) => ({
      claim_name: claim.claim_name,
      user_attribute_path: claim.user_attribute_path,
      required_scope: claim.required_scope ?? "",
    })));
    setEditingClientId(client.client_id);
    setCreated(null);
    setCredentialsUpdated(false);
    setError("");
    setClientFormMode("edit");
  }

  function closeClientForm() {
    setClientFormMode(null);
    setEditingClientId("");
    setError("");
  }

  function openCreateUser() {
    closeUserEditor();
    setInvitationLabel("");
    setInvitationEmail("");
    setInvitationMaxUses("10");
    setInvitationExpiry("7");
    setInvitationExpiryUnit("days");
    setUserGroups([]);
    setCreatedInvitation(null);
    setAdminActionMessage("");
    setUserFormOpen(true);
  }

  function closeUserForm() {
    setUserFormOpen(false);
    setAdminActionMessage("");
  }

  function openCreateGroup() {
    setGroupName("");
    setGroupDisplayName("");
    setGroupClaims([]);
    setEditingGroupId("");
    setAdminActionMessage("");
    setGroupFormOpen(true);
  }

  function openEditGroup(group: Group) {
    setGroupName(group.name);
    setGroupDisplayName(group.display_name);
    setGroupClaims((group.claims ?? []).map((claim) => ({
      claim_name: claim.claim_name,
      claim_value: JSON.stringify(claim.claim_value) ?? "null",
      required_scope: claim.required_scope,
    })));
    setEditingGroupId(group.id);
    setAdminActionMessage("");
    setGroupFormOpen(true);
  }

  function closeGroupForm() {
    setGroupFormOpen(false);
    setEditingGroupId("");
    setAdminActionMessage("");
  }

  async function openEditUser(user: AdminUser) {
    setEditingUser(user);
    setUserClaimDrafts([]);
    setUserClaimsLoading(true);
    setUserClaimsReady(false);
    setUserEditorError("");
    setUserEditorMessage("");
    try {
      const claims = await api<UserClaim[]>(`/api/admin/users/${encodeURIComponent(user.id)}/claims`);
      setUserClaimDrafts(claims.map((claim) => ({
        claim_name: claim.claim_name,
        claim_value: JSON.stringify(claim.claim_value) ?? "null",
        required_scope: claim.required_scope ?? "",
      })));
      setUserClaimsReady(true);
    } catch (loadError) {
      setUserEditorError(errorMessage(loadError));
    } finally {
      setUserClaimsLoading(false);
    }
  }

  function closeUserEditor() {
    setEditingUser(null);
    setUserClaimDrafts([]);
    setUserClaimsReady(false);
    setUserEditorError("");
    setUserEditorMessage("");
  }

  function updateUserClaim(index: number, key: keyof UserClaimDraft, value: string) {
    setUserClaimDrafts((current) => current.map((claim, claimIndex) =>
      claimIndex === index ? { ...claim, [key]: value } : claim));
  }

  async function saveUserClaims(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingUser) return;
    setUserClaimsBusy(true);
    setUserEditorError("");
    setUserEditorMessage("");
    try {
      const claims = userClaimDrafts
        .filter((claim) => claim.claim_name.trim() || claim.claim_value.trim())
        .map((claim) => {
          let claimValue: unknown;
          try {
            claimValue = JSON.parse(claim.claim_value);
          } catch {
            throw new Error(`Enter valid JSON for “${claim.claim_name || "new claim"}”.`);
          }
          return {
            claim_name: claim.claim_name.trim(),
            claim_value: claimValue,
            required_scope: claim.required_scope || null,
          };
        });
      await api(`/api/admin/users/${encodeURIComponent(editingUser.id)}/claims`, {
        method: "PUT",
        body: json({ claims }),
      });
      setUserEditorMessage("Custom claims saved.");
    } catch (saveError) {
      setUserEditorError(errorMessage(saveError));
    } finally {
      setUserClaimsBusy(false);
    }
  }

  async function openGroupMembers(group: Group) {
    setMembershipEditor({ kind: "group", id: group.id });
    setMembershipSelection([]);
    setMembershipReady(false);
    setMembershipError("");
    setMembershipLoading(true);
    try {
      const userList = await api<AdminUser[]>("/api/admin/users");
      setUsers(userList);
      setMembershipSelection(userList.filter((user) => user.groups.includes(group.name)).map((user) => user.id));
      setMembershipReady(true);
    } catch (loadError) {
      setMembershipError(errorMessage(loadError));
    } finally {
      setMembershipLoading(false);
    }
  }

  function toggleMembership(value: string) {
    setMembershipSelection((current) => current.includes(value)
      ? current.filter((item) => item !== value)
      : [...current, value]);
  }

  async function saveMembership(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!membershipEditor) return;
    setMembershipBusy(true);
    setMembershipError("");
    try {
      await api(`/api/admin/groups/${encodeURIComponent(membershipEditor.id)}/members`, {
        method: "PUT",
        body: json({ users: membershipSelection }),
      });
      const [userList, groupList] = await Promise.all([
        api<AdminUser[]>("/api/admin/users"),
        api<Group[]>("/api/admin/groups"),
      ]);
      setUsers(userList);
      setGroups(groupList);
      setMembershipEditor(null);
    } catch (saveError) {
      setMembershipError(errorMessage(saveError));
    } finally {
      setMembershipBusy(false);
    }
  }

  function closeMembershipEditor() {
    setMembershipEditor(null);
    setMembershipReady(false);
    setMembershipError("");
  }

  async function saveClient(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const redirects = splitLines(redirectUris);
    if (redirects.length === 0) {
      setError("Add at least one exact callback URL.");
      return;
    }
    const claimMappings = claims
      .filter((claim) => claim.claim_name.trim() || claim.user_attribute_path.trim())
      .map((claim) => ({
        claim_name: claim.claim_name.trim(),
        user_attribute_path: claim.user_attribute_path.trim(),
        required_scope: claim.required_scope || null,
      }));

    setBusy(true);
    try {
      const payload = {
        name: name.trim(),
        token_endpoint_auth_method: tokenAuthMethod,
        pkce_policy: pkcePolicy,
        ...(clientFormMode === "create"
          ? {
              client_type: tokenAuthMethod === "none" ? "public" : "confidential",
            }
          : { enabled: clientEnabled }),
        redirect_uris: redirects,
        post_logout_redirect_uris: splitLines(logoutUris),
        scopes: ["openid", ...scopes.filter((scope) => scope !== "openid")],
        allowed_groups: allowedGroups,
        claims: claimMappings,
      };
      const client = await api<CreatedClient>(clientFormMode === "edit"
        ? `/api/admin/clients/${encodeURIComponent(editingClientId)}`
        : "/api/admin/clients", {
        method: clientFormMode === "edit" ? "PUT" : "POST",
        body: json({
          ...payload,
        }),
      });
      if (clientFormMode === "create" || client.client_secret) {
        setCreated(client);
        setCredentialsUpdated(clientFormMode === "edit");
      }
      setClientFormMode(null);
      setEditingClientId("");
      await refreshClients();
    } catch (saveError) {
      setError(errorMessage(saveError));
    } finally {
      setBusy(false);
    }
  }

  async function removeClient(client: Client) {
    const confirmed = window.confirm(`Remove ${client.name}? This permanently deletes its client settings, in-progress sign-in requests, authorization codes, refresh tokens, and linked-user records. Hanko user accounts remain, but this application will no longer be able to sign users in through Hanko.`);
    if (!confirmed) return;
    setDeletingClientId(client.client_id);
    setError("");
    try {
      await api(`/api/admin/clients/${encodeURIComponent(client.client_id)}`, { method: "DELETE" });
      if (editingClientId === client.client_id) closeClientForm();
      await refreshClients();
    } catch (removeError) {
      setError(errorMessage(removeError));
    } finally {
      setDeletingClientId("");
    }
  }

  async function createInvitation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAdminActionBusy(true);
    setAdminActionMessage("");
    setCreatedInvitation(null);
    const label = invitationLabel.trim();
    const email = invitationEmail.trim() || null;
    try {
      const invitation = await api<Omit<CreatedInvitation, "label" | "email">>("/api/admin/invitations", {
        method: "POST",
        body: json({
          label,
          email,
          max_uses: email ? 1 : Number(invitationMaxUses),
          expires_in: Number(invitationExpiry),
          expires_unit: invitationExpiryUnit,
          groups: userGroups,
        }),
      });
      setCreatedInvitation({ ...invitation, label, email });
      setInvitationLabel("");
      setInvitationEmail("");
      setInvitationMaxUses("10");
      setInvitationExpiry("7");
      setInvitationExpiryUnit("days");
      setUserGroups([]);
      setInvitations(await api<Invitation[]>("/api/admin/invitations"));
    } catch (createError) {
      setAdminActionMessage(errorMessage(createError));
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function revokeInvitation(invitationId: string) {
    setAdminActionBusy(true);
    setAdminActionMessage("");
    try {
      await api(`/api/admin/invitations/${encodeURIComponent(invitationId)}/revoke`, { method: "POST" });
      setInvitations(await api<Invitation[]>("/api/admin/invitations"));
    } catch (revokeError) {
      setAdminActionMessage(errorMessage(revokeError));
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function createGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAdminActionMessage("");
    let claimMappings: { claim_name: string; claim_value: unknown; required_scope: Scope }[];
    try {
      claimMappings = groupClaims
        .filter((claim) => claim.claim_name.trim() || claim.claim_value.trim())
        .map((claim) => ({
          claim_name: claim.claim_name.trim(),
          claim_value: JSON.parse(claim.claim_value),
          required_scope: claim.required_scope,
        }));
    } catch {
      setAdminActionMessage("Each group claim value must be valid JSON, such as \"member\" or [\"read\"].");
      return;
    }

    setAdminActionBusy(true);
    try {
      await api(editingGroupId ? `/api/admin/groups/${encodeURIComponent(editingGroupId)}` : "/api/admin/groups", {
        method: editingGroupId ? "PUT" : "POST",
        body: json(editingGroupId
          ? { display_name: groupDisplayName.trim(), claims: claimMappings }
          : { name: groupName.trim(), display_name: groupDisplayName.trim(), claims: claimMappings }),
      });
      setGroupName("");
      setGroupDisplayName("");
      setGroupClaims([]);
      setGroups(await api<Group[]>("/api/admin/groups"));
      setGroupFormOpen(false);
      setEditingGroupId("");
    } catch (saveError) {
      setAdminActionMessage(errorMessage(saveError));
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function deleteGroup(group: Group) {
    const memberLabel = group.member_count === 1 ? "1 membership" : `${group.member_count} memberships`;
    const confirmed = window.confirm(`Delete ${group.display_name}? This permanently removes its ${memberLabel} and scoped claims, and removes it from pending invite links. A group used by a client access policy must first be removed from that policy.`);
    if (!confirmed) return;

    setDeletingGroupId(group.id);
    setAdminActionBusy(true);
    setAdminActionMessage("");
    try {
      await api(`/api/admin/groups/${encodeURIComponent(group.id)}`, { method: "DELETE" });
      if (membershipEditor?.kind === "group" && membershipEditor.id === group.id) closeMembershipEditor();
      setGroups((current) => current.filter((item) => item.id !== group.id));
      setUsers((current) => current.map((user) => ({
        ...user,
        groups: user.groups.filter((name) => name !== group.name),
      })));
      setUserGroups((current) => current.filter((name) => name !== group.name));
    } catch (deleteError) {
      setAdminActionMessage(errorMessage(deleteError));
    } finally {
      setDeletingGroupId("");
      setAdminActionBusy(false);
    }
  }

  async function rotateSigningKey() {
    setAdminActionBusy(true);
    setAdminActionMessage("");
    try {
      await api("/api/admin/signing-keys", { method: "POST" });
      setSigningKeys(await api<SigningKey[]>("/api/admin/signing-keys"));
      setAdminActionMessage("A new signing key is active.");
    } catch (rotateError) {
      setAdminActionMessage(errorMessage(rotateError));
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function addPasskey() {
    setAddingPasskey(true);
    setPasskeyError("");
    setPasskeyMessage("");
    try {
      const confirmation = await api<AuthenticationStart>("/api/passkeys/change/options", {
        method: "POST",
        body: json({ action: "add" }),
      });
      const assertion = await startAuthentication({ optionsJSON: confirmation.publicKey });
      const { approval_token } = await api<CredentialChangeApproval>("/api/passkeys/change/verify", {
        method: "POST",
        body: json({ ceremony_id: confirmation.ceremony_id, credential: assertion }),
      });
      const start = await api<RegistrationStart>("/api/passkeys/register/options", {
        method: "POST",
        body: json({ approval_token }),
      });
      const credentialPromise = startRegistration({ optionsJSON: start.publicKey });
      const credential = await credentialPromise;
      await api("/api/passkeys/register/verify", {
        method: "POST",
        body: json({ ceremony_id: start.ceremony_id, credential, label: defaultPasskeyLabel(new Date()) }),
      });
      await refreshPasskeys();
      setPasskeyMessage("Passkey added to this account.");
    } catch {
      setPasskeyError("Passkey registration wasn’t completed. You can try again.");
    } finally {
      setAddingPasskey(false);
    }
  }

  async function renamePasskey(event: FormEvent<HTMLFormElement>, passkey: AccountPasskey) {
    event.preventDefault();
    setPasskeyActionId(passkey.id);
    setPasskeyError("");
    setPasskeyMessage("");
    try {
      const label = passkeyDrafts[passkey.id]?.trim() ?? "";
      await api(`/api/passkeys/${encodeURIComponent(passkey.id)}`, {
        method: "PUT",
        body: json({ label }),
      });
      await refreshPasskeys();
      setPasskeyMessage("Passkey name updated.");
    } catch (renameError) {
      setPasskeyError(errorMessage(renameError));
    } finally {
      setPasskeyActionId("");
    }
  }

  async function removePasskey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!removeTarget || passkeys.length <= 1 || removalConfirmation !== "REMOVE") return;
    setPasskeyActionId(removeTarget.id);
    setPasskeyError("");
    setPasskeyMessage("");
    try {
      const confirmation = await api<AuthenticationStart>("/api/passkeys/change/options", {
        method: "POST",
        body: json({ action: "remove", passkey_id: removeTarget.id }),
      });
      const assertion = await startAuthentication({ optionsJSON: confirmation.publicKey });
      const { approval_token } = await api<CredentialChangeApproval>("/api/passkeys/change/verify", {
        method: "POST",
        body: json({ ceremony_id: confirmation.ceremony_id, credential: assertion }),
      });
      await api(`/api/passkeys/${encodeURIComponent(removeTarget.id)}`, {
        method: "DELETE",
        body: json({ confirmation: removalConfirmation, approval_token }),
      });
      await refreshPasskeys();
      setRemoveTarget(null);
      setRemovalConfirmation("");
      setPasskeyMessage("Passkey removed.");
    } catch (removeError) {
      setPasskeyError(errorMessage(removeError));
      try { await refreshPasskeys(); } catch { /* Keep the original action error visible. */ }
    } finally {
      setPasskeyActionId("");
    }
  }

  function beginPasskeyRemoval(passkey: AccountPasskey) {
    setPasskeyError("");
    setPasskeyMessage("");
    setRemovalConfirmation("");
    setRemoveTarget(passkey);
  }

  async function saveHanko() {
    setSavingHanko(true);
    setHankoMessage("");
    try {
      await api("/api/account/hanko", {
        method: "PUT",
        body: json({ color: hankoColor, seed: hankoSeed }),
      });
      setHankoMessage("Your personal hanko is saved.");
    } catch (saveError) {
      setHankoMessage(errorMessage(saveError));
    } finally {
      setSavingHanko(false);
    }
  }

  async function saveOidcProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSavingOidcProfile(true);
    setOidcProfileMessage("");
    try {
      const body: Record<string, unknown> = {
        username: oidcUsername.trim() || null,
        display_name: oidcName.trim() || null,
      };
      if (canEditUserClaim("picture")) body.picture = oidcPicture.trim();
      if (canEditUserClaim("phone_number")) body.phone_number = oidcPhone.trim();
      if (canEditUserClaim("address")) {
        body.address = Object.fromEntries(
          Object.entries(oidcAddress).filter(([claim]) => canEditUserClaim(claim)),
        );
      }
      const profileClaims: OidcProfileClaims = {};
      for (const claim of ["profile", "given_name", "family_name", "nickname", "website", "locale", "zoneinfo"] as const) {
        if (canEditUserClaim(claim)) profileClaims[claim] = oidcProfileClaims[claim];
      }
      if (Object.keys(profileClaims).length > 0) body.profile_claims = profileClaims;
      const profile = await api<{ username: string | null; display_name: string | null; picture: string | null; phone_number: string | null; address: Partial<OidcAddress> | null; profile_claims: OidcProfileClaims }>("/api/account/profile", {
        method: "PUT",
        body: json(body),
      });
      setOidcUsername(profile.username ?? "");
      setOidcName(profile.display_name ?? "");
      setOidcPicture(profile.picture ?? "");
      setOidcPhone(profile.phone_number ?? "");
      setOidcAddress({ ...EMPTY_OIDC_ADDRESS, ...(profile.address ?? {}) });
      setOidcProfileClaims({
        ...EMPTY_OIDC_PROFILE,
        ...profile.profile_claims,
      });
      setOidcProfileMessage("Your OIDC profile is saved.");
    } catch (saveError) {
      setOidcProfileMessage(errorMessage(saveError));
    } finally {
      setSavingOidcProfile(false);
    }
  }

  async function copyValue(label: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      window.setTimeout(() => setCopied(""), 1600);
    } catch {
      setCopied("");
    }
  }

  function selectTab(tab: Tab) {
    setAdminActionMessage("");
    setLoadError("");
    closeMembershipEditor();
    closeUserEditor();
    setActiveTab(tab);
  }

  const tabs: { id: Tab; label: string; icon: ReactNode }[] = [
    ...(isAdmin ? [
      { id: "clients" as const, label: "Clients", icon: <KeyRound aria-hidden="true" /> },
      { id: "users" as const, label: "Users", icon: <Users aria-hidden="true" /> },
      { id: "groups" as const, label: "Groups", icon: <UserRound aria-hidden="true" /> },
      { id: "keys" as const, label: "Signing keys", icon: <Shield aria-hidden="true" /> },
    ] : []),
    { id: "hanko", label: "Profile", icon: <Stamp aria-hidden="true" /> },
    { id: "passkeys", label: "Passkeys", icon: <Fingerprint aria-hidden="true" /> },
  ];
  const tabTitles: Record<Tab, [string, string]> = {
    clients: ["OIDC clients", "Connect applications to Hanko."],
    users: ["Users", "Create invite links, review accounts, and manage custom claims."],
    groups: ["Groups", "Manage memberships, scoped claims, and OIDC client access."],
    keys: ["Signing keys", "Manage the keys used to sign tokens."],
    hanko: ["Your profile", "Manage the details shared with apps and your personal Hanko."],
    passkeys: ["Passkeys", "Manage the devices that can sign in to your account."],
  };
  const [tabTitle, tabDescription] = tabTitles[activeTab];
  const clientBeingEdited = clients.find((client) => client.client_id === editingClientId) ?? null;
  const title = activeTab === "clients" && clientFormMode !== null
    ? clientFormMode === "edit" ? "Edit OIDC client" : "Add an OIDC client"
    : activeTab === "users" && editingUser ? "Edit user"
      : activeTab === "users" && userFormOpen ? "Invite a user"
      : activeTab === "groups" && groupFormOpen ? editingGroupId ? "Edit a group" : "Create a group" : tabTitle;
  const description = activeTab === "clients" && clientFormMode !== null
    ? "Configure how this application connects to Hanko."
    : activeTab === "users" && editingUser ? "Review account details and manage this user’s custom claims."
      : activeTab === "users" && userFormOpen ? "Create an invitation for someone to set up an account."
      : activeTab === "groups" && groupFormOpen ? "Set group details and the claims shared with its members." : tabDescription;

  return <AdminScene>
    <div className="admin-layout">
      <nav className="admin-nav" aria-label="Account and administration">
        <label className="admin-mobile-select"><span>Section</span><select value={activeTab} onChange={(event) => selectTab(event.target.value as Tab)}>
          {isAdmin && <optgroup label="Administration">{tabs.filter((tab) => ["clients", "users", "groups", "keys"].includes(tab.id)).map((tab) => <option key={tab.id} value={tab.id}>{tab.label}</option>)}</optgroup>}
          <optgroup label="Account">{tabs.filter((tab) => tab.id === "hanko" || tab.id === "passkeys").map((tab) => <option key={tab.id} value={tab.id}>{tab.label}</option>)}</optgroup>
        </select></label>
        {isAdmin && <div className="admin-nav-group">
          <p>Administration</p>
          {tabs.filter((tab) => ["clients", "users", "groups", "keys"].includes(tab.id)).map((tab) => <button key={tab.id} type="button" className="admin-nav-tab" aria-current={activeTab === tab.id ? "page" : undefined} onClick={() => selectTab(tab.id)}>{tab.icon}<span>{tab.label}</span></button>)}
        </div>}
        <div className="admin-nav-group admin-nav-account">
          <p>Account</p>
          {tabs.filter((tab) => tab.id === "hanko" || tab.id === "passkeys").map((tab) => <button key={tab.id} type="button" className="admin-nav-tab" aria-current={activeTab === tab.id ? "page" : undefined} onClick={() => selectTab(tab.id)}>{tab.icon}<span>{tab.label}</span></button>)}
        </div>
      </nav>

      <section className="admin-content" aria-labelledby="admin-page-title">
        <header className="admin-heading">
          {(activeTab === "clients" && clientFormMode !== null) && <button className="admin-back-action" type="button" onClick={closeClientForm}>← Back to clients</button>}
          {(activeTab === "users" && (userFormOpen || editingUser)) && <button className="admin-back-action" type="button" onClick={editingUser ? closeUserEditor : closeUserForm}>← Back to users</button>}
          {(activeTab === "groups" && groupFormOpen) && <button className="admin-back-action" type="button" onClick={closeGroupForm}>← Back to groups</button>}
          <h1 id="admin-page-title">{title}</h1>
          <p>{description}</p>
        </header>
        {loadError && <p className="admin-message admin-message-error" role="alert">{loadError}</p>}
        {loading ? <div className="admin-loading"><HankoSeal size={42} /><p>Loading…</p></div> : <>
          {activeTab === "clients" && isAdmin && clientFormMode === null && <>
    <section className="registered-clients">
      <div className="client-list-heading">
        <h2>Registered clients <span>{clients.length}</span></h2>
        <button className="client-add-action" type="button" onClick={openCreateClient}><Plus aria-hidden="true" /> Add a client</button>
      </div>
      {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
      {clients.length === 0
        ? <p className="admin-hint">No clients have been added yet.</p>
        : <div className="admin-table-scroll"><table className="admin-table client-table">
          <thead><tr><th scope="col">Application</th><th scope="col">Scopes</th><th scope="col">Client ID</th><th scope="col">Type</th><th scope="col">Users</th><th scope="col">Status</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>{clients.map((client) => <tr key={client.client_id}>
            <td><strong><PrivateValue>{client.name}</PrivateValue></strong></td>
            <td><div className="client-scope-list" aria-label={`Enabled scopes: ${client.scopes.join(", ")}`}>{client.scopes.map((scope) => <span className="client-scope-chip" key={scope}>{scope}</span>)}</div></td>
            <td><code className="table-id"><PrivateValue>{client.client_id}</PrivateValue></code></td>
            <td>{client.client_type === "public" ? "Public" : "Confidential"}<small>{client.token_endpoint_auth_method} · PKCE {client.pkce_policy}</small></td>
            <td>{client.user_count ?? 0}</td>
            <td><span className={client.enabled ? "client-status" : "client-status disabled"}>{client.enabled ? "Enabled" : "Disabled"}</span></td>
            <td><div className="table-actions">
              <button className="client-list-action" type="button" disabled={busy || deletingClientId !== ""} onClick={() => openEditClient(client)}><Pencil aria-hidden="true" /><span>Edit</span></button>
            </div></td>
          </tr>)}</tbody>
        </table></div>}
    </section>

    {created && <section className="created-client" role="status">
      <div className="created-title"><span><Check aria-hidden="true" /></span><div><h2>{credentialsUpdated ? "Client credentials updated" : "Client created"}</h2><p>Save these credentials in the application.</p></div></div>
      <Credential label="Client ID" value={created.client_id} copied={copied === "id"} onCopy={() => copyValue("id", created.client_id)} />
      {created.client_secret && <Credential label="Client secret · shown once" value={created.client_secret} copied={copied === "secret"} onCopy={() => copyValue("secret", created.client_secret!)} />}
      <p className="created-footnote">{created.client_secret
        ? "The client secret cannot be viewed again after you leave this screen."
        : "This client has no client secret and must use PKCE S256."}</p>
    </section>}

          </>}

          {activeTab === "clients" && isAdmin && clientFormMode !== null && <section className="client-editor-panel client-form-page" aria-labelledby="admin-page-title">
      <form className="client-form" onSubmit={saveClient}>
        <label className="admin-field"><span>Application name</span><input autoComplete="off" maxLength={120} value={name} onChange={(event) => setName(event.target.value)} placeholder="Jellyfin" required /></label>
        <label className="admin-field">
          <span>Token endpoint authentication</span>
          <select
            value={tokenAuthMethod}
            onChange={(event) => {
              const method = event.target.value as TokenEndpointAuthMethod;
              if (method === "none") setPkcePolicy("required");
              else if (tokenAuthMethod === "none") setPkcePolicy("optional");
              setTokenAuthMethod(method);
            }}
          >
            <option value="none">None · public client</option>
            <option value="client_secret_basic">Client secret Basic</option>
            <option value="client_secret_post">Client secret POST</option>
          </select>
          <small>{tokenAuthMethod === "none"
            ? "No secret is used; public clients always require PKCE S256."
            : "Confidential credentials use HTTP Basic or the form body. Switching a public client here generates a new secret shown once after saving."}</small>
        </label>
        <label className="admin-field">
          <span>PKCE policy</span>
          <select
            value={tokenAuthMethod === "none" ? "required" : pkcePolicy}
            disabled={tokenAuthMethod === "none"}
            onChange={(event) => setPkcePolicy(event.target.value as PkcePolicy)}
          >
            <option value="required">Required · S256</option>
            <option value="optional">Optional · S256 when used</option>
          </select>
          <small>{tokenAuthMethod === "none"
            ? "Public clients always require PKCE S256."
            : pkcePolicy === "required"
              ? "Every authorization must include a PKCE S256 challenge."
              : "The client may omit PKCE; any supplied challenge must use S256."}</small>
        </label>
        {clientFormMode === "edit" && <label className="admin-check client-enabled-check"><input type="checkbox" checked={clientEnabled} onChange={(event) => setClientEnabled(event.target.checked)} /><span><strong>Client enabled</strong><small>Disabled clients can no longer sign users in.</small></span></label>}
        <label className="admin-field"><span>Callback URLs</span><textarea value={redirectUris} onChange={(event) => setRedirectUris(event.target.value)} placeholder="https://app.example.com/oidc/callback" rows={2} required /><small>One exact URL per line. HTTPS is required except for localhost development.</small></label>
        <label className="admin-field"><span>Post-logout URLs <em>Optional</em></span><textarea value={logoutUris} onChange={(event) => setLogoutUris(event.target.value)} placeholder="https://app.example.com/" rows={2} /><small>One exact URL per line.</small></label>
        <fieldset className="admin-options">
          <legend>Scopes</legend>
          <label className="admin-check"><input type="checkbox" checked disabled /><span><strong>openid</strong><small>Required for sign-in</small></span></label>
          {AVAILABLE_SCOPES.map((scope) => <label className="admin-check" key={scope}><input type="checkbox" checked={scopes.includes(scope)} onChange={() => toggleScope(scope)} /><span><strong>{scope}</strong><small>{scopeDescription(scope)}</small></span></label>)}
        </fieldset>
        <fieldset className="admin-options">
          <legend>Allowed groups <em>Optional</em></legend>
          {groups.length === 0 ? <p className="admin-hint">No groups exist yet. This client can be used by any user.</p> : <><p className="admin-hint">Leave all unchecked to allow any user.</p><div className="admin-choice-grid">{groups.map((group) => <label className="admin-check admin-check-compact" key={group.id}><input type="checkbox" checked={allowedGroups.includes(group.name)} onChange={() => toggleGroup(group.name)} /><span><strong><PrivateValue>{group.display_name}</PrivateValue></strong><small><PrivateValue>{group.name} · {group.member_count} {group.member_count === 1 ? "member" : "members"}</PrivateValue></small></span></label>)}</div></>}
        </fieldset>
        <fieldset className="admin-options admin-claims">
          <legend>Custom claims <em>Optional</em></legend><p className="admin-hint">Map a user attribute to an additional token claim.</p>
          {claims.map((claim, index) => <div className="claim-editor" key={index}>
            <label className="admin-field"><span>Claim name</span><input value={claim.claim_name} onChange={(event) => updateClaim(index, "claim_name", event.target.value)} placeholder="department" /></label>
            <label className="admin-field"><span>User attribute path</span><input value={claim.user_attribute_path} onChange={(event) => updateClaim(index, "user_attribute_path", event.target.value)} placeholder="/organization/department" /></label>
            <label className="admin-field"><span>Required scope</span><select value={claim.required_scope} onChange={(event) => updateClaim(index, "required_scope", event.target.value)}><option value="">Always include</option>{["openid", ...scopes.filter((scope) => scope !== "openid")].map((scope) => <option value={scope} key={scope}>{scope}</option>)}</select></label>
            <button className="claim-remove" type="button" aria-label="Remove custom claim" onClick={() => setClaims((current) => current.filter((_, claimIndex) => claimIndex !== index))}><Trash2 aria-hidden="true" /></button>
          </div>)}
          <button className="add-claim" type="button" onClick={() => setClaims((current) => [...current, { claim_name: "", user_attribute_path: "", required_scope: "" }])}><Plus aria-hidden="true" /> Add claim</button>
        </fieldset>
        {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
        <div className="client-form-actions"><button className="primary-action client-submit" type="submit" disabled={busy || !name.trim()}>{busy ? "Saving client…" : clientFormMode === "edit" ? "Save changes" : "Create OIDC client"}</button><button className="client-list-action" type="button" disabled={busy} onClick={closeClientForm}>Cancel</button></div>
      </form>
      {clientFormMode === "edit" && clientBeingEdited && <section className="client-danger-zone" aria-labelledby="client-remove-title">
        <h2 id="client-remove-title">Remove client</h2>
        <p>Permanently delete this client’s settings, pending sign-ins, authorization codes, refresh tokens, and linked-user records. Hanko user accounts will remain, but this application will no longer be able to sign users in through Hanko.</p>
        <button className="client-list-action client-remove-action" type="button" disabled={busy || deletingClientId !== ""} onClick={() => void removeClient(clientBeingEdited)}><Trash2 aria-hidden="true" />{deletingClientId === clientBeingEdited.client_id ? "Removing…" : "Remove client"}</button>
      </section>}
    </section>}

          {activeTab === "users" && isAdmin && !userFormOpen && !editingUser && <>
            <div className="client-list-heading user-list-heading"><h2>Accounts <span>{users.length}</span></h2></div>
            {adminActionMessage && <p className="admin-message admin-message-error" role="alert">{adminActionMessage}</p>}
            <section className="registered-clients admin-records user-records">
              {users.length === 0 ? <p className="admin-hint">No accounts found.</p> : <div className="admin-table-scroll"><table className="admin-table user-table">
                <thead><tr><th scope="col">User</th><th scope="col">Username</th><th scope="col">Groups</th><th scope="col">Invite label</th><th scope="col">Status</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>{users.map((user) =>
                  <tr key={user.id}>
                    <td><strong><PrivateValue>{user.display_name || user.username}</PrivateValue></strong></td><td><code className="table-id"><PrivateValue>{user.username}</PrivateValue></code></td><td>{user.groups.length ? <PrivateValue>{user.groups.join(", ")}</PrivateValue> : <span className="table-muted">—</span>}</td><td>{user.invitation_label ? <PrivateValue>{user.invitation_label}</PrivateValue> : <span className="table-muted">—</span>}</td>
                    <td><span className={`client-status${user.disabled ? " disabled" : ""}`}>{user.disabled ? "Disabled" : user.is_admin ? "Administrator" : "Active"}</span></td>
                    <td><button className="client-list-action membership-action" type="button" onClick={() => void openEditUser(user)} disabled={userClaimsLoading || userClaimsBusy}><Pencil aria-hidden="true" />Edit user</button></td>
                  </tr>
                )}</tbody>
              </table></div>}
            </section>
            <section className="registered-clients admin-records">
              <div className="client-list-heading"><h2>Invite links <span>{invitations.length}</span></h2><button className="client-add-action" type="button" onClick={openCreateUser}><Plus aria-hidden="true" /> Create an invite</button></div>
              {invitations.length === 0 ? <p className="admin-hint">No invite links yet.</p> : <div className="admin-table-scroll"><table className="admin-table invitation-table">
                <thead><tr><th scope="col">Invite</th><th scope="col">Email</th><th scope="col">Uses</th><th scope="col">Expires</th><th scope="col">Status</th><th scope="col">Actions</th></tr></thead>
                <tbody>{invitations.map((invitation) => {
                  const status = invitationStatus(invitation);
                  return <tr key={invitation.id}>
                    <td><strong><PrivateValue>{invitation.label}</PrivateValue></strong></td>
                    <td>{invitation.email ? <PrivateValue>{invitation.email}</PrivateValue> : <span className="table-muted">Anyone with link</span>}</td>
                    <td><PrivateValue>{invitation.use_count} of {invitation.max_uses}</PrivateValue></td>
                    <td><PrivateValue>{new Date(invitation.expires_at * 1000).toLocaleDateString()}</PrivateValue></td>
                    <td><span className={`client-status${status === "Active" ? "" : " disabled"}`}>{status}</span></td>
                    <td>{status === "Active" ? <button className="invitation-revoke" type="button" onClick={() => revokeInvitation(invitation.id)} disabled={adminActionBusy}>Revoke</button> : <span className="table-muted">—</span>}</td>
                  </tr>;
                })}</tbody>
              </table></div>}
            </section>
          </>}

          {activeTab === "users" && isAdmin && editingUser && <section className="user-edit-page">
            <dl className="user-detail-grid">
              <div><dt>Display name</dt><dd><PrivateValue>{editingUser.display_name}</PrivateValue></dd></div>
              <div><dt>Username</dt><dd><PrivateValue>{editingUser.username}</PrivateValue></dd></div>
              <div><dt>Email</dt><dd>{editingUser.email ? <PrivateValue>{editingUser.email}</PrivateValue> : <span className="table-muted">No email</span>}</dd></div>
              <div><dt>Status</dt><dd>{editingUser.disabled ? "Disabled" : editingUser.is_admin ? "Administrator" : "Active"}</dd></div>
              <div><dt>Invite label</dt><dd>{editingUser.invitation_label ? <PrivateValue>{editingUser.invitation_label}</PrivateValue> : <span className="table-muted">—</span>}</dd></div>
              <div><dt>Groups</dt><dd>{editingUser.groups.length ? <PrivateValue>{editingUser.groups.join(", ")}</PrivateValue> : <span className="table-muted">—</span>}</dd></div>
              <div><dt>Created</dt><dd><PrivateValue>{new Date(editingUser.created_at * 1000).toLocaleDateString()}</PrivateValue></dd></div>
            </dl>
            <form className="client-form user-editor-form" onSubmit={saveUserClaims}>
              <fieldset className="admin-options admin-claims">
                <legend>Custom claims <em>Optional</em></legend>
                <p className="admin-hint">Add JSON claims to this user’s ID and access tokens. A user claim takes precedence over a group claim with the same name; a client-specific claim mapping takes precedence over both.</p>
                {userClaimsLoading ? <p className="admin-hint">Loading custom claims…</p> : userClaimDrafts.map((claim, index) => <div className="claim-editor user-claim-editor" key={index}>
                  <label className="admin-field"><span>Claim name</span><input autoComplete="off" maxLength={100} value={claim.claim_name} onChange={(event) => updateUserClaim(index, "claim_name", event.target.value)} placeholder="department" required={Boolean(claim.claim_value.trim())} /></label>
                  <label className="admin-field"><span>JSON value</span><textarea maxLength={4096} rows={2} value={claim.claim_value} onChange={(event) => updateUserClaim(index, "claim_value", event.target.value)} placeholder={'"design"'} required={Boolean(claim.claim_name.trim())} /></label>
                  <label className="admin-field"><span>Required scope</span><select value={claim.required_scope} onChange={(event) => updateUserClaim(index, "required_scope", event.target.value)}><option value="">Always include</option>{["openid", ...AVAILABLE_SCOPES].map((scope) => <option value={scope} key={scope}>{scope}</option>)}</select></label>
                  <button className="claim-remove" type="button" aria-label="Remove user claim" onClick={() => setUserClaimDrafts((current) => current.filter((_, claimIndex) => claimIndex !== index))}><Trash2 aria-hidden="true" /></button>
                </div>)}
                {!userClaimsLoading && <button className="add-claim" type="button" onClick={() => setUserClaimDrafts((current) => [...current, { claim_name: "", claim_value: "", required_scope: "" }])}><Plus aria-hidden="true" /> Add custom claim</button>}
              </fieldset>
              {userEditorError && <p className="admin-message admin-message-error" role="alert">{userEditorError}</p>}
              {userEditorMessage && <p className="admin-message" role="status">{userEditorMessage}</p>}
              <div className="client-form-actions"><button className="primary-action client-submit" type="submit" disabled={userClaimsBusy || userClaimsLoading || !userClaimsReady}>{userClaimsBusy ? "Saving…" : "Save custom claims"}</button><button className="client-list-action" type="button" disabled={userClaimsBusy} onClick={closeUserEditor}>Cancel</button></div>
            </form>
          </section>}

          {activeTab === "users" && isAdmin && userFormOpen && <>
      {createdInvitation ? <section className="created-client" role="status"><div className="created-title"><span><Check aria-hidden="true" /></span><div><h2>Invite link ready</h2><p>Anyone with this link can join until it expires or reaches its user limit.</p></div></div><Credential label={<>Invite link · <PrivateValue>{createdInvitation.label}</PrivateValue></>} value={createdInvitation.enrollment_url} copied={copied === "invitation"} onCopy={() => copyValue("invitation", createdInvitation.enrollment_url)} />{createdInvitation.email && <a className="secondary-action invitation-email-action" href={invitationEmailHref(createdInvitation)}><Mail aria-hidden="true" />Email this invite</a>}<p className="created-footnote">Expires {new Date(createdInvitation.expires_at * 1000).toLocaleString()}. The link is shown only now, so copy it before leaving this page.</p><button className="client-list-action create-another-invite" type="button" onClick={openCreateUser}><Plus aria-hidden="true" /> Create another invite</button></section> : <form className="client-form admin-create-form user-create-page" onSubmit={createInvitation}>
              <label className="admin-field"><span>Admin-only user label</span><input autoComplete="off" maxLength={80} value={invitationLabel} onChange={(event) => setInvitationLabel(event.target.value)} placeholder="Community event" required /><small>This label appears only in the administrator’s user list.</small></label>
              <label className="admin-field"><span>Email recipient <em>Optional</em></span><input type="email" autoComplete="email" maxLength={320} value={invitationEmail} onChange={(event) => { setInvitationEmail(event.target.value); if (event.target.value.trim()) setInvitationMaxUses("1"); else setInvitationMaxUses("10"); }} placeholder="person@example.com" /><small>Add an address to make this a one-use email invitation. You can open a prefilled email after creating it.</small></label>
              <div className="invitation-settings">
                <label className="admin-field"><span>User limit</span><input type="number" min={1} max={500} value={invitationMaxUses} onChange={(event) => setInvitationMaxUses(event.target.value)} disabled={Boolean(invitationEmail.trim())} required /><small>{invitationEmail.trim() ? "Email invitations are limited to one user." : "How many accounts can use this link?"}</small></label>
                <div className="invitation-expiry-fields"><label className="admin-field"><span>Link expires in</span><input type="number" min={1} max={Math.floor((10 * 365 * 24 * 60 * 60) / EXPIRY_UNIT_SECONDS[invitationExpiryUnit])} value={invitationExpiry} onChange={(event) => setInvitationExpiry(event.target.value)} required /></label><label className="admin-field"><span>Unit</span><select value={invitationExpiryUnit} onChange={(event) => setInvitationExpiryUnit(event.target.value as ExpiryUnit)}><option value="seconds">Seconds</option><option value="minutes">Minutes</option><option value="hours">Hours</option><option value="days">Days</option><option value="years">Years</option></select><small>Up to 10 years.</small></label></div>
              </div>
              {groups.length > 0 && <fieldset className="admin-options"><legend>Groups <em>Optional</em></legend><div className="admin-choice-grid">{groups.map((group) => <label className="admin-check" key={group.id}><input type="checkbox" checked={userGroups.includes(group.name)} onChange={() => setUserGroups((current) => current.includes(group.name) ? current.filter((name) => name !== group.name) : [...current, group.name])} /><span><strong><PrivateValue>{group.display_name}</PrivateValue></strong></span></label>)}</div></fieldset>}
              {adminActionMessage && <p className="admin-message admin-message-error" role="alert">{adminActionMessage}</p>}
              <div className="client-form-actions"><button className="primary-action client-submit" type="submit" disabled={adminActionBusy || !invitationLabel.trim() || (!invitationEmail.trim() && (!Number(invitationMaxUses) || Number(invitationMaxUses) > 500))}>{adminActionBusy ? "Creating link…" : "Create invite link"}</button><button className="client-list-action" type="button" disabled={adminActionBusy} onClick={closeUserForm}>Cancel</button></div>
            </form>}
          </>}

          {activeTab === "groups" && isAdmin && groupFormOpen && <form className="client-form admin-create-form user-create-page" onSubmit={createGroup}>
              <label className="admin-field"><span>Group name</span><input autoComplete="off" maxLength={80} value={groupName} onChange={(event) => setGroupName(event.target.value)} placeholder="media-users" required disabled={Boolean(editingGroupId)} /></label>
              <label className="admin-field"><span>Display name</span><input maxLength={120} value={groupDisplayName} onChange={(event) => setGroupDisplayName(event.target.value)} placeholder="Media users" required /></label>
              <fieldset className="admin-options admin-claims">
                <legend>Claims added for members <em>Optional</em></legend>
                <p className="admin-hint">These JSON values are added to matching members’ ID and access tokens when the required scope is requested. Quote string values, such as "media-user". If several groups provide the same claim, their values merge into a deduplicated array. Client-specific claim mappings take precedence.</p>
                {groupClaims.map((claim, index) => <div className="claim-editor group-claim-editor" key={index}>
                  <label className="admin-field"><span>Claim name</span><input value={claim.claim_name} onChange={(event) => updateGroupClaim(index, "claim_name", event.target.value)} placeholder="role" /></label>
                  <label className="admin-field"><span>JSON value</span><textarea value={claim.claim_value} onChange={(event) => updateGroupClaim(index, "claim_value", event.target.value)} placeholder='"media-user"' rows={2} /></label>
                  <label className="admin-field"><span>Required scope</span><select value={claim.required_scope} onChange={(event) => updateGroupClaim(index, "required_scope", event.target.value)}>{(["openid", ...AVAILABLE_SCOPES] as const).map((scope) => <option value={scope} key={scope}>{scope}</option>)}</select></label>
                  <button className="claim-remove" type="button" aria-label="Remove group claim" onClick={() => setGroupClaims((current) => current.filter((_, claimIndex) => claimIndex !== index))}><Trash2 aria-hidden="true" /></button>
                </div>)}
                <button className="add-claim" type="button" onClick={() => setGroupClaims((current) => [...current, { claim_name: "", claim_value: "", required_scope: "groups" }])}><Plus aria-hidden="true" /> Add group claim</button>
              </fieldset>
              {adminActionMessage && <p className="admin-message admin-message-error" role="alert">{adminActionMessage}</p>}
              <div className="client-form-actions"><button className="primary-action client-submit" type="submit" disabled={adminActionBusy || !groupName.trim() || !groupDisplayName.trim()}>{adminActionBusy ? "Saving…" : editingGroupId ? "Save group" : "Create group"}</button><button className="client-list-action" type="button" disabled={adminActionBusy} onClick={closeGroupForm}>Cancel</button></div>
            </form>}

          {activeTab === "groups" && isAdmin && !groupFormOpen && <>
            <div className="client-list-heading user-list-heading"><h2>Groups <span>{groups.length}</span></h2><button className="client-add-action" type="button" onClick={openCreateGroup}><Plus aria-hidden="true" /> Add a group</button></div>
            {adminActionMessage && <p className="admin-message admin-message-error" role="alert">{adminActionMessage}</p>}
            <section className="registered-clients admin-records user-records">{groups.length === 0 ? <p className="admin-hint">No groups have been created.</p> : <div className="admin-table-scroll"><table className="admin-table group-table">
              <thead><tr><th scope="col">Group name</th><th scope="col">Display name</th><th scope="col">Claims</th><th scope="col">Members</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>{groups.map((group) => <Fragment key={group.id}>
                <tr key={group.id}>
                  <td><code className="table-id"><PrivateValue>{group.name}</PrivateValue></code></td>
                  <td><strong><PrivateValue>{group.display_name}</PrivateValue></strong></td>
                  <td>{(group.claims ?? []).length ? <span>{(group.claims ?? []).map((claim) => claim.claim_name).join(", ")}</span> : <span className="table-muted">—</span>}</td>
                  <td><PrivateValue>{group.member_count}</PrivateValue></td>
                  <td><div className="table-actions"><button className="client-list-action" type="button" disabled={adminActionBusy} onClick={() => openEditGroup(group)}><Pencil aria-hidden="true" /><span>Edit</span></button><button className="client-list-action membership-action" type="button" onClick={() => void openGroupMembers(group)} disabled={adminActionBusy || membershipBusy || membershipLoading}><Users aria-hidden="true" />Manage members</button><button className="client-list-action client-remove-action" type="button" disabled={adminActionBusy} onClick={() => void deleteGroup(group)}><Trash2 aria-hidden="true" /><span>{deletingGroupId === group.id ? "Deleting…" : "Delete"}</span></button></div></td>
                </tr>
                {membershipEditor?.kind === "group" && membershipEditor.id === group.id && <tr key={`${group.id}-members`}><td colSpan={5}>
                  <form className="membership-editor" onSubmit={saveMembership}>
                    <h3>Members of <PrivateValue>{group.display_name}</PrivateValue></h3>
                    {membershipLoading ? <p className="admin-hint">Loading users…</p> : users.length === 0 ? <p className="admin-hint">No user accounts are available.</p> : <fieldset className="admin-options"><legend>Choose users</legend><div className="admin-choice-grid">{users.map((user) => <label className="admin-check" key={user.id}><input type="checkbox" checked={membershipSelection.includes(user.id)} onChange={() => toggleMembership(user.id)} disabled={membershipBusy} /><span><strong><PrivateValue>{user.display_name || user.username}</PrivateValue></strong><small><PrivateValue>{user.username}{user.disabled ? " · disabled" : ""}</PrivateValue></small></span></label>)}</div></fieldset>}
                    {membershipError && <p className="admin-message admin-message-error" role="alert">{membershipError}</p>}
                    <div className="client-form-actions"><button className="primary-action client-submit" type="submit" disabled={membershipBusy || membershipLoading || !membershipReady}>{membershipBusy ? "Saving…" : "Save members"}</button><button className="client-list-action" type="button" disabled={membershipBusy} onClick={closeMembershipEditor}>Cancel</button></div>
                  </form>
                </td></tr>}
              </Fragment>)}</tbody>
            </table></div>}</section>
          </>}

          {activeTab === "keys" && isAdmin && <>
            <div className="key-management"><div className="key-management-copy"><p className="admin-hint">Signing keys let Hanko sign the ID and access tokens it issues. Connected apps use the matching public keys to verify each token.</p><p className="admin-hint">Rotating creates a new active key for future tokens. The old public key stays available for 15 minutes so current tokens remain verifiable; users stay signed in.</p></div><button className="secondary-action" type="button" onClick={rotateSigningKey} disabled={adminActionBusy}><Shield aria-hidden="true" />{adminActionBusy ? "Creating new key…" : "Rotate signing key"}</button></div>
            {adminActionMessage && <p className="passkey-feedback passkey-feedback-success" role="status">{adminActionMessage}</p>}
            <section className="registered-clients admin-records"><h2>Keys <span>{signingKeys.length}</span></h2>{signingKeys.length === 0 ? <p className="admin-hint">No signing keys found.</p> : <div className="admin-table-scroll"><table className="admin-table signing-key-table">
              <thead><tr><th scope="col">Key ID</th><th scope="col">Algorithm</th><th scope="col">Status</th><th scope="col">Created</th><th scope="col">Retires</th></tr></thead>
              <tbody>{signingKeys.map((key) => <tr key={key.kid}>
                <td><code className="table-id"><PrivateValue>{key.kid}</PrivateValue></code></td>
                <td>{key.algorithm}</td>
                <td><span className={`client-status${key.status === "active" ? "" : " disabled"}`}>{key.status}</span></td>
                <td><PrivateValue>{new Date(key.created_at * 1000).toLocaleDateString()}</PrivateValue></td>
                <td>{key.retire_after ? <PrivateValue>{new Date(key.retire_after * 1000).toLocaleDateString()}</PrivateValue> : <span className="table-muted">—</span>}</td>
              </tr>)}</tbody>
            </table></div>}</section>
          </>}

          {activeTab === "hanko" && <section className="account-hanko">
            <div className="account-hanko-preview"><HankoSeal size={192} color={hankoColor} seed={hankoSeed} title="Your personal Hanko preview" /></div>
            <SealCustomizer color={hankoColor} seed={hankoSeed} onColorChange={setHankoColor} onSeedChange={setHankoSeed} />
            <div className="account-hanko-save"><button className="secondary-action" type="button" onClick={saveHanko} disabled={savingHanko}>{savingHanko ? "Saving…" : "Save your Hanko"}</button>{hankoMessage && <p role="status">{hankoMessage}</p>}</div>
            <form className="client-form account-oidc-profile" onSubmit={saveOidcProfile}>
              <div><h2>OIDC profile</h2><p className="admin-hint">Choose the details shared when apps request the matching scopes.</p></div>
              {canEditUserClaim("preferred_username") && <label className="admin-field"><span>Username <em>Optional</em></span><input autoComplete="username" autoCapitalize="none" maxLength={64} pattern={"[A-Za-z0-9._\\-]+"} value={oidcUsername} onChange={(event) => setOidcUsername(event.target.value.toLowerCase())} placeholder="Used as preferred_username" /><small>Leave blank to keep your username private.</small></label>}
              {canEditUserClaim("name") && <label className="admin-field"><span>Name <em>Optional</em></span><input autoComplete="name" maxLength={120} value={oidcName} onChange={(event) => setOidcName(event.target.value)} placeholder="How apps should know you" /><small>Leave blank to keep your name private.</small></label>}
              {canEditUserClaim("picture") && <label className="admin-field"><span>Picture URL <em>Optional</em></span><input type="url" maxLength={2048} value={oidcPicture} onChange={(event) => setOidcPicture(event.target.value)} placeholder="Generated from your Hanko stamp" /><small>Leave blank to use a generated image matching your Hanko stamp. A custom HTTPS image URL overrides it.</small></label>}
              {canEditUserClaim("phone_number") && <label className="admin-field"><span>Phone number <em>Optional</em></span><input type="tel" autoComplete="tel" maxLength={64} value={oidcPhone} onChange={(event) => setOidcPhone(event.target.value)} placeholder="+1 555 123 4567" /><small>Shared with apps that request the phone scope. Hanko does not verify phone ownership.</small></label>}
              {canEditUserClaim("address") && canEditUserClaim("street_address") && <label className="admin-field"><span>Street address <em>Optional</em></span><textarea autoComplete="street-address" maxLength={500} rows={2} value={oidcAddress.street_address} onChange={(event) => setOidcAddress((address) => ({ ...address, street_address: event.target.value }))} placeholder="Street, apartment or floor" /><small>Apartment and floor details can be included here. Shared with apps that request the address scope.</small></label>}
              {canEditUserClaim("address") && canEditUserClaim("locality") && <label className="admin-field"><span>City or locality <em>Optional</em></span><input autoComplete="address-level2" maxLength={500} value={oidcAddress.locality} onChange={(event) => setOidcAddress((address) => ({ ...address, locality: event.target.value }))} /></label>}
              {canEditUserClaim("address") && canEditUserClaim("region") && <label className="admin-field"><span>Region or state <em>Optional</em></span><input autoComplete="address-level1" maxLength={500} value={oidcAddress.region} onChange={(event) => setOidcAddress((address) => ({ ...address, region: event.target.value }))} /></label>}
              {canEditUserClaim("address") && canEditUserClaim("postal_code") && <label className="admin-field"><span>Postal code <em>Optional</em></span><input autoComplete="postal-code" maxLength={500} value={oidcAddress.postal_code} onChange={(event) => setOidcAddress((address) => ({ ...address, postal_code: event.target.value }))} /></label>}
              {canEditUserClaim("address") && canEditUserClaim("country") && <label className="admin-field"><span>Country <em>Optional</em></span><input autoComplete="country-name" maxLength={500} value={oidcAddress.country} onChange={(event) => setOidcAddress((address) => ({ ...address, country: event.target.value }))} /></label>}
              {canEditUserClaim("profile") && <label className="admin-field"><span>Profile URL <em>Optional</em></span><input type="url" maxLength={2048} value={oidcProfileClaims.profile} onChange={(event) => setOidcProfileClaims((claims) => ({ ...claims, profile: event.target.value }))} placeholder="https://example.com/about" /></label>}
              {canEditUserClaim("given_name") && <label className="admin-field"><span>Given name <em>Optional</em></span><input autoComplete="given-name" maxLength={120} value={oidcProfileClaims.given_name} onChange={(event) => setOidcProfileClaims((claims) => ({ ...claims, given_name: event.target.value }))} /></label>}
              {canEditUserClaim("family_name") && <label className="admin-field"><span>Family name <em>Optional</em></span><input autoComplete="family-name" maxLength={120} value={oidcProfileClaims.family_name} onChange={(event) => setOidcProfileClaims((claims) => ({ ...claims, family_name: event.target.value }))} /></label>}
              {canEditUserClaim("nickname") && <label className="admin-field"><span>Nickname <em>Optional</em></span><input autoComplete="nickname" maxLength={120} value={oidcProfileClaims.nickname} onChange={(event) => setOidcProfileClaims((claims) => ({ ...claims, nickname: event.target.value }))} /></label>}
              {canEditUserClaim("website") && <label className="admin-field"><span>Website <em>Optional</em></span><input type="url" maxLength={2048} value={oidcProfileClaims.website} onChange={(event) => setOidcProfileClaims((claims) => ({ ...claims, website: event.target.value }))} placeholder="https://example.com" /></label>}
              {canEditUserClaim("locale") && <label className="admin-field"><span>Locale <em>Optional</em></span><input maxLength={128} value={oidcProfileClaims.locale} onChange={(event) => setOidcProfileClaims((claims) => ({ ...claims, locale: event.target.value }))} placeholder="en-US" /></label>}
              {canEditUserClaim("zoneinfo") && <label className="admin-field"><span>Time zone <em>Optional</em></span><input maxLength={128} value={oidcProfileClaims.zoneinfo} onChange={(event) => setOidcProfileClaims((claims) => ({ ...claims, zoneinfo: event.target.value }))} placeholder="Europe/Stockholm" /></label>}
              {oidcProfileMessage && <p className={`admin-message${oidcProfileMessage.includes("saved") ? "" : " admin-message-error"}`} role={oidcProfileMessage.includes("saved") ? "status" : "alert"}>{oidcProfileMessage}</p>}
              <div className="client-form-actions"><button className="primary-action client-submit" type="submit" disabled={savingOidcProfile}>{savingOidcProfile ? "Saving profile…" : "Save OIDC profile"}</button></div>
            </form>
          </section>}

          {activeTab === "passkeys" && <section className="account-passkeys">
            <section className="passkey-list" aria-labelledby="passkey-list-title">
              <div className="client-list-heading"><h2 id="passkey-list-title">Registered devices <span>{passkeys.length}</span></h2><button className="client-add-action" type="button" onClick={() => void addPasskey()} disabled={addingPasskey}><Plus aria-hidden="true" /> {addingPasskey ? "Follow your device prompt…" : "Add passkey"}</button></div>
              {passkeyMessage && <p className="passkey-feedback passkey-feedback-success" role="status">{passkeyMessage}</p>}{passkeyError && <p className="passkey-feedback passkey-feedback-error" role="alert">{passkeyError}</p>}
              {passkeysLoading ? <p className="admin-hint">Loading passkeys…</p> : passkeys.length === 0 ? <p className="admin-hint">No passkeys are registered.</p> : <div className="admin-table-scroll"><table className="admin-table passkey-table">
                <thead><tr><th scope="col">Device</th><th scope="col">Added</th><th scope="col">Last used</th><th scope="col">Actions</th></tr></thead>
                <tbody>{passkeys.map((passkey) => <tr key={passkey.id}>
                  <td><form id={`rename-passkey-${passkey.id}`} onSubmit={(event) => renamePasskey(event, passkey)}><input aria-label={`Device name for ${passkey.label}`} className="passkey-table-input" value={passkeyDrafts[passkey.id] ?? passkey.label} onChange={(event) => setPasskeyDrafts((current) => ({ ...current, [passkey.id]: event.target.value }))} maxLength={100} required /></form></td>
                  <td><PrivateValue>{new Date(passkey.created_at * 1000).toLocaleDateString()}</PrivateValue></td>
                  <td>{passkey.last_used_at ? <PrivateValue>{new Date(passkey.last_used_at * 1000).toLocaleDateString()}</PrivateValue> : <span className="table-muted">Not used yet</span>}</td>
                  <td><div className="table-actions">
                    <button className="client-list-action" type="submit" form={`rename-passkey-${passkey.id}`} disabled={Boolean(passkeyActionId) || (passkeyDrafts[passkey.id] ?? passkey.label).trim() === passkey.label}>{passkeyActionId === passkey.id ? "Saving…" : "Rename"}</button>
                    <button className="passkey-remove-button" type="button" onClick={() => beginPasskeyRemoval(passkey)} disabled={passkeys.length <= 1 || Boolean(passkeyActionId)}><Trash2 aria-hidden="true" />Remove</button>
                  </div></td>
                </tr>)}</tbody>
              </table></div>}
            </section>
            {removeTarget && <form className="passkey-remove-confirmation" onSubmit={removePasskey}>
              <div><h3>Remove “<PrivateValue>{removeTarget.label}</PrivateValue>”?</h3><p>This permanently removes the passkey from your account. Type <strong>REMOVE</strong> to confirm.</p></div>
              <label className="admin-field"><span>Confirmation</span><input autoComplete="off" autoFocus value={removalConfirmation} onChange={(event) => setRemovalConfirmation(event.target.value)} placeholder="Type REMOVE" /></label>
              <div className="passkey-remove-actions"><button className="passkey-remove-button" type="submit" disabled={passkeys.length <= 1 || removalConfirmation !== "REMOVE" || Boolean(passkeyActionId)}>{passkeyActionId === removeTarget.id ? "Removing…" : "Remove passkey"}</button><button className="secondary-action passkey-row-action" type="button" disabled={Boolean(passkeyActionId)} onClick={() => { setRemoveTarget(null); setRemovalConfirmation(""); }}>Cancel</button></div>
            </form>}
          </section>}
        </>}
      </section>
    </div>
  </AdminScene>;
}

function scopeDescription(scope: (typeof AVAILABLE_SCOPES)[number]) {
  switch (scope) {
    case "profile": return "Name and profile details";
    case "email": return "Email address";
    case "address": return "Postal address";
    case "phone": return "Phone number";
    case "picture": return "Profile picture URL";
    case "groups": return "Group memberships";
    case "offline_access": return "Issue a refresh token for ongoing access";
  }
}

function Credential({ label, value, copied, onCopy }: { label: ReactNode; value: string; copied: boolean; onCopy: () => void }) {
  return <div className="credential-row">
    <label><span>{label}</span><input readOnly type="text" value={value} onFocus={(event) => event.currentTarget.select()} /></label>
    <button type="button" className="credential-copy" onClick={onCopy} aria-label={`Copy ${label}`}>{copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}</button>
  </div>;
}

function AdminScene({ children }: { children: ReactNode }) {
  return <main className="auth-scene admin-scene">
    <div className="paper-grain" aria-hidden="true" />
    <InkWash />
    <section className="admin-panel">{children}</section>
  </main>;
}

function InkWash() {
  return <svg className="ink-wash" viewBox="0 0 1440 190" preserveAspectRatio="xMidYMax slice" aria-hidden="true">
    <path d="M0 124 C75 112 98 94 163 110 C215 122 255 142 318 118 C375 97 408 80 456 103 C502 125 527 135 568 109 C612 82 657 40 710 68 C758 94 790 119 843 106 C905 91 951 49 1009 78 C1068 108 1093 145 1160 125 C1222 107 1260 71 1311 91 C1360 110 1381 124 1440 111 L1440 190 L0 190 Z" />
    <path d="M0 153 C74 143 112 127 167 138 C218 148 242 164 307 150 C361 139 394 121 451 140 C510 160 535 167 594 145 C646 125 683 91 733 111 C784 132 819 151 876 144 C933 137 967 111 1025 128 C1083 145 1127 168 1181 154 C1246 136 1284 121 1338 140 C1382 156 1406 164 1440 151 L1440 190 L0 190 Z" />
  </svg>;
}
