import { Check, Copy, Fingerprint, KeyRound, LogOut, Mail, Pencil, Plus, Shield, ShieldCheck, Users, UserRound, Stamp, Trash2 } from "lucide-react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { Fragment, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { HankoSeal } from "./components/HankoSeal";
import { PrivateValue } from "./components/PrivacyMode";
import { SealCustomizer } from "./components/SealCustomizer";
import { ORIGINAL_HANKO_GRADIENT } from "./components/generateHankoPath";
import { api, appPath, defaultPasskeyLabel, json, logUiIssue } from "./lib/utils";
import type { OidcProfileClaims } from "./lib/userClaims";
import { ProfileFields } from "./components/ProfileFields";
import { buildProfilePayload, createProfileDraft, missingProfileClaims, type OidcAddress, type SavedProfile } from "./lib/profile";

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
type UserClaim = { claim_name: string; claim_value: unknown; required_scope: string | null };
type UserClaimDraft = { claim_name: string; claim_value: string; required_scope: string };
type Invitation = { id: string; label: string; email: string | null; max_uses: number; use_count: number; created_at: number; expires_at: number; revoked: boolean };
type CreatedInvitation = { id: string; label: string; email: string | null; enrollment_url: string; expires_at: number };
type SigningKey = { kid: string; algorithm: string; status: string; created_at: number; retire_after: number | null };
type AccountPasskey = { id: string; label: string; created_at: number; last_used_at: number | null };
type ConsentGrant = { client_id: string; client_name: string; scopes: string[]; granted_at: number; expires_at: number | null };
type Tab = "clients" | "users" | "groups" | "keys" | "hanko" | "passkeys" | "consents";
type AdminRoute = {
  tab: Tab;
  canonicalPath: string;
  clientFormMode: "create" | "edit" | null;
  clientId: string;
  userFormOpen: boolean;
  userId: string;
  groupFormOpen: boolean;
  groupId: string;
};
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

const TAB_PATHS: Record<Tab, string> = {
  clients: "/admin/clients/clients",
  users: "/admin/clients/users",
  groups: "/admin/clients/groups",
  keys: "/admin/clients/keys",
  hanko: "/account/profile",
  passkeys: "/account/passkeys",
  consents: "/account/applications",
};

function decodeSegment(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function parseAdminRoute(pathname: string): AdminRoute {
  const parts = pathname.split("/").filter(Boolean);
  const route: AdminRoute = {
    tab: "clients",
    canonicalPath: TAB_PATHS.clients,
    clientFormMode: null,
    clientId: "",
    userFormOpen: false,
    userId: "",
    groupFormOpen: false,
    groupId: "",
  };

  if (parts[0] === "account") {
    const accountTab: Record<string, Tab> = { profile: "hanko", passkeys: "passkeys", applications: "consents" };
    route.tab = accountTab[parts[1] ?? ""] ?? "hanko";
    route.canonicalPath = TAB_PATHS[route.tab];
    return route;
  }

  const adminTabs: Record<string, Tab> = { clients: "clients", users: "users", groups: "groups", keys: "keys" };
  route.tab = adminTabs[parts[2] ?? ""] ?? "clients";
  route.canonicalPath = TAB_PATHS[route.tab];
  const detail = parts.slice(3);
  if (route.tab === "clients") {
    if (detail.length === 1 && detail[0] === "new") {
      route.clientFormMode = "create";
      route.canonicalPath = `${TAB_PATHS.clients}/new`;
    } else if (detail.length === 2 && detail[1] === "edit") {
      route.clientFormMode = "edit";
      route.clientId = decodeSegment(detail[0]);
      route.canonicalPath = `${TAB_PATHS.clients}/${encodeURIComponent(route.clientId)}/edit`;
    }
  } else if (route.tab === "users") {
    if (detail.length === 1 && detail[0] === "invite") {
      route.userFormOpen = true;
      route.canonicalPath = `${TAB_PATHS.users}/invite`;
    } else if (detail.length === 2 && detail[1] === "edit") {
      route.userId = decodeSegment(detail[0]);
      route.canonicalPath = `${TAB_PATHS.users}/${encodeURIComponent(route.userId)}/edit`;
    }
  } else if (route.tab === "groups") {
    if (detail.length === 1 && detail[0] === "new") {
      route.groupFormOpen = true;
      route.canonicalPath = `${TAB_PATHS.groups}/new`;
    } else if (detail.length === 2 && detail[1] === "edit") {
      route.groupFormOpen = true;
      route.groupId = decodeSegment(detail[0]);
      route.canonicalPath = `${TAB_PATHS.groups}/${encodeURIComponent(route.groupId)}/edit`;
    }
  }
  return route;
}

function splitLines(value: string) {
  return [...new Set(value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))];
}

function errorMessage(error: unknown, context: string) {
  logUiIssue(context, error);
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

export default function ClientAdmin({ isAdmin = true, defaultTab, accountName = "", requiredUserClaims = [] }: { isAdmin?: boolean; defaultTab?: Tab; accountName?: string; requiredUserClaims?: string[] }) {
  const location = useLocation();
  const navigate = useNavigate();
  const hankoLogoUrl = new URL(appPath("hanko.png"), window.location.origin).href;
  const route = parseAdminRoute(location.pathname);
  const routeState = location.state as { returnToGroup?: boolean; groupId?: string } | null;
  const userClaimsReturnGroup = Boolean(routeState?.returnToGroup);
  const userClaimsReturnGroupId = routeState?.groupId ?? "";
  const previewScreen = import.meta.env.DEV && new URLSearchParams(window.location.search).get("ui-preview") === "1"
    ? new URLSearchParams(window.location.search).get("screen")
    : null;
  const previewTab = (): Tab => {
    if (previewScreen === "users" || previewScreen === "invite" || previewScreen === "invite-ready") return "users";
    if (previewScreen === "groups") return "groups";
    if (previewScreen === "keys") return "keys";
    if (previewScreen === "passkeys") return "passkeys";
    if (previewScreen === "consents") return "consents";
    if (previewScreen === "hanko") return "hanko";
    return defaultTab ?? (isAdmin ? "clients" : "hanko");
  };
  const activeTab = previewScreen ? previewTab() : userClaimsReturnGroup ? "users" : route.tab;
  const [clients, setClients] = useState<Client[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [signingKeys, setSigningKeys] = useState<SigningKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [sessionsRevoked, setSessionsRevoked] = useState(false);
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
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState("");
  const clientFormMode = previewScreen === "client-form" ? "create" : route.clientFormMode;
  const [credentialsUpdated, setCredentialsUpdated] = useState(false);
  const userFormOpen = previewScreen === "invite" || previewScreen === "invite-ready" || route.userFormOpen;
  const groupFormOpen = route.groupFormOpen;
  const editingGroupId = route.groupId;
  const editingClientId = route.clientId;
  const [deletingClientId, setDeletingClientId] = useState("");
  const [created, setCreated] = useState<CreatedClient | null>(null);
  const [copied, setCopied] = useState("");
  const [addingPasskey, setAddingPasskey] = useState(false);
  const [passkeyAddStage, setPasskeyAddStage] = useState<"confirming" | "creating">("confirming");
  const [passkeyError, setPasskeyError] = useState("");
  const [passkeyMessage, setPasskeyMessage] = useState("");
  const [passkeys, setPasskeys] = useState<AccountPasskey[]>([]);
  const [allowMultiplePasskeysPerAuthenticator, setAllowMultiplePasskeysPerAuthenticator] = useState(true);
  const [consents, setConsents] = useState<ConsentGrant[]>([]);
  const [consentsLoading, setConsentsLoading] = useState(false);
  const [consentActionId, setConsentActionId] = useState("");
  const [consentMessage, setConsentMessage] = useState("");
  const [consentError, setConsentError] = useState("");
  const [passkeyDrafts, setPasskeyDrafts] = useState<Record<string, string>>({});
  const [passkeysLoading, setPasskeysLoading] = useState(false);
  const [passkeyActionId, setPasskeyActionId] = useState("");
  const [removeTarget, setRemoveTarget] = useState<AccountPasskey | null>(null);
  const [removalConfirmation, setRemovalConfirmation] = useState("");
  const [hankoColor, setHankoColor] = useState(ORIGINAL_HANKO_GRADIENT);
  const [hankoSeed, setHankoSeed] = useState("hanko");
  const [savingHanko, setSavingHanko] = useState(false);
  const [hankoMessage, setHankoMessage] = useState("");
  const [profileDraft, setProfileDraft] = useState(() => createProfileDraft());
  const [savingOidcProfile, setSavingOidcProfile] = useState(false);
  const [oidcProfileMessage, setOidcProfileMessage] = useState("");
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [invitationLabel, setInvitationLabel] = useState("");
  const [invitationEmail, setInvitationEmail] = useState("");
  const [invitationMaxUses, setInvitationMaxUses] = useState("1");
  const [invitationExpiry, setInvitationExpiry] = useState("15");
  const [invitationExpiryUnit, setInvitationExpiryUnit] = useState<ExpiryUnit>("minutes");
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
  const [groupMemberSelection, setGroupMemberSelection] = useState<string[]>([]);
  const [groupMemberSearch, setGroupMemberSearch] = useState("");
  const [groupMembersLoading, setGroupMembersLoading] = useState(false);
  const [groupMembersBusy, setGroupMembersBusy] = useState(false);
  const [groupMembersReady, setGroupMembersReady] = useState(false);
  const [groupMembersError, setGroupMembersError] = useState("");
  const [groupMembersMessage, setGroupMembersMessage] = useState("");
  const groupMemberLoadId = useRef(0);
  const [editingUser, setEditingUser] = useState<AdminUser | null>(null);
  const [deletingUserId, setDeletingUserId] = useState("");
  const [userClaimDrafts, setUserClaimDrafts] = useState<UserClaimDraft[]>([]);
  const [userClaimsLoading, setUserClaimsLoading] = useState(false);
  const [userClaimsReady, setUserClaimsReady] = useState(false);
  const [userClaimsBusy, setUserClaimsBusy] = useState(false);
  const [userEditorError, setUserEditorError] = useState("");
  const [userEditorMessage, setUserEditorMessage] = useState("");
  const initializedClientEdit = useRef("");
  const initializedGroupEdit = useRef("");
  const initializedUserEdit = useRef("");

  useEffect(() => {
    if (!previewScreen && route.canonicalPath !== location.pathname) {
      navigate(route.canonicalPath, { replace: true });
    }
  }, [location.pathname, navigate, previewScreen, route.canonicalPath]);

  async function refreshClients() {
    setClients(await api<Client[]>("/api/admin/clients"));
  }

  async function refreshPasskeys() {
    const records = await api<AccountPasskey[]>("/api/passkeys");
    setPasskeys(records);
    setPasskeyDrafts(Object.fromEntries(records.map((passkey) => [passkey.id, passkey.label])));
  }

  async function refreshConsents() {
    setConsents(await api<ConsentGrant[]>("/api/account/consents"));
  }

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const sessionPromise = api<{ hanko_color?: string; hanko_seed?: string; oidc_username?: string | null; oidc_name?: string | null; oidc_picture?: string | null; oidc_phone?: string | null; oidc_address?: Partial<OidcAddress> | null; oidc_profile_claims?: OidcProfileClaims | null; allow_multiple_passkeys_per_authenticator?: boolean }>("/api/session");
        const [session, clientList, groupList] = isAdmin
          ? await Promise.all([sessionPromise, api<Client[]>("/api/admin/clients"), api<Group[]>("/api/admin/groups")])
          : [await sessionPromise, [], []];
        if (active) {
          setClients(clientList);
          setGroups(groupList);
          if (session.hanko_color) setHankoColor(session.hanko_color === "#d64135" ? ORIGINAL_HANKO_GRADIENT : session.hanko_color);
          if (session.hanko_seed) setHankoSeed(session.hanko_seed);
          setProfileDraft(createProfileDraft({
            username: session.oidc_username ?? "", displayName: session.oidc_name ?? "",
            pictureUrl: session.oidc_picture ?? "", phoneNumber: session.oidc_phone ?? "",
            address: session.oidc_address ?? undefined, profileClaims: session.oidc_profile_claims ?? undefined,
          }));
          setAllowMultiplePasskeysPerAuthenticator(session.allow_multiple_passkeys_per_authenticator ?? true);
        }
      } catch (loadError) {
        if (active) setLoadError(errorMessage(loadError, "load admin dashboard"));
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
        if (activeTab === "consents") {
          setConsentsLoading(true);
          const records = await api<ConsentGrant[]>("/api/account/consents");
          if (active) setConsents(records);
        }
      } catch (tabError) {
        if (active) setLoadError(errorMessage(tabError, "load admin tab"));
      } finally {
        if (active && activeTab === "passkeys") setPasskeysLoading(false);
        if (active && activeTab === "consents") setConsentsLoading(false);
      }
    }
    void loadTabData();
    return () => { active = false; };
  }, [activeTab, isAdmin]);

  async function revokeConsent(grant: ConsentGrant) {
    setConsentActionId(grant.client_id);
    setConsentError("");
    setConsentMessage("");
    try {
      await api(`/api/account/consents/${encodeURIComponent(grant.client_id)}`, { method: "DELETE" });
      await refreshConsents();
      setConsentMessage(`Access for ${grant.client_name} was revoked.`);
    } catch (cause) {
      setConsentError(errorMessage(cause, "revoke application access"));
    } finally {
      setConsentActionId("");
    }
  }

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
    setCreated(null);
    setCredentialsUpdated(false);
    setError("");
    initializedClientEdit.current = "";
    navigate(`${TAB_PATHS.clients}/new`);
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
    setCreated(null);
    setCredentialsUpdated(false);
    setError("");
    initializedClientEdit.current = client.client_id;
    navigate(`${TAB_PATHS.clients}/${encodeURIComponent(client.client_id)}/edit`);
  }

  function closeClientForm() {
    setError("");
    initializedClientEdit.current = "";
    navigate(TAB_PATHS.clients);
  }

  function openCreateUser() {
    closeUserEditor();
    setInvitationLabel("");
    setInvitationEmail("");
    setInvitationMaxUses("1");
    setInvitationExpiry("15");
    setInvitationExpiryUnit("minutes");
    setUserGroups([]);
    setCreatedInvitation(null);
    setAdminActionMessage("");
    navigate(`${TAB_PATHS.users}/invite`);
  }

  function closeUserForm() {
    setAdminActionMessage("");
    navigate(TAB_PATHS.users);
  }

  function openCreateGroup() {
    groupMemberLoadId.current += 1;
    setGroupName("");
    setGroupDisplayName("");
    setGroupClaims([]);
    setGroupMemberSelection([]);
    setGroupMemberSearch("");
    setGroupMembersReady(false);
    setGroupMembersError("");
    setGroupMembersMessage("");
    initializedGroupEdit.current = "";
    setAdminActionMessage("");
    navigate(`${TAB_PATHS.groups}/new`);
  }

  async function openEditGroup(group: Group) {
    const loadId = ++groupMemberLoadId.current;
    setGroupName(group.name);
    setGroupDisplayName(group.display_name);
    setGroupClaims((group.claims ?? []).map((claim) => ({
      claim_name: claim.claim_name,
      claim_value: JSON.stringify(claim.claim_value) ?? "null",
      required_scope: claim.required_scope,
    })));
    initializedGroupEdit.current = group.id;
    setGroupMemberSelection([]);
    setGroupMemberSearch("");
    setGroupMembersReady(false);
    setGroupMembersError("");
    setGroupMembersMessage("");
    setGroupMembersLoading(true);
    setAdminActionMessage("");
    navigate(`${TAB_PATHS.groups}/${encodeURIComponent(group.id)}/edit`);
    try {
      const userList = await api<AdminUser[]>("/api/admin/users");
      if (groupMemberLoadId.current !== loadId) return;
      setUsers(userList);
      setGroupMemberSelection(userList.filter((user) => user.groups.includes(group.name)).map((user) => user.id));
      setGroupMembersReady(true);
    } catch (loadError) {
      if (groupMemberLoadId.current === loadId) setGroupMembersError(errorMessage(loadError, "load group members"));
    } finally {
      if (groupMemberLoadId.current === loadId) setGroupMembersLoading(false);
    }
  }

  function closeGroupForm() {
    groupMemberLoadId.current += 1;
    setGroupMemberSelection([]);
    setGroupMemberSearch("");
    setGroupMembersReady(false);
    setGroupMembersError("");
    setGroupMembersMessage("");
    initializedGroupEdit.current = "";
    setAdminActionMessage("");
    navigate(TAB_PATHS.groups);
  }

  async function openEditUser(user: AdminUser, returnToGroup = false) {
    setEditingUser(user);
    setUserClaimDrafts([]);
    setUserClaimsLoading(true);
    setUserClaimsReady(false);
    setUserEditorError("");
    setUserEditorMessage("");
    initializedUserEdit.current = user.id;
    navigate(`${TAB_PATHS.users}/${encodeURIComponent(user.id)}/edit`, {
      state: returnToGroup ? { returnToGroup: true, groupId: editingGroupId } : null,
    });
    try {
      const claims = await api<UserClaim[]>(`/api/admin/users/${encodeURIComponent(user.id)}/claims`);
      setUserClaimDrafts(claims.map((claim) => ({
        claim_name: claim.claim_name,
        claim_value: JSON.stringify(claim.claim_value) ?? "null",
        required_scope: claim.required_scope ?? "",
      })));
      setUserClaimsReady(true);
    } catch (loadError) {
      setUserEditorError(errorMessage(loadError, "load user claims"));
    } finally {
      setUserClaimsLoading(false);
    }
  }

  function closeUserEditor() {
    setEditingUser(null);
    setUserClaimDrafts([]);
    setUserClaimsLoading(false);
    setUserClaimsReady(false);
    setUserEditorError("");
    setUserEditorMessage("");
    initializedUserEdit.current = "";
    navigate(userClaimsReturnGroup && userClaimsReturnGroupId
      ? `${TAB_PATHS.groups}/${encodeURIComponent(userClaimsReturnGroupId)}/edit`
      : TAB_PATHS.users);
  }

  async function removeUser(user: AdminUser) {
    const label = user.display_name || user.username;
    const confirmed = window.confirm(`Permanently remove ${label}? This deletes the account, passkeys, active sessions, group memberships, OIDC consents, tokens, and custom claims. This action cannot be undone.`);
    if (!confirmed) return;

    setDeletingUserId(user.id);
    setUserEditorError("");
    try {
      await api(`/api/admin/users/${encodeURIComponent(user.id)}`, { method: "DELETE" });
      setUsers((current) => current.filter((item) => item.id !== user.id));
      setGroupMemberSelection((current) => current.filter((id) => id !== user.id));
      closeUserEditor();
    } catch (removeError) {
      setUserEditorError(errorMessage(removeError, "remove user"));
    } finally {
      setDeletingUserId("");
    }
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
      setUserEditorError(errorMessage(saveError, "save user claims"));
    } finally {
      setUserClaimsBusy(false);
    }
  }

  function toggleGroupMember(value: string) {
    setGroupMembersMessage("");
    setGroupMemberSelection((current) => current.includes(value)
      ? current.filter((item) => item !== value)
      : [...current, value]);
  }

  async function saveGroupMembers(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingGroupId) return;
    setGroupMembersBusy(true);
    setGroupMembersError("");
    setGroupMembersMessage("");
    try {
      await api(`/api/admin/groups/${encodeURIComponent(editingGroupId)}/members`, {
        method: "PUT",
        body: json({ users: groupMemberSelection }),
      });
      const [userList, groupList] = await Promise.all([
        api<AdminUser[]>("/api/admin/users"),
        api<Group[]>("/api/admin/groups"),
      ]);
      setUsers(userList);
      setGroups(groupList);
      setGroupMembersReady(true);
      setGroupMembersMessage("Members saved.");
    } catch (saveError) {
      setGroupMembersError(errorMessage(saveError, "save group members"));
    } finally {
      setGroupMembersBusy(false);
    }
  }

  async function saveClient(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const redirects = splitLines(redirectUris);
    if (redirects.length === 0) {
      logUiIssue("save OIDC client", new Error("At least one callback URL is required"));
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
      navigate(TAB_PATHS.clients);
      await refreshClients();
    } catch (saveError) {
      setError(errorMessage(saveError, "save OIDC client"));
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
      setError(errorMessage(removeError, "remove OIDC client"));
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
      setInvitationMaxUses("1");
      setInvitationExpiry("15");
      setInvitationExpiryUnit("minutes");
      setUserGroups([]);
      setInvitations(await api<Invitation[]>("/api/admin/invitations"));
    } catch (createError) {
      setAdminActionMessage(errorMessage(createError, "create invitation"));
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function removeInvitation(invitation: Invitation) {
    const confirmed = window.confirm("Remove this invite? This permanently deletes the invite link and makes it unusable.");
    if (!confirmed) return;
    setAdminActionBusy(true);
    setAdminActionMessage("");
    try {
      await api(`/api/admin/invitations/${encodeURIComponent(invitation.id)}`, { method: "DELETE" });
      setInvitations(await api<Invitation[]>("/api/admin/invitations"));
    } catch (removeError) {
      setAdminActionMessage(errorMessage(removeError, "remove invitation"));
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
      logUiIssue("save group", new Error("Group claim value is not valid JSON"));
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
      navigate(TAB_PATHS.groups);
    } catch (saveError) {
      setAdminActionMessage(errorMessage(saveError, "save group"));
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
      setGroups((current) => current.filter((item) => item.id !== group.id));
      setUsers((current) => current.map((user) => ({
        ...user,
        groups: user.groups.filter((name) => name !== group.name),
      })));
      setUserGroups((current) => current.filter((name) => name !== group.name));
    } catch (deleteError) {
      setAdminActionMessage(errorMessage(deleteError, "delete group"));
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
      setAdminActionMessage(errorMessage(rotateError, "rotate signing key"));
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function addPasskey() {
    setAddingPasskey(true);
    setPasskeyAddStage("confirming");
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
      setPasskeyAddStage("creating");
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
    } catch (cause) {
      setPasskeyError(errorMessage(cause, "add passkey"));
    } finally {
      setAddingPasskey(false);
      setPasskeyAddStage("confirming");
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
      setPasskeyError(errorMessage(renameError, "rename passkey"));
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
      setPasskeyError(errorMessage(removeError, "remove passkey"));
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
      setHankoMessage(errorMessage(saveError, "save personal Hanko"));
    } finally {
      setSavingHanko(false);
    }
  }

  async function saveOidcProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const missing = missingProfileClaims(profileDraft, requiredUserClaims);
    if (missing.length) {
      setOidcProfileMessage(`Complete the required fields: ${missing.join(", ")}.`);
      return;
    }
    setSavingOidcProfile(true);
    setOidcProfileMessage("");
    try {
      const profile = await api<SavedProfile>("/api/account/profile", {
        method: "PUT",
        body: json(buildProfilePayload(profileDraft, requiredUserClaims)),
      });
      setSessionsRevoked(profile.sessions_revoked);
      setProfileDraft(createProfileDraft({
        username: profile.username ?? "", displayName: profile.display_name ?? "",
        pictureUrl: profile.picture ?? "", phoneNumber: profile.phone_number ?? "",
        address: profile.address ?? undefined, profileClaims: profile.profile_claims,
      }));
      setOidcProfileMessage("Your OIDC profile is saved.");
    } catch (saveError) {
      setOidcProfileMessage(errorMessage(saveError, "save OIDC profile"));
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

  function resetTabState() {
    setAdminActionMessage("");
    setLoadError("");
    groupMemberLoadId.current += 1;
    setEditingUser(null);
    setUserClaimDrafts([]);
    setUserClaimsLoading(false);
    setUserClaimsReady(false);
    setUserEditorError("");
    setUserEditorMessage("");
    setError("");
    initializedUserEdit.current = "";
    initializedClientEdit.current = "";
    initializedGroupEdit.current = "";
    setGroupMembersReady(false);
    setGroupMembersError("");
    setGroupMembersMessage("");
  }

  function selectTab(tab: Tab) {
    resetTabState();
    navigate(TAB_PATHS[tab]);
  }

  async function logout() {
    setLoggingOut(true);
    setLogoutError("");
    try {
      await api("/logout", { method: "POST", body: json({}) });
      window.location.assign(appPath());
    } catch (cause) {
      setLogoutError(errorMessage(cause, "log out"));
      setLoggingOut(false);
    }
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
    { id: "consents", label: "Applications", icon: <ShieldCheck aria-hidden="true" /> },
  ];
  const tabTitles: Record<Tab, [string, string]> = {
    clients: ["OIDC clients", "Connect applications to Hanko."],
    users: ["Users", "Create invite links, review accounts, and manage custom claims."],
    groups: ["Groups", "Manage memberships, scoped claims, and OIDC client access."],
    keys: ["Signing keys", "Manage the keys used to sign tokens."],
    hanko: ["Your profile", "Manage the details shared with apps and your personal Hanko."],
    passkeys: ["Passkeys", "Manage the devices that can sign in to your account."],
    consents: ["Authorized applications", "Review the access you have granted and revoke it at any time."],
  };
  const [tabTitle, tabDescription] = tabTitles[activeTab];
  const clientBeingEdited = clients.find((client) => client.client_id === editingClientId) ?? null;
  const normalizedGroupMemberSearch = groupMemberSearch.trim().toLocaleLowerCase();
  const filteredGroupMembers = users.filter((user) => [user.display_name, user.username, user.email ?? "", user.invitation_label ?? ""]
    .some((value) => value.toLocaleLowerCase().includes(normalizedGroupMemberSearch)));

  useEffect(() => {
    if (clientFormMode !== "edit" || !editingClientId) {
      initializedClientEdit.current = "";
      return;
    }
    if (initializedClientEdit.current === editingClientId || !clientBeingEdited) return;
    setName(clientBeingEdited.name);
    setTokenAuthMethod(clientBeingEdited.token_endpoint_auth_method);
    setPkcePolicy(clientBeingEdited.pkce_policy);
    setClientEnabled(clientBeingEdited.enabled);
    setRedirectUris(clientBeingEdited.redirect_uris.join("\n"));
    setLogoutUris(clientBeingEdited.post_logout_redirect_uris.join("\n"));
    setScopes(clientBeingEdited.scopes);
    setAllowedGroups(clientBeingEdited.allowed_groups);
    setClaims(clientBeingEdited.claims.map((claim) => ({
      claim_name: claim.claim_name,
      user_attribute_path: claim.user_attribute_path,
      required_scope: claim.required_scope ?? "",
    })));
    initializedClientEdit.current = editingClientId;
  }, [clientBeingEdited, clientFormMode, editingClientId]);

  useEffect(() => {
    if (!editingGroupId) {
      if (!userClaimsReturnGroup) initializedGroupEdit.current = "";
      return;
    }
    if (initializedGroupEdit.current === editingGroupId) return;
    const group = groups.find((candidate) => candidate.id === editingGroupId);
    if (!group) return;
    setGroupName(group.name);
    setGroupDisplayName(group.display_name);
    setGroupClaims((group.claims ?? []).map((claim) => ({
      claim_name: claim.claim_name,
      claim_value: JSON.stringify(claim.claim_value) ?? "null",
      required_scope: claim.required_scope,
    })));
    initializedGroupEdit.current = editingGroupId;
    const loadId = ++groupMemberLoadId.current;
    setGroupMemberSelection([]);
    setGroupMemberSearch("");
    setGroupMembersReady(false);
    setGroupMembersError("");
    setGroupMembersMessage("");
    setGroupMembersLoading(true);
    void api<AdminUser[]>("/api/admin/users").then((userList) => {
      if (groupMemberLoadId.current !== loadId) return;
      setUsers(userList);
      setGroupMemberSelection(userList.filter((user) => user.groups.includes(group.name)).map((user) => user.id));
      setGroupMembersReady(true);
    }).catch((loadError) => {
      if (groupMemberLoadId.current === loadId) setGroupMembersError(errorMessage(loadError, "load group members"));
    }).finally(() => {
      if (groupMemberLoadId.current === loadId) setGroupMembersLoading(false);
    });
  }, [editingGroupId, groups]);

  useEffect(() => {
    if (!route.userId) {
      initializedUserEdit.current = "";
      setEditingUser(null);
      setUserClaimDrafts([]);
      setUserClaimsLoading(false);
      setUserClaimsReady(false);
      setUserEditorError("");
      setUserEditorMessage("");
      return;
    }
    if (initializedUserEdit.current === route.userId) return;
    const user = users.find((candidate) => candidate.id === route.userId);
    if (!user) return;

    initializedUserEdit.current = route.userId;
    setEditingUser(user);
    setUserClaimDrafts([]);
    setUserClaimsLoading(true);
    setUserClaimsReady(false);
    setUserEditorError("");
    setUserEditorMessage("");
    let active = true;
    void api<UserClaim[]>(`/api/admin/users/${encodeURIComponent(user.id)}/claims`).then((claims) => {
      if (!active) return;
      setUserClaimDrafts(claims.map((claim) => ({
        claim_name: claim.claim_name,
        claim_value: JSON.stringify(claim.claim_value) ?? "null",
        required_scope: claim.required_scope ?? "",
      })));
      setUserClaimsReady(true);
    }).catch((loadError) => {
      if (active) setUserEditorError(errorMessage(loadError, "load user claims"));
    }).finally(() => {
      if (active) setUserClaimsLoading(false);
    });
    return () => { active = false; };
  }, [location.state, route.userId, users]);
  const title = activeTab === "clients" && clientFormMode !== null
    ? clientFormMode === "edit" ? "Edit OIDC client" : "Add an OIDC client"
    : activeTab === "users" && editingUser ? "Edit user"
      : activeTab === "users" && userFormOpen ? "Invite a user"
      : activeTab === "groups" && groupFormOpen ? editingGroupId ? "Edit a group" : "Create a group" : tabTitle;
  const description = activeTab === "clients" && clientFormMode !== null
    ? "Configure how this application connects to Hanko."
      : activeTab === "users" && editingUser ? userClaimsReturnGroup ? "Manage this member’s custom claims."
        : "Review account details and manage this user’s custom claims."
      : activeTab === "users" && userFormOpen ? "Create an invitation for someone to set up an account."
      : activeTab === "groups" && groupFormOpen ? "Set group details, membership, and claims shared with its members." : tabDescription;

  if (sessionsRevoked) {
    return <AdminScene><section className="account-oidc-profile" role="status">
      <h1>Your profile is saved</h1>
      <p>Your account’s security policy signed you out of all Hanko sessions after this change.</p>
      <a className="primary-action" href={appPath("account")}>Sign in again</a>
    </section></AdminScene>;
  }

  return <AdminScene>
    <div className="admin-layout">
      <nav className="admin-nav" aria-label="Account and administration">
        <label className="admin-mobile-select"><span>Section</span><select value={activeTab} onChange={(event) => selectTab(event.target.value as Tab)}>
          {isAdmin && <optgroup label="Administration">{tabs.filter((tab) => ["clients", "users", "groups", "keys"].includes(tab.id)).map((tab) => <option key={tab.id} value={tab.id}>{tab.label}</option>)}</optgroup>}
          <optgroup label="Account">{tabs.filter((tab) => tab.id === "hanko" || tab.id === "passkeys" || tab.id === "consents").map((tab) => <option key={tab.id} value={tab.id}>{tab.label}</option>)}</optgroup>
        </select></label>
        {isAdmin && <div className="admin-nav-group">
          <p>Administration</p>
          {tabs.filter((tab) => ["clients", "users", "groups", "keys"].includes(tab.id)).map((tab) => <NavLink key={tab.id} to={TAB_PATHS[tab.id]} className="admin-nav-tab" onClick={resetTabState}>{tab.icon}<span>{tab.label}</span></NavLink>)}
        </div>}
        <div className="admin-nav-group admin-nav-account">
          <p>Account</p>
          {tabs.filter((tab) => tab.id === "hanko" || tab.id === "passkeys" || tab.id === "consents").map((tab) => <NavLink key={tab.id} to={TAB_PATHS[tab.id]} className="admin-nav-tab" onClick={resetTabState}>{tab.icon}<span>{tab.label}</span></NavLink>)}
        </div>
        <div className="admin-nav-actions">
          <button className="admin-nav-tab admin-nav-logout" type="button" onClick={() => void logout()} disabled={loggingOut}>
            <LogOut aria-hidden="true" /><span>{loggingOut ? "Logging out…" : "Log out"}</span>
          </button>
          {logoutError && <p className="admin-message admin-message-error" role="alert">{logoutError}</p>}
        </div>
      </nav>

      <section className="admin-content" aria-labelledby="admin-page-title">
        <header className="admin-heading">
          {(activeTab === "clients" && clientFormMode !== null) && <button className="admin-back-action" type="button" onClick={closeClientForm}>← Back to clients</button>}
          {(activeTab === "users" && (userFormOpen || editingUser)) && <button className="admin-back-action" type="button" onClick={editingUser ? closeUserEditor : closeUserForm}>{editingUser && userClaimsReturnGroup ? "← Back to group" : "← Back to users"}</button>}
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
        {clientFormMode === "create" && <div className="client-logo-link">
          <img src={appPath("hanko.png")} alt="" />
          <div className="client-logo-link-content">
            <div><strong>Hanko logo</strong><p>Use this public PNG URL when an application asks for a logo.</p></div>
            <Credential label="Logo URL" value={hankoLogoUrl} copied={copied === "logo"} onCopy={() => copyValue("logo", hankoLogoUrl)} />
          </div>
        </div>}
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
                    <td><button className="invitation-remove" type="button" onClick={() => removeInvitation(invitation)} disabled={adminActionBusy}>Remove</button></td>
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
              <fieldset className="admin-options admin-claims" disabled={Boolean(deletingUserId)}>
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
              <div className="client-form-actions"><button className="primary-action client-submit" type="submit" disabled={userClaimsBusy || userClaimsLoading || !userClaimsReady || Boolean(deletingUserId)}>{userClaimsBusy ? "Saving…" : "Save custom claims"}</button><button className="client-list-action" type="button" disabled={userClaimsBusy || Boolean(deletingUserId)} onClick={closeUserEditor}>Cancel</button></div>
            </form>
            <section className="client-danger-zone user-danger-zone" aria-labelledby="user-remove-title">
              <h2 id="user-remove-title">Remove user</h2>
              <p>Permanently delete this account, including its passkeys, active sessions, group memberships, OIDC consents, tokens, and custom claims.</p>
              <button className="client-list-action client-remove-action" type="button" disabled={userClaimsBusy || Boolean(deletingUserId)} onClick={() => void removeUser(editingUser)}><Trash2 aria-hidden="true" />{deletingUserId === editingUser.id ? "Removing…" : "Remove user"}</button>
            </section>
          </section>}

          {activeTab === "users" && isAdmin && userFormOpen && <>
      {createdInvitation ? <section className="created-client" role="status"><div className="created-title"><span><Check aria-hidden="true" /></span><div><h2>Invite link ready</h2><p>Anyone with this link can join until it expires or reaches its user limit.</p></div></div><Credential label={<>Invite link · <PrivateValue>{createdInvitation.label}</PrivateValue></>} value={createdInvitation.enrollment_url} copied={copied === "invitation"} onCopy={() => copyValue("invitation", createdInvitation.enrollment_url)} />{createdInvitation.email && <a className="secondary-action invitation-email-action" href={invitationEmailHref(createdInvitation)}><Mail aria-hidden="true" />Email this invite</a>}<p className="created-footnote">Expires {new Date(createdInvitation.expires_at * 1000).toLocaleString()}. The link is shown only now, so copy it before leaving this page.</p><button className="client-list-action create-another-invite" type="button" onClick={openCreateUser}><Plus aria-hidden="true" /> Create another invite</button></section> : <form className="client-form admin-create-form user-create-page" onSubmit={createInvitation}>
              <label className="admin-field"><span>Admin-only user label</span><input autoComplete="off" maxLength={80} value={invitationLabel} onChange={(event) => setInvitationLabel(event.target.value)} placeholder="Community event" required /><small>This label appears only in the administrator’s user list.</small></label>
              <label className="admin-field"><span>Email recipient <em>Optional</em></span><input type="email" autoComplete="email" maxLength={320} value={invitationEmail} onChange={(event) => { setInvitationEmail(event.target.value); setInvitationMaxUses("1"); }} placeholder="person@example.com" /><small>Add an address to make this a one-use email invitation. You can open a prefilled email after creating it.</small></label>
              <div className="invitation-settings">
                <label className="admin-field"><span>User limit</span><input type="number" min={1} max={500} value={invitationMaxUses} onChange={(event) => setInvitationMaxUses(event.target.value)} disabled={Boolean(invitationEmail.trim())} required /><small>{invitationEmail.trim() ? "Email invitations are limited to one user." : "How many accounts can use this link?"}</small></label>
                <div className="invitation-expiry-setting"><div className="invitation-expiry-fields"><label className="admin-field"><span>Link expires in</span><input type="number" min={1} max={Math.floor((10 * 365 * 24 * 60 * 60) / EXPIRY_UNIT_SECONDS[invitationExpiryUnit])} value={invitationExpiry} onChange={(event) => setInvitationExpiry(event.target.value)} required /></label><label className="admin-field"><span>Unit</span><select value={invitationExpiryUnit} onChange={(event) => setInvitationExpiryUnit(event.target.value as ExpiryUnit)}><option value="seconds">Seconds</option><option value="minutes">Minutes</option><option value="hours">Hours</option><option value="days">Days</option><option value="years">Years</option></select></label></div><small>Up to 10 years.</small></div>
              </div>
              {groups.length > 0 && <fieldset className="admin-options"><legend>Groups <em>Optional</em></legend><div className="admin-choice-grid">{groups.map((group) => <label className="admin-check" key={group.id}><input type="checkbox" checked={userGroups.includes(group.name)} onChange={() => setUserGroups((current) => current.includes(group.name) ? current.filter((name) => name !== group.name) : [...current, group.name])} /><span><strong><PrivateValue>{group.display_name}</PrivateValue></strong></span></label>)}</div></fieldset>}
              {adminActionMessage && <p className="admin-message admin-message-error" role="alert">{adminActionMessage}</p>}
              <div className="client-form-actions"><button className="primary-action client-submit" type="submit" disabled={adminActionBusy || !invitationLabel.trim() || (!invitationEmail.trim() && (!Number(invitationMaxUses) || Number(invitationMaxUses) > 500))}>{adminActionBusy ? "Creating link…" : "Create invite link"}</button><button className="client-list-action" type="button" disabled={adminActionBusy} onClick={closeUserForm}>Cancel</button></div>
            </form>}
          </>}

          {activeTab === "groups" && isAdmin && groupFormOpen && <section className="group-edit-page">
            <form className="client-form admin-create-form user-create-page" onSubmit={createGroup}>
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
            </form>
            {editingGroupId && <section className="group-members-panel" aria-labelledby="group-members-heading">
              <div className="group-members-toolbar">
                <div>
                  <h2 id="group-members-heading">Members <span>{groupMemberSelection.length}</span></h2>
                  <p>Choose who belongs to this group. Changes take effect in newly issued tokens.</p>
                </div>
                <label className="admin-field group-member-search"><span>Search users</span><input type="search" value={groupMemberSearch} onChange={(event) => setGroupMemberSearch(event.target.value)} placeholder="Name, username, or email" disabled={groupMembersLoading || groupMembersBusy} /></label>
              </div>
              {groupMembersError && <p className="admin-message admin-message-error" role="alert">{groupMembersError}</p>}
              {groupMembersMessage && <p className="admin-message" role="status">{groupMembersMessage}</p>}
              {groupMembersLoading ? <p className="admin-hint">Loading users…</p> : users.length === 0 ? <p className="admin-hint">No user accounts are available.</p> : filteredGroupMembers.length === 0 ? <p className="admin-hint">No users match “{groupMemberSearch.trim()}”.</p> : <div className="admin-table-scroll group-member-table-scroll"><table className="admin-table group-member-table">
                <thead><tr><th scope="col">Member</th><th scope="col">User</th><th scope="col">Username</th><th scope="col">Email</th><th scope="col">Status</th><th scope="col">Claims</th></tr></thead>
                <tbody>{filteredGroupMembers.map((user) => <tr key={user.id}>
                  <td><label className="group-member-toggle"><input type="checkbox" aria-label={`Toggle ${user.display_name || user.username} in ${groupDisplayName}`} checked={groupMemberSelection.includes(user.id)} onChange={() => toggleGroupMember(user.id)} disabled={groupMembersBusy} /></label></td>
                  <td><strong><PrivateValue>{user.display_name || user.username}</PrivateValue></strong>{user.invitation_label && <small><PrivateValue>{user.invitation_label}</PrivateValue></small>}</td>
                  <td><code className="table-id"><PrivateValue>{user.username}</PrivateValue></code></td>
                  <td>{user.email ? <PrivateValue>{user.email}</PrivateValue> : <span className="table-muted">—</span>}</td>
                  <td><span className={`client-status${user.disabled ? " disabled" : ""}`}>{user.disabled ? "Disabled" : user.is_admin ? "Administrator" : "Active"}</span></td>
                  <td><button className="client-list-action membership-action" type="button" onClick={() => void openEditUser(user, true)} disabled={userClaimsLoading || userClaimsBusy || groupMembersBusy}><Pencil aria-hidden="true" />Edit claims</button></td>
                </tr>)}</tbody>
              </table></div>}
              <form className="group-members-actions" onSubmit={saveGroupMembers}>
                <p className="admin-hint">{groupMemberSelection.length} {groupMemberSelection.length === 1 ? "user is" : "users are"} selected. Per-user claims can override claims set above.</p>
                <button className="primary-action client-submit" type="submit" disabled={groupMembersBusy || groupMembersLoading || !groupMembersReady}>{groupMembersBusy ? "Saving members…" : "Save members"}</button>
              </form>
            </section>}
          </section>}

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
                  <td><div className="table-actions"><button className="client-list-action" type="button" disabled={adminActionBusy} onClick={() => void openEditGroup(group)}><Pencil aria-hidden="true" /><span>Edit</span></button><button className="client-list-action client-remove-action" type="button" disabled={adminActionBusy} onClick={() => void deleteGroup(group)}><Trash2 aria-hidden="true" /><span>{deletingGroupId === group.id ? "Deleting…" : "Delete"}</span></button></div></td>
                </tr>
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
              <ProfileFields value={profileDraft} onChange={setProfileDraft} requiredUserClaims={requiredUserClaims} />
              {oidcProfileMessage && <p className={`admin-message${oidcProfileMessage.includes("saved") ? "" : " admin-message-error"}`} role={oidcProfileMessage.includes("saved") ? "status" : "alert"}>{oidcProfileMessage}</p>}
              <div className="client-form-actions"><button className="primary-action client-submit" type="submit" disabled={savingOidcProfile}>{savingOidcProfile ? "Saving profile…" : "Save OIDC profile"}</button></div>
            </form>
          </section>}

          {activeTab === "consents" && <section className="account-consents" aria-labelledby="consent-list-title">
            <div className="client-list-heading"><h2 id="consent-list-title">Authorized applications <span>{consents.length}</span></h2></div>
            <p className="admin-hint">Consent expiry means the application must ask again on your next sign-in. Offline access can continue after consent expires. Revoke access to disable its refresh tokens and require consent again; already issued access tokens remain valid until they expire.</p>
            {consentMessage && <p className="admin-message" role="status">{consentMessage}</p>}
            {consentError && <p className="admin-message admin-message-error" role="alert">{consentError}</p>}
            {consentsLoading ? <p className="admin-hint">Loading authorized applications…</p> : consents.length === 0 ? <p className="admin-hint">You haven’t authorized any applications.</p> : <div className="admin-table-scroll"><table className="admin-table consent-table">
              <thead><tr><th scope="col">Application</th><th scope="col">Authorized</th><th scope="col">Consent expires</th><th scope="col">Granted scopes</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>{consents.map((grant) => <tr key={grant.client_id}>
                <td><strong>{grant.client_name}</strong><small><code className="table-id"><PrivateValue>{grant.client_id}</PrivateValue></code></small></td>
                <td><PrivateValue>{new Date(grant.granted_at * 1000).toLocaleDateString()}</PrivateValue></td>
                <td>{grant.expires_at ? <PrivateValue>{new Date(grant.expires_at * 1000).toLocaleString()}{grant.expires_at <= Date.now() / 1000 ? " (expired)" : ""}</PrivateValue> : <span className="table-muted">No expiry</span>}</td>
                <td><div className="client-scope-list" aria-label={`Granted scopes: ${grant.scopes.join(", ")}`}>{grant.scopes.map((scope) => <span className="client-scope-chip" key={scope}>{scope}</span>)}</div></td>
                <td><div className="table-actions"><button className="client-list-action client-remove-action" type="button" onClick={() => void revokeConsent(grant)} disabled={Boolean(consentActionId)}><Trash2 aria-hidden="true" />{consentActionId === grant.client_id ? "Revoking…" : "Revoke access"}</button></div></td>
              </tr>)}</tbody>
            </table></div>}
          </section>}

          {activeTab === "passkeys" && <section className="account-passkeys">
            <section className="passkey-list" aria-labelledby="passkey-list-title">
              <div className="client-list-heading"><h2 id="passkey-list-title">Registered devices <span>{passkeys.length}</span></h2><button className="client-add-action" type="button" onClick={() => void addPasskey()} disabled={addingPasskey}><Plus aria-hidden="true" /> {addingPasskey ? passkeyAddStage === "confirming" ? "Confirm with an existing passkey…" : "Create a new passkey…" : "Add passkey"}</button></div>
              <p className="admin-hint">Adding a passkey takes two prompts: first, use an existing passkey to confirm it’s you. Then register the new passkey when your device prompts again.</p>
              {!allowMultiplePasskeysPerAuthenticator && <p className="passkey-policy-warning" role="status">This Hanko server prevents registering another passkey with an authenticator that already has one for this account. Use a different authenticator, or enable WEBAUTHN_ALLOW_MULTIPLE_PASSKEYS_PER_AUTHENTICATOR and restart Hanko.</p>}
              {accountName && <p className="admin-hint">Sign-in account name: <PrivateValue>{accountName}</PrivateValue>. Save this name in case an older passkey needs account-specific sign-in.</p>}
              {passkeys.length < 2 && !passkeysLoading && <p className="admin-hint">Add a second passkey stored independently, then test signing in with it in a separate browser session.</p>}
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
