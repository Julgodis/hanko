import { InvitationEditor } from "./admin/InvitationEditor";
import { GroupEditor } from "./admin/GroupEditor";
import { ClientEditor } from "./admin/ClientEditor";
import { UserEditor } from "./admin/UserEditor";
import { Credential } from "./admin/Credential";
import type { Session, Client, Group, AdminUser, Invitation, SigningKey, AccountPasskey, ConsentGrant, CreatedClient, RegistrationStart, AuthenticationStart, CredentialChangeApproval } from "./lib/apiTypes";
import { Check, Fingerprint, KeyRound, LogOut, Pencil, Plus, Shield, ShieldCheck, Users, UserRound, Stamp, Trash2 } from "lucide-react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { Fragment, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { HankoSeal } from "./components/HankoSeal";
import { PrivateValue } from "./components/PrivacyMode";
import { SealCustomizer } from "./components/SealCustomizer";
import { ORIGINAL_HANKO_GRADIENT } from "./components/generateHankoPath";
import { api, appPath, errorMessage, defaultPasskeyLabel, json } from "./lib/utils";
import { loadDashboardTab, type DashboardTab } from "./lib/dashboard";
import { ProfileFields } from "./components/ProfileFields";
import { buildProfilePayload, createProfileDraft, missingProfileClaims, type SavedProfile } from "./lib/profile";

type Tab = DashboardTab;
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

function invitationStatus(invitation: Invitation) {
  if (invitation.revoked) return "Revoked";
  if (invitation.expires_at <= Date.now() / 1000) return "Expired";
  if (invitation.use_count >= invitation.max_uses) return "Limit reached";
  return "Active";
}

function formatBuildDate(value: string | undefined) {
  if (!value || value === "unknown") return "Unknown";
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? value
    : date.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZoneName: "short" });
}

export default function ClientAdmin({ isAdmin = true, defaultTab, accountName = "", requiredUserClaims = [], session }: { isAdmin?: boolean; defaultTab?: Tab; accountName?: string; requiredUserClaims?: string[]; session: Session }) {
  const location = useLocation();
  const navigate = useNavigate();
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
  const [usersRevision, setUsersRevision] = useState(0);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const editingUser = users.find(user => user.id === route.userId) ?? null;
  const [signingKeys, setSigningKeys] = useState<SigningKey[]>([]);
  const [tabLoading, setTabLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [sessionsRevoked, setSessionsRevoked] = useState(false);
  const [error, setError] = useState("");
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState("");
  const clientFormMode = previewScreen === "client-form" ? "create" : route.clientFormMode;
  const [credentialsUpdated, setCredentialsUpdated] = useState(false);
  const userFormOpen = previewScreen === "invite" || previewScreen === "invite-ready" || route.userFormOpen;
  const groupFormOpen = route.groupFormOpen;
  const editingGroupId = route.groupId || (userClaimsReturnGroup ? userClaimsReturnGroupId : "");
  const groupBeingEdited = groups.find(group => group.id === editingGroupId) ?? null;
  const editingClientId = route.clientId;
  const [created, setCreated] = useState<CreatedClient | null>(null);
  const [copied, setCopied] = useState("");
  const [addingPasskey, setAddingPasskey] = useState(false);
  const [passkeyAddStage, setPasskeyAddStage] = useState<"confirming" | "creating">("confirming");
  const [passkeyError, setPasskeyError] = useState("");
  const [passkeyMessage, setPasskeyMessage] = useState("");
  const [passkeyMessageWarning, setPasskeyMessageWarning] = useState(false);
  const [passkeys, setPasskeys] = useState<AccountPasskey[]>([]);
  const allowMultiplePasskeysPerAuthenticator = session.allow_multiple_passkeys_per_authenticator ?? true;
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
  const [hankoColor, setHankoColor] = useState(() => session.hanko_color ? (session.hanko_color === "#d64135" ? ORIGINAL_HANKO_GRADIENT : session.hanko_color) : ORIGINAL_HANKO_GRADIENT);
  const [hankoSeed, setHankoSeed] = useState(() => session.hanko_seed ?? "hanko");
  const [savingHanko, setSavingHanko] = useState(false);
  const [hankoMessage, setHankoMessage] = useState("");
  const [profileDraft, setProfileDraft] = useState(() => createProfileDraft({
    username: session.oidc_username ?? "", displayName: session.oidc_name ?? "",
    pictureUrl: session.oidc_picture ?? "", phoneNumber: session.oidc_phone ?? "",
    address: session.oidc_address ?? undefined, profileClaims: session.oidc_profile_claims ?? undefined,
  }));
  const profileHydrated = session.authenticated;
  const [savingOidcProfile, setSavingOidcProfile] = useState(false);
  const [oidcProfileMessage, setOidcProfileMessage] = useState("");
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [deletingGroupId, setDeletingGroupId] = useState("");
  const [adminActionBusy, setAdminActionBusy] = useState(false);
  const [adminActionMessage, setAdminActionMessage] = useState("");

  useEffect(() => {
    if (!previewScreen && route.canonicalPath !== location.pathname) {
      navigate(route.canonicalPath, { replace: true });
    }
  }, [location.pathname, navigate, previewScreen, route.canonicalPath]);

  function openCreateClient() { setCreated(null); setCredentialsUpdated(false); setError(""); navigate(`${TAB_PATHS.clients}/new`); }
  function openEditClient(client: Client) { setCreated(null); setCredentialsUpdated(false); setError(""); navigate(`${TAB_PATHS.clients}/${encodeURIComponent(client.client_id)}/edit`); }
  function closeClientForm() { setError(""); navigate(TAB_PATHS.clients); }

  function openCreateGroup() { navigate(`${TAB_PATHS.groups}/new`); }
  function openEditGroup(group: Group) { navigate(`${TAB_PATHS.groups}/${encodeURIComponent(group.id)}/edit`); }
  function closeGroupForm() { navigate(TAB_PATHS.groups); }

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
    async function loadTabData() {
      setTabLoading(true);
      setLoadError("");
      setPasskeysLoading(activeTab === "passkeys");
      setConsentsLoading(activeTab === "consents");
      try {
        const data = await loadDashboardTab<unknown>(activeTab, isAdmin, path => api(path));
        if (!active) return;
        if (data.clients) setClients(data.clients as Client[]);
        if (data.groups) setGroups(data.groups as Group[]);
        if (data.users) setUsers(data.users as AdminUser[]);
        if (data.invitations) setInvitations(data.invitations as Invitation[]);
        if (data.keys) setSigningKeys(data.keys as SigningKey[]);
        if (data.passkeys) {
          const records = data.passkeys as AccountPasskey[];
          setPasskeys(records);
          setPasskeyDrafts(Object.fromEntries(records.map(passkey => [passkey.id, passkey.label])));
        }
        if (data.consents) setConsents(data.consents as ConsentGrant[]);
      } catch (tabError) {
        if (active) setLoadError(errorMessage(tabError, "load admin tab"));
      } finally {
        if (active) {
          setTabLoading(false);
          setPasskeysLoading(false);
          setConsentsLoading(false);
        }
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

  function openCreateUser() { navigate(`${TAB_PATHS.users}/invite`); }

  function closeUserForm() {
    setAdminActionMessage("");
    navigate(TAB_PATHS.users);
  }

  function openEditUser(user: AdminUser, returnToGroup = false) {
    navigate(`${TAB_PATHS.users}/${encodeURIComponent(user.id)}/edit`, {
      state: returnToGroup ? { returnToGroup: true, groupId: editingGroupId } : null,
    });
  }

  function closeUserEditor() {
    navigate(userClaimsReturnGroup && userClaimsReturnGroupId
      ? `${TAB_PATHS.groups}/${encodeURIComponent(userClaimsReturnGroupId)}/edit`
      : TAB_PATHS.users);
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
    setPasskeyMessageWarning(false);
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
      const verification = await api<{ discoverable?: boolean | null }>("/api/passkeys/register/verify", {
        method: "POST",
        body: json({ ceremony_id: start.ceremony_id, credential, label: defaultPasskeyLabel(new Date()) }),
      });
      await refreshPasskeys();
      setPasskeyMessageWarning(verification.discoverable === false);
      setPasskeyMessage(verification.discoverable === false
        ? "Passkey added. At sign-in, choose ‘Passkey not listed? Use account name’ and enter your username or email."
        : "Passkey added to this account.");
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
    if (!profileHydrated || savingOidcProfile) return;
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
    setError("");
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
        {tabLoading ? <div className="admin-loading"><HankoSeal size={42} /><p>Loading…</p></div> : <>
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
              <button className="client-list-action" type="button" onClick={() => openEditClient(client)}><Pencil aria-hidden="true" /><span>Edit</span></button>
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

          {activeTab === "clients" && isAdmin && clientFormMode !== null && (clientFormMode === "create" || clientBeingEdited) && <ClientEditor
            key={editingClientId || "new"} clientBeingEdited={clientBeingEdited} groups={groups} closeClientForm={closeClientForm}
            onSaved={async client => {
              if (clientFormMode === "create" || client.client_secret) { setCreated(client); setCredentialsUpdated(clientFormMode === "edit"); }
              await refreshClients();
              closeClientForm();
            }}
            onDeleted={async () => { await refreshClients(); closeClientForm(); }}
          />}

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
                    <td><button className="client-list-action membership-action" type="button" onClick={() => void openEditUser(user)}><Pencil aria-hidden="true" />Edit user</button></td>
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

          {activeTab === "users" && isAdmin && editingUser && <UserEditor key={editingUser.id} editingUser={editingUser} closeUserEditor={closeUserEditor} onDeleted={id => { setUsers(current => current.filter(user => user.id !== id)); setUsersRevision(value => value + 1); }} />}

          {activeTab === "users" && isAdmin && userFormOpen && <InvitationEditor groups={groups} previewReady={previewScreen === "invite-ready"} closeUserForm={closeUserForm} onCreated={async () => setInvitations(await api<Invitation[]>("/api/admin/invitations"))} />}

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
              {profileHydrated
                ? <fieldset className="account-profile-fieldset" disabled={savingOidcProfile}>
                    <ProfileFields value={profileDraft} onChange={setProfileDraft} requiredUserClaims={requiredUserClaims} />
                  </fieldset>
                : <p className="admin-message admin-message-error" role="alert">Your profile could not be loaded. Reload the page before editing it.</p>}
              {oidcProfileMessage && <p className={`admin-message${oidcProfileMessage.includes("saved") ? "" : " admin-message-error"}`} role={oidcProfileMessage.includes("saved") ? "status" : "alert"}>{oidcProfileMessage}</p>}
              <div className="client-form-actions"><button className="primary-action client-submit" type="submit" disabled={!profileHydrated || savingOidcProfile}>{savingOidcProfile ? "Saving profile…" : "Save OIDC profile"}</button></div>
            </form>
            <section className="account-server-version" aria-labelledby="server-version-title">
              <div className="account-server-version-heading">
                <h2 id="server-version-title">Hanko server</h2>
                <p className="admin-hint">Build currently running on this server.</p>
              </div>
              <dl>
                <div><dt>Version</dt><dd>{session.server?.version ?? "Unknown"}</dd></div>
                <div><dt>Commit</dt><dd><code>{session.server?.commit && session.server.commit !== "unknown" ? session.server.commit.slice(0, 12) : "Unknown"}</code></dd></div>
                <div><dt>Build date</dt><dd>{formatBuildDate(session.server?.build_date)}</dd></div>
              </dl>
            </section>
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
              {passkeyMessage && <p className={`passkey-feedback ${passkeyMessageWarning ? "passkey-feedback-warning" : "passkey-feedback-success"}`} role="status">{passkeyMessage}</p>}{passkeyError && <p className="passkey-feedback passkey-feedback-error" role="alert">{passkeyError}</p>}
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
        {isAdmin && (groupFormOpen || userClaimsReturnGroup) && (!editingGroupId || groupBeingEdited) && <div hidden={activeTab !== "groups" || tabLoading}>
          <GroupEditor key={editingGroupId || "new"} group={groupBeingEdited} usersRevision={usersRevision} closeGroupForm={closeGroupForm}
            onSaved={async () => { setGroups(await api<Group[]>("/api/admin/groups")); closeGroupForm(); }}
            onMembersSaved={setGroups} openEditUser={openEditUser} />
        </div>}
      </section>
    </div>
  </AdminScene>;
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
