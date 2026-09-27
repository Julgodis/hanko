import { Check, Copy, Fingerprint, KeyRound, Pencil, Plus, Shield, Users, UserRound, Stamp, Trash2 } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { HankoSeal } from "./components/HankoSeal";
import { SealCustomizer } from "./components/SealCustomizer";
import { ORIGINAL_HANKO_GRADIENT } from "./components/generateHankoPath";
import { api, json } from "./lib/utils";

const AVAILABLE_SCOPES = ["profile", "email", "groups"] as const;

type Scope = "openid" | (typeof AVAILABLE_SCOPES)[number];
type Client = {
  client_id: string;
  name: string;
  client_type: "public" | "confidential";
  enabled: boolean;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  scopes: Scope[];
  allowed_groups: string[];
  claims: { claim_name: string; user_attribute_path: string; required_scope: string | null }[];
  user_count: number;
};
type Group = { id: string; name: string; display_name: string; member_count: number };
type AdminUser = { id: string; username: string; display_name: string; email: string | null; is_admin: boolean; disabled: boolean; groups: string[] };
type SigningKey = { kid: string; algorithm: string; status: string; created_at: number; retire_after: number | null };
type AccountPasskey = { id: string; label: string; created_at: number; last_used_at: number | null };
type Tab = "clients" | "users" | "groups" | "keys" | "hanko" | "passkeys";
type ClaimDraft = { claim_name: string; user_attribute_path: string; required_scope: string };
type CreatedClient = {
  client_id: string;
  client_secret: string | null;
  name: string;
  client_type: "public" | "confidential";
  scopes: Scope[];
};
type RegistrationStart = {
  ceremony_id: string;
  publicKey: Parameters<typeof startRegistration>[0]["optionsJSON"];
};

function splitLines(value: string) {
  return [...new Set(value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))];
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "The request could not be completed.";
}

export default function ClientAdmin({ isAdmin = true }: { isAdmin?: boolean }) {
  const clientEditorRef = useRef<HTMLElement>(null);
  const [activeTab, setActiveTab] = useState<Tab>(isAdmin ? "clients" : "hanko");
  const [clients, setClients] = useState<Client[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [signingKeys, setSigningKeys] = useState<SigningKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [name, setName] = useState("");
  const [clientType, setClientType] = useState<"public" | "confidential">("public");
  const [clientEnabled, setClientEnabled] = useState(true);
  const [redirectUris, setRedirectUris] = useState("");
  const [logoutUris, setLogoutUris] = useState("");
  const [scopes, setScopes] = useState<Scope[]>(["openid", "profile", "email"]);
  const [allowedGroups, setAllowedGroups] = useState<string[]>([]);
  const [claims, setClaims] = useState<ClaimDraft[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [clientFormMode, setClientFormMode] = useState<"create" | "edit" | null>(null);
  const [editingClientId, setEditingClientId] = useState("");
  const [deletingClientId, setDeletingClientId] = useState("");
  const [created, setCreated] = useState<CreatedClient | null>(null);
  const [copied, setCopied] = useState("");
  const [passkeyLabel, setPasskeyLabel] = useState("");
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
  const [userName, setUserName] = useState("");
  const [userDisplayName, setUserDisplayName] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [userGroups, setUserGroups] = useState<string[]>([]);
  const [createdInvitation, setCreatedInvitation] = useState("");
  const [groupName, setGroupName] = useState("");
  const [groupDisplayName, setGroupDisplayName] = useState("");
  const [adminActionBusy, setAdminActionBusy] = useState(false);
  const [adminActionMessage, setAdminActionMessage] = useState("");

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
        const sessionPromise = api<{ hanko_color?: string; hanko_seed?: string }>("/api/session");
        const [session, clientList, groupList] = isAdmin
          ? await Promise.all([sessionPromise, api<Client[]>("/api/admin/clients"), api<Group[]>("/api/admin/groups")])
          : [await sessionPromise, [], []];
        if (active) {
          setClients(clientList);
          setGroups(groupList);
          if (session.hanko_color) setHankoColor(session.hanko_color === "#d64135" ? ORIGINAL_HANKO_GRADIENT : session.hanko_color);
          if (session.hanko_seed) setHankoSeed(session.hanko_seed);
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
        if (activeTab === "users" && isAdmin) setUsers(await api<AdminUser[]>("/api/admin/users"));
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
    if (clientFormMode !== null) {
      clientEditorRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [clientFormMode]);

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

  function openCreateClient() {
    setName("");
    setClientType("public");
    setClientEnabled(true);
    setRedirectUris("");
    setLogoutUris("");
    setScopes(["openid", "profile", "email"]);
    setAllowedGroups([]);
    setClaims([]);
    setEditingClientId("");
    setCreated(null);
    setError("");
    setClientFormMode("create");
  }

  function openEditClient(client: Client) {
    setName(client.name);
    setClientType(client.client_type);
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
    setError("");
    setClientFormMode("edit");
  }

  function closeClientForm() {
    setClientFormMode(null);
    setEditingClientId("");
    setError("");
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
        ...(clientFormMode === "create"
          ? { client_type: clientType }
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
      if (clientFormMode === "create") setCreated(client);
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
    if (!window.confirm(`Remove “${client.name}”? Its settings and sign-in count will be deleted.`)) return;
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

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAdminActionBusy(true);
    setAdminActionMessage("");
    setCreatedInvitation("");
    try {
      const invitation = await api<{ enrollment_url: string }>("/api/admin/users", {
        method: "POST",
        body: json({
          username: userName.trim(),
          display_name: userDisplayName.trim(),
          email: userEmail.trim() || null,
          attributes: {},
          groups: userGroups,
        }),
      });
      setCreatedInvitation(invitation.enrollment_url);
      setUserName("");
      setUserDisplayName("");
      setUserEmail("");
      setUserGroups([]);
      setUsers(await api<AdminUser[]>("/api/admin/users"));
    } catch (createError) {
      setAdminActionMessage(errorMessage(createError));
    } finally {
      setAdminActionBusy(false);
    }
  }

  async function createGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAdminActionBusy(true);
    setAdminActionMessage("");
    try {
      await api("/api/admin/groups", {
        method: "POST",
        body: json({ name: groupName.trim(), display_name: groupDisplayName.trim() }),
      });
      setGroupName("");
      setGroupDisplayName("");
      setGroups(await api<Group[]>("/api/admin/groups"));
    } catch (createError) {
      setAdminActionMessage(errorMessage(createError));
    } finally {
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

  async function addPasskey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAddingPasskey(true);
    setPasskeyError("");
    setPasskeyMessage("");
    try {
      const start = await api<RegistrationStart>("/api/passkeys/register/options", {
        method: "POST",
        body: json({}),
      });
      const credentialPromise = startRegistration({ optionsJSON: start.publicKey });
      const credential = await credentialPromise;
      await api("/api/passkeys/register/verify", {
        method: "POST",
        body: json({ ceremony_id: start.ceremony_id, credential, label: passkeyLabel.trim() }),
      });
      await refreshPasskeys();
      setPasskeyMessage(`Passkey added${passkeyLabel.trim() ? ` as “${passkeyLabel.trim()}”` : " to this account"}.`);
      setPasskeyLabel("");
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
      setPasskeyMessage(`Passkey renamed to “${label}”.`);
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
      await api(`/api/passkeys/${encodeURIComponent(removeTarget.id)}`, {
        method: "DELETE",
        body: json({ confirmation: removalConfirmation }),
      });
      await refreshPasskeys();
      setRemoveTarget(null);
      setRemovalConfirmation("");
      setPasskeyMessage(`Passkey “${removeTarget.label}” removed.`);
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
    setActiveTab(tab);
  }

  const tabs: { id: Tab; label: string; icon: ReactNode }[] = [
    ...(isAdmin ? [
      { id: "clients" as const, label: "Clients", icon: <KeyRound aria-hidden="true" /> },
      { id: "users" as const, label: "Users", icon: <Users aria-hidden="true" /> },
      { id: "groups" as const, label: "Groups", icon: <UserRound aria-hidden="true" /> },
      { id: "keys" as const, label: "Signing keys", icon: <Shield aria-hidden="true" /> },
    ] : []),
    { id: "hanko", label: "Your Hanko", icon: <Stamp aria-hidden="true" /> },
    { id: "passkeys", label: "Passkeys", icon: <Fingerprint aria-hidden="true" /> },
  ];
  const tabTitles: Record<Tab, [string, string]> = {
    clients: ["OIDC clients", "Connect applications to Hanko."],
    users: ["Users", "Invite people and review their accounts."],
    groups: ["Groups", "Organize access to OIDC clients."],
    keys: ["Signing keys", "Manage the keys used to sign tokens."],
    hanko: ["Your Hanko", "Your personal seal."],
    passkeys: ["Passkeys", "Manage the devices that can sign in to your account."],
  };
  const [title, description] = tabTitles[activeTab];

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
          <h1 id="admin-page-title">{title}</h1>
          <p>{description}</p>
        </header>
        {loadError && <p className="admin-message admin-message-error" role="alert">{loadError}</p>}
        {loading ? <div className="admin-loading"><HankoSeal size={42} /><p>Loading…</p></div> : <>
          {activeTab === "clients" && isAdmin && <>
    <section className="registered-clients">
      <div className="client-list-heading">
        <h2>Registered clients <span>{clients.length}</span></h2>
        {clientFormMode === null && <button className="client-add-action" type="button" onClick={openCreateClient}><Plus aria-hidden="true" /> Add a client</button>}
      </div>
      {error && clientFormMode === null && <p className="admin-message admin-message-error" role="alert">{error}</p>}
      {clients.length === 0
        ? <p className="admin-hint">No clients have been added yet.</p>
        : clients.map((client) => <article className="registered-client" key={client.client_id}>
          <div className="registered-client-title"><h3>{client.name}</h3><span className={client.enabled ? "client-status" : "client-status disabled"}>{client.enabled ? "Enabled" : "Disabled"}</span><span className="client-user-count">{client.user_count ?? 0} {(client.user_count ?? 0) === 1 ? "user" : "users"}</span></div>
          <code className="registered-client-id">{client.client_id}</code>
          <p>{client.client_type === "public" ? "Public client" : "Confidential client"} · {client.scopes.join(", ")} · users who have signed in</p>
          <details><summary>Redirect URLs and access</summary>
            <ul>{client.redirect_uris.map((uri) => <li key={uri}><code>{uri}</code></li>)}</ul>
            {client.post_logout_redirect_uris.length > 0 && <><strong>Post-logout URLs</strong><ul>{client.post_logout_redirect_uris.map((uri) => <li key={uri}><code>{uri}</code></li>)}</ul></>}
            <p>{client.allowed_groups.length ? `Allowed groups: ${client.allowed_groups.join(", ")}` : "Available to all users"}</p>
            {client.claims.length > 0 && <><strong>Custom claims</strong><ul>{client.claims.map((claim) => <li key={claim.claim_name}><code>{claim.claim_name}</code> from <code>{claim.user_attribute_path}</code>{claim.required_scope ? ` · ${claim.required_scope}` : ""}</li>)}</ul></>}
          </details>
          <div className="registered-client-actions">
            <button className="client-list-action" type="button" disabled={busy || deletingClientId !== ""} onClick={() => openEditClient(client)}><Pencil aria-hidden="true" /> Edit</button>
            <button className="client-list-action client-remove-action" type="button" disabled={busy || deletingClientId !== ""} onClick={() => void removeClient(client)}><Trash2 aria-hidden="true" /> {deletingClientId === client.client_id ? "Removing…" : "Remove"}</button>
          </div>
        </article>)}
    </section>

    {created && <section className="created-client" role="status">
      <div className="created-title"><span><Check aria-hidden="true" /></span><div><h2>Client created</h2><p>Save these credentials in the application.</p></div></div>
      <Credential label="Client ID" value={created.client_id} copied={copied === "id"} onCopy={() => copyValue("id", created.client_id)} />
      {created.client_secret && <Credential label="Client secret · shown once" value={created.client_secret} copied={copied === "secret"} onCopy={() => copyValue("secret", created.client_secret!)} />}
      <p className="created-footnote">The client secret cannot be viewed again after you leave this screen.</p>
    </section>}

    {clientFormMode !== null && <section ref={clientEditorRef} className="client-editor-panel" aria-labelledby="client-form-title">
      <div className="client-editor-heading"><h2 id="client-form-title">{clientFormMode === "edit" ? "Edit client" : "Add a client"}</h2><button className="client-list-action" type="button" disabled={busy} onClick={closeClientForm}>Cancel</button></div>
      <form className="client-form" onSubmit={saveClient}>
        <label className="admin-field"><span>Application name</span><input autoComplete="off" maxLength={120} value={name} onChange={(event) => setName(event.target.value)} placeholder="Jellyfin" required /></label>
        {clientFormMode === "create" && <label className="admin-field">
          <span>Client type</span>
          <select value={clientType} onChange={(event) => setClientType(event.target.value as "public" | "confidential")}>
            <option value="public">Public · PKCE</option>
            <option value="confidential">Confidential · client secret</option>
          </select>
          <small>{clientType === "public" ? "For browser and native apps. PKCE is required." : "For server-side apps that can keep a secret safely."}</small>
        </label>}
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
          {groups.length === 0 ? <p className="admin-hint">No groups exist yet. This client can be used by any user.</p> : <><p className="admin-hint">Leave all unchecked to allow any user.</p><div className="admin-choice-grid">{groups.map((group) => <label className="admin-check admin-check-compact" key={group.id}><input type="checkbox" checked={allowedGroups.includes(group.name)} onChange={() => toggleGroup(group.name)} /><span><strong>{group.display_name}</strong><small>{group.name} · {group.member_count} {group.member_count === 1 ? "member" : "members"}</small></span></label>)}</div></>}
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
    </section>}
          </>}

          {activeTab === "users" && isAdmin && <>
            <form className="client-form admin-create-form" onSubmit={createUser}>
              <label className="admin-field"><span>Username</span><input autoComplete="off" maxLength={80} value={userName} onChange={(event) => setUserName(event.target.value)} required /></label>
              <label className="admin-field"><span>Display name</span><input autoComplete="name" maxLength={120} value={userDisplayName} onChange={(event) => setUserDisplayName(event.target.value)} required /></label>
              <label className="admin-field"><span>Email <em>Optional</em></span><input type="email" autoComplete="email" maxLength={320} value={userEmail} onChange={(event) => setUserEmail(event.target.value)} /></label>
              {groups.length > 0 && <fieldset className="admin-options"><legend>Groups <em>Optional</em></legend><div className="admin-choice-grid">{groups.map((group) => <label className="admin-check" key={group.id}><input type="checkbox" checked={userGroups.includes(group.name)} onChange={() => setUserGroups((current) => current.includes(group.name) ? current.filter((name) => name !== group.name) : [...current, group.name])} /><span><strong>{group.display_name}</strong></span></label>)}</div></fieldset>}
              {adminActionMessage && <p className="admin-message admin-message-error" role="alert">{adminActionMessage}</p>}
              <button className="primary-action client-submit" type="submit" disabled={adminActionBusy || !userName.trim() || !userDisplayName.trim()}>{adminActionBusy ? "Creating invitation…" : "Invite user"}</button>
            </form>
            {createdInvitation && <section className="created-client" role="status"><div className="created-title"><span><Check aria-hidden="true" /></span><div><h2>Invitation ready</h2><p>Share this one-time link with the user.</p></div></div><Credential label="Enrollment link · expires in 24 hours" value={createdInvitation} copied={copied === "invitation"} onCopy={() => copyValue("invitation", createdInvitation)} /></section>}
            <section className="registered-clients admin-records"><h2>Accounts <span>{users.length}</span></h2>
              {users.length === 0 ? <p className="admin-hint">No accounts found.</p> : users.map((user) => <article className="registered-client" key={user.id}><div className="registered-client-title"><h3>{user.display_name || user.username}</h3><span className={`client-status${user.disabled ? " disabled" : ""}`}>{user.disabled ? "Disabled" : user.is_admin ? "Administrator" : "Active"}</span></div><code className="registered-client-id">{user.username}</code><p>{user.email || "No email address"}{user.groups.length ? ` · ${user.groups.join(", ")}` : ""}</p></article>)}
            </section>
          </>}

          {activeTab === "groups" && isAdmin && <>
            <form className="client-form admin-create-form" onSubmit={createGroup}>
              <label className="admin-field"><span>Group name</span><input autoComplete="off" maxLength={80} value={groupName} onChange={(event) => setGroupName(event.target.value)} placeholder="media-users" required /></label>
              <label className="admin-field"><span>Display name</span><input maxLength={120} value={groupDisplayName} onChange={(event) => setGroupDisplayName(event.target.value)} placeholder="Media users" required /></label>
              {adminActionMessage && <p className="admin-message admin-message-error" role="alert">{adminActionMessage}</p>}
              <button className="primary-action client-submit" type="submit" disabled={adminActionBusy || !groupName.trim() || !groupDisplayName.trim()}>{adminActionBusy ? "Creating…" : "Create group"}</button>
            </form>
            <section className="registered-clients admin-records"><h2>Groups <span>{groups.length}</span></h2>{groups.length === 0 ? <p className="admin-hint">No groups have been created.</p> : groups.map((group) => <article className="registered-client" key={group.id}><div className="registered-client-title"><h3>{group.display_name}</h3><span className="client-status">{group.member_count} {group.member_count === 1 ? "member" : "members"}</span></div><code className="registered-client-id">{group.name}</code></article>)}</section>
          </>}

          {activeTab === "keys" && isAdmin && <>
            <div className="key-management"><p className="admin-hint">New tokens use the active key. Previous public keys remain available to verify tokens already issued.</p><button className="secondary-action" type="button" onClick={rotateSigningKey} disabled={adminActionBusy}><Shield aria-hidden="true" />{adminActionBusy ? "Rotating…" : "Rotate signing key"}</button></div>
            {adminActionMessage && <p className="passkey-feedback passkey-feedback-success" role="status">{adminActionMessage}</p>}
            <section className="registered-clients admin-records"><h2>Keys <span>{signingKeys.length}</span></h2>{signingKeys.length === 0 ? <p className="admin-hint">No signing keys found.</p> : signingKeys.map((key) => <article className="registered-client" key={key.kid}><div className="registered-client-title"><h3>{key.algorithm}</h3><span className={`client-status${key.status === "active" ? "" : " disabled"}`}>{key.status}</span></div><code className="registered-client-id">{key.kid}</code><p>Created {new Date(key.created_at * 1000).toLocaleString()}{key.retire_after ? ` · Retires ${new Date(key.retire_after * 1000).toLocaleString()}` : ""}</p></article>)}</section>
          </>}

          {activeTab === "hanko" && <section className="account-hanko">
            <div className="account-hanko-preview"><HankoSeal size={192} color={hankoColor} seed={hankoSeed} title="Your personal Hanko preview" /></div>
            <SealCustomizer color={hankoColor} seed={hankoSeed} onColorChange={setHankoColor} onSeedChange={setHankoSeed} />
            <div className="account-hanko-save"><button className="secondary-action" type="button" onClick={saveHanko} disabled={savingHanko}>{savingHanko ? "Saving…" : "Save your Hanko"}</button>{hankoMessage && <p role="status">{hankoMessage}</p>}</div>
          </section>}

          {activeTab === "passkeys" && <section className="account-passkeys">
            <div className="passkey-section-heading"><span><Fingerprint aria-hidden="true" /></span><div><h2>Your passkeys</h2><p>Rename devices or remove ones you no longer use. Keep at least one passkey on your account.</p></div></div>
            <form className="passkey-add-form" onSubmit={addPasskey}><label className="admin-field"><span>Device label <em>Optional</em></span><input value={passkeyLabel} onChange={(event) => setPasskeyLabel(event.target.value)} maxLength={100} placeholder="e.g. MacBook" /></label><button className="secondary-action passkey-add-button" type="submit" disabled={addingPasskey}><Fingerprint aria-hidden="true" /> {addingPasskey ? "Follow your device prompt…" : "Add passkey"}</button></form>
            {passkeyMessage && <p className="passkey-feedback passkey-feedback-success" role="status">{passkeyMessage}</p>}{passkeyError && <p className="passkey-feedback passkey-feedback-error" role="alert">{passkeyError}</p>}
            <section className="passkey-list" aria-labelledby="passkey-list-title">
              <h3 id="passkey-list-title">Registered devices <span>{passkeys.length}</span></h3>
              {passkeysLoading ? <p className="admin-hint">Loading passkeys…</p> : passkeys.length === 0 ? <p className="admin-hint">No passkeys are registered.</p> : passkeys.map((passkey) => <article className="passkey-record" key={passkey.id}>
                <div className="passkey-record-heading"><h4>{passkey.label}</h4><p>Added {new Date(passkey.created_at * 1000).toLocaleDateString()}{passkey.last_used_at ? ` · Last used ${new Date(passkey.last_used_at * 1000).toLocaleDateString()}` : " · Not used yet"}</p></div>
                <form className="passkey-rename-form" onSubmit={(event) => renamePasskey(event, passkey)}>
                  <label className="admin-field"><span>Device name</span><input value={passkeyDrafts[passkey.id] ?? passkey.label} onChange={(event) => setPasskeyDrafts((current) => ({ ...current, [passkey.id]: event.target.value }))} maxLength={100} required /></label>
                  <button className="secondary-action passkey-row-action" type="submit" disabled={Boolean(passkeyActionId) || (passkeyDrafts[passkey.id] ?? passkey.label).trim() === passkey.label}>{passkeyActionId === passkey.id ? "Saving…" : "Rename"}</button>
                  <button className="passkey-remove-button" type="button" onClick={() => beginPasskeyRemoval(passkey)} disabled={passkeys.length <= 1 || Boolean(passkeyActionId)}><Trash2 aria-hidden="true" /> Remove</button>
                </form>
                {passkeys.length <= 1 && <p className="passkey-last-note">Your account must keep at least one passkey.</p>}
              </article>)}
            </section>
            {removeTarget && <form className="passkey-remove-confirmation" onSubmit={removePasskey}>
              <div><h3>Remove “{removeTarget.label}”?</h3><p>This permanently removes the passkey from your account. Type <strong>REMOVE</strong> to confirm.</p></div>
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
    case "groups": return "Group memberships";
  }
}

function Credential({ label, value, copied, onCopy }: { label: string; value: string; copied: boolean; onCopy: () => void }) {
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
    <span className="signature-seal"><HankoSeal size={27} variant="clean" title="Hanko" /></span>
  </main>;
}

function InkWash() {
  return <svg className="ink-wash" viewBox="0 0 1440 190" preserveAspectRatio="xMidYMax slice" aria-hidden="true">
    <path d="M0 124 C75 112 98 94 163 110 C215 122 255 142 318 118 C375 97 408 80 456 103 C502 125 527 135 568 109 C612 82 657 40 710 68 C758 94 790 119 843 106 C905 91 951 49 1009 78 C1068 108 1093 145 1160 125 C1222 107 1260 71 1311 91 C1360 110 1381 124 1440 111 L1440 190 L0 190 Z" />
    <path d="M0 153 C74 143 112 127 167 138 C218 148 242 164 307 150 C361 139 394 121 451 140 C510 160 535 167 594 145 C646 125 683 91 733 111 C784 132 819 151 876 144 C933 137 967 111 1025 128 C1083 145 1127 168 1181 154 C1246 136 1284 121 1338 140 C1382 156 1406 164 1440 151 L1440 190 L0 190 Z" />
  </svg>;
}
