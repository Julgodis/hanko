import { Check, Copy, Fingerprint, Plus, Trash2 } from "lucide-react";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
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
  scopes: Scope[];
  allowed_groups: string[];
};
type Group = { id: string; name: string; display_name: string; member_count: number };
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

export default function ClientAdmin() {
  const [clients, setClients] = useState<Client[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [name, setName] = useState("");
  const [clientType, setClientType] = useState<"public" | "confidential">("public");
  const [redirectUris, setRedirectUris] = useState("");
  const [logoutUris, setLogoutUris] = useState("");
  const [scopes, setScopes] = useState<Scope[]>(["openid", "profile", "email"]);
  const [allowedGroups, setAllowedGroups] = useState<string[]>([]);
  const [claims, setClaims] = useState<ClaimDraft[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<CreatedClient | null>(null);
  const [copied, setCopied] = useState("");
  const [passkeyLabel, setPasskeyLabel] = useState("");
  const [addingPasskey, setAddingPasskey] = useState(false);
  const [passkeyError, setPasskeyError] = useState("");
  const [passkeyMessage, setPasskeyMessage] = useState("");
  const [hankoColor, setHankoColor] = useState(ORIGINAL_HANKO_GRADIENT);
  const [hankoSeed, setHankoSeed] = useState("hanko");
  const [savingHanko, setSavingHanko] = useState(false);
  const [hankoMessage, setHankoMessage] = useState("");

  async function refreshClients() {
    setClients(await api<Client[]>("/api/admin/clients"));
  }

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [clientList, groupList, session] = await Promise.all([
          api<Client[]>("/api/admin/clients"),
          api<Group[]>("/api/admin/groups"),
          api<{ hanko_color?: string; hanko_seed?: string }>("/api/session"),
        ]);
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
  }, []);

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

  async function createClient(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setCreated(null);
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
      const client = await api<CreatedClient>("/api/admin/clients", {
        method: "POST",
        body: json({
          name: name.trim(),
          client_type: clientType,
          redirect_uris: redirects,
          post_logout_redirect_uris: splitLines(logoutUris),
          scopes: ["openid", ...scopes.filter((scope) => scope !== "openid")],
          allowed_groups: allowedGroups,
          claims: claimMappings,
        }),
      });
      setCreated(client);
      setName("");
      setRedirectUris("");
      setLogoutUris("");
      setAllowedGroups([]);
      setClaims([]);
      await refreshClients();
    } catch (createError) {
      setError(errorMessage(createError));
    } finally {
      setBusy(false);
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
      setPasskeyMessage(`Passkey added${passkeyLabel.trim() ? ` as “${passkeyLabel.trim()}”` : " to this account"}.`);
      setPasskeyLabel("");
    } catch {
      setPasskeyError("Passkey registration wasn’t completed. You can try again.");
    } finally {
      setAddingPasskey(false);
    }
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

  if (loading) {
    return <AdminScene><div className="admin-loading"><HankoSeal size={54} /><p>Loading clients…</p></div></AdminScene>;
  }

  return <AdminScene>
    <header className="admin-heading">
      <HankoSeal size={34} variant="clean" title="Hanko" />
      <h1>OIDC clients</h1>
      <p>Connect an application to Hanko.</p>
    </header>

    <section className="account-hanko">
      <div className="account-hanko-heading">
        <HankoSeal size={42} color={hankoColor} seed={hankoSeed} title="Your personal Hanko" />
        <div><h2>Your Hanko</h2><p>One personal seal for your identity. Your passkeys remain separate.</p></div>
      </div>
      <SealCustomizer color={hankoColor} seed={hankoSeed} onColorChange={setHankoColor} onSeedChange={setHankoSeed} />
      <div className="account-hanko-save">
        <button className="secondary-action" type="button" onClick={saveHanko} disabled={savingHanko}>{savingHanko ? "Saving…" : "Save your Hanko"}</button>
        {hankoMessage && <p role="status">{hankoMessage}</p>}
      </div>
    </section>

    <section className="account-passkeys">
      <div className="passkey-section-heading">
        <span><Fingerprint aria-hidden="true" /></span>
        <div><h2>Your passkeys</h2><p>Add another device to this account.</p></div>
      </div>
      <form className="passkey-add-form" onSubmit={addPasskey}>
        <label className="admin-field"><span>Device label <em>Optional</em></span><input value={passkeyLabel} onChange={(event) => setPasskeyLabel(event.target.value)} maxLength={100} placeholder="e.g. MacBook" /></label>
        <button className="secondary-action passkey-add-button" type="submit" disabled={addingPasskey}>
          <Fingerprint aria-hidden="true" /> {addingPasskey ? "Follow your device prompt…" : "Add passkey"}
        </button>
      </form>
      {passkeyMessage && <p className="passkey-feedback passkey-feedback-success" role="status">{passkeyMessage}</p>}
      {passkeyError && <p className="passkey-feedback passkey-feedback-error" role="alert">{passkeyError}</p>}
    </section>

    {loadError && <p className="admin-message admin-message-error" role="alert">{loadError}</p>}

    <form className="client-form" onSubmit={createClient}>
      <label className="admin-field">
        <span>Application name</span>
        <input autoComplete="off" maxLength={120} value={name} onChange={(event) => setName(event.target.value)} placeholder="Jellyfin" required />
      </label>

      <label className="admin-field">
        <span>Client type</span>
        <select value={clientType} onChange={(event) => setClientType(event.target.value as "public" | "confidential")}>
          <option value="public">Public · PKCE</option>
          <option value="confidential">Confidential · client secret</option>
        </select>
        <small>{clientType === "public" ? "For browser and native apps. PKCE is required." : "For server-side apps that can keep a secret safely."}</small>
      </label>

      <label className="admin-field">
        <span>Callback URLs</span>
        <textarea value={redirectUris} onChange={(event) => setRedirectUris(event.target.value)} placeholder="https://app.example.com/oidc/callback" rows={2} required />
        <small>One exact URL per line. HTTPS is required except for localhost development.</small>
      </label>

      <label className="admin-field">
        <span>Post-logout URLs <em>Optional</em></span>
        <textarea value={logoutUris} onChange={(event) => setLogoutUris(event.target.value)} placeholder="https://app.example.com/" rows={2} />
        <small>One exact URL per line.</small>
      </label>

      <fieldset className="admin-options">
        <legend>Scopes</legend>
        <label className="admin-check"><input type="checkbox" checked disabled /><span><strong>openid</strong><small>Required for sign-in</small></span></label>
        {AVAILABLE_SCOPES.map((scope) => <label className="admin-check" key={scope}>
          <input type="checkbox" checked={scopes.includes(scope)} onChange={() => toggleScope(scope)} />
          <span><strong>{scope}</strong><small>{scopeDescription(scope)}</small></span>
        </label>)}
      </fieldset>

      <fieldset className="admin-options">
        <legend>Allowed groups <em>Optional</em></legend>
        {groups.length === 0
          ? <p className="admin-hint">No groups exist yet. This client can be used by any user.</p>
          : <>
            <p className="admin-hint">Leave all unchecked to allow any user.</p>
            <div className="admin-choice-grid">{groups.map((group) => <label className="admin-check admin-check-compact" key={group.id}>
              <input type="checkbox" checked={allowedGroups.includes(group.name)} onChange={() => toggleGroup(group.name)} />
              <span><strong>{group.display_name}</strong><small>{group.name} · {group.member_count} {group.member_count === 1 ? "member" : "members"}</small></span>
            </label>)}</div>
          </>}
      </fieldset>

      <fieldset className="admin-options admin-claims">
        <legend>Custom claims <em>Optional</em></legend>
        <p className="admin-hint">Map a user attribute to an additional token claim.</p>
        {claims.map((claim, index) => <div className="claim-editor" key={index}>
          <label className="admin-field"><span>Claim name</span><input value={claim.claim_name} onChange={(event) => updateClaim(index, "claim_name", event.target.value)} placeholder="department" /></label>
          <label className="admin-field"><span>User attribute path</span><input value={claim.user_attribute_path} onChange={(event) => updateClaim(index, "user_attribute_path", event.target.value)} placeholder="/organization/department" /></label>
          <label className="admin-field"><span>Required scope</span><select value={claim.required_scope} onChange={(event) => updateClaim(index, "required_scope", event.target.value)}>
            <option value="">Always include</option>
            {["openid", ...scopes.filter((scope) => scope !== "openid")].map((scope) => <option value={scope} key={scope}>{scope}</option>)}
          </select></label>
          <button className="claim-remove" type="button" aria-label="Remove custom claim" onClick={() => setClaims((current) => current.filter((_, claimIndex) => claimIndex !== index))}><Trash2 aria-hidden="true" /></button>
        </div>)}
        <button className="add-claim" type="button" onClick={() => setClaims((current) => [...current, { claim_name: "", user_attribute_path: "", required_scope: "" }])}><Plus aria-hidden="true" /> Add claim</button>
      </fieldset>

      {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
      <button className="primary-action client-submit" type="submit" disabled={busy || !name.trim()}>
        {busy ? "Creating client…" : "Create OIDC client"}
      </button>
    </form>

    {created && <section className="created-client" role="status">
      <div className="created-title"><span><Check aria-hidden="true" /></span><div><h2>Client created</h2><p>Save these credentials in the application.</p></div></div>
      <Credential label="Client ID" value={created.client_id} copied={copied === "id"} onCopy={() => copyValue("id", created.client_id)} />
      {created.client_secret && <Credential label="Client secret · shown once" value={created.client_secret} copied={copied === "secret"} onCopy={() => copyValue("secret", created.client_secret!)} />}
      <p className="created-footnote">The client secret cannot be viewed again after you leave this screen.</p>
    </section>}

    <section className="registered-clients">
      <h2>Registered clients <span>{clients.length}</span></h2>
      {clients.length === 0
        ? <p className="admin-hint">No clients have been added yet.</p>
        : clients.map((client) => <article className="registered-client" key={client.client_id}>
          <div className="registered-client-title"><h3>{client.name}</h3><span className={client.enabled ? "client-status" : "client-status disabled"}>{client.enabled ? "Enabled" : "Disabled"}</span></div>
          <code className="registered-client-id">{client.client_id}</code>
          <p>{client.client_type === "public" ? "Public client" : "Confidential client"} · {client.scopes.join(", ")}</p>
          <details><summary>Redirect URLs and access</summary>
            <ul>{client.redirect_uris.map((uri) => <li key={uri}><code>{uri}</code></li>)}</ul>
            <p>{client.allowed_groups.length ? `Allowed groups: ${client.allowed_groups.join(", ")}` : "Available to all users"}</p>
          </details>
        </article>)}
    </section>
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
