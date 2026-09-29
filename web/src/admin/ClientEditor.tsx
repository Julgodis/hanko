import { useState, type FormEvent } from "react";
import { Plus, Trash2 } from "lucide-react";
import { PrivateValue } from "../components/PrivacyMode";
import { Credential } from "./Credential";
import { OPTIONAL_SCOPES as AVAILABLE_SCOPES, scopeDescription, type Scope } from "../lib/scopes";
import { api, appPath, json, errorMessage, logUiIssue } from "../lib/utils";
import type { Client, CreatedClient, Group, TokenEndpointAuthMethod, PkcePolicy } from "../lib/apiTypes";
type ClaimDraft = { claim_name: string; user_attribute_path: string; required_scope: string };
function splitLines(value: string) { return [...new Set(value.split(/\r?\n/).map(line => line.trim()).filter(Boolean))]; }

export function ClientEditor({ clientBeingEdited, groups, closeClientForm, onSaved, onDeleted }: {
  clientBeingEdited: Client | null; groups: Group[]; closeClientForm: () => void;
  onSaved: (client: CreatedClient) => Promise<void>; onDeleted: () => Promise<void>;
}) {
  const clientFormMode = clientBeingEdited ? "edit" : "create";
  const editingClientId = clientBeingEdited?.client_id ?? "";
  const hankoLogoUrl = new URL(appPath("hanko.png"), window.location.origin).href;
  const [name, setName] = useState(clientBeingEdited?.name ?? "");
  const [tokenAuthMethod, setTokenAuthMethod] = useState<TokenEndpointAuthMethod>(clientBeingEdited?.token_endpoint_auth_method ?? "none");
  const [pkcePolicy, setPkcePolicy] = useState<PkcePolicy>(clientBeingEdited?.pkce_policy ?? "required");
  const [clientEnabled, setClientEnabled] = useState(clientBeingEdited?.enabled ?? true);
  const [redirectUris, setRedirectUris] = useState(clientBeingEdited?.redirect_uris.join("\n") ?? "");
  const [logoutUris, setLogoutUris] = useState(clientBeingEdited?.post_logout_redirect_uris.join("\n") ?? "");
  const [scopes, setScopes] = useState<Scope[]>(clientBeingEdited?.scopes ?? ["openid", "profile", "email"]);
  const [allowedGroups, setAllowedGroups] = useState<string[]>(clientBeingEdited?.allowed_groups ?? []);
  const [claims, setClaims] = useState<ClaimDraft[]>(() => clientBeingEdited?.claims.map(claim => ({ ...claim, required_scope: claim.required_scope ?? "" })) ?? []);
  const [busy, setBusy] = useState(false);
  const [deletingClientId, setDeletingClientId] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState("");
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
      await onSaved(client);
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
      await onDeleted();
    } catch (removeError) {
      setError(errorMessage(removeError, "remove OIDC client"));
    } finally {
      setDeletingClientId("");
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
  return <section className="client-editor-panel client-form-page" aria-labelledby="admin-page-title">
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
    </section>;
}
