import { useEffect, useState, type FormEvent } from "react";
import { Plus, Trash2 } from "lucide-react";
import { PrivateValue } from "../components/PrivacyMode";
import { OPTIONAL_SCOPES as AVAILABLE_SCOPES } from "../lib/scopes";
import { api, json, errorMessage } from "../lib/utils";
import type { AdminUser, UserClaim } from "../lib/apiTypes";
type UserClaimDraft = { claim_name: string; claim_value: string; required_scope: string };

export function UserEditor({ editingUser, closeUserEditor, onDeleted }: {
  editingUser: AdminUser; closeUserEditor: () => void; onDeleted: (id: string) => void;
}) {
  const [deletingUserId, setDeletingUserId] = useState("");
  const [userClaimDrafts, setUserClaimDrafts] = useState<UserClaimDraft[]>([]);
  const [userClaimsLoading, setUserClaimsLoading] = useState(true);
  const [userClaimsReady, setUserClaimsReady] = useState(false);
  const [userClaimsBusy, setUserClaimsBusy] = useState(false);
  const [userEditorError, setUserEditorError] = useState("");
  const [userEditorMessage, setUserEditorMessage] = useState("");
  useEffect(() => {
    const user = editingUser;
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
  }, [editingUser.id]);
  async function removeUser(user: AdminUser) {
    const label = user.display_name || user.username;
    const confirmed = window.confirm(`Permanently remove ${label}? This deletes the account, passkeys, active sessions, group memberships, OIDC consents, tokens, and custom claims. This action cannot be undone.`);
    if (!confirmed) return;

    setDeletingUserId(user.id);
    setUserEditorError("");
    try {
      await api(`/api/admin/users/${encodeURIComponent(user.id)}`, { method: "DELETE" });
      onDeleted(user.id);
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
  return <section className="user-edit-page">
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
          </section>;
}
