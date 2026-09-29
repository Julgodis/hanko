import { useEffect, useRef, useState, type FormEvent } from "react";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { PrivateValue } from "../components/PrivacyMode";
import { OPTIONAL_SCOPES as AVAILABLE_SCOPES, type Scope } from "../lib/scopes";
import { api, json, errorMessage, logUiIssue } from "../lib/utils";
import type { Group, AdminUser } from "../lib/apiTypes";
type GroupClaimDraft = { claim_name: string; claim_value: string; required_scope: Scope };

export function GroupEditor({ group, usersRevision, closeGroupForm, onSaved, onMembersSaved, openEditUser }: {
  group: Group | null; usersRevision: number; closeGroupForm: () => void;
  onSaved: () => Promise<void>; onMembersSaved: (groups: Group[]) => void;
  openEditUser: (user: AdminUser, returnToGroup: boolean) => void;
}) {
  const editingGroupId = group?.id ?? "";
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [adminActionBusy, setAdminActionBusy] = useState(false);
  const [adminActionMessage, setAdminActionMessage] = useState("");
  const initializedMembers = useRef(false);
  const [groupName, setGroupName] = useState(group?.name ?? "");
  const [groupDisplayName, setGroupDisplayName] = useState(group?.display_name ?? "");
  const [groupClaims, setGroupClaims] = useState<GroupClaimDraft[]>(() => group?.claims?.map(claim => ({ ...claim, claim_value: JSON.stringify(claim.claim_value) })) ?? []);
  const [groupMemberSelection, setGroupMemberSelection] = useState<string[]>([]);
  const [groupMemberSearch, setGroupMemberSearch] = useState("");
  const [groupMembersLoading, setGroupMembersLoading] = useState(false);
  const [groupMembersBusy, setGroupMembersBusy] = useState(false);
  const [groupMembersReady, setGroupMembersReady] = useState(false);
  const [groupMembersError, setGroupMembersError] = useState("");
  const [groupMembersMessage, setGroupMembersMessage] = useState("");
  useEffect(() => {
    if (!editingGroupId) return;
    let active = true;
    setGroupMembersLoading(true);
    setGroupMembersReady(false);
    void api<AdminUser[]>("/api/admin/users").then(userList => {
      if (!active) return;
      setUsers(userList);
      if (initializedMembers.current) {
        setGroupMemberSelection(current => current.filter(id => userList.some(user => user.id === id)));
      } else {
        setGroupMemberSelection(userList.filter(user => user.groups.includes(group!.name)).map(user => user.id));
        initializedMembers.current = true;
      }
      setGroupMembersReady(true);
    }).catch(cause => {
      if (active) setGroupMembersError(errorMessage(cause, "load group members"));
    }).finally(() => { if (active) setGroupMembersLoading(false); });
    return () => { active = false; };
  }, [editingGroupId, usersRevision]);
  const normalizedGroupMemberSearch = groupMemberSearch.trim().toLocaleLowerCase();
  const filteredGroupMembers = users.filter(user => [user.display_name, user.username, user.email ?? "", user.invitation_label ?? ""]
    .some(value => value.toLocaleLowerCase().includes(normalizedGroupMemberSearch)));
  function updateGroupClaim(index: number, key: keyof GroupClaimDraft, value: string) {
    setGroupClaims((current) => current.map((claim, claimIndex) =>
      claimIndex !== index
        ? claim
        : key === "required_scope"
          ? { ...claim, required_scope: value as Scope }
          : { ...claim, [key]: value }));
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
      onMembersSaved(groupList);
      setGroupMembersReady(true);
      setGroupMembersMessage("Members saved.");
    } catch (saveError) {
      setGroupMembersError(errorMessage(saveError, "save group members"));
    } finally {
      setGroupMembersBusy(false);
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
      await onSaved();
    } catch (saveError) {
      setAdminActionMessage(errorMessage(saveError, "save group"));
    } finally {
      setAdminActionBusy(false);
    }
  }
  return <section className="group-edit-page">
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
                  <td><button className="client-list-action membership-action" type="button" onClick={() => void openEditUser(user, true)} disabled={groupMembersBusy}><Pencil aria-hidden="true" />Edit claims</button></td>
                </tr>)}</tbody>
              </table></div>}
              <form className="group-members-actions" onSubmit={saveGroupMembers}>
                <p className="admin-hint">{groupMemberSelection.length} {groupMemberSelection.length === 1 ? "user is" : "users are"} selected. Per-user claims can override claims set above.</p>
                <button className="primary-action client-submit" type="submit" disabled={groupMembersBusy || groupMembersLoading || !groupMembersReady}>{groupMembersBusy ? "Saving members…" : "Save members"}</button>
              </form>
            </section>}
          </section>;
}
