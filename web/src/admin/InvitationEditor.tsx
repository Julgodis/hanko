import { useState, type FormEvent } from "react";
import { Check, Mail, Plus } from "lucide-react";
import { PrivateValue } from "../components/PrivacyMode";
import { Credential } from "./Credential";
import { api, json, errorMessage } from "../lib/utils";
import type { Group, CreatedInvitation } from "../lib/apiTypes";
const EXPIRY_UNIT_SECONDS = { seconds: 1, minutes: 60, hours: 60 * 60, days: 24 * 60 * 60, years: 365 * 24 * 60 * 60 } as const;
type ExpiryUnit = keyof typeof EXPIRY_UNIT_SECONDS;
function invitationEmailHref(invitation: CreatedInvitation) {
  const subject = `Your Hanko invite: ${invitation.label}`;
  const expiry = new Date(invitation.expires_at * 1000).toLocaleString();
  const body = `You have been invited to set up a Hanko account.\n\nUse this link before ${expiry}:\n${invitation.enrollment_url}`;
  return `mailto:${encodeURIComponent(invitation.email ?? "")}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

export function InvitationEditor({ groups, previewReady, closeUserForm, onCreated }: {
  groups: Group[]; previewReady: boolean; closeUserForm: () => void; onCreated: () => Promise<void>;
}) {
  const [adminActionBusy, setAdminActionBusy] = useState(false);
  const [adminActionMessage, setAdminActionMessage] = useState("");
  const [copied, setCopied] = useState("");
  function openCreateUser() { setCreatedInvitation(null); setAdminActionMessage(""); }
  const [invitationLabel, setInvitationLabel] = useState("");
  const [invitationEmail, setInvitationEmail] = useState("");
  const [invitationMaxUses, setInvitationMaxUses] = useState("1");
  const [invitationExpiry, setInvitationExpiry] = useState("15");
  const [invitationExpiryUnit, setInvitationExpiryUnit] = useState<ExpiryUnit>("minutes");
  const [userGroups, setUserGroups] = useState<string[]>([]);
  const [createdInvitation, setCreatedInvitation] = useState<CreatedInvitation | null>(previewReady ? {
    id: "inv_preview_ready",
    label: "Studio team",
    email: "person@example.com",
    enrollment_url: "https://id.example.com/enroll/sample-invite-token",
    expires_at: 1_793_109_600,
  } : null);
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
      await onCreated();
    } catch (createError) {
      setAdminActionMessage(errorMessage(createError, "create invitation"));
    } finally {
      setAdminActionBusy(false);
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
  return <>
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
          </>;
}
