import App from "./App";
import { Sun } from "lucide-react";
import { useEffect, useState } from "react";
import "./styles.css";

type PreviewScreen = "signin" | "consent" | "welcome" | "setup" | "join-invite" | "clients" | "users" | "invite" | "invite-ready" | "groups" | "keys" | "passkeys" | "hanko" | "client-form";

const previewScreens: { id: PreviewScreen; label: string }[] = [
  { id: "signin", label: "Sign in" },
  { id: "consent", label: "Consent" },
  { id: "welcome", label: "Welcome" },
  { id: "setup", label: "First run" },
  { id: "join-invite", label: "Accept invite" },
  { id: "clients", label: "Clients" },
  { id: "client-form", label: "Add client" },
  { id: "users", label: "Users" },
  { id: "invite", label: "Invite user" },
  { id: "invite-ready", label: "Invite ready" },
  { id: "groups", label: "Groups" },
  { id: "keys", label: "Signing keys" },
  { id: "passkeys", label: "Passkeys" },
  { id: "hanko", label: "Hanko" },
];

const screenParam = new URLSearchParams(window.location.search).get("screen") as PreviewScreen | null;
const screen: PreviewScreen = previewScreens.some((item) => item.id === screenParam) ? screenParam! : "signin";
const adminScreens = ["clients", "client-form", "users", "invite", "invite-ready", "groups", "keys"];

const clients = [
  {
    client_id: "hnk_7f83d20a1c5e4a",
    name: "Jellyfin",
    client_type: "public",
    token_endpoint_auth_method: "none",
    enabled: true,
    redirect_uris: ["https://media.example.com/sso/OID/redirect/hanko"],
    post_logout_redirect_uris: ["https://media.example.com/"],
    scopes: ["openid", "profile", "email", "groups"],
    allowed_groups: ["media-users"],
    claims: [],
    user_count: 8,
  },
  {
    client_id: "hnk_5bc21f460e9a73",
    name: "Paperless-ngx",
    client_type: "confidential",
    token_endpoint_auth_method: "client_secret_post",
    enabled: true,
    redirect_uris: ["https://docs.example.com/accounts/oidc/hanko/login/callback/"],
    post_logout_redirect_uris: [],
    scopes: ["openid", "profile", "email"],
    allowed_groups: [],
    claims: [{ claim_name: "department", user_attribute_path: "/organization/department", required_scope: "profile" }],
    user_count: 3,
  },
  {
    client_id: "hnk_02c63e1812fa44",
    name: "Immich",
    client_type: "public",
    token_endpoint_auth_method: "none",
    enabled: false,
    redirect_uris: ["https://photos.example.com/auth/login"],
    post_logout_redirect_uris: [],
    scopes: ["openid", "profile", "email"],
    allowed_groups: [],
    claims: [],
    user_count: 0,
  },
];

const users = [
  { id: "usr_01", username: "admin", display_name: "Hanko Administrator", email: "admin@example.com", invitation_label: null, is_admin: true, disabled: false, groups: ["administrators"] },
  { id: "usr_02", username: "sana.lee", display_name: "Sana Lee", email: "sana.lee@example.com", invitation_label: "Design team", is_admin: false, disabled: false, groups: ["media-users", "staff"] },
  { id: "usr_03", username: "tom.rivers", display_name: "Tom Rivers", email: null, invitation_label: "Community event", is_admin: false, disabled: false, groups: [] },
  { id: "usr_04", username: "former-member", display_name: "Former member", email: "former@example.com", invitation_label: null, is_admin: false, disabled: true, groups: ["media-users"] },
];

const invitations = [
  { id: "inv_01", label: "Design team", email: "sana.lee@example.com", max_uses: 1, use_count: 1, created_at: 1_790_517_600, expires_at: 1_793_109_600, revoked: false },
  { id: "inv_02", label: "Community event", email: null, max_uses: 10, use_count: 3, created_at: 1_790_517_600, expires_at: 1_791_122_400, revoked: false },
];

const groups = [
  { id: "grp_01", name: "media-users", display_name: "Media users", member_count: 4, claims: [{ claim_name: "role", claim_value: "media-user", required_scope: "groups" }] },
  { id: "grp_02", name: "administrators", display_name: "Administrators", member_count: 1, claims: [{ claim_name: "role", claim_value: "administrator", required_scope: "groups" }] },
  { id: "grp_03", name: "staff", display_name: "Staff", member_count: 6, claims: [] },
];

const signingKeys = [
  { kid: "hanko-es256-2026-09", algorithm: "ES256", status: "active", created_at: 1_790_517_600, retire_after: null },
  { kid: "hanko-es256-2026-03", algorithm: "ES256", status: "retiring", created_at: 1_772_647_200, retire_after: 1_791_122_400 },
];

let previewClients = [...clients];
let previewInvitations = [...invitations];
let previewGroups = [...groups];
const originalFetch = window.fetch.bind(window);

const previewPasskeys = [
  { id: "pk_01", label: "MacBook Touch ID", created_at: 1_790_517_600, last_used_at: 1_790_604_000 },
  { id: "pk_02", label: "YubiKey 5C NFC", created_at: 1_781_884_800, last_used_at: 1_790_431_200 },
];

function jsonResponse(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}

function installPreviewApi() {
  const fetchPreviewApi: typeof window.fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, window.location.href);
    if (!url.pathname.startsWith("/api/")) return originalFetch(input, init);

    const method = init?.method?.toUpperCase() ?? (input instanceof Request ? input.method : "GET");
    if (url.pathname === "/api/session") return jsonResponse({
      authenticated: screen === "join-invite" ? false : !["signin", "setup"].includes(screen),
      setup_only: false,
      is_admin: adminScreens.includes(screen),
      hanko_color: "#d64135",
      hanko_seed: "hanko",
      oidc_username: screen === "join-invite" ? null : "sana.lee",
      oidc_name: screen === "join-invite" ? null : "Sana Lee",
    });
    if (url.pathname === "/api/setup-status") return jsonResponse({ initialized: screen !== "setup", bootstrap_enabled: true });
    if (url.pathname === "/api/authorize/request") return jsonResponse({
      client_name: "Test 2",
      scopes: ["openid", "profile", "email", "groups", "offline_access"],
      claims: {
        name: "Sana Lee",
        preferred_username: "sana.lee",
        email: "sana.lee@example.com",
        groups: ["media-users", "staff"],
        role: ["media-user"],
        department: "Product design",
      },
    });
    if (url.pathname === "/api/authorize/continue" && method === "POST") return jsonResponse({ redirect_to: previewHref("welcome") });
    if (url.pathname === "/api/authorize/deny" && method === "POST") return jsonResponse({ redirect_to: previewHref("signin") });
    if (url.pathname === "/api/admin/clients" && method === "GET") return jsonResponse(previewClients);
    if (url.pathname === "/api/admin/clients" && method === "POST") {
      const payload = JSON.parse(String(init?.body ?? "{}"));
      const createdClient = {
        ...payload,
        client_id: "hnk_new_sample_client",
        client_secret: payload.client_type === "confidential" ? "sample-secret-shown-once" : null,
        token_endpoint_auth_method: payload.client_type === "public" ? "none" : "client_secret_post",
        user_count: 0,
      };
      previewClients.push({ ...createdClient, enabled: true });
      return jsonResponse(createdClient);
    }
    if (url.pathname.startsWith("/api/admin/clients/") && method === "PUT") {
      const clientIndex = previewClients.findIndex((item) => item.client_id === decodeURIComponent(url.pathname.split("/").at(-1) ?? ""));
      if (clientIndex < 0) return jsonResponse({}, 404);
      previewClients[clientIndex] = { ...previewClients[clientIndex], ...JSON.parse(String(init?.body ?? "{}")) };
      return jsonResponse(previewClients[clientIndex]);
    }
    if (url.pathname.startsWith("/api/admin/clients/") && method === "DELETE") {
      previewClients = previewClients.filter((item) => item.client_id !== decodeURIComponent(url.pathname.split("/").at(-1) ?? ""));
      return jsonResponse({});
    }
    if (url.pathname === "/api/admin/groups" && method === "GET") return jsonResponse(previewGroups);
    if (url.pathname === "/api/admin/groups" && method === "POST") {
      const payload = JSON.parse(String(init?.body ?? "{}"));
      const createdGroup = { id: `grp_preview_${previewGroups.length + 1}`, member_count: 0, ...payload };
      previewGroups.push(createdGroup);
      return jsonResponse(createdGroup);
    }
    if (url.pathname.startsWith("/api/admin/groups/") && method === "PUT") {
      const groupId = decodeURIComponent(url.pathname.split("/").at(-1) ?? "");
      const groupIndex = previewGroups.findIndex((group) => group.id === groupId);
      if (groupIndex < 0) return jsonResponse({}, 404);
      previewGroups[groupIndex] = { ...previewGroups[groupIndex], ...JSON.parse(String(init?.body ?? "{}")) };
      return jsonResponse({});
    }
    if (url.pathname === "/api/admin/users" && method === "GET") return jsonResponse(users);
    if (url.pathname === "/api/admin/invitations" && method === "GET") return jsonResponse(previewInvitations);
    if (url.pathname === "/api/admin/invitations" && method === "POST") {
      const payload = JSON.parse(String(init?.body ?? "{}"));
      const createdInvitation = { id: "inv_new_sample", label: payload.label, email: payload.email, enrollment_url: "https://id.example.com/enroll/sample-invite-token", expires_at: 1_793_109_600 };
      previewInvitations.push({ ...createdInvitation, max_uses: payload.max_uses, use_count: 0, created_at: 1_790_517_600, revoked: false });
      return jsonResponse(createdInvitation);
    }
    if (url.pathname.startsWith("/api/admin/invitations/") && method === "POST") {
      const invitationId = decodeURIComponent(url.pathname.split("/").at(-2) ?? "");
      previewInvitations = previewInvitations.map((invitation) => invitation.id === invitationId ? { ...invitation, revoked: true } : invitation);
      return jsonResponse({});
    }
    if (url.pathname === "/api/admin/signing-keys" && method === "GET") return jsonResponse(signingKeys);
    if (url.pathname === "/api/admin/signing-keys" && method === "POST") return jsonResponse({});
    if (url.pathname === "/api/passkeys") return jsonResponse(previewPasskeys);
    return jsonResponse({});
  };

  window.fetch = fetchPreviewApi;
}

document.title = "Hanko · UI preview";
installPreviewApi();

function previewHref(target: PreviewScreen) {
  const path = adminScreens.includes(target) ? "/admin/clients" : ["hanko", "passkeys"].includes(target) ? "/account" : "/";
  const query = new URLSearchParams({ "ui-preview": "1", screen: target });
  if (target === "consent") query.set("request_id", "preview-consent");
  if (target === "join-invite") query.set("enroll", "preview-invite-token");
  return `${path}?${query.toString()}`;
}

export default function DevPreview() {
  const [lightMode, setLightMode] = useState(() => window.localStorage.getItem("hanko-ui-preview-theme") === "light");

  useEffect(() => {
    if (lightMode) {
      document.documentElement.dataset.previewTheme = "light";
      window.localStorage.setItem("hanko-ui-preview-theme", "light");
    } else {
      delete document.documentElement.dataset.previewTheme;
      window.localStorage.removeItem("hanko-ui-preview-theme");
    }
  }, [lightMode]);

  return <>
    <nav className="preview-toolbar" aria-label="UI preview screens">
      <span className="preview-label">Preview</span>
      {previewScreens.map((item) => <a
        key={item.id}
        href={previewHref(item.id)}
        aria-current={screen === item.id ? "page" : undefined}
      >{item.label}</a>)}
      <button
        className="preview-theme-button"
        type="button"
        aria-label="Light mode preview"
        aria-pressed={lightMode}
        onClick={() => setLightMode((value) => !value)}
      ><Sun aria-hidden="true" />Light mode</button>
    </nav>
    <App key={screen} />
  </>;
}
