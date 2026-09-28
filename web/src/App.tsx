import { startAuthentication } from "@simplewebauthn/browser";
import { ArrowRight, Clock3, Fingerprint, Mail, MapPin, Phone, ShieldCheck, UserRound, Users, type LucideIcon } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";
import { useEffect, useMemo, useState, type CSSProperties, type FormEvent, type ReactNode } from "react";
import ClientAdmin from "./ClientAdmin";
import FirstRun from "./FirstRun";
import { HankoSeal, type HankoState } from "./components/HankoSeal";
import { PrivateValue } from "./components/PrivacyMode";
import { ApiError, api, json, logUiIssue } from "./lib/utils";
import type { OidcProfileClaims } from "./lib/userClaims";

type Phase = "idle" | "preparing" | "authenticating" | "success" | "error";
type Session = {
  authenticated: boolean;
  setup_only: boolean;
  is_admin: boolean;
  username?: string | null;
  hanko_color?: string | null;
  hanko_seed?: string | null;
  oidc_username?: string | null;
  oidc_name?: string | null;
  oidc_picture?: string | null;
  oidc_phone?: string | null;
  oidc_address?: { street_address?: string; locality?: string; region?: string; postal_code?: string; country?: string } | null;
  oidc_profile_claims?: OidcProfileClaims | null;
  required_user_claims?: string[];
  allow_multiple_passkeys_per_authenticator?: boolean;
};
type SetupStatus = { initialized: boolean; bootstrap_enabled: boolean };
type AuthorizationRequest = {
  client_name: string;
  scopes: string[];
  requires_fresh_authentication: boolean;
  consent_required: boolean;
  claims?: Record<string, unknown> | null;
};
type PasskeyStart = {
  ceremony_id: string;
  publicKey: Parameters<typeof startAuthentication>[0]["optionsJSON"];
};

type UserFacingError = { title: string; text: string; retry?: boolean };

const GROUP_ACCESS_DENIED_MESSAGE = "Your account is not a member of a group allowed to access this application. Ask an administrator to add your account to an allowed group.";

function isGroupAccessDenied(cause: unknown): boolean {
  return cause instanceof ApiError && cause.code === "access_denied";
}

function isTemporaryFailure(cause: unknown): boolean {
  return cause instanceof TypeError
    || (cause instanceof ApiError && (cause.status >= 500 || cause.code === "temporarily_unavailable"));
}

function authorizationPageErrorCopy(code: string | null): UserFacingError {
  switch (code) {
    case "invalid_client":
      return { title: "Application not recognized", text: "This sign-in request doesn’t match a registered application. Return to the application and start again." };
    case "invalid_redirect_uri":
      return { title: "Callback address not registered", text: "The application’s callback address isn’t registered with Hanko. Contact the application administrator." };
    case "temporarily_unavailable":
      return { title: "Hanko is temporarily unavailable", text: "Hanko couldn’t start this sign-in. Return to the application and try again in a moment." };
    default:
      return { title: "Sign-in request couldn’t be completed", text: "This request is incomplete or invalid. Return to the application and start again." };
  }
}

function loadErrorCopy(cause: unknown, hasAuthorizationRequest: boolean): UserFacingError {
  if (isGroupAccessDenied(cause)) {
    return { title: "Access not allowed", text: GROUP_ACCESS_DENIED_MESSAGE };
  }
  if (cause instanceof ApiError && cause.code === "invalid_grant" && hasAuthorizationRequest) {
    return { title: "This sign-in has expired", text: "Return to the application and start again." };
  }
  if (isTemporaryFailure(cause)) {
    return { title: "Hanko is temporarily unavailable", text: "Please try again in a moment.", retry: true };
  }
  return hasAuthorizationRequest
    ? { title: "Sign-in request couldn’t be completed", text: "Return to the application and start again." }
    : { title: "Hanko is unavailable", text: "Please try again in a moment.", retry: true };
}

type SignInFailure = "passkey" | "access_denied" | "expired" | "temporarily_unavailable" | "completion";

function signInFailure(cause: unknown, passkeyVerified: boolean, hasAuthorizationRequest: boolean): SignInFailure {
  if (isGroupAccessDenied(cause)) return "access_denied";
  if (passkeyVerified && hasAuthorizationRequest && cause instanceof ApiError && cause.code === "invalid_grant") {
    return "expired";
  }
  if (isTemporaryFailure(cause)) return "temporarily_unavailable";
  return passkeyVerified ? "completion" : "passkey";
}

function App() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const requestId = useMemo(() => new URLSearchParams(window.location.search).get("request_id"), []);
  const authorizationPageError = useMemo(() => new URLSearchParams(window.location.search).get("hanko_error"), []);
  const enrollmentToken = useMemo(() => new URLSearchParams(window.location.search).get("enroll"), []);
  const clientsRoute = pathname === "/admin/clients" || pathname.startsWith("/admin/clients/");
  const accountRoute = pathname === "/account" || pathname.startsWith("/account/");
  const homeRoute = pathname === "/";
  const [session, setSession] = useState<Session | null>(null);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [request, setRequest] = useState<AuthorizationRequest | null>(null);
  const [loading, setLoading] = useState(!authorizationPageError);
  const [loadError, setLoadError] = useState<UserFacingError | null>(null);

  useEffect(() => {
    if (homeRoute && session?.authenticated && !session.setup_only && !requestId) {
      navigate("/account/profile", { replace: true });
    }
  }, [homeRoute, navigate, requestId, session]);

  async function loadAuthorizationRequest(id: string): Promise<AuthorizationRequest> {
    let authorizationRequest = await api<AuthorizationRequest>(
      `/api/authorize/request?request_id=${encodeURIComponent(id)}`,
    );
    if (!authorizationRequest.consent_required && !authorizationRequest.requires_fresh_authentication) {
      try {
        const result = await api<{ redirect_to: string }>("/api/authorize/continue", {
          method: "POST",
          body: json({ request_id: id, consent: false }),
        });
        window.location.assign(result.redirect_to);
      } catch (cause) {
        if (!(cause instanceof ApiError) || cause.code !== "consent_required") throw cause;
        authorizationRequest = await api<AuthorizationRequest>(
          `/api/authorize/request?request_id=${encodeURIComponent(id)}`,
        );
      }
    }
    return authorizationRequest;
  }

  useEffect(() => {
    let active = true;
    async function load() {
      if (authorizationPageError) return;
      try {
        if (enrollmentToken) {
          const cleanUrl = new URL(window.location.href);
          cleanUrl.searchParams.delete("enroll");
          window.history.replaceState(null, "", cleanUrl);
        }
        const [identity, setup] = await Promise.all([
          api<Session>("/api/session"),
          api<SetupStatus>("/api/setup-status"),
        ]);
        const setupStage = !setup.initialized || identity.setup_only || Boolean(enrollmentToken);
        if (active) {
          setSession(identity);
          setSetupStatus(setup);
        }
        let authorizationRequest: AuthorizationRequest | null = null;
        if (requestId && !setupStage) {
          authorizationRequest = await loadAuthorizationRequest(requestId);
        }
        if (active) {
          setRequest(authorizationRequest);
        }
      } catch (cause) {
        if (active) {
          logUiIssue("load sign-in", cause);
          setLoadError(loadErrorCopy(cause, Boolean(requestId)));
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    void load();
    return () => { active = false; };
  }, [authorizationPageError, enrollmentToken, requestId]);

  async function refreshSession() {
    const [identity, authorizationRequest] = await Promise.all([
      api<Session>("/api/session"),
      requestId
        ? loadAuthorizationRequest(requestId)
        : Promise.resolve(null),
    ]);
    setSession(identity);
    if (requestId) setRequest(authorizationRequest);
  }

  async function completeSetup() {
    const [identity, setup, authorizationRequest] = await Promise.all([
      api<Session>("/api/session"),
      api<SetupStatus>("/api/setup-status"),
      requestId
        ? loadAuthorizationRequest(requestId)
        : Promise.resolve(null),
    ]);
    setSession(identity);
    setSetupStatus(setup);
    if (requestId) setRequest(authorizationRequest);
  }

  function requireFreshAuthorizationAuthentication() {
    setRequest(current => current
      ? { ...current, requires_fresh_authentication: true }
      : current);
  }

  if (authorizationPageError) {
    const pageError = authorizationPageErrorCopy(authorizationPageError);
    return <Scene phase="error"><Seal phase="error" /><Copy title={pageError.title} text={pageError.text} /></Scene>;
  }

  if (loading) {
    return <Scene phase="idle"><Seal phase="idle" /><Copy title="Hanko" text="Preparing your sign-in…" /></Scene>;
  }

  if (loadError) {
    return <Scene phase="error"><Seal phase="error" /><Copy title={loadError.title} text={loadError.text} />
      {loadError.retry && <button className="primary-action" onClick={() => window.location.reload()}>Try again</button>}
    </Scene>;
  }

  if (setupStatus && (!setupStatus.initialized || session?.setup_only || enrollmentToken)) {
    if (!setupStatus.bootstrap_enabled && !session?.setup_only && !enrollmentToken) {
      return <Scene phase="error"><Seal phase="error" /><Copy title="Hanko setup is disabled" text="Configure a bootstrap token on the server to create the first administrator." /></Scene>;
    }
    return <FirstRun
      hasSetupSession={session?.setup_only ?? false}
      invitationToken={enrollmentToken}
      loginAttemptDuringSetup={Boolean(requestId)}
      initialColor={session?.hanko_color ?? undefined}
      initialSeed={session?.hanko_seed ?? undefined}
      initialProfile={{ username: session?.oidc_username ?? "", displayName: session?.oidc_name ?? "", pictureUrl: session?.oidc_picture ?? "", phoneNumber: session?.oidc_phone ?? "", address: session?.oidc_address ?? undefined, profileClaims: session?.oidc_profile_claims ?? undefined }}
      requiredUserClaims={session?.required_user_claims ?? []}
      onComplete={completeSetup}
    />;
  }

  if (clientsRoute || accountRoute) {
    if (!session?.authenticated || session.setup_only) {
      return <SignIn clientName="Hanko" requestId={null} onAuthenticated={refreshSession} />;
    }
    if (clientsRoute && !session.is_admin) {
      return <Scene phase="error"><Seal phase="error" /><Copy title="Administrator access required" text="Sign in with an administrator account to manage OIDC clients." /></Scene>;
    }
    return <ClientAdmin isAdmin={session.is_admin} defaultTab={clientsRoute ? "clients" : "hanko"} accountName={session.username ?? ""} requiredUserClaims={session.required_user_claims ?? []} />;
  }

  if (requestId && request?.requires_fresh_authentication) {
    return <SignIn
      clientName={request.client_name}
      requestId={requestId}
      freshAuthentication
      onAuthenticated={refreshSession}
    />;
  }

  if (session?.authenticated && !session.setup_only && requestId && request) {
    return <Consent
      request={request}
      requestId={requestId}
      hankoColor={session.hanko_color}
      hankoSeed={session.hanko_seed}
      onFreshAuthenticationRequired={requireFreshAuthorizationAuthentication}
    />;
  }

  if (session?.authenticated && !session.setup_only) {
    return <Scene phase="success"><Seal phase="success" color={session.hanko_color} seed={session.hanko_seed} />
      <span className="sr-only" role="status">Signed in. Opening account settings.</span>
    </Scene>;
  }

  return <SignIn
    clientName={request?.client_name ?? "Hanko"}
    requestId={requestId}
    onAuthenticated={refreshSession}
  />;
}

function SignIn({
  clientName,
  requestId,
  freshAuthentication = false,
  onAuthenticated,
}: {
  clientName: string;
  requestId: string | null;
  freshAuthentication?: boolean;
  onAuthenticated: () => Promise<void>;
}) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [failure, setFailure] = useState<SignInFailure | null>(null);
  const [useAccountName, setUseAccountName] = useState(false);
  const [account, setAccount] = useState("");

  async function signIn() {
    if (useAccountName && !account.trim()) return;
    setFailure(null);
    setPhase("preparing");
    let passkeyVerified = false;
    try {
      const start = await api<PasskeyStart>("/api/passkeys/login/options", {
        method: "POST",
        body: json(useAccountName ? { account: account.trim() } : {}),
      });
      const authentication = startAuthentication({ optionsJSON: start.publicKey });
      setPhase("authenticating");
      const credential = await authentication;
      await api("/api/passkeys/login/verify", {
        method: "POST",
        body: json({ ceremony_id: start.ceremony_id, credential }),
      });
      passkeyVerified = true;
      setPhase("success");
      const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      await new Promise(resolve => window.setTimeout(resolve, reducedMotion ? 120 : 820));
      await onAuthenticated();
    } catch (cause) {
      logUiIssue("passkey sign-in", cause);
      setFailure(signInFailure(cause, passkeyVerified, Boolean(requestId)));
      setPhase("error");
    }
  }

  function retry() {
    setFailure(null);
    setPhase("idle");
  }

  function accountSignIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void signIn();
  }

  function switchSignInMode() {
    setUseAccountName((current) => !current);
    setFailure(null);
    setPhase("idle");
  }

  let title = freshAuthentication ? "Confirm it’s you" : `Sign in to ${clientName}`;
  let text = freshAuthentication
    ? `Use your passkey again to continue to ${clientName}.`
    : useAccountName
      ? "Enter the account name or email associated with your passkey."
      : "Use your passkey to continue.";
  if (phase === "preparing") {
    title = "Preparing your device…";
    text = "Follow your device prompt.";
  } else if (phase === "authenticating") {
    title = "Confirm it’s you";
    text = "Approve this sign-in on your device.";
  } else if (phase === "error") {
    if (failure === "access_denied") {
      title = "Access not allowed";
      text = GROUP_ACCESS_DENIED_MESSAGE;
    } else if (failure === "expired") {
      title = "This sign-in has expired";
      text = "Your passkey was accepted, but this request is no longer valid. Return to the application and start again.";
    } else if (failure === "temporarily_unavailable") {
      title = "Hanko is temporarily unavailable";
      text = "Your sign-in couldn’t be completed. Please try again in a moment.";
    } else if (failure === "completion") {
      title = "Sign-in couldn’t be completed";
      text = "Your passkey was accepted, but Hanko couldn’t finish loading this sign-in request. Please try again.";
    } else {
      title = "Passkey wasn’t accepted";
      text = useAccountName
        ? "Check the account name and try again with its saved passkey."
        : "Please try again.";
    }
  }

  return <Scene phase={phase}>
    <Seal phase={phase} />
    {phase !== "success" && <Copy title={title} text={text} />}
    {phase === "idle" && (useAccountName
      ? <form className="account-sign-in" onSubmit={accountSignIn}>
        <label htmlFor="passkey-account">Account name or email</label>
        <input id="passkey-account" type="text" autoComplete="username" value={account}
          onChange={(event) => setAccount(event.target.value)} required maxLength={254} />
        <p>For older passkeys, use the account name saved with the passkey.</p>
        <button className="primary-action" type="submit">
          <Fingerprint aria-hidden="true" className="size-[19px]" strokeWidth={1.8} />
          <span>{freshAuthentication ? "Confirm with passkey" : "Sign in with passkey"}</span>
        </button>
      </form>
      : <button className="primary-action" onClick={signIn}>
        <Fingerprint aria-hidden="true" className="size-[19px]" strokeWidth={1.8} />
        <span>{freshAuthentication ? "Confirm with passkey" : "Sign in with passkey"}</span>
      </button>)}
    {phase === "error" && failure !== "access_denied" && failure !== "expired" && <button className="primary-action" onClick={retry}>
      <span>Try again</span><ArrowRight aria-hidden="true" className="size-4" />
    </button>}
    {(phase === "idle" || (phase === "error" && failure === "passkey")) && <button
      className="auth-mode-switch" type="button" onClick={switchSignInMode}>
      {useAccountName ? "Use a discoverable passkey" : "Passkey not listed? Use account name"}
    </button>}
  </Scene>;
}

function Consent({ request, requestId, hankoColor, hankoSeed, onFreshAuthenticationRequired }: {
  request: AuthorizationRequest;
  requestId: string;
  hankoColor?: string | null;
  hankoSeed?: string | null;
  onFreshAuthenticationRequired: () => void;
}) {
  const [decision, setDecision] = useState<"idle" | "allowing" | "denying">("idle");
  const [error, setError] = useState("");
  const name = request.client_name || "This application";
  const stampStyle = useMemo(() => ({
    "--stamp-angle": `${(Math.random() * 8 - 4).toFixed(1)}deg`,
    "--stamp-offset-x": `${(Math.random() * 10 - 5).toFixed(1)}px`,
    "--stamp-offset-y": `${(Math.random() * 6 - 3).toFixed(1)}px`,
  }) as CSSProperties, []);

  async function decide(allow: boolean) {
    setDecision(allow ? "allowing" : "denying");
    setError("");
    try {
      const endpoint = allow ? "/api/authorize/continue" : "/api/authorize/deny";
      const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      const animation = reducedMotion
        ? Promise.resolve()
        : new Promise(resolve => window.setTimeout(resolve, allow ? 860 : 540));
      const [result] = await Promise.all([
        api<{ redirect_to: string }>(endpoint, {
          method: "POST",
          body: json({ request_id: requestId, consent: allow }),
        }),
        animation,
      ]);
      window.location.assign(result.redirect_to);
    } catch (cause) {
      logUiIssue("authorization decision", cause);
      if (cause instanceof ApiError && cause.code === "login_required") {
        setDecision("idle");
        onFreshAuthenticationRequired();
        return;
      }
      setDecision("idle");
      if (isGroupAccessDenied(cause)) {
        setError(GROUP_ACCESS_DENIED_MESSAGE);
      } else if (cause instanceof ApiError && cause.code === "invalid_grant") {
        setError("This sign-in has expired. Return to the application and start again.");
      } else if (isTemporaryFailure(cause)) {
        setError("Hanko is temporarily unavailable. Please try again in a moment.");
      } else {
        setError("This request could not be completed. Please return to the application and try again.");
      }
    }
  }

  return <Scene phase="idle" className={`consent-scene consent-is-${decision}`}>
    <div className="application-mark" role="img" aria-label={`${name} application`} style={stampStyle}>
      <span className="application-initial" aria-hidden="true">{name.trim().charAt(0).toLocaleUpperCase() || "·"}</span>
      <span className="approval-stamp" aria-hidden="true">
        <HankoSeal state={decision === "allowing" ? "stamping" : "idle"} size={152} color={hankoColor ?? undefined} seed={hankoSeed ?? undefined} title="" />
      </span>
    </div>
    <Copy title={`${name} is requesting access`} />
    <ul className="claim-list">
      {(request.scopes ?? []).filter(scope => scope !== "openid").map(scope => {
        const claim = claimForScope(scope, name);
        const ClaimIcon = claim.icon;
        const scopeValues = valuesForScope(scope, request.claims);
        return <li key={scope}>
          <ClaimIcon aria-hidden="true" />
          <span className="claim-copy">
            <span className="claim-label">{claim.label}</span>
            {scopeValues.length > 0 && <span className="claim-values">{scopeValues.map(([label, value]) => <span className="claim-value" key={label}><span>{label}</span><PrivateValue>{value}</PrivateValue></span>)}</span>}
            {claim.detail && <span className="claim-detail">{claim.detail}</span>}
          </span>
        </li>;
      })}
      {(request.scopes ?? []).every(scope => scope === "openid") && <li><ShieldCheck aria-hidden="true" /><span>Confirm your identity</span></li>}
      {customClaimValues(request.claims).length > 0 && <li>
        <ShieldCheck aria-hidden="true" />
        <span className="claim-copy">
          <span className="claim-label">Additional details</span>
          <span className="claim-values">{customClaimValues(request.claims).map(([label, value]) => <span className="claim-value" key={label}><span>{label}</span><PrivateValue>{value}</PrivateValue></span>)}</span>
        </span>
      </li>}
    </ul>
    {error && <p className="inline-error" role="alert">{error}</p>}
    <div className="consent-actions">
      <button className="secondary-action" onClick={() => decide(false)} disabled={decision !== "idle"}>
        {decision === "denying" ? "Returning…" : "Cancel"}
      </button>
      <button className="primary-action" onClick={() => decide(true)} disabled={decision !== "idle"}>
        <span>{decision === "allowing" ? "Stamping…" : "Allow"}</span><ArrowRight aria-hidden="true" className="size-4" />
      </button>
    </div>
  </Scene>;
}

function valuesForScope(scope: string, claims: Record<string, unknown> | null = {}): [string, string][] {
  const claimData = claims ?? {};
  if (scope === "address") {
    const address = claimData.address;
    if (address && typeof address === "object" && !Array.isArray(address)) {
      const fields = address as Record<string, unknown>;
      if (typeof fields.formatted === "string" && fields.formatted) return [["Address", fields.formatted]];
      const labels: [string, string][] = [
        ["Street address", "street_address"],
        ["City / locality", "locality"],
        ["Region / state", "region"],
        ["Postal code", "postal_code"],
        ["Country", "country"],
      ].flatMap(([label, key]) => typeof fields[key] === "string" && fields[key] ? [[label, fields[key] as string] as [string, string]] : []);
      if (labels.length) return labels;
    }
    return [["Address", "No postal address is set"]];
  }
  const keys = scope === "profile"
    ? [["name", "Name"], ["preferred_username", "Username"], ["profile", "Profile URL"], ["given_name", "Given name"], ["family_name", "Family name"], ["nickname", "Nickname"], ["website", "Website"], ["locale", "Locale"], ["zoneinfo", "Time zone"], ["picture", "Picture"]] as const
      : scope === "email"
        ? [["email", "Email"], ["email_verified", "Email verified"]] as const
        : scope === "phone"
          ? [["phone_number", "Phone number"]] as const
      : scope === "picture"
        ? [["picture", "Picture"]] as const
        : scope === "groups"
          ? [["groups", "Groups"]] as const
          : [];
  const values = keys.flatMap(([key, label]) => {
    const value = claimData[key];
    if (value === undefined || value === null || value === "") return [];
    const display = typeof value === "boolean" ? (value ? "Yes" : "No") : Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : String(value);
    return display ? [[label, display] as [string, string]] : [];
  });
  if (values.length > 0) return values;
  if (scope === "profile") return [["Details", "No profile details are shared"]];
  if (scope === "email") return [["Email", "No email address on file"]];
  if (scope === "phone") return [["Phone number", "No phone number is set"]];
  if (scope === "picture") return [["Picture", "No profile picture is set"]];
  if (scope === "groups") return [["Groups", "No group memberships"]];
  return [];
}

function customClaimValues(claims: Record<string, unknown> | null = {}): [string, string][] {
  const claimData = claims ?? {};
  const standardClaims = new Set(["name", "preferred_username", "profile", "given_name", "family_name", "nickname", "website", "locale", "zoneinfo", "email", "email_verified", "picture", "groups", "address", "phone_number", "phone_number_verified"]);
  return Object.entries(claimData).flatMap(([label, value]) => {
    if (standardClaims.has(label) || value === undefined || value === null || value === "") return [];
    const display = Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : String(value);
    return display ? [[label, display] as [string, string]] : [];
  });
}

function claimForScope(scope: string, clientName: string): { label: string; icon: LucideIcon; detail?: string } {
  switch (scope) {
    case "profile": return { label: "Your profile", icon: UserRound };
    case "picture": return { label: "Your profile picture", detail: `Shares your custom picture or generated Hanko image with ${clientName}.`, icon: UserRound };
    case "email": return { label: "Your email address", icon: Mail };
    case "address": return { label: "Your postal address", detail: `Shares your saved address with ${clientName}.`, icon: MapPin };
    case "phone": return { label: "Your phone number", detail: `Shares your saved phone number with ${clientName}. Hanko has not verified it.`, icon: Phone };
    case "groups": return { label: "Your group memberships", icon: Users };
    case "offline_access": return {
      label: "Keep access between visits",
      detail: `Lets ${clientName} renew your sign-in in the background without asking for your passkey each time.`,
      icon: Clock3,
    };
    default: return { label: scope.replace(/[_-]+/g, " "), icon: ShieldCheck };
  }
}

function Scene({
  phase,
  className = "",
  children,
}: {
  phase: Phase;
  className?: string;
  children: ReactNode;
}) {
  return <main className={`auth-scene phase-${phase} ${className}`}>
    <div className="paper-grain" aria-hidden="true" />
    <InkWash />
    <section className="auth-panel" aria-live="polite">
      {children}
    </section>
  </main>;
}

function Copy({ title, text }: { title: string; text?: string }) {
  return <div className="auth-copy">
    <h1>{title}</h1>
    {text && <p>{text}</p>}
  </div>;
}

function Seal({ phase, size = "large", color, seed }: { phase: Phase; size?: "large" | "small"; color?: string | null; seed?: string | null }) {
  const sealSize = phase === "success" ? 176 : 112;
  return <div className={`seal-stage seal-stage-${size} seal-state-${phase}`}>
    {size === "large" && <span className="seal-shadow" aria-hidden="true">
      <HankoSeal size={sealSize} title="" />
    </span>}
    <HankoSeal className="hanko-seal" state={sealState(phase)} size={sealSize} color={color ?? undefined} seed={seed ?? undefined} title={phase === "success" ? "Sign-in complete" : "Hanko seal"} />
    <span className="seal-impression" aria-hidden="true" />
    <span className="ink-particle particle-one" aria-hidden="true" />
    <span className="ink-particle particle-two" aria-hidden="true" />
    <span className="ink-particle particle-three" aria-hidden="true" />
    <span className="ink-particle particle-four" aria-hidden="true" />
  </div>;
}

function sealState(phase: Phase): HankoState {
  return phase === "success" ? "stamping" : phase;
}

function InkWash() {
  return <svg className="ink-wash" viewBox="0 0 1440 190" preserveAspectRatio="xMidYMax slice" aria-hidden="true">
    <path d="M0 124 C75 112 98 94 163 110 C215 122 255 142 318 118 C375 97 408 80 456 103 C502 125 527 135 568 109 C612 82 657 40 710 68 C758 94 790 119 843 106 C905 91 951 49 1009 78 C1068 108 1093 145 1160 125 C1222 107 1260 71 1311 91 C1360 110 1381 124 1440 111 L1440 190 L0 190 Z" />
    <path d="M0 153 C74 143 112 127 167 138 C218 148 242 164 307 150 C361 139 394 121 451 140 C510 160 535 167 594 145 C646 125 683 91 733 111 C784 132 819 151 876 144 C933 137 967 111 1025 128 C1083 145 1127 168 1181 154 C1246 136 1284 121 1338 140 C1382 156 1406 164 1440 151 L1440 190 L0 190 Z" />
  </svg>;
}

export default App;
