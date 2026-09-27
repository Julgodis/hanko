import { startAuthentication } from "@simplewebauthn/browser";
import { ArrowRight, Check, Clock3, Fingerprint, LockKeyhole, Mail, ShieldCheck, UserRound, Users } from "lucide-react";
import { useEffect, useMemo, useState, type CSSProperties, type ReactNode } from "react";
import ClientAdmin from "./ClientAdmin";
import FirstRun from "./FirstRun";
import { HankoSeal, type HankoState } from "./components/HankoSeal";
import { PrivateValue } from "./components/PrivacyMode";
import { api, appPath, json } from "./lib/utils";

type Phase = "idle" | "preparing" | "authenticating" | "success" | "error";
type Session = {
  authenticated: boolean;
  setup_only: boolean;
  is_admin: boolean;
  hanko_color?: string | null;
  hanko_seed?: string | null;
  oidc_username?: string | null;
  oidc_name?: string | null;
};
type SetupStatus = { initialized: boolean; bootstrap_enabled: boolean };
type AuthorizationRequest = {
  client_name: string;
  scopes: string[];
  requires_fresh_authentication: boolean;
  claims?: Record<string, unknown> | null;
};
type PasskeyStart = {
  ceremony_id: string;
  publicKey: Parameters<typeof startAuthentication>[0]["optionsJSON"];
};

function App() {
  const requestId = useMemo(() => new URLSearchParams(window.location.search).get("request_id"), []);
  const enrollmentToken = useMemo(() => new URLSearchParams(window.location.search).get("enroll"), []);
  const clientsRoute = useMemo(() => {
    const routePath = appPath("admin/clients").replace(/\/+$/, "");
    return window.location.pathname.replace(/\/+$/, "") === routePath;
  }, []);
  const accountRoute = useMemo(() => {
    const routePath = appPath("account").replace(/\/+$/, "");
    return window.location.pathname.replace(/\/+$/, "") === routePath;
  }, []);
  const [session, setSession] = useState<Session | null>(null);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [request, setRequest] = useState<AuthorizationRequest | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);

  useEffect(() => {
    let active = true;
    async function load() {
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
        let authorizationRequest: AuthorizationRequest | null = null;
        if (requestId) {
          authorizationRequest = await api<AuthorizationRequest>(
            `/api/authorize/request?request_id=${encodeURIComponent(requestId)}`,
          );
        }
        if (active) {
          setSession(identity);
          setSetupStatus(setup);
          setRequest(authorizationRequest);
        }
      } catch {
        if (active) setLoadError(true);
      } finally {
        if (active) setLoading(false);
      }
    }
    void load();
    return () => { active = false; };
  }, [enrollmentToken, requestId]);

  async function refreshSession() {
    const [identity, authorizationRequest] = await Promise.all([
      api<Session>("/api/session"),
      requestId
        ? api<AuthorizationRequest>(`/api/authorize/request?request_id=${encodeURIComponent(requestId)}`)
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
        ? api<AuthorizationRequest>(`/api/authorize/request?request_id=${encodeURIComponent(requestId)}`)
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

  if (loading) {
    return <Scene phase="idle"><Seal phase="idle" /><Copy title="Hanko" text="Preparing your sign-in…" /></Scene>;
  }

  if (loadError) {
    return <Scene phase="error"><Seal phase="error" /><Copy title={requestId ? "This sign-in has expired" : "Hanko is unavailable"} text={requestId ? "Return to the application and start again." : "Please try again in a moment."} /></Scene>;
  }

  if (setupStatus && (!setupStatus.initialized || session?.setup_only || enrollmentToken)) {
    if (!setupStatus.bootstrap_enabled && !session?.setup_only && !enrollmentToken) {
      return <Scene phase="error"><Seal phase="error" /><Copy title="Hanko setup is disabled" text="Configure a bootstrap token on the server to create the first administrator." /></Scene>;
    }
    return <FirstRun
      hasSetupSession={session?.setup_only ?? false}
      invitationToken={enrollmentToken}
      initialColor={session?.hanko_color ?? undefined}
      initialSeed={session?.hanko_seed ?? undefined}
      initialProfile={{ username: session?.oidc_username ?? "", displayName: session?.oidc_name ?? "" }}
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
    return <ClientAdmin isAdmin={session.is_admin} />;
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
    return <Scene phase="success"><Seal phase="success" color={session.hanko_color} seed={session.hanko_seed} /><Success name="Hanko" /></Scene>;
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

  async function signIn() {
    setPhase("preparing");
    try {
      const start = await api<PasskeyStart>("/api/passkeys/login/options", {
        method: "POST",
        body: json({}),
      });
      const authentication = startAuthentication({ optionsJSON: start.publicKey });
      setPhase("authenticating");
      const credential = await authentication;
      await api("/api/passkeys/login/verify", {
        method: "POST",
        body: json({ ceremony_id: start.ceremony_id, credential }),
      });
      setPhase("success");
      const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      await new Promise(resolve => window.setTimeout(resolve, reducedMotion ? 120 : 820));
      await onAuthenticated();
    } catch {
      setPhase("error");
    }
  }

  function retry() {
    setPhase("idle");
  }

  let title = freshAuthentication ? "Confirm it’s you" : `Sign in to ${clientName}`;
  let text = freshAuthentication
    ? `Use your passkey again to continue to ${clientName}.`
    : "Use your passkey to continue.";
  if (phase === "preparing") {
    title = "Preparing your device…";
    text = "Follow your device prompt.";
  } else if (phase === "authenticating") {
    title = "Confirm it’s you";
    text = "Approve this sign-in on your device.";
  } else if (phase === "success") {
    title = "Welcome back";
    text = `You’re signed in to ${clientName}.`;
  } else if (phase === "error") {
    title = "Passkey wasn’t accepted";
    text = "Please try again.";
  }

  return <Scene phase={phase}>
    <Seal phase={phase} />
    <Copy title={title} text={text} />
    {phase === "idle" && <button className="primary-action" onClick={signIn}>
      <Fingerprint aria-hidden="true" className="size-[19px]" strokeWidth={1.8} />
      <span>{freshAuthentication ? "Confirm with passkey" : "Sign in with passkey"}</span>
    </button>}
    {phase === "success" && <span className="success-check" aria-label="Signed in"><Check aria-hidden="true" /></span>}
    {phase === "error" && <button className="primary-action" onClick={retry}>
      <span>Try again</span><ArrowRight aria-hidden="true" className="size-4" />
    </button>}
    {requestId && phase === "idle" && <p className="device-note"><LockKeyhole aria-hidden="true" /> Your passkey stays on your device.</p>}
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
          body: json({ request_id: requestId }),
        }),
        animation,
      ]);
      window.location.assign(result.redirect_to);
    } catch (cause) {
      if (cause instanceof Error && cause.message === "a fresh user authentication is required") {
        setDecision("idle");
        onFreshAuthenticationRequired();
        return;
      }
      setDecision("idle");
      setError("This request could not be completed. Please return to the application and try again.");
    }
  }

  return <Scene phase="idle" className={`consent-scene consent-is-${decision}`}>
    <div className="application-mark" role="img" aria-label={`${name} application`} style={stampStyle}>
      <span className="application-initial" aria-hidden="true">{name.trim().charAt(0).toLocaleUpperCase() || "·"}</span>
      <span className="approval-stamp private-value" aria-hidden="true">
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
  const keys = scope === "profile"
    ? [["name", "Name"], ["preferred_username", "Username"]] as const
    : scope === "email"
      ? [["email", "Email"]] as const
      : scope === "groups"
        ? [["groups", "Groups"]] as const
        : [];
  const values = keys.flatMap(([key, label]) => {
    const value = claimData[key];
    if (value === undefined || value === null || value === "") return [];
    const display = Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : String(value);
    return display ? [[label, display] as [string, string]] : [];
  });
  if (values.length > 0) return values;
  if (scope === "profile") return [["Details", "No profile details are shared"]];
  if (scope === "email") return [["Email", "No email address on file"]];
  if (scope === "groups") return [["Groups", "No group memberships"]];
  return [];
}

function customClaimValues(claims: Record<string, unknown> | null = {}): [string, string][] {
  const claimData = claims ?? {};
  const standardClaims = new Set(["name", "preferred_username", "email", "groups"]);
  return Object.entries(claimData).flatMap(([label, value]) => {
    if (standardClaims.has(label) || value === undefined || value === null || value === "") return [];
    const display = Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : String(value);
    return display ? [[label, display] as [string, string]] : [];
  });
}

function claimForScope(scope: string, clientName: string): { label: string; icon: typeof UserRound; detail?: string } {
  switch (scope) {
    case "profile": return { label: "Your profile", icon: UserRound };
    case "email": return { label: "Your email address", icon: Mail };
    case "groups": return { label: "Your group memberships", icon: Users };
    case "offline_access": return {
      label: "Keep access between visits",
      detail: `Lets ${clientName} renew your sign-in in the background without asking for your passkey each time.`,
      icon: Clock3,
    };
    default: return { label: scope.replace(/[_-]+/g, " "), icon: ShieldCheck };
  }
}

function Success({ name }: { name: string }) {
  return <>
    <Copy title="Welcome back" text={`You’re signed in to ${name}.`} />
    <span className="success-check" aria-label="Signed in"><Check aria-hidden="true" /></span>
  </>;
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
  return <div className={`seal-stage seal-stage-${size} seal-state-${phase}`}>
    {size === "large" && <span className="seal-shadow" aria-hidden="true">
      <HankoSeal size={112} title="" />
    </span>}
    <HankoSeal className={`hanko-seal${seed ? " private-value" : ""}`} state={sealState(phase)} size={112} color={color ?? undefined} seed={seed ?? undefined} title={seed ? "Your personal Hanko seal" : "Hanko seal"} />
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
