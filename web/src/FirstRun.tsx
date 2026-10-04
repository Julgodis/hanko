import type { RegistrationStart } from "./lib/apiTypes";
import { ArrowLeft, ArrowRight, Check } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { HankoSeal, type HankoState } from "./components/HankoSeal";
import { SealCustomizer } from "./components/SealCustomizer";
import { generateHankoPalette, makeHankoSeed, ORIGINAL_HANKO_GRADIENT } from "./components/generateHankoPath";
import { ApiError, api, defaultPasskeyLabel, json, logUiIssue } from "./lib/utils";
import { ProfileFields } from "./components/ProfileFields";
import { buildProfilePayload, createProfileDraft, missingProfileClaims, type InitialProfile } from "./lib/profile";

type Step = "bootstrap" | "profile" | "hanko" | "passkey";
type Props = {
  hasSetupSession: boolean;
  invitationToken?: string | null;
  loginAttemptDuringSetup?: boolean;
  initialColor?: string;
  initialSeed?: string;
  initialProfile?: InitialProfile;
  requiredUserClaims: string[];
  onRegistrationComplete: () => void;
  onComplete: () => Promise<void>;
};
type Phase = "idle" | "preparing" | "authenticating" | "success" | "error";
type InvitationStatus = "none" | "checking" | "valid" | "in_progress" | "invalid" | "error";
type PasskeyDiagnosticReport = {
  occurred_at: string;
  operation: string;
  stage: string;
  page: string;
  browser: {
    user_agent: string;
    platform: string;
    language: string;
    secure_context: boolean;
    web_authn_available: boolean;
  };
  requested_passkey?: {
    resident_key: string | null;
    require_resident_key: boolean | null;
    cred_props: boolean | null;
  };
  browser_credential_result?: {
    client_extension_results_present: boolean;
    cred_props_present: boolean;
    cred_props_rk: boolean | "missing" | "invalid";
  };
  failure: {
    name: string;
    message: string;
    http_status: number | null;
    error_code: string | null;
    diagnostic_id: string | null;
  };
};

function credentialDiscoverabilityResult(credential: unknown): PasskeyDiagnosticReport["browser_credential_result"] {
  if (!credential || typeof credential !== "object") return undefined;
  const root = credential as Record<string, unknown>;
  const extensions = root.clientExtensionResults && typeof root.clientExtensionResults === "object"
    ? root.clientExtensionResults as Record<string, unknown>
    : null;
  const hasCredProps = Boolean(extensions && Object.hasOwn(extensions, "credProps"));
  const credProps = extensions?.credProps && typeof extensions.credProps === "object"
    ? extensions.credProps as Record<string, unknown>
    : null;
  const rk = credProps && Object.hasOwn(credProps, "rk") ? credProps.rk : undefined;
  return {
    client_extension_results_present: extensions !== null,
    cred_props_present: hasCredProps,
    cred_props_rk: typeof rk === "boolean" ? rk : rk === undefined ? "missing" : "invalid",
  };
}

const INVALID_INVITATION_MESSAGE = "This invite is no longer valid. It may have expired, been revoked, already been used, or reached its user limit. Ask the person who sent it for a new invite.";

function getError(error: unknown) {
  if (error instanceof ApiError && error.diagnosticId) {
    return `${error.message} (Support reference: ${error.diagnosticId})`;
  }
  return error instanceof Error ? error.message : "The request could not be completed.";
}

function registrationCapacityMessage(retryAfterSeconds: number | null, inviteReserved: boolean) {
  let wait = "Try again shortly.";
  if (retryAfterSeconds != null && retryAfterSeconds < 60) {
    const seconds = Math.max(1, retryAfterSeconds);
    wait = `Try again in about ${seconds} second${seconds === 1 ? "" : "s"}.`;
  } else if (retryAfterSeconds != null) {
    const minutes = Math.ceil(retryAfterSeconds / 60);
    wait = `Try again in about ${minutes} minute${minutes === 1 ? "" : "s"}.`;
  }
  return `${inviteReserved ? "Your invite is reserved for this setup and won’t count until you finish adding a passkey. " : ""}There are too many active passkey registration requests right now. ${wait}`;
}

const INK_WASH = <svg className="ink-wash" viewBox="0 0 1440 190" preserveAspectRatio="xMidYMax slice" aria-hidden="true">
  <path d="M0 124 C75 112 98 94 163 110 C215 122 255 142 318 118 C375 97 408 80 456 103 C502 125 527 135 568 109 C612 82 657 40 710 68 C758 94 790 119 843 106 C905 91 951 49 1009 78 C1068 108 1093 145 1160 125 C1222 107 1260 71 1311 91 C1360 110 1381 124 1440 111 L1440 190 L0 190 Z" />
  <path d="M0 153 C74 143 112 127 167 138 C218 148 242 164 307 150 C361 139 394 121 451 140 C510 160 535 167 594 145 C646 125 683 91 733 111 C784 132 819 151 876 144 C933 137 967 111 1025 128 C1083 145 1127 168 1181 154 C1246 136 1284 121 1338 140 C1382 156 1406 164 1440 151 L1440 190 L0 190 Z" />
</svg>;

export default function FirstRun({ hasSetupSession, invitationToken, loginAttemptDuringSetup = false, initialColor, initialSeed, initialProfile, requiredUserClaims, onRegistrationComplete, onComplete }: Props) {
  const isAdminSetup = !hasSetupSession && !invitationToken;
  const [setupSession, setSetupSession] = useState(hasSetupSession);
  const [pendingInvitation, setPendingInvitation] = useState(invitationToken ?? null);
  const [step, setStep] = useState<Step>(hasSetupSession || invitationToken ? "profile" : "bootstrap");
  const [profileDraft, setProfileDraft] = useState(() => createProfileDraft(initialProfile));
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [initialMark] = useState(() => {
    const seed = initialSeed ?? makeHankoSeed();
    const color = initialColor === "#d64135" ? ORIGINAL_HANKO_GRADIENT : initialColor;
    return { seed, color: color ?? generateHankoPalette(seed)[0].color };
  });
  const [hankoColor, setHankoColor] = useState(initialMark.color);
  const [hankoSeed, setHankoSeed] = useState(initialMark.seed);
  const [phase, setPhase] = useState<Phase>("idle");
  const [busy, setBusy] = useState(false);
  const [registrationComplete, setRegistrationComplete] = useState(false);
  const [passkeyDiscoverable, setPasskeyDiscoverable] = useState<boolean | null>(null);
  const [error, setError] = useState("");
  const [diagnosticReport, setDiagnosticReport] = useState<PasskeyDiagnosticReport | null>(null);
  const [diagnosticCopyMessage, setDiagnosticCopyMessage] = useState("");
  const [invitationStatus, setInvitationStatus] = useState<InvitationStatus>(invitationToken ? "checking" : "none");
  const [invitationCheckAttempt, setInvitationCheckAttempt] = useState(0);

  useEffect(() => {
    if (!invitationToken || registrationComplete) return;
    let active = true;
    setInvitationStatus("checking");
    api<{ valid: boolean; in_progress: boolean }>("/api/invitations/validate", {
      method: "POST",
      body: json({ token: invitationToken }),
    }).then(({ valid, in_progress }) => {
      if (active) {
        if (!valid && !in_progress) {
          logUiIssue("validate invitation", new Error("Invitation is invalid or unavailable"));
        }
        setInvitationStatus(valid ? "valid" : in_progress ? "in_progress" : "invalid");
      }
    }).catch((cause) => {
      if (active) {
        logUiIssue("validate invitation", cause);
        setInvitationStatus("error");
      }
    });
    return () => { active = false; };
  }, [invitationToken, invitationCheckAttempt, registrationComplete]);

  const steps: { id: Step; label: string }[] = isAdminSetup
    ? [{ id: "bootstrap", label: "Bootstrap code" }, { id: "profile", label: "OIDC information" }, { id: "hanko", label: "Hanko" }, { id: "passkey", label: "Passkey" }]
    : [{ id: "profile", label: invitationToken ? "Your profile" : "OIDC information" }, { id: "hanko", label: "Hanko" }, { id: "passkey", label: "Passkey" }];
  const currentStep = Math.max(0, steps.findIndex((item) => item.id === step));
  const stepLabel = steps[currentStep]?.label ?? "Setup";
  const interactive = phase === "idle" || phase === "error";
  const showHanko = step === "hanko" || step === "passkey";

  async function continueBootstrap(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || !bootstrapToken.trim()) return;
    setBusy(true);
    setError("");
    try {
      await api("/api/bootstrap", { method: "POST", body: json({ token: bootstrapToken }) });
      setBootstrapToken("");
      setSetupSession(true);
      setStep("profile");
    } catch (cause) {
      logUiIssue("validate bootstrap code", cause);
      setError(cause instanceof ApiError && cause.status === 401
        ? "The setup code was not accepted. Check the code and try again."
        : getError(cause));
    } finally {
      setBusy(false);
    }
  }

  function continueProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const missing = missingProfileClaims(profileDraft, requiredUserClaims);
    if (missing.length) {
      setError(`Complete the required fields: ${missing.join(", ")}.`);
      return;
    }
    setError("");
    setStep("hanko");
  }

  function continueHanko(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setStep("passkey");
  }

  async function copyDiagnosticReport() {
    if (!diagnosticReport) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(diagnosticReport, null, 2));
      setDiagnosticCopyMessage("Diagnostic details copied. Send them to your administrator.");
    } catch {
      setDiagnosticCopyMessage("Copy is unavailable here. Open the details below, then press and hold the report to copy it.");
    }
  }

  async function registerPasskey() {
    if (busy) return;
    if (registrationComplete) {
      setBusy(true);
      setError("");
      setPhase("preparing");
      try {
        await onComplete();
      } catch (completionError) {
        logUiIssue("finish account setup", completionError);
        setError(`Your passkey is registered, but your account could not be loaded yet. Try again to continue. ${getError(completionError)}`);
        setPhase("error");
      } finally {
        setBusy(false);
      }
      return;
    }

    setError("");
    setDiagnosticReport(null);
    setDiagnosticCopyMessage("");
    setPasskeyDiscoverable(null);
    setBusy(true);
    setPhase("preparing");
    let inviteReserved = Boolean(invitationToken && setupSession);
    let passkeyRegistered = false;
    let diagnosticStage = "prepare_registration";
    let requestedPasskey: PasskeyDiagnosticReport["requested_passkey"] = undefined;
    let browserCredentialResult: PasskeyDiagnosticReport["browser_credential_result"] = undefined;
    try {
      let ready = setupSession;
      if (!ready && pendingInvitation) {
        diagnosticStage = "consume_invitation";
        try {
          await api("/api/invitations/consume", {
            method: "POST",
            body: json({ token: pendingInvitation }),
          });
        } catch (consumeError) {
          if (consumeError instanceof ApiError && consumeError.status === 401) {
            try {
              await api("/api/invitations/validate", {
                method: "POST",
                body: json({ token: pendingInvitation }),
              });
            } catch {
              // The consume response already identifies this invitation as unavailable.
            }
            setInvitationStatus("invalid");
            throw new Error(INVALID_INVITATION_MESSAGE);
          }
          throw consumeError;
        }
        inviteReserved = true;
        setPendingInvitation(null);
        ready = true;
        setSetupSession(true);
      }
      if (!ready) throw new Error("This setup session could not be started.");

      diagnosticStage = "save_profile";
      await api("/api/account/profile", {
        method: "PUT",
        body: json(buildProfilePayload(profileDraft, requiredUserClaims)),
      });
      await api("/api/account/hanko", {
        method: "PUT",
        body: json({ color: hankoColor, seed: hankoSeed }),
      });
      diagnosticStage = "request_registration_options";
      const start = await api<RegistrationStart>("/api/passkeys/register/options", {
        method: "POST",
        body: json({}),
      });
      const publicKeyOptions = start.publicKey as unknown as {
        authenticatorSelection?: Record<string, unknown>;
        extensions?: Record<string, unknown>;
      };
      const residentKey = publicKeyOptions.authenticatorSelection?.residentKey;
      const requireResidentKey = publicKeyOptions.authenticatorSelection?.requireResidentKey;
      const credProps = publicKeyOptions.extensions?.credProps;
      requestedPasskey = {
        resident_key: typeof residentKey === "string" ? residentKey : null,
        require_resident_key: typeof requireResidentKey === "boolean" ? requireResidentKey : null,
        cred_props: typeof credProps === "boolean" ? credProps : null,
      };
      diagnosticStage = "browser_passkey_creation";
      const credentialPromise = startRegistration({ optionsJSON: start.publicKey });
      setPhase("authenticating");
      const credential = await credentialPromise;
      browserCredentialResult = credentialDiscoverabilityResult(credential);
      diagnosticStage = "verify_registration";
      const verification = await api<{ discoverable?: boolean | null }>("/api/passkeys/register/verify", {
        method: "POST",
        body: json({ ceremony_id: start.ceremony_id, credential, label: defaultPasskeyLabel(new Date()) }),
      });
      passkeyRegistered = true;
      setPasskeyDiscoverable(verification.discoverable ?? null);
      setRegistrationComplete(true);
      onRegistrationComplete();
      setPhase("success");
      if (verification.discoverable === false) return;
      const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      await new Promise((resolve) => window.setTimeout(resolve, reducedMotion ? 120 : 620));
      diagnosticStage = "finish_account_setup";
      await onComplete();
    } catch (registrationError) {
      const apiError = registrationError instanceof ApiError ? registrationError : null;
      setDiagnosticReport({
        occurred_at: new Date().toISOString(),
        operation: "first_run_passkey_registration",
        stage: diagnosticStage,
        page: window.location.pathname,
        browser: {
          user_agent: navigator.userAgent,
          platform: navigator.platform,
          language: navigator.language,
          secure_context: window.isSecureContext,
          web_authn_available: typeof window.PublicKeyCredential !== "undefined",
        },
        ...(requestedPasskey ? { requested_passkey: requestedPasskey } : {}),
        ...(browserCredentialResult ? { browser_credential_result: browserCredentialResult } : {}),
        failure: {
          name: registrationError instanceof Error ? registrationError.name : "UnknownError",
          message: registrationError instanceof Error ? registrationError.message : "The request could not be completed.",
          http_status: apiError?.status ?? null,
          error_code: apiError?.code || null,
          diagnostic_id: apiError?.diagnosticId ?? null,
        },
      });
      if (registrationError instanceof Error && registrationError.message === INVALID_INVITATION_MESSAGE) {
        setStep("profile");
        setError("");
        setPhase("idle");
      } else if (passkeyRegistered) {
        logUiIssue("finish account setup", registrationError);
        setError(`Your passkey is registered, but your account could not be loaded yet. Try again to continue. ${getError(registrationError)}`);
        setPhase("error");
      } else {
        logUiIssue("complete account setup", registrationError);
        const invitationMayHaveExpired = registrationError instanceof ApiError && (
          registrationError.status === 401
          || registrationError.code === "could not start passkey registration"
          || registrationError.code === "passkey registration failed"
        );
        if (invitationToken && inviteReserved && invitationMayHaveExpired) {
          try {
            const invitation = await api<{ valid: boolean; in_progress: boolean }>("/api/invitations/validate", {
              method: "POST",
              body: json({ token: invitationToken }),
            });
            if (!invitation.valid && !invitation.in_progress) {
              setInvitationStatus("invalid");
              setStep("profile");
              setError("");
              setPhase("idle");
              return;
            }
          } catch {
            // Keep the registration error visible if invite status cannot be checked.
          }
        }
        setError(registrationError instanceof ApiError && registrationError.code === "too many active registration requests; try again shortly"
          ? registrationCapacityMessage(registrationError.retryAfterSeconds, inviteReserved)
          : getError(registrationError));
        setPhase("error");
      }
    } finally {
      setBusy(false);
    }
  }

  let title = "Enter setup code";
  if (step === "profile") {
    title = invitationToken ? "Set up your account" : "OIDC information";
  } else if (step === "hanko") {
    title = "Create your Hanko";
  } else if (step === "passkey") {
    title = "Add a passkey";
  }
  if (phase === "preparing") {
    title = registrationComplete ? "Finishing setup…" : "Preparing your device…";
  } else if (phase === "authenticating") {
    title = "Confirm it’s you";
  } else if (phase === "success") {
    title = "Your passkey is ready";
  } else if (phase === "error" && step === "passkey") {
    title = registrationComplete ? "Your account is ready" : "Setup couldn’t be completed";
  }

  const sealState: HankoState = phase === "success" ? "stamping" : phase;

  if (invitationToken && invitationStatus === "invalid" && !registrationComplete) {
    return <main className="auth-scene setup-scene phase-error">
      <div className="paper-grain" aria-hidden="true" />
      {INK_WASH}
      <section className="setup-panel" aria-live="polite">
        <div className="auth-copy">
          <h1>Invite link unavailable</h1>
          <p>{INVALID_INVITATION_MESSAGE}</p>
        </div>
        <div className="first-run-seal-stage">
          <HankoSeal state="error" size={216} title="Invite link unavailable" color={hankoColor} seed={hankoSeed} />
        </div>
      </section>
    </main>;
  }

  return <main className={`auth-scene setup-scene phase-${phase}`}>
    <div className="paper-grain" aria-hidden="true" />
    {INK_WASH}
    <section className="setup-panel" aria-live="polite">
      <div className="auth-copy">
        <h1>{title}</h1>
        {loginAttemptDuringSetup && <p className="setup-status" role="status">Finish the invitation or first-run setup before signing in.</p>}
        {invitationToken && step === "profile" && <p>Choose the profile details apps can see. Next, you’ll create your Hanko and add a passkey.</p>}
      </div>

      <div className="setup-progress" aria-label={`${stepLabel}, step ${currentStep + 1} of ${steps.length}`}>
        <span className="setup-progress-caption">{stepLabel}</span>
        <span className="setup-progress-count">{currentStep + 1} / {steps.length}</span>
        <div className="setup-progress-track" aria-hidden="true">
          {steps.map((item, index) => <span key={item.id} className={index <= currentStep ? "is-complete" : ""} />)}
        </div>
      </div>

      {showHanko && <div className="first-run-seal-stage">
        <HankoSeal state={sealState} size={216} title="Your Hanko seal" color={hankoColor} seed={hankoSeed} />
      </div>}

      {interactive && step === "bootstrap" && <form className="setup-form" onSubmit={continueBootstrap}>
        <label className="admin-field">
          <span>Bootstrap code</span>
          <input type="password" required disabled={busy} autoComplete="off" value={bootstrapToken} onChange={(event) => setBootstrapToken(event.target.value)} placeholder="From the server’s environment" />
          <small>This code creates the first administrator account or resumes setup before its first passkey is saved.</small>
        </label>
        {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
        <button className="primary-action setup-action" type="submit" disabled={busy || !bootstrapToken.trim()}>
          <span>{busy ? "Checking…" : "Continue"}</span><ArrowRight aria-hidden="true" className="setup-arrow" />
        </button>
      </form>}

      {interactive && step === "profile" && <form className="setup-form" onSubmit={continueProfile}>
        {invitationToken && invitationStatus === "checking" && <p className="setup-status" role="status">Checking whether this invite can still be used…</p>}
        {invitationToken && invitationStatus === "valid" && <p className="setup-status" role="status">This invite is valid and ready to use.</p>}
        {invitationToken && invitationStatus === "in_progress" && <p className="admin-message" role="status">This invite is reserved while someone finishes setting up an account. It only counts if setup completes; if setup is abandoned, it becomes available again when their setup session expires, as long as the invite hasn’t expired.</p>}
        {invitationToken && invitationStatus === "invalid" && <p className="admin-message admin-message-error" role="alert">{INVALID_INVITATION_MESSAGE}</p>}
        {invitationToken && invitationStatus === "error" && <div className="setup-invitation-check-error"><p className="admin-message admin-message-error" role="alert">We couldn’t check this invite right now. Try again when you’re back online.</p><button className="setup-back" type="button" onClick={() => setInvitationCheckAttempt((attempt) => attempt + 1)}>Check invite again</button></div>}
        <ProfileFields value={profileDraft} onChange={setProfileDraft} requiredUserClaims={requiredUserClaims} />
        {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
        <StepActions onBack={isAdminSetup && !setupSession ? () => { setError(""); setStep("bootstrap"); } : undefined} busy={false} disabled={Boolean(invitationToken && !setupSession && invitationStatus !== "valid")} label="Continue" />
      </form>}

      {interactive && step === "hanko" && <form className="setup-form" onSubmit={continueHanko}>
        <SealCustomizer color={hankoColor} seed={hankoSeed} onColorChange={setHankoColor} onSeedChange={setHankoSeed} />
        {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
        <StepActions onBack={() => { setError(""); setStep("profile"); }} busy={false} label="Continue" />
      </form>}

      {interactive && step === "passkey" && <div className="setup-form">
        {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
        {diagnosticReport && phase === "error" && <section className="setup-diagnostics" aria-label="Support diagnostics">
          <p>These details include your browser and the passkey error, but not your invite code or passkey credential.</p>
          <button className="setup-diagnostics-copy" type="button" onClick={() => void copyDiagnosticReport()}>Copy diagnostic details</button>
          {diagnosticCopyMessage && <p className="setup-diagnostics-status" role="status">{diagnosticCopyMessage}</p>}
          <details>
            <summary>View details</summary>
            <pre tabIndex={0}>{JSON.stringify(diagnosticReport, null, 2)}</pre>
          </details>
        </section>}
        <StepActions onBack={registrationComplete ? undefined : () => { setError(""); setStep("hanko"); }} busy={busy} label={registrationComplete ? "Continue to account" : phase === "error" ? "Try again" : "Register passkey"} onContinue={registerPasskey} />
      </div>}

      {registrationComplete && passkeyDiscoverable === false && <div className="setup-form">
        <p className="admin-message setup-passkey-warning" role="status">This passkey isn’t discoverable. At sign-in, choose “Passkey not listed? Use account name” and enter your account username or email.</p>
        {phase === "success" && <StepActions busy={busy} label="Continue to account" onContinue={registerPasskey} />}
      </div>}

      {(phase === "preparing" || phase === "authenticating") && <p className="setup-status">{phase === "preparing" ? registrationComplete ? "Loading your account" : "Preparing passkey registration" : "Follow your device prompt"}</p>}
      {phase === "success" && <span className="success-check" aria-label="Passkey registered"><Check aria-hidden="true" /></span>}
    </section>
  </main>;
}

function StepActions({ onBack, busy, disabled = false, label, onContinue }: { onBack?: () => void; busy: boolean; disabled?: boolean; label: string; onContinue?: () => void }) {
  return <div className={`setup-step-actions ${onBack ? "has-back" : ""}`}>
    {onBack && <button className="setup-back" type="button" onClick={onBack} disabled={busy}><ArrowLeft aria-hidden="true" /> Back</button>}
    <button className="primary-action setup-action" type={onContinue ? "button" : "submit"} onClick={onContinue} disabled={busy || disabled}>
      <span>{busy ? "Saving…" : label}</span><ArrowRight aria-hidden="true" className="setup-arrow" />
    </button>
  </div>;
}
