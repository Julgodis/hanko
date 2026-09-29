import { ArrowLeft, ArrowRight, Check } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { HankoSeal, type HankoState } from "./components/HankoSeal";
import { SealCustomizer } from "./components/SealCustomizer";
import { generateHankoPalette, makeHankoSeed, ORIGINAL_HANKO_GRADIENT } from "./components/generateHankoPath";
import { ApiError, api, defaultPasskeyLabel, json, logUiIssue } from "./lib/utils";
import { ProfileFields } from "./components/ProfileFields";
import { buildProfilePayload, createProfileDraft, missingProfileClaims, type InitialProfile } from "./lib/profile";

type RegistrationStart = {
  ceremony_id: string;
  publicKey: Parameters<typeof startRegistration>[0]["optionsJSON"];
};
type Step = "bootstrap" | "profile" | "hanko" | "passkey";
type Props = {
  hasSetupSession: boolean;
  invitationToken?: string | null;
  loginAttemptDuringSetup?: boolean;
  initialColor?: string;
  initialSeed?: string;
  initialProfile?: InitialProfile;
  requiredUserClaims: string[];
  onComplete: () => Promise<void>;
};
type Phase = "idle" | "preparing" | "authenticating" | "success" | "error";
type InvitationStatus = "none" | "checking" | "valid" | "in_progress" | "invalid" | "error";

const INVALID_INVITATION_MESSAGE = "This invite is no longer valid. It may have expired, been revoked, already been used, or reached its user limit. Ask the person who sent it for a new invite.";

function getError(error: unknown) {
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

export default function FirstRun({ hasSetupSession, invitationToken, loginAttemptDuringSetup = false, initialColor, initialSeed, initialProfile, requiredUserClaims, onComplete }: Props) {
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
  const [error, setError] = useState("");
  const [invitationStatus, setInvitationStatus] = useState<InvitationStatus>(invitationToken ? "checking" : "none");
  const [invitationCheckAttempt, setInvitationCheckAttempt] = useState(0);

  useEffect(() => {
    if (!invitationToken) return;
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
  }, [invitationToken, invitationCheckAttempt]);

  const steps: { id: Step; label: string }[] = isAdminSetup
    ? [{ id: "bootstrap", label: "Bootstrap code" }, { id: "profile", label: "OIDC information" }, { id: "hanko", label: "Hanko" }, { id: "passkey", label: "Passkey" }]
    : [{ id: "profile", label: invitationToken ? "Your profile" : "OIDC information" }, { id: "hanko", label: "Hanko" }, { id: "passkey", label: "Passkey" }];
  const currentStep = Math.max(0, steps.findIndex((item) => item.id === step));
  const stepLabel = steps[currentStep]?.label ?? "Setup";
  const interactive = phase === "idle" || phase === "error";
  const showHanko = step === "hanko" || step === "passkey";

  function continueBootstrap(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setStep("profile");
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

  async function registerPasskey() {
    setError("");
    setBusy(true);
    setPhase("preparing");
    let inviteReserved = Boolean(invitationToken && setupSession);
    try {
      let ready = setupSession;
      if (!ready && pendingInvitation) {
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
      } else if (!ready && isAdminSetup) {
        await api("/api/bootstrap", {
          method: "POST",
          body: json({ token: bootstrapToken }),
        });
        setBootstrapToken("");
        ready = true;
        setSetupSession(true);
      }
      if (!ready) throw new Error("This setup session could not be started.");

      await api("/api/account/profile", {
        method: "PUT",
        body: json(buildProfilePayload(profileDraft, requiredUserClaims)),
      });
      await api("/api/account/hanko", {
        method: "PUT",
        body: json({ color: hankoColor, seed: hankoSeed }),
      });
      const start = await api<RegistrationStart>("/api/passkeys/register/options", {
        method: "POST",
        body: json({}),
      });
      const credentialPromise = startRegistration({ optionsJSON: start.publicKey });
      setPhase("authenticating");
      const credential = await credentialPromise;
      await api("/api/passkeys/register/verify", {
        method: "POST",
        body: json({ ceremony_id: start.ceremony_id, credential, label: defaultPasskeyLabel(new Date()) }),
      });
      setPhase("success");
      const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      await new Promise((resolve) => window.setTimeout(resolve, reducedMotion ? 120 : 620));
      await onComplete();
    } catch (registrationError) {
      if (registrationError instanceof Error && registrationError.message === INVALID_INVITATION_MESSAGE) {
        setStep("profile");
        setError("");
        setPhase("idle");
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
    title = "Preparing your device…";
  } else if (phase === "authenticating") {
    title = "Confirm it’s you";
  } else if (phase === "success") {
    title = "Your passkey is ready";
  } else if (phase === "error" && step === "passkey") {
    title = "Setup couldn’t be completed";
  }

  const sealState: HankoState = phase === "success" ? "stamping" : phase;

  if (invitationToken && invitationStatus === "invalid") {
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
          <input type="password" autoComplete="off" value={bootstrapToken} onChange={(event) => setBootstrapToken(event.target.value)} placeholder="From the server’s environment" />
          <small>This code creates the first administrator account or resumes setup before its first passkey is saved.</small>
        </label>
        {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
        <button className="primary-action setup-action" type="submit">
          <span>Continue</span><ArrowRight aria-hidden="true" className="setup-arrow" />
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
        <StepActions onBack={() => { setError(""); setStep("hanko"); }} busy={busy} label={phase === "error" ? "Try again" : "Register passkey"} onContinue={registerPasskey} />
      </div>}

      {(phase === "preparing" || phase === "authenticating") && <p className="setup-status">{phase === "preparing" ? "Preparing passkey registration" : "Follow your device prompt"}</p>}
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
