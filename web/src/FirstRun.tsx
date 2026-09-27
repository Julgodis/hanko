import { ArrowLeft, ArrowRight, Check } from "lucide-react";
import { useState, type FormEvent } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { HankoSeal, type HankoState } from "./components/HankoSeal";
import { SealCustomizer } from "./components/SealCustomizer";
import { generateHankoPalette, makeHankoSeed, ORIGINAL_HANKO_GRADIENT } from "./components/generateHankoPath";
import { api, json } from "./lib/utils";

type RegistrationStart = {
  ceremony_id: string;
  publicKey: Parameters<typeof startRegistration>[0]["optionsJSON"];
};
type Step = "bootstrap" | "profile" | "hanko" | "passkey";
type Props = {
  hasSetupSession: boolean;
  invitationToken?: string | null;
  initialColor?: string;
  initialSeed?: string;
  initialProfile?: { username?: string; displayName?: string };
  onComplete: () => Promise<void>;
};
type Phase = "idle" | "preparing" | "authenticating" | "success" | "error";

function getError(error: unknown) {
  return error instanceof Error ? error.message : "The request could not be completed.";
}

const INK_WASH = <svg className="ink-wash" viewBox="0 0 1440 190" preserveAspectRatio="xMidYMax slice" aria-hidden="true">
  <path d="M0 124 C75 112 98 94 163 110 C215 122 255 142 318 118 C375 97 408 80 456 103 C502 125 527 135 568 109 C612 82 657 40 710 68 C758 94 790 119 843 106 C905 91 951 49 1009 78 C1068 108 1093 145 1160 125 C1222 107 1260 71 1311 91 C1360 110 1381 124 1440 111 L1440 190 L0 190 Z" />
  <path d="M0 153 C74 143 112 127 167 138 C218 148 242 164 307 150 C361 139 394 121 451 140 C510 160 535 167 594 145 C646 125 683 91 733 111 C784 132 819 151 876 144 C933 137 967 111 1025 128 C1083 145 1127 168 1181 154 C1246 136 1284 121 1338 140 C1382 156 1406 164 1440 151 L1440 190 L0 190 Z" />
</svg>;

export default function FirstRun({ hasSetupSession, invitationToken, initialColor, initialSeed, initialProfile, onComplete }: Props) {
  const isAdminSetup = !hasSetupSession && !invitationToken;
  const [setupSession, setSetupSession] = useState(hasSetupSession);
  const [pendingInvitation, setPendingInvitation] = useState(invitationToken ?? null);
  const [step, setStep] = useState<Step>(hasSetupSession || invitationToken ? "profile" : "bootstrap");
  const [username, setUsername] = useState(initialProfile?.username ?? "");
  const [displayName, setDisplayName] = useState(initialProfile?.displayName ?? "");
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

  const steps: { id: Step; label: string }[] = isAdminSetup
    ? [{ id: "bootstrap", label: "Bootstrap code" }, { id: "profile", label: "OIDC information" }, { id: "hanko", label: "Hanko" }, { id: "passkey", label: "Passkey" }]
    : [{ id: "profile", label: "OIDC information" }, { id: "hanko", label: "Hanko" }, { id: "passkey", label: "Passkey" }];
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
    try {
      let ready = setupSession;
      if (!ready && pendingInvitation) {
        await api("/api/invitations/consume", {
          method: "POST",
          body: json({ token: pendingInvitation }),
        });
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
        body: json({ username: username.trim() || null, display_name: displayName.trim() || null }),
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
        body: json({ ceremony_id: start.ceremony_id, credential, label: "This device" }),
      });
      setPhase("success");
      const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      await new Promise((resolve) => window.setTimeout(resolve, reducedMotion ? 120 : 620));
      await onComplete();
    } catch (registrationError) {
      setError(getError(registrationError));
      setPhase("error");
    } finally {
      setBusy(false);
    }
  }

  let title = "Enter setup code";
  if (step === "profile") {
    title = "OIDC information";
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

  return <main className={`auth-scene setup-scene phase-${phase}`}>
    <div className="paper-grain" aria-hidden="true" />
    {INK_WASH}
    <section className="setup-panel" aria-live="polite">
      <div className="auth-copy">
        <h1>{title}</h1>
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
          <small>This one-time code creates the first administrator account.</small>
        </label>
        {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
        <button className="primary-action setup-action" type="submit">
          <span>Continue</span><ArrowRight aria-hidden="true" className="setup-arrow" />
        </button>
      </form>}

      {interactive && step === "profile" && <form className="setup-form" onSubmit={continueProfile}>
        <label className="admin-field">
          <span>Username <em>Optional</em></span>
          <input autoComplete="username" autoCapitalize="none" maxLength={64} pattern="[A-Za-z0-9._-]+" value={username} onChange={(event) => setUsername(event.target.value.toLowerCase())} placeholder="Used as preferred_username" />
          <small>Passkey sign-in never asks for it. Leave blank to keep it private.</small>
        </label>
        <label className="admin-field">
          <span>Name <em>Optional</em></span>
          <input autoComplete="name" maxLength={120} value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="How apps should know you" />
          <small>Shared as the OIDC name claim when provided.</small>
        </label>
        {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
        <StepActions onBack={isAdminSetup && !setupSession ? () => { setError(""); setStep("bootstrap"); } : undefined} busy={false} label="Continue" />
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

function StepActions({ onBack, busy, label, onContinue }: { onBack?: () => void; busy: boolean; label: string; onContinue?: () => void }) {
  return <div className={`setup-step-actions ${onBack ? "has-back" : ""}`}>
    {onBack && <button className="setup-back" type="button" onClick={onBack} disabled={busy}><ArrowLeft aria-hidden="true" /> Back</button>}
    <button className="primary-action setup-action" type={onContinue ? "button" : "submit"} onClick={onContinue} disabled={busy}>
      <span>{busy ? "Saving…" : label}</span><ArrowRight aria-hidden="true" className="setup-arrow" />
    </button>
  </div>;
}
