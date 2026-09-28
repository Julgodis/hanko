import { ArrowLeft, ArrowRight, Check } from "lucide-react";
import { useState, type FormEvent } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { HankoSeal, type HankoState } from "./components/HankoSeal";
import { SealCustomizer } from "./components/SealCustomizer";
import { generateHankoPalette, makeHankoSeed, ORIGINAL_HANKO_GRADIENT } from "./components/generateHankoPath";
import { api, defaultPasskeyLabel, json } from "./lib/utils";
import { canEditUserClaim, formatAppRoles, parseAppRoles, type OidcProfileClaims } from "./lib/userClaims";

type RegistrationStart = {
  ceremony_id: string;
  publicKey: Parameters<typeof startRegistration>[0]["optionsJSON"];
};
type Step = "bootstrap" | "profile" | "hanko" | "passkey";
type OidcAddress = { street_address: string; locality: string; region: string; postal_code: string; country: string };
const EMPTY_OIDC_ADDRESS: OidcAddress = { street_address: "", locality: "", region: "", postal_code: "", country: "" };
type OidcProfileDraft = Required<Omit<OidcProfileClaims, "app_roles">> & { app_roles: string };
const EMPTY_OIDC_PROFILE: OidcProfileDraft = { profile: "", given_name: "", family_name: "", nickname: "", website: "", locale: "", zoneinfo: "", app_roles: "" };
type Props = {
  hasSetupSession: boolean;
  invitationToken?: string | null;
  initialColor?: string;
  initialSeed?: string;
  initialProfile?: { username?: string; displayName?: string; pictureUrl?: string; phoneNumber?: string; address?: Partial<OidcAddress>; profileClaims?: OidcProfileClaims };
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
  const [pictureUrl, setPictureUrl] = useState(initialProfile?.pictureUrl ?? "");
  const [phoneNumber, setPhoneNumber] = useState(initialProfile?.phoneNumber ?? "");
  const [address, setAddress] = useState<OidcAddress>({ ...EMPTY_OIDC_ADDRESS, ...(initialProfile?.address ?? {}) });
  const [profileClaims, setProfileClaims] = useState<OidcProfileDraft>({
    ...EMPTY_OIDC_PROFILE,
    ...(initialProfile?.profileClaims ?? {}),
    app_roles: formatAppRoles(initialProfile?.profileClaims?.app_roles),
  });
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

      const profileBody: Record<string, unknown> = {
        username: username.trim() || null,
        display_name: displayName.trim() || null,
      };
      if (canEditUserClaim("picture")) profileBody.picture = pictureUrl.trim();
      if (canEditUserClaim("phone_number")) profileBody.phone_number = phoneNumber.trim();
      if (canEditUserClaim("address")) {
        profileBody.address = Object.fromEntries(
          Object.entries(address).filter(([claim]) => canEditUserClaim(claim)),
        );
      }
      const profileInput: OidcProfileClaims = {};
      for (const claim of ["profile", "given_name", "family_name", "nickname", "website", "locale", "zoneinfo"] as const) {
        if (canEditUserClaim(claim)) profileInput[claim] = profileClaims[claim];
      }
      if (canEditUserClaim("app_roles")) {
        profileInput.app_roles = parseAppRoles(profileClaims.app_roles);
      }
      if (Object.keys(profileInput).length > 0) profileBody.profile_claims = profileInput;
      await api("/api/account/profile", {
        method: "PUT",
        body: json(profileBody),
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
      setError(getError(registrationError));
      setPhase("error");
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

  return <main className={`auth-scene setup-scene phase-${phase}`}>
    <div className="paper-grain" aria-hidden="true" />
    {INK_WASH}
    <section className="setup-panel" aria-live="polite">
      <div className="auth-copy">
        <h1>{title}</h1>
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
          <small>This one-time code creates the first administrator account.</small>
        </label>
        {error && <p className="admin-message admin-message-error" role="alert">{error}</p>}
        <button className="primary-action setup-action" type="submit">
          <span>Continue</span><ArrowRight aria-hidden="true" className="setup-arrow" />
        </button>
      </form>}

      {interactive && step === "profile" && <form className="setup-form" onSubmit={continueProfile}>
        {canEditUserClaim("preferred_username") && <label className="admin-field">
          <span>Username <em>Optional</em></span>
          <input autoComplete="username" autoCapitalize="none" maxLength={64} pattern={"[A-Za-z0-9._\\-]+"} value={username} onChange={(event) => setUsername(event.target.value.toLowerCase())} placeholder="Used as preferred_username" />
          <small>Passkey sign-in never asks for it. Leave blank to keep it private.</small>
        </label>}
        {canEditUserClaim("name") && <label className="admin-field">
          <span>Name <em>Optional</em></span>
          <input autoComplete="name" maxLength={120} value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="How apps should know you" />
          <small>Shared as the OIDC name claim when provided.</small>
        </label>}
        {canEditUserClaim("picture") && <label className="admin-field">
          <span>Picture URL <em>Optional</em></span>
          <input type="url" maxLength={2048} value={pictureUrl} onChange={(event) => setPictureUrl(event.target.value)} placeholder="Generated from your Hanko stamp" />
          <small>Leave blank to use a generated image matching your Hanko stamp. A custom HTTPS image URL overrides it.</small>
        </label>}
        {canEditUserClaim("phone_number") && <label className="admin-field">
          <span>Phone number <em>Optional</em></span>
          <input type="tel" autoComplete="tel" maxLength={64} value={phoneNumber} onChange={(event) => setPhoneNumber(event.target.value)} placeholder="+1 555 123 4567" />
          <small>Shared with apps that request the phone scope. Hanko does not verify phone ownership.</small>
        </label>}
        {canEditUserClaim("address") && canEditUserClaim("street_address") && <label className="admin-field">
          <span>Street address <em>Optional</em></span>
          <textarea autoComplete="street-address" maxLength={500} rows={2} value={address.street_address} onChange={(event) => setAddress((current) => ({ ...current, street_address: event.target.value }))} placeholder="Street, apartment or floor" />
          <small>Apartment and floor details can go here. Shared with apps that request the address scope.</small>
        </label>}
        {canEditUserClaim("address") && canEditUserClaim("locality") && <label className="admin-field"><span>City or locality <em>Optional</em></span><input autoComplete="address-level2" maxLength={500} value={address.locality} onChange={(event) => setAddress((current) => ({ ...current, locality: event.target.value }))} /></label>}
        {canEditUserClaim("address") && canEditUserClaim("region") && <label className="admin-field"><span>Region or state <em>Optional</em></span><input autoComplete="address-level1" maxLength={500} value={address.region} onChange={(event) => setAddress((current) => ({ ...current, region: event.target.value }))} /></label>}
        {canEditUserClaim("address") && canEditUserClaim("postal_code") && <label className="admin-field"><span>Postal code <em>Optional</em></span><input autoComplete="postal-code" maxLength={500} value={address.postal_code} onChange={(event) => setAddress((current) => ({ ...current, postal_code: event.target.value }))} /></label>}
        {canEditUserClaim("address") && canEditUserClaim("country") && <label className="admin-field"><span>Country <em>Optional</em></span><input autoComplete="country-name" maxLength={500} value={address.country} onChange={(event) => setAddress((current) => ({ ...current, country: event.target.value }))} /></label>}
        {canEditUserClaim("profile") && <label className="admin-field"><span>Profile URL <em>Optional</em></span><input type="url" maxLength={2048} value={profileClaims.profile} onChange={(event) => setProfileClaims((claims) => ({ ...claims, profile: event.target.value }))} placeholder="https://example.com/about" /></label>}
        {canEditUserClaim("given_name") && <label className="admin-field"><span>Given name <em>Optional</em></span><input autoComplete="given-name" maxLength={120} value={profileClaims.given_name} onChange={(event) => setProfileClaims((claims) => ({ ...claims, given_name: event.target.value }))} /></label>}
        {canEditUserClaim("family_name") && <label className="admin-field"><span>Family name <em>Optional</em></span><input autoComplete="family-name" maxLength={120} value={profileClaims.family_name} onChange={(event) => setProfileClaims((claims) => ({ ...claims, family_name: event.target.value }))} /></label>}
        {canEditUserClaim("nickname") && <label className="admin-field"><span>Nickname <em>Optional</em></span><input autoComplete="nickname" maxLength={120} value={profileClaims.nickname} onChange={(event) => setProfileClaims((claims) => ({ ...claims, nickname: event.target.value }))} /></label>}
        {canEditUserClaim("website") && <label className="admin-field"><span>Website <em>Optional</em></span><input type="url" maxLength={2048} value={profileClaims.website} onChange={(event) => setProfileClaims((claims) => ({ ...claims, website: event.target.value }))} placeholder="https://example.com" /></label>}
        {canEditUserClaim("locale") && <label className="admin-field"><span>Locale <em>Optional</em></span><input maxLength={128} value={profileClaims.locale} onChange={(event) => setProfileClaims((claims) => ({ ...claims, locale: event.target.value }))} placeholder="en-US" /></label>}
        {canEditUserClaim("zoneinfo") && <label className="admin-field"><span>Time zone <em>Optional</em></span><input maxLength={128} value={profileClaims.zoneinfo} onChange={(event) => setProfileClaims((claims) => ({ ...claims, zoneinfo: event.target.value }))} placeholder="Europe/Stockholm" /></label>}
        {canEditUserClaim("app_roles") && <label className="admin-field"><span>Application roles <em>Optional</em></span><textarea maxLength={4096} rows={3} value={profileClaims.app_roles} onChange={(event) => setProfileClaims((claims) => ({ ...claims, app_roles: event.target.value }))} placeholder={"hnk_client_id: viewer\nhnk_client_id: editor"} /><small>Enter one <code>client-id: role</code> per line. In that client’s custom claims, map a claim such as <code>roles</code> to <code>/app_roles/client-id</code>.</small></label>}
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
