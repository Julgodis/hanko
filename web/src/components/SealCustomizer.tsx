import { Dices, Eye, EyeOff, Shuffle } from "lucide-react";
import { useState } from "react";
import { HankoSeal, type HankoState } from "./HankoSeal";
import { generateHankoPalette, makeHankoSeed, type HankoColorVariant } from "./generateHankoPath";

type Props = {
  color: string;
  seed: string;
  onColorChange: (color: string) => void;
  onSeedChange: (seed: string) => void;
};

function swatchPaint(color: string) {
  const gradient = color.match(/^linear\((#[\da-f]{6}),(#[\da-f]{6})\)$/i);
  return gradient ? `linear-gradient(135deg, ${gradient[1]}, ${gradient[2]})` : color;
}

function chooseRandom<T>(items: T[]) {
  const randomValue = new Uint32Array(1);
  crypto.getRandomValues(randomValue);
  return items[randomValue[0] % items.length];
}

const PREVIEW_STATES: { state: HankoState; label: string }[] = [
  { state: "idle", label: "Ready" },
  { state: "preparing", label: "Preparing" },
  { state: "authenticating", label: "Authenticating" },
  { state: "stamping", label: "Accepted" },
  { state: "error", label: "Not accepted" },
];

export function SealCustomizer({ color, seed, onColorChange, onSeedChange }: Props) {
  const [showPreview, setShowPreview] = useState(false);
  const [paletteSeed, setPaletteSeed] = useState(seed);
  const generatedPalette = generateHankoPalette(paletteSeed);
  const palette: HankoColorVariant[] = generatedPalette.some((variant) => variant.color === color)
    ? generatedPalette
    : [...generatedPalette, { name: "Current", color, kind: color.startsWith("linear(") ? "gradient" : "solid" }];

  function randomizeMark() {
    const nextSeed = makeHankoSeed();
    const nextPalette = generateHankoPalette(nextSeed);
    setPaletteSeed(nextSeed);
    onSeedChange(nextSeed);
    onColorChange(chooseRandom(nextPalette.slice(1)).color);
    setShowPreview(false);
  }

  function randomizeColor() {
    const nextPaletteSeed = makeHankoSeed();
    const nextPalette = generateHankoPalette(nextPaletteSeed);
    setPaletteSeed(nextPaletteSeed);
    onColorChange(chooseRandom(nextPalette.slice(1)).color);
  }

  return <section className="seal-customizer" aria-label="Hanko appearance">
    <div className="seal-customizer-controls">
      <div className="seal-color-options" role="radiogroup" aria-label="Generated Hanko colors">
        {palette.map((variant) => <button
          key={variant.name}
          className="seal-color-choice"
          type="button"
          role="radio"
          aria-checked={color === variant.color}
          aria-label={variant.name}
          title={variant.name}
          onClick={() => onColorChange(variant.color)}
        ><span style={{ background: swatchPaint(variant.color) }} /></button>)}
      </div>
      <div className="seal-customizer-actions">
        <button className="seal-tool-button" type="button" onClick={randomizeColor}><Shuffle aria-hidden="true" /> Random color</button>
        <button className="seal-tool-button" type="button" onClick={randomizeMark}><Dices aria-hidden="true" /> Random mark</button>
        <button className="seal-tool-button" type="button" aria-expanded={showPreview} onClick={() => setShowPreview((visible) => !visible)}>
          {showPreview ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
          {showPreview ? "Hide previews" : "Preview states"}
        </button>
      </div>
    </div>
    {showPreview && <div className="seal-animation-gallery" aria-label="Hanko sign-in animation states">
      {PREVIEW_STATES.map(({ state, label }) => <div className="seal-animation-card" key={state}>
        <HankoSeal key={`${seed}-${color}-${state}`} state={state} size={72} color={color} seed={seed} title={`${label} Hanko preview`} />
        <span>{label}</span>
      </div>)}
    </div>}
  </section>;
}
