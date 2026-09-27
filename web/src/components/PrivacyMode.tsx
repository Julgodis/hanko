import { Eye, EyeOff } from "lucide-react";
import { createContext, useContext, useEffect, useId, useState, type KeyboardEvent, type MouseEvent, type ReactNode } from "react";

type PrivacyContextValue = {
  hidden: boolean;
  overrides: Record<string, boolean>;
  revealValue: (id: string, currentlyHidden: boolean) => void;
};

const PrivacyContext = createContext<PrivacyContextValue>({
  hidden: true,
  overrides: {},
  revealValue: () => undefined,
});

export function PrivacyMode({ children }: { children: ReactNode }) {
  const [hidden, setHidden] = useState(true);
  const [overrides, setOverrides] = useState<Record<string, boolean>>({});

  useEffect(() => {
    document.documentElement.dataset.privateInfo = hidden ? "hidden" : "visible";
  }, [hidden]);

  function toggleAll() {
    setOverrides({});
    setHidden((value) => !value);
  }

  function revealValue(id: string, currentlyHidden: boolean) {
    setOverrides((current) => ({ ...current, [id]: !currentlyHidden }));
  }

  return <PrivacyContext.Provider value={{ hidden, overrides, revealValue }}>
    {children}
    <button
      type="button"
      className="privacy-toggle"
      aria-label={hidden ? "Show private information" : "Hide private information"}
      title={hidden ? "Show private information" : "Hide private information"}
      aria-pressed={!hidden}
      onClick={toggleAll}
    >
      {hidden ? <Eye aria-hidden="true" /> : <EyeOff aria-hidden="true" />}
    </button>
  </PrivacyContext.Provider>;
}

export function PrivateValue({ children, className = "" }: { children: ReactNode; className?: string }) {
  const { hidden, overrides, revealValue } = useContext(PrivacyContext);
  const id = useId();
  const isHidden = overrides[id] ?? hidden;

  function toggleValue(event: MouseEvent<HTMLSpanElement> | KeyboardEvent<HTMLSpanElement>) {
    event.preventDefault();
    event.stopPropagation();
    revealValue(id, isHidden);
  }

  return <span
    className={`private-value${className ? ` ${className}` : ""}`}
    role="button"
    tabIndex={0}
    data-private-hidden={isHidden || undefined}
    aria-label={isHidden ? "Reveal hidden information" : undefined}
    aria-pressed={!isHidden}
    onClick={toggleValue}
    onKeyDown={(event) => {
      if (event.key === "Enter" || event.key === " ") toggleValue(event);
    }}
  >{children}</span>;
}
