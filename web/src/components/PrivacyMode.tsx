import { Eye, EyeOff } from "lucide-react";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

const PrivacyContext = createContext(false);

export function PrivacyMode({ children }: { children: ReactNode }) {
  const [hidden, setHidden] = useState(true);

  useEffect(() => {
    document.documentElement.dataset.privateInfo = hidden ? "hidden" : "visible";
  }, [hidden]);

  return <PrivacyContext.Provider value={hidden}>
    {children}
    <button
      type="button"
      className="privacy-toggle"
      aria-pressed={!hidden}
      onClick={() => setHidden((value) => !value)}
    >
      {hidden ? <Eye aria-hidden="true" /> : <EyeOff aria-hidden="true" />}
      <span>{hidden ? "Show private info" : "Hide private info"}</span>
    </button>
  </PrivacyContext.Provider>;
}

export function PrivateValue({ children, className = "" }: { children: ReactNode; className?: string }) {
  const hidden = useContext(PrivacyContext);
  return <span className={`private-value${className ? ` ${className}` : ""}`} data-private-hidden={hidden || undefined}>{children}</span>;
}
