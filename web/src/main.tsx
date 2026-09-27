import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { PrivacyMode } from "./components/PrivacyMode";
import "./styles.css";

const root = ReactDOM.createRoot(document.getElementById("root")!);
const showUiPreview = import.meta.env.DEV && new URLSearchParams(window.location.search).get("ui-preview") === "1";
document.documentElement.dataset.privateInfo = "hidden";
if (showUiPreview) document.documentElement.dataset.uiPreview = "true";

if (showUiPreview) {
  void import("./DevPreview").then(({ default: DevPreview }) => {
    root.render(<React.StrictMode><PrivacyMode><DevPreview /></PrivacyMode></React.StrictMode>);
  });
} else {
  root.render(<React.StrictMode><PrivacyMode><App /></PrivacyMode></React.StrictMode>);
}
