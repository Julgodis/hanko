import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { PrivacyMode } from "./components/PrivacyMode";
import "./styles.css";

const root = ReactDOM.createRoot(document.getElementById("root")!);
const routerBase = import.meta.env.BASE_URL.replace(/\/+$/, "") || "/";
const showUiPreview = import.meta.env.DEV && new URLSearchParams(window.location.search).get("ui-preview") === "1";
document.documentElement.dataset.privateInfo = "hidden";
if (showUiPreview) document.documentElement.dataset.uiPreview = "true";

if (showUiPreview) {
  void import("./DevPreview").then(({ default: DevPreview }) => {
    root.render(<React.StrictMode><BrowserRouter basename={routerBase}><PrivacyMode><DevPreview /></PrivacyMode></BrowserRouter></React.StrictMode>);
  });
} else {
  root.render(<React.StrictMode><BrowserRouter basename={routerBase}><PrivacyMode><App /></PrivacyMode></BrowserRouter></React.StrictMode>);
}
