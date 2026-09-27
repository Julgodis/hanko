import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

const root = ReactDOM.createRoot(document.getElementById("root")!);
const showUiPreview = import.meta.env.DEV && new URLSearchParams(window.location.search).get("ui-preview") === "1";

if (showUiPreview) {
  void import("./DevPreview").then(({ default: DevPreview }) => {
    root.render(<React.StrictMode><DevPreview /></React.StrictMode>);
  });
} else {
  root.render(<React.StrictMode><App /></React.StrictMode>);
}
