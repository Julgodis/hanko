import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/browser",
  use: {
    baseURL: "http://localhost:5179",
    browserName: "chromium",
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH }
      : {},
  },
  webServer: [
    {
      command: "cargo run --locked --manifest-path ../Cargo.toml",
      url: "http://127.0.0.1:38127/healthz",
      timeout: 300_000,
      env: {
        PUBLIC_ORIGIN: "http://localhost:5179",
        BIND_ADDRESS: "127.0.0.1:38127",
        DATABASE_URL: "sqlite::memory:",
        IDENTITY_MASTER_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        BOOTSTRAP_TOKEN: "browser-test-bootstrap",
      },
    },
    {
      command: "npm run dev -- --port 5179 --strictPort",
      url: "http://localhost:5179",
      env: { VITE_BASE_PATH: "/", HANKO_API: "http://127.0.0.1:38127" },
    },
  ],
});
