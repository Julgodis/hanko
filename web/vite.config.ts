import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "node:path";

const apiTarget = process.env.HANKO_API ?? "http://127.0.0.1:3000";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  return {
    base: process.env.VITE_BASE_PATH ?? env.VITE_BASE_PATH ?? "/",
    plugins: [react(), tailwindcss()],
    server: {
      fs: { allow: [resolve(process.cwd(), "..")] },
      proxy: Object.fromEntries(
        ["/api", "/authorize", "/token", "/userinfo", "/logout", "/jwks", "/.well-known", "/healthz"].map((path) => [path, apiTarget]),
      ),
    },
    build: { outDir: "dist", emptyOutDir: true },
  };
});
