import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const appBase = import.meta.env.BASE_URL.endsWith("/")
  ? import.meta.env.BASE_URL
  : `${import.meta.env.BASE_URL}/`;
const appRoot = appBase === "/" ? "/" : appBase.slice(0, -1);

export function appPath(path = "") {
  if (!path) return appRoot;
  return `${appBase}${path.replace(/^\/+/, "")}`;
}

export function csrfToken() {
  const prefix = "hanko_csrf=";
  const cookie = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix));
  return cookie?.slice(prefix.length) ?? "";
}

export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (init.method && !["GET", "HEAD"].includes(init.method.toUpperCase())) {
    headers.set("X-CSRF-Token", csrfToken());
  }
  const response = await fetch(appPath(path), { ...init, headers, credentials: "same-origin" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = body.error_description || body.error || body.message || "The request could not be completed.";
    throw new Error(typeof error === "string" ? error : "The request could not be completed.");
  }
  return body as T;
}

export const json = (value: unknown): string => JSON.stringify(value);
