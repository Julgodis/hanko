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

export class ApiError extends Error {
  constructor(message: string, readonly code: string, readonly status: number, readonly retryAfterSeconds: number | null = null) {
    super(message);
    this.name = "ApiError";
  }
}

export function logUiIssue(context: string, cause: unknown) {
  const details = cause instanceof ApiError
    ? {
        error: cause.message,
        error_code: cause.code || undefined,
        status: cause.status,
        retry_after_seconds: cause.retryAfterSeconds ?? undefined,
      }
    : cause instanceof Error
      ? { error: cause.message, error_type: cause.name }
      : { error: "Unknown error", error_type: "UnknownError" };
  const log = cause instanceof ApiError && cause.status >= 500 ? console.error : console.warn;
  log.call(console, "Hanko UI issue", { context, ...details });
}

export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (init.method && !["GET", "HEAD"].includes(init.method.toUpperCase())) {
    headers.set("X-CSRF-Token", csrfToken());
  }
  const response = await fetch(appPath(path), { ...init, headers, credentials: "same-origin" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = body.error_description || body.error || body.message || "The request could not be completed.";
    const retryAfterHeader = response.headers.get("Retry-After");
    throw new ApiError(
      typeof error === "string" ? error : "The request could not be completed.",
      typeof body.error === "string" ? body.error : "",
      response.status,
      retryAfterHeader && Number.isFinite(Number(retryAfterHeader))
        ? Math.max(0, Number(retryAfterHeader))
        : null,
    );
  }
  return body as T;
}

export const json = (value: unknown): string => JSON.stringify(value);

export function defaultPasskeyLabel(addedAt = new Date()) {
  const navigatorInfo = navigator as Navigator & { userAgentData?: { platform?: string } };
  const platform = `${navigatorInfo.userAgentData?.platform ?? ""} ${navigator.platform} ${navigator.userAgent}`.toLowerCase();
  let device = "This device";

  if (/iphone|ipod/.test(platform)) device = "iPhone";
  else if (/ipad/.test(platform) || (/macintel/.test(platform) && navigator.maxTouchPoints > 1)) device = "iPad";
  else if (/android/.test(platform)) device = "Android device";
  else if (/macintosh|macintel|macos/.test(platform)) device = "Mac";
  else if (/windows|win32|win64/.test(platform)) device = "Windows PC";
  else if (/cros/.test(platform)) device = "Chromebook";
  else if (/linux/.test(platform)) device = "Linux computer";

  const time = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(addedAt);
  return `${device} · added ${time}`;
}
