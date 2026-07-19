/** Auth helpers: signup/login/refresh/logout API calls + client-side token storage. */

"use client";

import { apiFetch } from "./api";

const TOKEN_KEY = "octo_token";

export type User = { id: string; email: string };
export type AuthResult = { token: string; user: User };

export async function signup(email: string, password: string): Promise<AuthResult> {
  return apiFetch<AuthResult>("/v1/auth/signup", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function login(email: string, password: string): Promise<AuthResult> {
  return apiFetch<AuthResult>("/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function me(token: string): Promise<User> {
  return apiFetch<User>("/v1/auth/me", { token });
}

/**
 * Refresh the current session token.
 *
 * Sends the current token to POST /v1/auth/refresh. The server atomically revokes the old
 * token and issues a new one. The returned token MUST overwrite the stored one — calling code
 * must call saveToken(result.token) immediately after this resolves.
 *
 * Never hold onto the old token after a successful refresh: the server has already revoked it
 * and any request carrying it will receive 401.
 */
export async function refreshToken(token: string): Promise<AuthResult> {
  const result = await apiFetch<AuthResult>("/v1/auth/refresh", {
    method: "POST",
    token,
  });
  // Immediately overwrite the stored token — never hold both simultaneously.
  saveToken(result.token);
  return result;
}

/**
 * Log out: revoke the current token on the server, then clear it locally.
 *
 * The server inserts the token into the deny-list so it cannot be replayed even within its
 * original TTL window. Local storage is cleared regardless of whether the server call succeeds
 * so the user is always logged out client-side.
 */
export async function logoutRequest(token: string): Promise<void> {
  try {
    await apiFetch<unknown>("/v1/auth/logout", {
      method: "POST",
      token,
    });
  } finally {
    // Always clear locally, even if the server request failed (network error, already
    // revoked, etc.) — the user experience must be "logged out" either way.
    clearToken();
  }
}

// --- token storage (localStorage; bearer-token auth, not cookies) ---

/** Overwrite the stored token with a new one. Always use this after login, signup, or refresh. */
export function saveToken(token: string) {
  if (typeof window !== "undefined") localStorage.setItem(TOKEN_KEY, token);
}

/** Read the current stored token. Returns null if not set or running server-side. */
export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

/** Remove the stored token (called on logout). */
export function clearToken() {
  if (typeof window !== "undefined") localStorage.removeItem(TOKEN_KEY);
}
