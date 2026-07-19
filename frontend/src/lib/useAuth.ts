"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { getToken, clearToken, saveToken, logoutRequest, refreshToken, me, type User } from "./auth";

/**
 * Guard a page: ensures a valid token exists, verifies it with /v1/auth/me, and exposes helpers
 * for logout and token refresh.
 *
 * # Token storage contract
 * - After login/signup: `saveToken(result.token)` is called by the caller before navigation.
 * - After refresh: `refreshToken()` internally calls `saveToken(newToken)` — the hook reads
 *   the updated value from localStorage so `token` state is always the latest valid token.
 * - After logout: `logoutRequest()` revokes the token server-side and calls `clearToken()`.
 *   The hook then redirects to /login. Local storage holds at most one token at any time.
 */
export function useAuth() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = getToken();
    if (!t) {
      router.replace("/login");
      return;
    }
    me(t)
      .then((u) => {
        setUser(u);
        // Store the token in state so consumers get a stable reference.
        setToken(t);
      })
      .catch(() => {
        // Token is invalid or revoked — clear it and redirect.
        clearToken();
        router.replace("/login");
      })
      .finally(() => setLoading(false));
  }, [router]);

  /**
   * Logout: revoke the current token server-side, clear local storage, and redirect to /login.
   *
   * The server call is best-effort — the local token is always cleared (and the redirect always
   * fires) regardless of whether the network request succeeds, so the user is never stuck.
   */
  const logout = useCallback(async () => {
    const t = getToken();
    if (t) {
      await logoutRequest(t); // clears local token internally via finally{}
    } else {
      clearToken();
    }
    setUser(null);
    setToken(null);
    router.replace("/login");
  }, [router]);

  /**
   * Refresh the session token. Issues a new token (server revokes the old one atomically) and
   * updates both localStorage and the hook's `token` state so subsequent requests use the new
   * token immediately.
   *
   * Returns the new token string on success. Redirects to /login if the refresh fails (e.g.
   * the current token was already revoked).
   */
  const refresh = useCallback(async (): Promise<string | null> => {
    const t = getToken();
    if (!t) {
      router.replace("/login");
      return null;
    }
    try {
      const result = await refreshToken(t); // saves new token to localStorage internally
      setToken(result.token);
      setUser(result.user);
      return result.token;
    } catch {
      clearToken();
      setUser(null);
      setToken(null);
      router.replace("/login");
      return null;
    }
  }, [router]);

  return { user, token, loading, logout, refresh };
}
