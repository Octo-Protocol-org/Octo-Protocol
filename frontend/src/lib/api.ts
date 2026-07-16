/**
 * Thin client for the octo REST API.
 */

import { clearToken } from "./auth";

export const API_URL =
  process.env.NEXT_PUBLIC_OCTO_API_URL ?? "http://localhost:8080";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

type Envelope<T> = {
  statusCode: number;
  message: string;
  data: T;
};

export async function apiFetch<T>(
  path: string,
  options: RequestInit & { token?: string } = {},
): Promise<T> {
  const { token, headers, ...rest } = options;

  const res = await fetch(`${API_URL}${path}`, {
    ...rest,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
  });

  let body: Envelope<T> | null = null;
  try {
    body = (await res.json()) as Envelope<T>;
  } catch { }

  if (!res.ok) {
    // Handling 401: Clear session and redirect to login
    if (res.status === 401 && window.location.pathname !== "/login") {
      clearToken(); // استعملنا الدالة اللي كاينه في auth.ts
      
      const currentPath = window.location.pathname + window.location.search;
      window.location.href = `/login?redirect=${encodeURIComponent(currentPath)}`;
      
      return new Promise(() => {});
    }

    throw new ApiError(body?.message ?? `Request failed (${res.status})`, res.status);
  }
  return body!.data;
}
