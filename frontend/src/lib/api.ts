/**
 * Thin client for the octo REST API.
 *
 * All responses use the envelope `{ statusCode, message, data }`. `apiFetch` unwraps `data` on
 * success and throws an `ApiError` carrying the server message on failure.
 */

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
  } catch {
    // non-JSON response
  }

  if (!res.ok) {
    // التعديل الجديد هنا:
    if (res.status === 401 && window.location.pathname !== "/login") {
      // 1. مسح الـ Session (ممكن تستعملي الطريقة اللي كيستعملو في المشروع)
      localStorage.removeItem("token"); // أو أي مفتاح كتستعملوه
      
      // 2. الـ Redirect لـ /login
      window.location.href = "/login";
      
      // نرجعو Promise فارغة باش ما يكملش الكود لتحت
      return new Promise(() => {});
    }

    throw new ApiError(body?.message ?? `Request failed (${res.status})`, res.status);
  }
  return body!.data;
}
