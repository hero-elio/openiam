import axios, {
  AxiosError,
  AxiosInstance,
  AxiosRequestConfig,
  InternalAxiosRequestConfig,
} from "axios";
import { notification } from "antd";
import {
  applyRefreshedTokens,
  clearTokens,
  getAccessToken,
  getRefreshToken,
} from "@/stores/auth";
import type { ApiError, AuthnTokenResponse } from "@/types/api";

// Use a relative base so the SPA works whether it lives at /__admin/
// (embedded) or at the Vite dev origin (proxied to :8080).
export const API_BASE_URL = "/api/v1";

export const client: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30_000,
});

// Track the in-flight refresh so concurrent 401s share a single attempt
// instead of stampeding the refresh endpoint.
let refreshPromise: Promise<AuthnTokenResponse> | null = null;

interface RetryConfig extends InternalAxiosRequestConfig {
  __retried?: boolean;
}

async function refreshTokens(): Promise<AuthnTokenResponse> {
  if (refreshPromise) return refreshPromise;
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    throw new Error("no refresh token");
  }
  refreshPromise = axios
    .post<AuthnTokenResponse>(`${API_BASE_URL}/auth/token/refresh`, {
      refresh_token: refreshToken,
    })
    .then((resp) => {
      applyRefreshedTokens(resp.data.access_token, resp.data.refresh_token);
      return resp.data;
    })
    .finally(() => {
      refreshPromise = null;
    });
  return refreshPromise;
}

client.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

client.interceptors.response.use(
  (resp) => resp,
  async (error: AxiosError<ApiError>) => {
    const original = error.config as RetryConfig | undefined;
    const status = error.response?.status;

    // 401 → try refresh once, replay original; on second failure surface and clear.
    if (status === 401 && original && !original.__retried) {
      original.__retried = true;
      const url = original.url ?? "";
      // Don't try to refresh if the failing request _is_ the refresh
      // call (avoids infinite loops).
      if (!url.includes("/auth/token/refresh") && !url.includes("/auth/login")) {
        try {
          await refreshTokens();
          const token = getAccessToken();
          if (token && original.headers) {
            original.headers.Authorization = `Bearer ${token}`;
          }
          return client.request(original);
        } catch {
          clearTokens();
          if (typeof window !== "undefined") {
            const next = encodeURIComponent(window.location.pathname + window.location.search);
            window.location.replace(`/__admin/login?next=${next}`);
          }
          return Promise.reject(error);
        }
      }
    }

    surfaceApiError(error);
    return Promise.reject(error);
  },
);

// Centralised error toast. Skips silent paths (401 we already handled,
// 404 on optional resources) by inspecting a header callers can set.
function surfaceApiError(error: AxiosError<ApiError>) {
  const status = error.response?.status;
  if (status === 401) return;
  const cfg = error.config as AxiosRequestConfig | undefined;
  if (cfg?.headers && (cfg.headers as Record<string, unknown>)["X-Suppress-Error"]) {
    return;
  }
  const body = error.response?.data;
  const code = body?.code ?? "network_error";
  const message = body?.message ?? error.message ?? "请求失败";
  notification.error({
    key: `api-error-${code}-${message}`,
    message: `请求失败 (${status ?? "ERR"})`,
    description: `${code}: ${message}${body?.request_id ? `\nrequest_id=${body.request_id}` : ""}`,
    duration: 5,
  });
}

export type RequestConfig = AxiosRequestConfig;
