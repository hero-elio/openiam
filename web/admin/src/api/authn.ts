import { client } from "./client";
import type {
  AuthnTokenResponse,
  ChallengeResponse,
  SessionResponse,
} from "@/types/api";

export interface LoginRequest {
  app_id: string;
  email: string;
  password: string;
  provider?: string;
}

interface LoginWirePayload {
  app_id: string;
  provider: string;
  params: Record<string, unknown>;
}

export interface RegisterRequest {
  tenant_id: string;
  app_id: string;
  email: string;
  password: string;
}

export interface ChallengeRequest {
  app_id: string;
  tenant_id: string;
  provider: string;
  identifier: string;
}

export interface BindCredentialRequest {
  user_id: string;
  app_id: string;
  tenant_id: string;
  provider: string;
  challenge: string;
  signature: string;
  public_key?: string;
}

export const authnApi = {
  login: (body: LoginRequest) => {
    const provider = body.provider || "password";
    const wire: LoginWirePayload = {
      app_id: body.app_id,
      provider,
      params: { email: body.email, password: body.password },
    };
    return client.post<AuthnTokenResponse>("/auth/login", wire).then((r) => r.data);
  },

  register: (body: RegisterRequest) =>
    client.post<AuthnTokenResponse>("/auth/register", body).then((r) => r.data),

  refresh: (refresh_token: string) =>
    client
      .post<AuthnTokenResponse>("/auth/token/refresh", { refresh_token })
      .then((r) => r.data),

  challenge: (body: ChallengeRequest) =>
    client.post<ChallengeResponse>("/auth/challenge", body).then((r) => r.data),

  bind: (body: BindCredentialRequest) =>
    client.post<{ id: string }>("/auth/bind", body).then((r) => r.data),

  listSessions: () =>
    client.get<SessionResponse[]>("/auth/sessions").then((r) => r.data),

  revokeSession: (id: string) =>
    client.delete<void>(`/auth/sessions/${encodeURIComponent(id)}`).then((r) => r.data),

  logout: () => client.post<void>("/auth/logout").then((r) => r.data),
};
