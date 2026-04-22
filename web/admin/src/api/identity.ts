import { client } from "./client";
import type { UserResponse } from "@/types/api";

export interface ListUsersParams {
  tenant_id?: string;
  email_like?: string;
  limit?: number;
  offset?: number;
}

export interface RegisterUserBody {
  tenant_id: string;
  app_id: string;
  email: string;
  password: string;
  provider?: string;
}

export interface UpdateProfileBody {
  display_name: string;
  avatar_url: string;
}

export interface ChangePasswordBody {
  old_password: string;
  new_password: string;
}

export const identityApi = {
  list: (params: ListUsersParams = {}) =>
    client.get<UserResponse[]>("/users", { params }).then((r) => r.data),

  get: (id: string) =>
    client.get<UserResponse>(`/users/${encodeURIComponent(id)}`).then((r) => r.data),

  register: (body: RegisterUserBody) =>
    client.post<{ id: string }>("/users/register", body).then((r) => r.data),

  updateProfile: (id: string, body: UpdateProfileBody) =>
    client
      .put<void>(`/users/${encodeURIComponent(id)}/profile`, body)
      .then((r) => r.data),

  changePassword: (id: string, body: ChangePasswordBody) =>
    client
      .put<void>(`/users/${encodeURIComponent(id)}/password`, body)
      .then((r) => r.data),
};
