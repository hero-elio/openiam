import { client } from "./client";
import type {
  ApplicationResponse,
  CreateApplicationResponse,
  TenantResponse,
} from "@/types/api";

export interface ListTenantsParams {
  limit?: number;
  offset?: number;
}

export const tenantApi = {
  list: (params: ListTenantsParams = {}) =>
    client.get<TenantResponse[]>("/tenants", { params }).then((r) => r.data),

  get: (id: string) =>
    client.get<TenantResponse>(`/tenants/${encodeURIComponent(id)}`).then((r) => r.data),

  create: (name: string) =>
    client.post<{ id: string }>("/tenants", { name }).then((r) => r.data),

  listApplications: (tenantID: string) =>
    client
      .get<ApplicationResponse[]>(`/tenants/${encodeURIComponent(tenantID)}/applications`)
      .then((r) => r.data),

  createApplication: (tenantID: string, name: string) =>
    client
      .post<CreateApplicationResponse>(
        `/tenants/${encodeURIComponent(tenantID)}/applications`,
        { name },
      )
      .then((r) => r.data),

  getApplication: (appID: string) =>
    client
      .get<ApplicationResponse>(`/applications/${encodeURIComponent(appID)}`)
      .then((r) => r.data),

  updateApplication: (
    appID: string,
    body: { name?: string; redirect_uris?: string[]; scopes?: string[] },
  ) =>
    client
      .put<void>(`/applications/${encodeURIComponent(appID)}`, body)
      .then((r) => r.data),
};
