import { client } from "./client";
import type {
  CheckPermissionResponse,
  PermissionDefinitionResponse,
  ResourcePermissionResponse,
  RoleResponse,
  UserAppRoleResponse,
} from "@/types/api";

export interface CreateRoleBody {
  app_id: string;
  tenant_id: string;
  name: string;
  description?: string;
}

export interface AssignRoleBody {
  app_id: string;
  role_id: string;
  tenant_id: string;
}

export interface PermissionBody {
  resource: string;
  action: string;
}

export interface CheckPermissionBody {
  user_id: string;
  app_id: string;
  resource: string;
  action: string;
}

export interface CheckResourcePermissionBody {
  user_id: string;
  app_id: string;
  resource_type: string;
  resource_id: string;
  action: string;
}

export interface GrantResourcePermissionBody {
  user_id: string;
  app_id: string;
  tenant_id: string;
  resource_type: string;
  resource_id: string;
  action: string;
}

export interface RevokeResourcePermissionBody {
  user_id: string;
  app_id: string;
  resource_type: string;
  resource_id: string;
  action: string;
}

export interface RegisterPermissionBody {
  app_id: string;
  resource: string;
  action: string;
  description?: string;
}

export interface DeletePermissionBody {
  app_id: string;
  resource: string;
  action: string;
}

export const authzApi = {
  // Role management
  listRoles: (app_id: string) =>
    client
      .get<RoleResponse[]>("/authz/roles", { params: { app_id } })
      .then((r) => r.data),

  createRole: (body: CreateRoleBody) =>
    client.post<{ id: string }>("/authz/roles", body).then((r) => r.data),

  deleteRole: (id: string) =>
    client.delete<void>(`/authz/roles/${encodeURIComponent(id)}`).then((r) => r.data),

  // Role permissions
  grantPermission: (roleID: string, body: PermissionBody) =>
    client
      .post<void>(`/authz/roles/${encodeURIComponent(roleID)}/permissions`, body)
      .then((r) => r.data),

  revokePermission: (roleID: string, body: PermissionBody) =>
    client
      .delete<void>(`/authz/roles/${encodeURIComponent(roleID)}/permissions`, {
        data: body,
      })
      .then((r) => r.data),

  // Role assignment
  assignRole: (userID: string, body: AssignRoleBody) =>
    client
      .post<void>(`/authz/users/${encodeURIComponent(userID)}/roles`, body)
      .then((r) => r.data),

  unassignRole: (userID: string, roleID: string, app_id: string) =>
    client
      .delete<void>(
        `/authz/users/${encodeURIComponent(userID)}/roles/${encodeURIComponent(roleID)}`,
        { params: { app_id } },
      )
      .then((r) => r.data),

  listUserRoles: (userID: string, app_id: string) =>
    client
      .get<UserAppRoleResponse[]>(
        `/authz/users/${encodeURIComponent(userID)}/roles`,
        { params: { app_id } },
      )
      .then((r) => r.data),

  listRoleMembers: (roleID: string) =>
    client
      .get<UserAppRoleResponse[]>(
        `/authz/roles/${encodeURIComponent(roleID)}/users`,
      )
      .then((r) => r.data),

  // Permission checks
  checkPermission: (body: CheckPermissionBody) =>
    client
      .post<CheckPermissionResponse>("/authz/check", body)
      .then((r) => r.data),

  checkResourcePermission: (body: CheckResourcePermissionBody) =>
    client
      .post<CheckPermissionResponse>("/authz/resources/check", body)
      .then((r) => r.data),

  // Resource ACL
  listResourcePermissions: (params: { user_id: string; app_id: string }) =>
    client
      .get<ResourcePermissionResponse[]>("/authz/resources/permissions", {
        params,
      })
      .then((r) => r.data),

  grantResourcePermission: (body: GrantResourcePermissionBody) =>
    client
      .post<void>("/authz/resources/permissions", body)
      .then((r) => r.data),

  revokeResourcePermission: (body: RevokeResourcePermissionBody) =>
    client
      .delete<void>("/authz/resources/permissions", { data: body })
      .then((r) => r.data),

  // Permission definitions
  listPermissionDefinitions: (app_id: string) =>
    client
      .get<PermissionDefinitionResponse[]>("/authz/permissions", {
        params: { app_id },
      })
      .then((r) => r.data),

  registerPermission: (body: RegisterPermissionBody) =>
    client.post<void>("/authz/permissions", body).then((r) => r.data),

  deletePermission: (body: DeletePermissionBody) =>
    client.delete<void>("/authz/permissions", { data: body }).then((r) => r.data),
};
