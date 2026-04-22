// Type definitions mirroring the Go DTOs returned by the OpenIAM REST
// transport (see pkg/iam/transport/rest). Keep this file aligned with
// the public response structs.

export interface AuthnTokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user_id: string;
  tenant_id: string;
  app_id: string;
}

export interface ChallengeResponse {
  challenge: string;
  nonce?: string;
  expires_at: string;
}

export interface SessionResponse {
  id: string;
  user_id: string;
  app_id: string;
  tenant_id: string;
  provider: string;
  user_agent?: string;
  ip_address?: string;
  created_at: string;
  expires_at: string;
}

export interface TenantResponse {
  id: string;
  name: string;
  status: string;
  created_at: string;
}

export interface ApplicationResponse {
  id: string;
  tenant_id: string;
  name: string;
  client_id: string;
  redirect_uris: string[];
  scopes: string[];
  status: string;
  created_at: string;
}

export interface CreateApplicationResponse extends ApplicationResponse {
  client_secret: string;
}

export interface UserResponse {
  id: string;
  email: string;
  display_name: string;
  avatar_url: string;
  status: string;
  tenant_id: string;
  created_at: string;
}

export interface RoleResponse {
  id: string;
  app_id: string;
  tenant_id: string;
  name: string;
  description: string;
  permissions: string[];
  is_system: boolean;
  created_at: string;
}

export interface UserAppRoleResponse {
  user_id: string;
  app_id: string;
  role_id: string;
  tenant_id: string;
  assigned_at: string;
}

export interface ResourcePermissionResponse {
  id: string;
  user_id: string;
  app_id: string;
  tenant_id: string;
  resource_type: string;
  resource_id: string;
  action: string;
  granted_at: string;
  granted_by: string;
}

export interface PermissionDefinitionResponse {
  id: string;
  app_id: string;
  resource: string;
  action: string;
  description: string;
  is_builtin: boolean;
  created_at: string;
}

export interface CheckPermissionResponse {
  allowed: boolean;
}

export interface ApiError {
  code: string;
  message: string;
  request_id?: string;
  details?: Record<string, unknown>;
}

export interface JwtClaims {
  sub: string;
  user_id: string;
  tenant_id: string;
  app_id: string;
  provider: string;
  iat: number;
  exp: number;
  iss?: string;
  aud?: string | string[];
}
