package rest

type CreateRoleRequest struct {
	AppID       string `json:"app_id"`
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type GrantPermissionRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type RevokePermissionRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type AssignRoleRequest struct {
	AppID    string `json:"app_id"`
	RoleID   string `json:"role_id"`
	TenantID string `json:"tenant_id"`
}

type CheckPermissionRequest struct {
	UserID   string `json:"user_id"`
	AppID    string `json:"app_id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type GrantResourcePermissionRequest struct {
	UserID       string `json:"user_id"`
	AppID        string `json:"app_id"`
	TenantID     string `json:"tenant_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
}

type RevokeResourcePermissionRequest struct {
	UserID       string `json:"user_id"`
	AppID        string `json:"app_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
}

type CheckResourcePermissionRequest struct {
	UserID       string `json:"user_id"`
	AppID        string `json:"app_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
}

type RegisterPermissionRequest struct {
	AppID       string `json:"app_id"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type DeletePermissionRequest struct {
	AppID    string `json:"app_id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type RoleResponse struct {
	ID          string   `json:"id"`
	AppID       string   `json:"app_id"`
	TenantID    string   `json:"tenant_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	IsSystem    bool     `json:"is_system"`
	CreatedAt   string   `json:"created_at"`
}

type UserAppRoleResponse struct {
	UserID     string `json:"user_id"`
	AppID      string `json:"app_id"`
	RoleID     string `json:"role_id"`
	TenantID   string `json:"tenant_id"`
	AssignedAt string `json:"assigned_at"`
}

type CheckPermissionResponse struct {
	Allowed bool `json:"allowed"`
}

type ResourcePermissionResponse struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	AppID        string `json:"app_id"`
	TenantID     string `json:"tenant_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
	GrantedAt    string `json:"granted_at"`
	GrantedBy    string `json:"granted_by"`
}

type PermissionDefinitionResponse struct {
	ID          string `json:"id"`
	AppID       string `json:"app_id"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
	IsBuiltin   bool   `json:"is_builtin"`
	CreatedAt   string `json:"created_at"`
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
