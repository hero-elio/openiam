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

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
