package rest

type RegisterRequest struct {
	AppID    string `json:"app_id"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
	Password string `json:"password"`
	TenantID string `json:"tenant_id"`
}

type UserResponse struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
	Status      string `json:"status"`
	TenantID    string `json:"tenant_id"`
	CreatedAt   string `json:"created_at"`
}

type UpdateProfileRequest struct {
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
