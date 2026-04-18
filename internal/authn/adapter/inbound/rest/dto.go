package rest

import "encoding/json"

type LoginRequest struct {
	AppID    string          `json:"app_id"`
	Provider string          `json:"provider"`
	Params   json.RawMessage `json:"params"`
}

type RegisterRequest struct {
	AppID    string `json:"app_id"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
	Password string `json:"password"`
	TenantID string `json:"tenant_id"`
}

type ChallengeRequest struct {
	AppID    string          `json:"app_id"`
	Provider string          `json:"provider"`
	Params   json.RawMessage `json:"params,omitempty"`
}

type BindCredentialRequest struct {
	Provider string          `json:"provider"`
	Params   json.RawMessage `json:"params"`
}

type ChallengeResponse struct {
	ChallengeID string         `json:"challenge_id"`
	Provider    string         `json:"provider"`
	Data        map[string]any `json:"data"`
	ExpiresAt   string         `json:"expires_at"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type SessionResponse struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	AppID        string `json:"app_id"`
	Provider     string `json:"provider"`
	UserAgent    string `json:"user_agent"`
	IPAddress    string `json:"ip_address"`
	ExpiresAt    string `json:"expires_at"`
	CreatedAt    string `json:"created_at"`
	LastActiveAt string `json:"last_active_at"`
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
