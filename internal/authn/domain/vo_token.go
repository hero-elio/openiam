package domain

import "github.com/golang-jwt/jwt/v5"

type TokenClaims struct {
	UserID    string   `json:"uid"`
	TenantID  string   `json:"tid"`
	AppID     string   `json:"aid"`
	SessionID string   `json:"sid"`
	Roles     []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

type TokenProvider interface {
	Generate(claims TokenClaims) (*TokenPair, error)
	Validate(raw string) (*TokenClaims, error)
}
