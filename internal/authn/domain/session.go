package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

type Session struct {
	shared.AggregateRoot
	ID           shared.SessionID
	UserID       shared.UserID
	TenantID     shared.TenantID
	AppID        shared.AppID
	Provider     string
	RefreshToken string
	UserAgent    string
	IPAddress    string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	LastActiveAt time.Time
}

func NewSession(
	id shared.SessionID,
	userID shared.UserID,
	tenantID shared.TenantID,
	appID shared.AppID,
	provider, refreshToken, userAgent, ipAddress string,
	expiresAt time.Time,
) *Session {
	now := time.Now()
	return &Session{
		ID:           id,
		UserID:       userID,
		TenantID:     tenantID,
		AppID:        appID,
		Provider:     provider,
		RefreshToken: refreshToken,
		UserAgent:    userAgent,
		IPAddress:    ipAddress,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
		LastActiveAt: now,
	}
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

func (s *Session) Refresh(newRefreshToken string, newExpiry time.Time) {
	s.RefreshToken = newRefreshToken
	s.ExpiresAt = newExpiry
	s.LastActiveAt = time.Now()
}

// RecordClient updates the request-context fields a session listing exposes
// (UserAgent, IPAddress) when they are present. Empty values are ignored
// so a token refresh from a client that doesn't surface them does not wipe
// the originally captured values.
func (s *Session) RecordClient(userAgent, ipAddress string) {
	if userAgent != "" {
		s.UserAgent = userAgent
	}
	if ipAddress != "" {
		s.IPAddress = ipAddress
	}
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type ClientInfo struct {
	UserAgent string
	IPAddress string
}
