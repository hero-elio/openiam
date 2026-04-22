package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	authnApp "openiam/internal/authn/application"
	identityDomain "openiam/internal/identity/domain"
	sharedAuth "openiam/internal/shared/auth"
	"openiam/pkg/iam/authn"
)

// Endpoint names accepted by SkipEndpoints for MountAuthn.
const (
	AuthnEndpointRegister      = "register"
	AuthnEndpointLogin         = "login"
	AuthnEndpointChallenge     = "challenge"
	AuthnEndpointRefresh       = "token.refresh"
	AuthnEndpointBindCred      = "bind"
	AuthnEndpointLogout        = "logout"
	AuthnEndpointListSessions  = "sessions.list"
	AuthnEndpointRevokeSession = "sessions.revoke"
)

// MountAuthn registers the authentication routes onto r against svc.
//
// Default route layout (relative to the chi router supplied by the
// caller; nest further with WithPathPrefix):
//
//	POST   /register
//	POST   /login
//	POST   /challenge
//	POST   /token/refresh
//	POST   /bind            (bearer-protected)
//	POST   /logout          (bearer-protected)
//	GET    /sessions        (bearer-protected)
//	DELETE /sessions/{id}   (bearer-protected)
//
// The bearer-protected group runs Service.AuthenticateToken via
// BearerAuth so every transport (REST, gRPC) shares the same gate.
func MountAuthn(r chi.Router, svc authn.Service, opts ...Option) {
	cfg := newMountConfig(opts)

	mount := func(target chi.Router) {
		for _, mw := range cfg.extraMiddleware {
			target.Use(mw)
		}

		if !cfg.skipped(AuthnEndpointRegister) {
			target.Post("/register", authnHandleRegister(svc))
		}
		if !cfg.skipped(AuthnEndpointLogin) {
			target.Post("/login", authnHandleLogin(svc))
		}
		if !cfg.skipped(AuthnEndpointChallenge) {
			target.Post("/challenge", authnHandleChallenge(svc))
		}
		if !cfg.skipped(AuthnEndpointRefresh) {
			target.Post("/token/refresh", authnHandleRefresh(svc))
		}

		target.Group(func(protected chi.Router) {
			protected.Use(BearerAuth(svc.AuthenticateToken))

			if !cfg.skipped(AuthnEndpointBindCred) {
				protected.Post("/bind", authnHandleBindCredential(svc))
			}
			if !cfg.skipped(AuthnEndpointLogout) {
				protected.Post("/logout", authnHandleLogout(svc))
			}
			if !cfg.skipped(AuthnEndpointListSessions) {
				protected.Get("/sessions", authnHandleListSessions(svc))
			}
			if !cfg.skipped(AuthnEndpointRevokeSession) {
				protected.Delete("/sessions/{id}", authnHandleRevokeSession(svc))
			}
		})
	}

	if cfg.pathPrefix != "" {
		r.Route(cfg.pathPrefix, mount)
		return
	}
	mount(r)
}

// --- Request / Response DTOs (transport-only) ---

type AuthnRegisterRequest struct {
	AppID    string `json:"app_id"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
	Password string `json:"password"`
	TenantID string `json:"tenant_id"`
}

type AuthnLoginRequest struct {
	AppID    string          `json:"app_id"`
	Provider string          `json:"provider"`
	Params   json.RawMessage `json:"params"`
}

type AuthnChallengeRequest struct {
	AppID    string          `json:"app_id"`
	Provider string          `json:"provider"`
	Params   json.RawMessage `json:"params,omitempty"`
}

type AuthnChallengeResponse struct {
	ChallengeID string         `json:"challenge_id"`
	Provider    string         `json:"provider"`
	Data        map[string]any `json:"data"`
	ExpiresAt   string         `json:"expires_at"`
}

type AuthnBindCredentialRequest struct {
	Provider string          `json:"provider"`
	Params   json.RawMessage `json:"params"`
}

type AuthnRefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type AuthnTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type AuthnSessionResponse struct {
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

// --- Handlers ---

func authnHandleRegister(svc authn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuthnRegisterRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if req.AppID == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "app_id is required")
			return
		}
		if req.Email == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "email and password are required")
			return
		}

		tokenPair, err := svc.Register(r.Context(), &authn.RegisterCommand{
			AppID:    req.AppID,
			Provider: req.Provider,
			Email:    req.Email,
			Password: req.Password,
			TenantID: req.TenantID,
		})
		if err != nil {
			writeAuthnBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, AuthnTokenResponse{
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
			TokenType:    tokenPair.TokenType,
			ExpiresIn:    tokenPair.ExpiresIn,
		})
	}
}

func authnHandleLogin(svc authn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuthnLoginRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if req.AppID == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "app_id is required")
			return
		}

		provider := req.Provider
		if provider == "" {
			provider = "password"
		}

		tokenPair, err := svc.Login(r.Context(), &authn.LoginCommand{
			AppID:     req.AppID,
			Provider:  provider,
			Params:    req.Params,
			UserAgent: r.UserAgent(),
			IPAddress: realIP(r),
		})
		if err != nil {
			slog.ErrorContext(r.Context(), "login failed", "provider", provider, "error", err)
			writeAuthnBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, AuthnTokenResponse{
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
			TokenType:    tokenPair.TokenType,
			ExpiresIn:    tokenPair.ExpiresIn,
		})
	}
}

func authnHandleChallenge(svc authn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuthnChallengeRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if req.AppID == "" || req.Provider == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "app_id and provider are required")
			return
		}

		resp, err := svc.BeginChallenge(r.Context(), &authn.ChallengeCommand{
			AppID:    req.AppID,
			Provider: req.Provider,
			Params:   req.Params,
		})
		if err != nil {
			writeAuthnBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, AuthnChallengeResponse{
			ChallengeID: resp.ChallengeID,
			Provider:    resp.Provider,
			Data:        resp.Data,
			ExpiresAt:   resp.ExpiresAt.Format(time.RFC3339),
		})
	}
}

func authnHandleRefresh(svc authn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuthnRefreshTokenRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if req.RefreshToken == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "refresh_token is required")
			return
		}

		tokenPair, err := svc.RefreshToken(r.Context(), &authn.RefreshTokenCommand{
			RefreshToken: req.RefreshToken,
			UserAgent:    r.UserAgent(),
			IPAddress:    realIP(r),
		})
		if err != nil {
			writeAuthnBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, AuthnTokenResponse{
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
			TokenType:    tokenPair.TokenType,
			ExpiresIn:    tokenPair.ExpiresIn,
		})
	}
}

func authnHandleBindCredential(svc authn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, _ := sharedAuth.ClaimsFromContext(r.Context())

		var req AuthnBindCredentialRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if req.Provider == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "provider is required")
			return
		}

		if err := svc.BindCredential(r.Context(), &authn.BindCredentialCommand{
			UserID:   claims.UserID,
			AppID:    claims.AppID,
			Provider: req.Provider,
			Params:   req.Params,
		}); err != nil {
			writeAuthnBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func authnHandleLogout(svc authn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, _ := sharedAuth.ClaimsFromContext(r.Context())

		if err := svc.Logout(r.Context(), &authn.LogoutCommand{
			SessionID: claims.SessionID,
			UserID:    claims.UserID,
		}); err != nil {
			writeAuthnBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func authnHandleListSessions(svc authn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, _ := sharedAuth.ClaimsFromContext(r.Context())

		sessions, err := svc.ListSessions(r.Context(), claims.UserID)
		if err != nil {
			writeAuthnBusinessError(w, err)
			return
		}

		resp := make([]AuthnSessionResponse, len(sessions))
		for i, s := range sessions {
			resp[i] = AuthnSessionResponse{
				ID:           s.ID,
				UserID:       s.UserID,
				AppID:        s.AppID,
				Provider:     s.Provider,
				UserAgent:    s.UserAgent,
				IPAddress:    s.IPAddress,
				ExpiresAt:    s.ExpiresAt,
				CreatedAt:    s.CreatedAt,
				LastActiveAt: s.LastActiveAt,
			}
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func authnHandleRevokeSession(svc authn.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, _ := sharedAuth.ClaimsFromContext(r.Context())
		sessionID := chi.URLParam(r, "id")

		if err := svc.Logout(r.Context(), &authn.LogoutCommand{
			SessionID: sessionID,
			UserID:    claims.UserID,
		}); err != nil {
			writeAuthnBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// writeAuthnBusinessError translates the authn (and a few cross-module
// identity) domain errors into the matching HTTP status. The mapping is
// deliberately exhaustive — adding a new domain error and forgetting
// the case here would silently fall through to 500, hiding real bugs.
func writeAuthnBusinessError(w http.ResponseWriter, err error) {
	var rl *authn.RateLimitedError
	if errors.As(err, &rl) {
		writeRateLimited(w, rl.RetryAfter)
		return
	}
	switch {
	case errors.Is(err, authn.ErrInvalidCredential), errors.Is(err, identityDomain.ErrInvalidPassword):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
	case errors.Is(err, authn.ErrCredentialNotFound):
		writeError(w, http.StatusNotFound, "credential_not_found", "credential not found, registration required")
	case errors.Is(err, identityDomain.ErrUserNotFound):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
	case errors.Is(err, identityDomain.ErrEmailAlreadyTaken):
		writeError(w, http.StatusConflict, "email_taken", "email is already registered")
	case errors.Is(err, identityDomain.ErrPasswordTooShort):
		writeError(w, http.StatusBadRequest, "password_too_short", "password must be at least 8 characters")
	case errors.Is(err, identityDomain.ErrUserDisabled):
		writeError(w, http.StatusForbidden, "user_disabled", "account is disabled")
	case errors.Is(err, identityDomain.ErrUserLocked):
		writeError(w, http.StatusForbidden, "user_locked", "account is locked")
	case errors.Is(err, authn.ErrSessionNotFound):
		writeError(w, http.StatusUnauthorized, "session_not_found", "session not found")
	case errors.Is(err, authn.ErrSessionExpired):
		writeError(w, http.StatusUnauthorized, "session_expired", "session has expired")
	case errors.Is(err, authn.ErrUnsupportedProvider):
		writeError(w, http.StatusBadRequest, "unsupported_provider", "unsupported authentication provider")
	case errors.Is(err, authn.ErrChallengeNotSupported):
		writeError(w, http.StatusBadRequest, "challenge_not_supported", "this provider does not support challenge flow")
	case errors.Is(err, authn.ErrChallengeNotFound):
		writeError(w, http.StatusBadRequest, "challenge_expired", "challenge not found or expired")
	case errors.Is(err, authn.ErrChallengeInvalid):
		writeError(w, http.StatusBadRequest, "challenge_invalid", "invalid challenge response")
	case errors.Is(err, authn.ErrCredentialAlreadyBound):
		writeError(w, http.StatusConflict, "credential_already_bound", "credential is already bound to another user")
	case errors.Is(err, authn.ErrCredentialAlreadyExists):
		writeError(w, http.StatusConflict, "credential_already_exists", "credential is already bound to this user")
	case errors.Is(err, authn.ErrInvalidToken), errors.Is(err, authn.ErrTokenExpired):
		writeError(w, http.StatusUnauthorized, "invalid_token", "token is invalid or expired")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "an internal error occurred")
	}
}

// writeRateLimited maps the application's RateLimitedError to HTTP
// 429. The retry hint comes straight from the error so the throttling
// policy stays in the application layer.
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	if retryAfter <= 0 {
		retryAfter = authnApp.DefaultLoginRateWindow
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	writeError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts; please retry later")
}
