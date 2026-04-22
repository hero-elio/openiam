package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"openiam/internal/authn/application"
	"openiam/internal/authn/application/command"
	"openiam/internal/authn/domain"
	identityDomain "openiam/internal/identity/domain"
	sharedAuth "openiam/internal/shared/auth"
	"openiam/pkg/httpx"
)

type Handler struct {
	svc           *application.AuthnAppService
	tokenProvider domain.TokenProvider
}

func NewHandler(svc *application.AuthnAppService, tokenProvider domain.TokenProvider) *Handler {
	return &Handler{svc: svc, tokenProvider: tokenProvider}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Post("/register", h.handleRegister)
	r.Post("/login", h.handleLogin)
	r.Post("/challenge", h.handleChallenge)
	r.Post("/token/refresh", h.handleRefreshToken)

	r.Group(func(r chi.Router) {
		r.Use(h.AuthMiddleware)
		r.Post("/bind", h.handleBindCredential)
		r.Post("/logout", h.handleLogout)
		r.Get("/sessions", h.handleListSessions)
		r.Delete("/sessions/{id}", h.handleRevokeSession)
	})

	return r
}

func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := extractBearerToken(r)
		if raw == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		// All token + account-state policy lives in the application layer
		// so gRPC / internal RPC adapters can share the same gate without
		// re-implementing it. We only translate the resulting error into
		// HTTP status here.
		claims, err := h.svc.AuthenticateToken(r.Context(), raw)
		if err != nil {
			writeAuthError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(sharedAuth.ContextWithClaims(r.Context(), claims)))
	})
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identityDomain.ErrUserDisabled):
		writeError(w, http.StatusForbidden, "user_disabled", "account is disabled")
	case errors.Is(err, identityDomain.ErrUserLocked):
		writeError(w, http.StatusForbidden, "user_locked", "account is locked")
	case errors.Is(err, identityDomain.ErrUserNotFound):
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
	case errors.Is(err, domain.ErrTokenExpired):
		writeError(w, http.StatusUnauthorized, "token_expired", "token has expired")
	default:
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
	}
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
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

	tokenPair, err := h.svc.Register(r.Context(), &command.Register{
		AppID:    req.AppID,
		Provider: req.Provider,
		Email:    req.Email,
		Password: req.Password,
		TenantID: req.TenantID,
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
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

	tokenPair, err := h.svc.Login(r.Context(), &command.Login{
		AppID:     req.AppID,
		Provider:  provider,
		Params:    req.Params,
		UserAgent: r.UserAgent(),
		IPAddress: realIP(r),
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "login failed", "provider", provider, "error", err)
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
	})
}

func (h *Handler) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req ChallengeRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if req.AppID == "" || req.Provider == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "app_id and provider are required")
		return
	}

	resp, err := h.svc.BeginChallenge(r.Context(), &command.Challenge{
		AppID:    req.AppID,
		Provider: req.Provider,
		Params:   req.Params,
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, ChallengeResponse{
		ChallengeID: resp.ChallengeID,
		Provider:    resp.Provider,
		Data:        resp.Data,
		ExpiresAt:   resp.ExpiresAt.Format(time.RFC3339),
	})
}

func (h *Handler) handleBindCredential(w http.ResponseWriter, r *http.Request) {
	claims, _ := sharedAuth.ClaimsFromContext(r.Context())
	userID := claims.UserID
	appID := claims.AppID

	var req BindCredentialRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if req.Provider == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "provider is required")
		return
	}

	if err := h.svc.BindCredential(r.Context(), &command.BindCredential{
		UserID:   userID,
		AppID:    appID,
		Provider: req.Provider,
		Params:   req.Params,
	}); err != nil {
		writeBusinessError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	claims, _ := sharedAuth.ClaimsFromContext(r.Context())
	userID := claims.UserID
	sessionID := claims.SessionID

	if err := h.svc.Logout(r.Context(), &command.Logout{
		SessionID: sessionID,
		UserID:    userID,
	}); err != nil {
		writeBusinessError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "refresh_token is required")
		return
	}

	tokenPair, err := h.svc.RefreshToken(r.Context(), &command.RefreshToken{
		RefreshToken: req.RefreshToken,
		UserAgent:    r.UserAgent(),
		IPAddress:    realIP(r),
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
	})
}

func (h *Handler) handleListSessions(w http.ResponseWriter, r *http.Request) {
	claims, _ := sharedAuth.ClaimsFromContext(r.Context())
	userID := claims.UserID

	sessions, err := h.svc.ListSessions(r.Context(), userID)
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	resp := make([]SessionResponse, len(sessions))
	for i, s := range sessions {
		resp[i] = SessionResponse{
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

func (h *Handler) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	claims, _ := sharedAuth.ClaimsFromContext(r.Context())
	userID := claims.UserID
	sessionID := chi.URLParam(r, "id")

	if err := h.svc.Logout(r.Context(), &command.Logout{
		SessionID: sessionID,
		UserID:    userID,
	}); err != nil {
		writeBusinessError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{Code: code, Message: message})
}

func writeBusinessError(w http.ResponseWriter, err error) {
	var rl *domain.RateLimitedError
	if errors.As(err, &rl) {
		writeRateLimited(w, rl.RetryAfter)
		return
	}
	switch {
	case errors.Is(err, domain.ErrInvalidCredential), errors.Is(err, identityDomain.ErrInvalidPassword):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
	case errors.Is(err, domain.ErrCredentialNotFound):
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
	case errors.Is(err, domain.ErrSessionNotFound):
		writeError(w, http.StatusUnauthorized, "session_not_found", "session not found")
	case errors.Is(err, domain.ErrSessionExpired):
		writeError(w, http.StatusUnauthorized, "session_expired", "session has expired")
	case errors.Is(err, domain.ErrUnsupportedProvider):
		writeError(w, http.StatusBadRequest, "unsupported_provider", "unsupported authentication provider")
	case errors.Is(err, domain.ErrChallengeNotSupported):
		writeError(w, http.StatusBadRequest, "challenge_not_supported", "this provider does not support challenge flow")
	case errors.Is(err, domain.ErrChallengeNotFound):
		writeError(w, http.StatusBadRequest, "challenge_expired", "challenge not found or expired")
	case errors.Is(err, domain.ErrChallengeInvalid):
		writeError(w, http.StatusBadRequest, "challenge_invalid", "invalid challenge response")
	case errors.Is(err, domain.ErrCredentialAlreadyBound):
		writeError(w, http.StatusConflict, "credential_already_bound", "credential is already bound to another user")
	case errors.Is(err, domain.ErrCredentialAlreadyExists):
		writeError(w, http.StatusConflict, "credential_already_exists", "credential is already bound to this user")
	case errors.Is(err, domain.ErrInvalidToken), errors.Is(err, domain.ErrTokenExpired):
		writeError(w, http.StatusUnauthorized, "invalid_token", "token is invalid or expired")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "an internal error occurred")
	}
}

// writeRateLimited maps a domain.RateLimitedError into HTTP 429. The
// throttling policy itself (which buckets to check, how big they are)
// lives in AuthnAppService so that gRPC / RPC adapters get the same
// guarantees without re-implementing it.
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	if retryAfter <= 0 {
		retryAfter = application.DefaultLoginRateWindow
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	writeError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts; please retry later")
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func realIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}
