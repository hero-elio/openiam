package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	authnDomain "openiam/internal/authn/domain"
	sharedAuth "openiam/internal/shared/auth"
)

func BearerAuth(tokenProvider authnDomain.TokenProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractBearerToken(r)
			if raw == "" {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
				return
			}
			tc, err := tokenProvider.Validate(raw)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid token")
				return
			}
			ctx := sharedAuth.ContextWithClaims(r.Context(), sharedAuth.Claims{
				UserID:    tc.UserID,
				TenantID:  tc.TenantID,
				AppID:     tc.AppID,
				SessionID: tc.SessionID,
				Roles:     tc.Roles,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission wraps a protocol-agnostic Checker as chi middleware.
func RequirePermission(check sharedAuth.Checker, resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := check(r.Context(), resource, action); err != nil {
				writeErr(w, http.StatusForbidden, "forbidden", "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func writeErr(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}
