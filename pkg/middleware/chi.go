package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	authnDomain "openiam/internal/authn/domain"
	authzApp "openiam/internal/authz/application"
	authzQuery "openiam/internal/authz/application/query"
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

func RequirePermission(authzSvc *authzApp.AuthzAppService, resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := sharedAuth.ClaimsFromContext(r.Context())
			if !ok {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "no claims in context")
				return
			}

			appID := claims.AppID
			if appID == "" {
				appID = "default"
			}

			result, err := authzSvc.CheckPermission(r.Context(), &authzQuery.CheckPermission{
				UserID:   claims.UserID,
				AppID:    appID,
				Resource: resource,
				Action:   action,
			})
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "internal_error", "permission check failed")
				return
			}
			if !result.Allowed {
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

func RequireOwnerOrPermission(authzSvc *authzApp.AuthzAppService, resource, action, userIDParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := sharedAuth.ClaimsFromContext(r.Context())
			if !ok {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "no claims in context")
				return
			}

			targetUID := chi.URLParam(r, userIDParam)
			if targetUID == claims.UserID {
				next.ServeHTTP(w, r)
				return
			}

			RequirePermission(authzSvc, resource, action)(next).ServeHTTP(w, r)
		})
	}
}
