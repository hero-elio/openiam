package rest

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	identityDomain "openiam/internal/identity/domain"
	sharedAuth "openiam/internal/shared/auth"
	shared "openiam/internal/shared/domain"
	"openiam/pkg/iam/identity"
	"openiam/pkg/iam/sharedauth"
)

// Endpoint names accepted by SkipEndpoints for MountIdentity.
const (
	IdentityEndpointRegister       = "register"
	IdentityEndpointListUsers      = "user.list"
	IdentityEndpointGetUser        = "user.get"
	IdentityEndpointUpdateProfile  = "user.profile.update"
	IdentityEndpointChangePassword = "user.password.change"
)

// MountIdentity registers identity routes onto r against svc.
//
// Default route layout (relative to r; nest with WithPathPrefix):
//
//	POST /register                user provisioning
//	GET  /{id}                    fetch a user (owner OR users:read)
//	PUT  /{id}/profile            update profile (owner OR users:update)
//	PUT  /{id}/password           change password (owner OR users:update)
//
// "owner OR" means that when the URL {id} matches the caller's
// Claims.UserID, the request bypasses the permission check — users can
// always operate on their own record without needing the privileged
// permission. The supplied check is the same Checker the rest of the
// SDK uses (typically authz.BuildChecker(authz.Service)).
func MountIdentity(r chi.Router, svc identity.Service, check sharedauth.Checker, opts ...Option) {
	cfg := newMountConfig(opts)

	mount := func(target chi.Router) {
		for _, mw := range cfg.extraMiddleware {
			target.Use(mw)
		}

		if !cfg.skipped(IdentityEndpointRegister) {
			target.Post("/register", identityHandleRegister(svc))
		}
		if !cfg.skipped(IdentityEndpointListUsers) {
			target.With(RequirePermission(check, identity.ResourceUsers, identity.ActionRead)).
				Get("/", identityHandleListUsers(svc))
		}
		if !cfg.skipped(IdentityEndpointGetUser) {
			target.With(requireOwnerOr(check, identity.ResourceUsers, identity.ActionRead)).
				Get("/{id}", identityHandleGetUser(svc))
		}
		if !cfg.skipped(IdentityEndpointUpdateProfile) {
			target.With(requireOwnerOr(check, identity.ResourceUsers, identity.ActionUpdate)).
				Put("/{id}/profile", identityHandleUpdateProfile(svc))
		}
		if !cfg.skipped(IdentityEndpointChangePassword) {
			target.With(requireOwnerOr(check, identity.ResourceUsers, identity.ActionUpdate)).
				Put("/{id}/password", identityHandleChangePassword(svc))
		}
	}

	if cfg.pathPrefix != "" {
		r.Route(cfg.pathPrefix, mount)
		return
	}
	mount(r)
}

// requireOwnerOr lets the request through if the URL "id" param
// matches the authenticated user, otherwise falls back to a permission
// check. Lives next to MountIdentity because it is the only consumer
// today, but the shape is generic enough to lift into a public helper
// later if other modules grow the same need.
func requireOwnerOr(check sharedauth.Checker, resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := sharedAuth.ClaimsFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthorized", "missing authentication")
				return
			}
			targetUID := chi.URLParam(r, "id")
			if targetUID == claims.UserID {
				next.ServeHTTP(w, r)
				return
			}
			if err := check(r.Context(), resource, action); err != nil {
				writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- Request / Response DTOs ---

type IdentityRegisterRequest struct {
	AppID    string `json:"app_id"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
	Password string `json:"password"`
	TenantID string `json:"tenant_id"`
}

type IdentityUserResponse struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
	Status      string `json:"status"`
	TenantID    string `json:"tenant_id"`
	CreatedAt   string `json:"created_at"`
}

type IdentityUpdateProfileRequest struct {
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
}

type IdentityChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// --- Handlers ---

func identityHandleRegister(svc identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req IdentityRegisterRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if req.Email == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "email and password are required")
			return
		}
		if req.AppID == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "app_id is required")
			return
		}

		userID, err := svc.RegisterUser(r.Context(), &identity.RegisterUserCommand{
			AppID:    req.AppID,
			Provider: req.Provider,
			Email:    req.Email,
			Password: req.Password,
			TenantID: req.TenantID,
		})
		if err != nil {
			writeIdentityBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{"id": userID.String()})
	}
}

func identityHandleListUsers(svc identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))

		dtos, err := svc.ListUsers(r.Context(), &identity.ListUsersQuery{
			TenantID:  q.Get("tenant_id"),
			EmailLike: q.Get("email_like"),
			Limit:     limit,
			Offset:    offset,
		})
		if err != nil {
			writeIdentityBusinessError(w, err)
			return
		}

		resp := make([]IdentityUserResponse, 0, len(dtos))
		for _, dto := range dtos {
			resp = append(resp, IdentityUserResponse{
				ID:          dto.ID,
				Email:       dto.Email,
				DisplayName: dto.DisplayName,
				AvatarURL:   dto.AvatarURL,
				Status:      dto.Status,
				TenantID:    dto.TenantID,
				CreatedAt:   dto.CreatedAt,
			})
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func identityHandleGetUser(svc identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := chi.URLParam(r, "id")

		dto, err := svc.GetUser(r.Context(), &identity.GetUserQuery{UserID: userID})
		if err != nil {
			writeIdentityBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, IdentityUserResponse{
			ID:          dto.ID,
			Email:       dto.Email,
			DisplayName: dto.DisplayName,
			AvatarURL:   dto.AvatarURL,
			Status:      dto.Status,
			TenantID:    dto.TenantID,
			CreatedAt:   dto.CreatedAt,
		})
	}
}

func identityHandleUpdateProfile(svc identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := chi.URLParam(r, "id")

		var req IdentityUpdateProfileRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		err := svc.UpdateProfile(r.Context(), &identity.UpdateProfileCommand{
			UserID:      userID,
			DisplayName: req.DisplayName,
			AvatarURL:   req.AvatarURL,
		})
		if err != nil {
			writeIdentityBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func identityHandleChangePassword(svc identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := chi.URLParam(r, "id")

		var req IdentityChangePasswordRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		err := svc.ChangePassword(r.Context(), &identity.ChangePasswordCommand{
			UserID:      userID,
			OldPassword: req.OldPassword,
			NewPassword: req.NewPassword,
		})
		if err != nil {
			writeIdentityBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func writeIdentityBusinessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identityDomain.ErrUserNotFound):
		writeError(w, http.StatusNotFound, "user_not_found", "user not found")
	case errors.Is(err, identityDomain.ErrUserAlreadyExists),
		errors.Is(err, identityDomain.ErrEmailAlreadyTaken):
		writeError(w, http.StatusConflict, "user_already_exists", "user already exists")
	case errors.Is(err, identityDomain.ErrInvalidEmail),
		errors.Is(err, identityDomain.ErrPasswordTooShort):
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid input")
	case errors.Is(err, identityDomain.ErrInvalidPassword):
		writeError(w, http.StatusUnauthorized, "invalid_password", "invalid password")
	case errors.Is(err, shared.ErrConcurrentUpdate):
		writeError(w, http.StatusConflict, "conflict", "user was modified concurrently, please retry")
	default:
		log.Printf("identity transport: unhandled error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
