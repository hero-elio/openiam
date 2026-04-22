package rest

import (
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	authzDomain "openiam/internal/authz/domain"
	sharedAuth "openiam/internal/shared/auth"
	shared "openiam/internal/shared/domain"
	"openiam/pkg/iam/authz"
	"openiam/pkg/iam/sharedauth"
)

// Endpoint names accepted by SkipEndpoints for MountAuthz.
const (
	AuthzEndpointCreateRole          = "role.create"
	AuthzEndpointListRoles           = "role.list"
	AuthzEndpointDeleteRole          = "role.delete"
	AuthzEndpointGrantPermission     = "role.permission.grant"
	AuthzEndpointRevokePermission    = "role.permission.revoke"
	AuthzEndpointAssignRole          = "user.role.assign"
	AuthzEndpointUnassignRole        = "user.role.unassign"
	AuthzEndpointListUserRoles       = "user.role.list"
	AuthzEndpointCheckPermission     = "permission.check"
	AuthzEndpointGrantResource       = "resource.permission.grant"
	AuthzEndpointRevokeResource      = "resource.permission.revoke"
	AuthzEndpointCheckResource       = "resource.permission.check"
	AuthzEndpointListResource        = "resource.permission.list"
	AuthzEndpointRegisterPermission  = "permission.definition.create"
	AuthzEndpointListPermissionDefs  = "permission.definition.list"
	AuthzEndpointDeletePermission    = "permission.definition.delete"
)

// MountAuthz registers the authorization routes onto r against svc.
//
// Default route layout (relative to r; nest with WithPathPrefix):
//
//	POST   /roles
//	GET    /roles
//	DELETE /roles/{id}
//	POST   /roles/{id}/permissions
//	DELETE /roles/{id}/permissions
//	POST   /users/{uid}/roles
//	DELETE /users/{uid}/roles/{rid}
//	GET    /users/{uid}/roles
//	POST   /check
//	POST   /resources/permissions
//	DELETE /resources/permissions
//	POST   /resources/check
//	GET    /resources/permissions
//	POST   /permissions
//	GET    /permissions
//	DELETE /permissions
//
// Every route gates through check; the resource/action vocabulary is
// owned by pkg/iam/authz/keys.go so a typo at mount time is a compile
// error rather than a runtime 403.
func MountAuthz(r chi.Router, svc authz.Service, check sharedauth.Checker, opts ...Option) {
	cfg := newMountConfig(opts)

	mount := func(target chi.Router) {
		for _, mw := range cfg.extraMiddleware {
			target.Use(mw)
		}

		if !cfg.skipped(AuthzEndpointCreateRole) {
			target.With(RequirePermission(check, authz.ResourceRoles, authz.ActionCreate)).
				Post("/roles", authzHandleCreateRole(svc))
		}
		if !cfg.skipped(AuthzEndpointListRoles) {
			target.With(RequirePermission(check, authz.ResourceRoles, authz.ActionRead)).
				Get("/roles", authzHandleListRoles(svc))
		}
		if !cfg.skipped(AuthzEndpointDeleteRole) {
			target.With(RequirePermission(check, authz.ResourceRoles, authz.ActionDelete)).
				Delete("/roles/{id}", authzHandleDeleteRole(svc))
		}
		if !cfg.skipped(AuthzEndpointGrantPermission) {
			target.With(RequirePermission(check, authz.ResourcePermissions, authz.ActionGrant)).
				Post("/roles/{id}/permissions", authzHandleGrantPermission(svc))
		}
		if !cfg.skipped(AuthzEndpointRevokePermission) {
			target.With(RequirePermission(check, authz.ResourcePermissions, authz.ActionRevoke)).
				Delete("/roles/{id}/permissions", authzHandleRevokePermission(svc))
		}
		if !cfg.skipped(AuthzEndpointAssignRole) {
			target.With(RequirePermission(check, authz.ResourceRoles, authz.ActionAssign)).
				Post("/users/{uid}/roles", authzHandleAssignRole(svc))
		}
		if !cfg.skipped(AuthzEndpointUnassignRole) {
			target.With(RequirePermission(check, authz.ResourceRoles, authz.ActionAssign)).
				Delete("/users/{uid}/roles/{rid}", authzHandleUnassignRole(svc))
		}
		if !cfg.skipped(AuthzEndpointListUserRoles) {
			target.With(RequirePermission(check, authz.ResourceRoles, authz.ActionRead)).
				Get("/users/{uid}/roles", authzHandleListUserRoles(svc))
		}
		if !cfg.skipped(AuthzEndpointCheckPermission) {
			target.With(RequirePermission(check, authz.ResourcePermissions, authz.ActionCheck)).
				Post("/check", authzHandleCheckPermission(svc))
		}
		if !cfg.skipped(AuthzEndpointGrantResource) {
			target.With(RequirePermission(check, authz.ResourceResources, authz.ActionGrant)).
				Post("/resources/permissions", authzHandleGrantResource(svc))
		}
		if !cfg.skipped(AuthzEndpointRevokeResource) {
			target.With(RequirePermission(check, authz.ResourceResources, authz.ActionRevoke)).
				Delete("/resources/permissions", authzHandleRevokeResource(svc))
		}
		if !cfg.skipped(AuthzEndpointCheckResource) {
			target.With(RequirePermission(check, authz.ResourcePermissions, authz.ActionCheck)).
				Post("/resources/check", authzHandleCheckResource(svc))
		}
		if !cfg.skipped(AuthzEndpointListResource) {
			target.With(RequirePermission(check, authz.ResourceResources, authz.ActionRead)).
				Get("/resources/permissions", authzHandleListResource(svc))
		}
		if !cfg.skipped(AuthzEndpointRegisterPermission) {
			target.With(RequirePermission(check, authz.ResourcePermissions, authz.ActionCreate)).
				Post("/permissions", authzHandleRegisterPermission(svc))
		}
		if !cfg.skipped(AuthzEndpointListPermissionDefs) {
			target.With(RequirePermission(check, authz.ResourcePermissions, authz.ActionRead)).
				Get("/permissions", authzHandleListPermissionDefinitions(svc))
		}
		if !cfg.skipped(AuthzEndpointDeletePermission) {
			target.With(RequirePermission(check, authz.ResourcePermissions, authz.ActionDelete)).
				Delete("/permissions", authzHandleDeletePermission(svc))
		}
	}

	if cfg.pathPrefix != "" {
		r.Route(cfg.pathPrefix, mount)
		return
	}
	mount(r)
}

// --- Request / Response DTOs ---

type AuthzCreateRoleRequest struct {
	AppID       string `json:"app_id"`
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AuthzGrantPermissionRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type AuthzRevokePermissionRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type AuthzAssignRoleRequest struct {
	AppID    string `json:"app_id"`
	RoleID   string `json:"role_id"`
	TenantID string `json:"tenant_id"`
}

type AuthzCheckPermissionRequest struct {
	UserID   string `json:"user_id"`
	AppID    string `json:"app_id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type AuthzGrantResourcePermissionRequest struct {
	UserID       string `json:"user_id"`
	AppID        string `json:"app_id"`
	TenantID     string `json:"tenant_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
}

type AuthzRevokeResourcePermissionRequest struct {
	UserID       string `json:"user_id"`
	AppID        string `json:"app_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
}

type AuthzCheckResourcePermissionRequest struct {
	UserID       string `json:"user_id"`
	AppID        string `json:"app_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
}

type AuthzRegisterPermissionRequest struct {
	AppID       string `json:"app_id"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type AuthzDeletePermissionRequest struct {
	AppID    string `json:"app_id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type AuthzRoleResponse struct {
	ID          string   `json:"id"`
	AppID       string   `json:"app_id"`
	TenantID    string   `json:"tenant_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	IsSystem    bool     `json:"is_system"`
	CreatedAt   string   `json:"created_at"`
}

type AuthzUserAppRoleResponse struct {
	UserID     string `json:"user_id"`
	AppID      string `json:"app_id"`
	RoleID     string `json:"role_id"`
	TenantID   string `json:"tenant_id"`
	AssignedAt string `json:"assigned_at"`
}

type AuthzCheckPermissionResponse struct {
	Allowed bool `json:"allowed"`
}

type AuthzResourcePermissionResponse struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	AppID        string `json:"app_id"`
	TenantID     string `json:"tenant_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
	GrantedAt    string `json:"granted_at"`
	GrantedBy    string `json:"granted_by"`
}

type AuthzPermissionDefinitionResponse struct {
	ID          string `json:"id"`
	AppID       string `json:"app_id"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
	IsBuiltin   bool   `json:"is_builtin"`
	CreatedAt   string `json:"created_at"`
}

// --- Handlers ---

func authzHandleCreateRole(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuthzCreateRoleRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.Name == "" || req.AppID == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "name and app_id are required")
			return
		}

		roleID, err := svc.CreateRole(r.Context(), &authz.CreateRoleCommand{
			AppID:       req.AppID,
			TenantID:    req.TenantID,
			Name:        req.Name,
			Description: req.Description,
		})
		if err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{"id": roleID.String()})
	}
}

func authzHandleListRoles(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appID := r.URL.Query().Get("app_id")
		if appID == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "app_id query parameter is required")
			return
		}

		roles, err := svc.ListRoles(r.Context(), &authz.ListRolesQuery{AppID: appID})
		if err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		resp := make([]AuthzRoleResponse, 0, len(roles))
		for _, dto := range roles {
			resp = append(resp, AuthzRoleResponse{
				ID:          dto.ID,
				AppID:       dto.AppID,
				TenantID:    dto.TenantID,
				Name:        dto.Name,
				Description: dto.Description,
				Permissions: dto.Permissions,
				IsSystem:    dto.IsSystem,
				CreatedAt:   dto.CreatedAt,
			})
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func authzHandleDeleteRole(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		roleID := chi.URLParam(r, "id")

		if err := svc.DeleteRole(r.Context(), roleID); err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func authzHandleGrantPermission(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		roleID := chi.URLParam(r, "id")

		var req AuthzGrantPermissionRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.Resource == "" || req.Action == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "resource and action are required")
			return
		}

		if err := svc.GrantPermission(r.Context(), &authz.GrantPermissionCommand{
			RoleID:   roleID,
			Resource: req.Resource,
			Action:   req.Action,
		}); err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func authzHandleRevokePermission(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		roleID := chi.URLParam(r, "id")

		var req AuthzRevokePermissionRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if err := svc.RevokePermission(r.Context(), &authz.RevokePermissionCommand{
			RoleID:   roleID,
			Resource: req.Resource,
			Action:   req.Action,
		}); err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func authzHandleAssignRole(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := chi.URLParam(r, "uid")

		var req AuthzAssignRoleRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.RoleID == "" || req.AppID == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "role_id and app_id are required")
			return
		}

		// The Checker only verified `roles:assign` against the
		// caller's own claims.AppID. Refuse cross-app mutation here
		// so a privileged user in app A can't reach into app B by
		// pointing the request body at a different app id.
		if claims, ok := sharedAuth.ClaimsFromContext(r.Context()); !ok || claims.AppID != req.AppID {
			writeError(w, http.StatusForbidden, "forbidden", "cannot assign roles outside the caller's app context")
			return
		}

		if err := svc.AssignRole(r.Context(), &authz.AssignRoleCommand{
			UserID:   userID,
			AppID:    req.AppID,
			RoleID:   req.RoleID,
			TenantID: req.TenantID,
		}); err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func authzHandleUnassignRole(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := chi.URLParam(r, "uid")
		roleID := chi.URLParam(r, "rid")
		appID := r.URL.Query().Get("app_id")
		if appID == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "app_id query parameter is required")
			return
		}

		if claims, ok := sharedAuth.ClaimsFromContext(r.Context()); !ok || claims.AppID != appID {
			writeError(w, http.StatusForbidden, "forbidden", "cannot unassign roles outside the caller's app context")
			return
		}

		if err := svc.UnassignRole(r.Context(), userID, appID, roleID); err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func authzHandleListUserRoles(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := chi.URLParam(r, "uid")
		appID := r.URL.Query().Get("app_id")
		if appID == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "app_id query parameter is required")
			return
		}

		dtos, err := svc.ListUserRoles(r.Context(), &authz.ListUserRolesQuery{UserID: uid, AppID: appID})
		if err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		resp := make([]AuthzUserAppRoleResponse, 0, len(dtos))
		for _, d := range dtos {
			resp = append(resp, AuthzUserAppRoleResponse{
				UserID:     d.UserID,
				AppID:      d.AppID,
				RoleID:     d.RoleID,
				TenantID:   d.TenantID,
				AssignedAt: d.AssignedAt,
			})
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func authzHandleCheckPermission(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuthzCheckPermissionRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.UserID == "" || req.AppID == "" || req.Resource == "" || req.Action == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "user_id, app_id, resource, and action are required")
			return
		}

		result, err := svc.CheckPermission(r.Context(), &authz.CheckPermissionQuery{
			UserID:   req.UserID,
			AppID:    req.AppID,
			Resource: req.Resource,
			Action:   req.Action,
		})
		if err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, AuthzCheckPermissionResponse{Allowed: result.Allowed})
	}
}

func authzHandleGrantResource(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := sharedAuth.ClaimsFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing authentication")
			return
		}

		var req AuthzGrantResourcePermissionRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.UserID == "" || req.AppID == "" || req.ResourceType == "" || req.ResourceID == "" || req.Action == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "user_id, app_id, resource_type, resource_id, and action are required")
			return
		}

		if err := svc.GrantResourcePermission(r.Context(), &authz.GrantResourcePermissionCommand{
			UserID:       req.UserID,
			AppID:        req.AppID,
			TenantID:     req.TenantID,
			ResourceType: req.ResourceType,
			ResourceID:   req.ResourceID,
			Action:       req.Action,
			GrantedBy:    claims.UserID,
		}); err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func authzHandleRevokeResource(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuthzRevokeResourcePermissionRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if err := svc.RevokeResourcePermission(r.Context(), &authz.RevokeResourcePermissionCommand{
			UserID:       req.UserID,
			AppID:        req.AppID,
			ResourceType: req.ResourceType,
			ResourceID:   req.ResourceID,
			Action:       req.Action,
		}); err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func authzHandleCheckResource(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuthzCheckResourcePermissionRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.UserID == "" || req.AppID == "" || req.ResourceType == "" || req.ResourceID == "" || req.Action == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "user_id, app_id, resource_type, resource_id, and action are required")
			return
		}

		result, err := svc.CheckResourcePermission(r.Context(), &authz.CheckResourcePermissionQuery{
			UserID:       req.UserID,
			AppID:        req.AppID,
			ResourceType: req.ResourceType,
			ResourceID:   req.ResourceID,
			Action:       req.Action,
		})
		if err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, AuthzCheckPermissionResponse{Allowed: result.Allowed})
	}
}

func authzHandleListResource(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		appID := r.URL.Query().Get("app_id")
		if userID == "" || appID == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "user_id and app_id query parameters are required")
			return
		}

		dtos, err := svc.ListResourcePermissions(r.Context(), &authz.ListResourcePermissionsQuery{
			UserID: userID,
			AppID:  appID,
		})
		if err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		resp := make([]AuthzResourcePermissionResponse, 0, len(dtos))
		for _, d := range dtos {
			resp = append(resp, AuthzResourcePermissionResponse{
				ID:           d.ID,
				UserID:       d.UserID,
				AppID:        d.AppID,
				TenantID:     d.TenantID,
				ResourceType: d.ResourceType,
				ResourceID:   d.ResourceID,
				Action:       d.Action,
				GrantedAt:    d.GrantedAt,
				GrantedBy:    d.GrantedBy,
			})
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func authzHandleRegisterPermission(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuthzRegisterPermissionRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.AppID == "" || req.Resource == "" || req.Action == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "app_id, resource, and action are required")
			return
		}

		if err := svc.RegisterPermission(r.Context(), &authz.RegisterPermissionCommand{
			AppID:       req.AppID,
			Resource:    req.Resource,
			Action:      req.Action,
			Description: req.Description,
		}); err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

func authzHandleListPermissionDefinitions(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appID := r.URL.Query().Get("app_id")
		if appID == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "app_id query parameter is required")
			return
		}

		dtos, err := svc.ListPermissionDefinitions(r.Context(), &authz.ListPermissionDefinitionsQuery{AppID: appID})
		if err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		resp := make([]AuthzPermissionDefinitionResponse, 0, len(dtos))
		for _, d := range dtos {
			resp = append(resp, AuthzPermissionDefinitionResponse{
				ID:          d.ID,
				AppID:       d.AppID,
				Resource:    d.Resource,
				Action:      d.Action,
				Description: d.Description,
				IsBuiltin:   d.IsBuiltin,
				CreatedAt:   d.CreatedAt,
			})
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func authzHandleDeletePermission(svc authz.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuthzDeletePermissionRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.AppID == "" || req.Resource == "" || req.Action == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "app_id, resource, and action are required")
			return
		}

		if err := svc.DeletePermissionDefinition(r.Context(), &authz.DeletePermissionCommand{
			AppID:    req.AppID,
			Resource: req.Resource,
			Action:   req.Action,
		}); err != nil {
			writeAuthzBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func writeAuthzBusinessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authzDomain.ErrRoleNotFound):
		writeError(w, http.StatusNotFound, "role_not_found", "role not found")
	case errors.Is(err, authzDomain.ErrRoleAlreadyExists):
		writeError(w, http.StatusConflict, "role_already_exists", "role already exists")
	case errors.Is(err, authzDomain.ErrPermissionAlreadyGranted):
		writeError(w, http.StatusConflict, "permission_already_granted", "permission already granted")
	case errors.Is(err, authzDomain.ErrSystemRoleProtected):
		writeError(w, http.StatusForbidden, "system_role_protected", "system role cannot be modified")
	case errors.Is(err, authzDomain.ErrRoleAppMismatch):
		writeError(w, http.StatusBadRequest, "role_app_mismatch", "role does not belong to the target app")
	case errors.Is(err, authzDomain.ErrUnknownSubject):
		writeError(w, http.StatusUnprocessableEntity, "unknown_subject", "user or application does not exist")
	case errors.Is(err, shared.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "invalid_argument", "invalid request")
	case errors.Is(err, shared.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, shared.ErrConcurrentUpdate):
		writeError(w, http.StatusConflict, "conflict", "resource was modified concurrently, please retry")
	default:
		log.Printf("authz transport: unhandled error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
