package rest

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	sharedAuth "openiam/internal/shared/auth"
	shared "openiam/internal/shared/domain"
	tenantDomain "openiam/internal/tenant/domain"
	"openiam/pkg/iam/sharedauth"
	"openiam/pkg/iam/tenant"
)

// Endpoint names accepted by SkipEndpoints for MountTenant /
// MountApplications.
const (
	TenantEndpointCreateTenant      = "tenant.create"
	TenantEndpointGetTenant         = "tenant.get"
	TenantEndpointListTenants       = "tenant.list"
	TenantEndpointCreateApplication = "tenant.application.create"
	TenantEndpointListApplications  = "tenant.application.list"

	ApplicationEndpointGet    = "application.get"
	ApplicationEndpointUpdate = "application.update"
)

// MountTenant registers the tenant-rooted routes onto r against svc.
//
// Default route layout (relative to r):
//
//	POST /                       create tenant
//	GET  /                       list tenants (paged via ?limit & ?offset)
//	GET  /{tid}                  fetch tenant
//	POST /{tid}/applications     create application under tenant
//	GET  /{tid}/applications     list applications under tenant
//
// MountApplications registers the application-rooted routes (typically
// nested under /applications). They are split because production
// deployments tend to expose the two trees separately
// (tenants/{tid}/… vs applications/{aid}/…).
func MountTenant(r chi.Router, svc tenant.Service, check sharedauth.Checker, opts ...Option) {
	cfg := newMountConfig(opts)

	mount := func(target chi.Router) {
		for _, mw := range cfg.extraMiddleware {
			target.Use(mw)
		}

		if !cfg.skipped(TenantEndpointCreateTenant) {
			target.With(RequirePermission(check, tenant.ResourceTenants, tenant.ActionCreate)).
				Post("/", tenantHandleCreateTenant(svc))
		}
		if !cfg.skipped(TenantEndpointListTenants) {
			target.With(RequirePermission(check, tenant.ResourceTenants, tenant.ActionRead)).
				Get("/", tenantHandleListTenants(svc))
		}
		if !cfg.skipped(TenantEndpointGetTenant) {
			target.With(RequirePermission(check, tenant.ResourceTenants, tenant.ActionRead)).
				Get("/{tid}", tenantHandleGetTenant(svc))
		}
		if !cfg.skipped(TenantEndpointCreateApplication) {
			target.With(RequirePermission(check, tenant.ResourceApplications, tenant.ActionCreate)).
				Post("/{tid}/applications", tenantHandleCreateApplication(svc))
		}
		if !cfg.skipped(TenantEndpointListApplications) {
			target.With(RequirePermission(check, tenant.ResourceApplications, tenant.ActionRead)).
				Get("/{tid}/applications", tenantHandleListApplications(svc))
		}
	}

	if cfg.pathPrefix != "" {
		r.Route(cfg.pathPrefix, mount)
		return
	}
	mount(r)
}

// MountApplications registers the application-rooted routes onto r.
// Typically mounted under /applications; the routes use chi URL params
// {aid} (application id).
//
//	GET /{aid}      fetch application
//	PUT /{aid}      update application
func MountApplications(r chi.Router, svc tenant.Service, check sharedauth.Checker, opts ...Option) {
	cfg := newMountConfig(opts)

	mount := func(target chi.Router) {
		for _, mw := range cfg.extraMiddleware {
			target.Use(mw)
		}

		if !cfg.skipped(ApplicationEndpointGet) {
			target.With(RequirePermission(check, tenant.ResourceApplications, tenant.ActionRead)).
				Get("/{aid}", tenantHandleGetApplication(svc))
		}
		if !cfg.skipped(ApplicationEndpointUpdate) {
			target.With(RequirePermission(check, tenant.ResourceApplications, tenant.ActionUpdate)).
				Put("/{aid}", tenantHandleUpdateApplication(svc))
		}
	}

	if cfg.pathPrefix != "" {
		r.Route(cfg.pathPrefix, mount)
		return
	}
	mount(r)
}

// --- Request / Response DTOs ---

type TenantCreateTenantRequest struct {
	Name string `json:"name"`
}

type TenantCreateApplicationRequest struct {
	Name string `json:"name"`
}

type TenantUpdateApplicationRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
}

type TenantResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type ApplicationResponse struct {
	ID           string   `json:"id"`
	TenantID     string   `json:"tenant_id"`
	Name         string   `json:"name"`
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Status       string   `json:"status"`
	CreatedAt    string   `json:"created_at"`
}

type CreateApplicationResponse struct {
	ApplicationResponse
	ClientSecret string `json:"client_secret"`
}

// --- Handlers ---

func tenantHandleCreateTenant(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TenantCreateTenantRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "name is required")
			return
		}

		tenantID, err := svc.CreateTenant(r.Context(), &tenant.CreateTenantCommand{Name: req.Name})
		if err != nil {
			writeTenantBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{"id": tenantID.String()})
	}
}

func tenantHandleListTenants(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

		dtos, err := svc.ListTenants(r.Context(), &tenant.ListTenantsQuery{
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			writeTenantBusinessError(w, err)
			return
		}

		resp := make([]TenantResponse, 0, len(dtos))
		for _, dto := range dtos {
			resp = append(resp, TenantResponse{
				ID:        dto.ID,
				Name:      dto.Name,
				Status:    dto.Status,
				CreatedAt: dto.CreatedAt,
			})
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func tenantHandleGetTenant(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := chi.URLParam(r, "tid")

		dto, err := svc.GetTenant(r.Context(), &tenant.GetTenantQuery{TenantID: tid})
		if err != nil {
			writeTenantBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, TenantResponse{
			ID:        dto.ID,
			Name:      dto.Name,
			Status:    dto.Status,
			CreatedAt: dto.CreatedAt,
		})
	}
}

func tenantHandleCreateApplication(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := chi.URLParam(r, "tid")

		claims, ok := sharedAuth.ClaimsFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing authentication")
			return
		}

		var req TenantCreateApplicationRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "invalid_argument", "name is required")
			return
		}

		result, err := svc.CreateApplication(r.Context(), &tenant.CreateApplicationCommand{
			TenantID:  tid,
			Name:      req.Name,
			CreatedBy: claims.UserID,
		})
		if err != nil {
			writeTenantBusinessError(w, err)
			return
		}

		dto := result.Application
		writeJSON(w, http.StatusCreated, CreateApplicationResponse{
			ApplicationResponse: ApplicationResponse{
				ID:           dto.ID,
				TenantID:     dto.TenantID,
				Name:         dto.Name,
				ClientID:     dto.ClientID,
				RedirectURIs: dto.RedirectURIs,
				Scopes:       dto.Scopes,
				Status:       dto.Status,
				CreatedAt:    dto.CreatedAt,
			},
			ClientSecret: result.ClientSecret,
		})
	}
}

func tenantHandleListApplications(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := chi.URLParam(r, "tid")

		dtos, err := svc.ListApplications(r.Context(), &tenant.ListApplicationsQuery{TenantID: tid})
		if err != nil {
			writeTenantBusinessError(w, err)
			return
		}

		resp := make([]ApplicationResponse, 0, len(dtos))
		for _, dto := range dtos {
			resp = append(resp, ApplicationResponse{
				ID:           dto.ID,
				TenantID:     dto.TenantID,
				Name:         dto.Name,
				ClientID:     dto.ClientID,
				RedirectURIs: dto.RedirectURIs,
				Scopes:       dto.Scopes,
				Status:       dto.Status,
				CreatedAt:    dto.CreatedAt,
			})
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func tenantHandleGetApplication(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		aid := chi.URLParam(r, "aid")

		dto, err := svc.GetApplication(r.Context(), &tenant.GetApplicationQuery{AppID: aid})
		if err != nil {
			writeTenantBusinessError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, ApplicationResponse{
			ID:           dto.ID,
			TenantID:     dto.TenantID,
			Name:         dto.Name,
			ClientID:     dto.ClientID,
			RedirectURIs: dto.RedirectURIs,
			Scopes:       dto.Scopes,
			Status:       dto.Status,
			CreatedAt:    dto.CreatedAt,
		})
	}
}

func tenantHandleUpdateApplication(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		aid := chi.URLParam(r, "aid")

		var req TenantUpdateApplicationRequest
		if err := DecodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		err := svc.UpdateApplication(r.Context(), &tenant.UpdateApplicationCommand{
			AppID:        aid,
			Name:         req.Name,
			RedirectURIs: req.RedirectURIs,
			Scopes:       req.Scopes,
		})
		if err != nil {
			writeTenantBusinessError(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func writeTenantBusinessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, tenantDomain.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	case errors.Is(err, tenantDomain.ErrAppNotFound):
		writeError(w, http.StatusNotFound, "application_not_found", "application not found")
	case errors.Is(err, tenantDomain.ErrTenantAlreadyExists):
		writeError(w, http.StatusConflict, "tenant_already_exists", "tenant already exists")
	case errors.Is(err, tenantDomain.ErrAppAlreadyExists):
		writeError(w, http.StatusConflict, "application_already_exists", "application already exists")
	case errors.Is(err, tenantDomain.ErrClientIDTaken):
		writeError(w, http.StatusConflict, "client_id_taken", "client id already taken")
	case errors.Is(err, shared.ErrConcurrentUpdate):
		writeError(w, http.StatusConflict, "conflict", "resource was modified concurrently, please retry")
	case errors.Is(err, shared.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "invalid_argument", "invalid request")
	default:
		log.Printf("tenant transport: unhandled error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
