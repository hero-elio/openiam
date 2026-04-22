package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"openiam/pkg/iam/tenant"
)

type fakeTenantService struct {
	tenant.Service

	listFn func(ctx context.Context, q *tenant.ListTenantsQuery) ([]*tenant.TenantDTO, error)
}

func (f *fakeTenantService) ListTenants(ctx context.Context, q *tenant.ListTenantsQuery) ([]*tenant.TenantDTO, error) {
	if f.listFn == nil {
		return nil, nil
	}
	return f.listFn(ctx, q)
}

func allowAll(_ context.Context, _, _ string) error { return nil }

func TestMountTenant_ListTenants(t *testing.T) {
	wantQ := &tenant.ListTenantsQuery{}
	svc := &fakeTenantService{
		listFn: func(_ context.Context, q *tenant.ListTenantsQuery) ([]*tenant.TenantDTO, error) {
			*wantQ = *q
			return []*tenant.TenantDTO{
				{ID: "t1", Name: "acme", Status: "active", CreatedAt: "2026-01-01T00:00:00Z"},
				{ID: "t2", Name: "globex", Status: "active", CreatedAt: "2026-01-02T00:00:00Z"},
			}, nil
		},
	}

	r := chi.NewRouter()
	MountTenant(r, svc, allowAll)

	req := httptest.NewRequest(http.MethodGet, "/?limit=25&offset=50", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if wantQ.Limit != 25 || wantQ.Offset != 50 {
		t.Fatalf("paging not forwarded: %+v", wantQ)
	}

	var got []TenantResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(got) != 2 || got[0].ID != "t1" || got[1].Name != "globex" {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestMountTenant_ListTenants_NoPagingParams(t *testing.T) {
	captured := tenant.ListTenantsQuery{Limit: 999, Offset: 999}
	svc := &fakeTenantService{
		listFn: func(_ context.Context, q *tenant.ListTenantsQuery) ([]*tenant.TenantDTO, error) {
			captured = *q
			return []*tenant.TenantDTO{}, nil
		},
	}

	r := chi.NewRouter()
	MountTenant(r, svc, allowAll)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}
	if captured.Limit != 0 || captured.Offset != 0 {
		t.Fatalf("expected zero paging defaults, got %+v", captured)
	}
}
