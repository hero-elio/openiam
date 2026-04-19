package domain

import "testing"

func TestNewTenant_SetsDefaultsAndRecordsEvent(t *testing.T) {
	tenant := NewTenant("acme")

	if tenant.ID == "" {
		t.Fatal("tenant id should not be empty")
	}
	if tenant.Name != "acme" {
		t.Fatalf("tenant name mismatch: got %q, want acme", tenant.Name)
	}
	if tenant.Status != "active" {
		t.Fatalf("tenant status mismatch: got %q, want active", tenant.Status)
	}
	if tenant.CreatedAt.IsZero() {
		t.Fatal("tenant created at should not be zero")
	}

	events := tenant.PullEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 domain event, got %d", len(events))
	}

	evt, ok := events[0].(TenantCreatedEvent)
	if !ok {
		t.Fatalf("unexpected event type: %T", events[0])
	}
	if evt.TenantID != tenant.ID || evt.Name != "acme" {
		t.Fatalf("tenant created event payload mismatch")
	}
}
