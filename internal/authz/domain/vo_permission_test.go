package domain

import "testing"

func TestParsePermission(t *testing.T) {
	p, err := ParsePermission("users:read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Resource != "users" || p.Action != "read" {
		t.Fatalf("parsed permission mismatch")
	}

	_, err = ParsePermission("invalid-format")
	if err == nil {
		t.Fatalf("expected parse error for invalid format")
	}
}

func TestPermissionMatchesAndHelpers(t *testing.T) {
	if !NewPermission("*", "*").Matches("users", "delete") {
		t.Fatalf("wildcard permission should match any resource/action")
	}
	if !NewPermission("roles", "*").Matches("roles", "update") {
		t.Fatalf("resource wildcard action should match")
	}
	if NewPermission("roles", "read").Matches("users", "read") {
		t.Fatalf("resource mismatch should deny")
	}

	p := NewPermission("roles", "read")
	if p.String() != "roles:read" {
		t.Fatalf("string render mismatch: got %q", p.String())
	}
	if p.IsZero() {
		t.Fatalf("non-empty permission should not be zero")
	}
	if !(Permission{}).IsZero() {
		t.Fatalf("empty permission should be zero")
	}
}
