package domain

import "testing"

func TestNewEmail_NormalizesAndLowercases(t *testing.T) {
	email, err := NewEmail("  Alice.Example+tag@Example.COM ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := email.String(), "alice.example+tag@example.com"; got != want {
		t.Fatalf("normalized email mismatch: got %q, want %q", got, want)
	}
}

func TestNewEmail_InvalidEmail(t *testing.T) {
	_, err := NewEmail("not-an-email")
	if err == nil {
		t.Fatal("expected invalid email error")
	}
	if err != ErrInvalidEmail {
		t.Fatalf("unexpected error: got %v, want %v", err, ErrInvalidEmail)
	}
}
