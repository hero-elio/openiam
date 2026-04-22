package authn

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateJWTSecret(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		wantErr error
	}{
		{"empty is rejected", "", ErrInsecureJWTSecret},
		{"sentinel is rejected", InsecureJWTSecretSentinel, ErrInsecureJWTSecret},
		{"too-short is rejected", strings.Repeat("a", MinJWTSecretLength-1), ErrInsecureJWTSecret},
		{"strong secret is accepted", strings.Repeat("a", MinJWTSecretLength), nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateJWTSecret(tc.secret)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("validateJWTSecret(%q): want %v, got %v", tc.secret, tc.wantErr, err)
			}
		})
	}
}
