package domain

import "errors"

var (
	ErrCredentialNotFound      = errors.New("credential not found")
	ErrCredentialAlreadyExists = errors.New("credential already exists")
	ErrInvalidCredential       = errors.New("invalid credential")
	ErrSessionNotFound         = errors.New("session not found")
	ErrSessionExpired          = errors.New("session expired")
	ErrInvalidToken            = errors.New("invalid token")
	ErrTokenExpired            = errors.New("token expired")
	ErrUnsupportedProvider     = errors.New("unsupported authentication provider")
	ErrChallengeNotSupported   = errors.New("challenge not supported for this provider")
	ErrChallengeNotFound       = errors.New("challenge not found or expired")
	ErrChallengeInvalid        = errors.New("invalid challenge response")
	ErrCredentialAlreadyBound  = errors.New("credential already bound to a user")
)
