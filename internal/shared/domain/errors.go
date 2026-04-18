package domain

import "errors"

var (
	ErrNotFound          = errors.New("not found")
	ErrAlreadyExists     = errors.New("already exists")
	ErrInvalidInput      = errors.New("invalid input")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrForbidden         = errors.New("forbidden")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrEmailAlreadyTaken = errors.New("email already taken")
	ErrInvalidEmail      = errors.New("invalid email")
	ErrPasswordTooShort  = errors.New("password must be at least 8 characters")
	ErrInvalidPassword   = errors.New("invalid password")

	ErrUserAlreadyActivated = errors.New("user already activated")
	ErrUserDisabled         = errors.New("user is disabled")
	ErrUserLocked           = errors.New("user is locked")

	ErrCredentialNotFound      = errors.New("credential not found")
	ErrCredentialAlreadyExists = errors.New("credential already exists")
	ErrInvalidCredential       = errors.New("invalid credential")

	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrInvalidToken    = errors.New("invalid token")
	ErrTokenExpired    = errors.New("token expired")

	ErrRoleNotFound             = errors.New("role not found")
	ErrRoleAlreadyExists        = errors.New("role already exists")
	ErrPermissionAlreadyGranted = errors.New("permission already granted")

	ErrUnsupportedProvider = errors.New("unsupported authentication provider")

	ErrChallengeNotSupported = errors.New("challenge not supported for this provider")
	ErrChallengeNotFound     = errors.New("challenge not found or expired")
	ErrChallengeInvalid      = errors.New("invalid challenge response")

	ErrCredentialAlreadyBound = errors.New("credential already bound to a user")
)
