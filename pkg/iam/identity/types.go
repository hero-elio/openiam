// Package identity is the public SDK surface for the IAM identity
// module: user provisioning, profile management, and the cross-module
// adapters other modules consume (authn IdentityIntegration, authz
// SubjectExistence partial).
//
// SDK consumers should depend on this package, not on
// internal/identity/*. Phase 2b lifts the public types and Builder API;
// the canonical implementations stay under internal until Phase 5.
package identity

import (
	"openiam/internal/identity/domain"
	shared "openiam/internal/shared/domain"
)

// Identifier aliases.
//
// Kept as type aliases of the shared domain types so callers can pass
// values across modules without explicit conversions.
type (
	UserID   = shared.UserID
	TenantID = shared.TenantID
	AppID    = shared.AppID
)

// Domain types re-exported for SDK consumers.
type (
	User       = domain.User
	UserStatus = domain.UserStatus
	Email      = domain.Email
	Profile    = domain.Profile

	ScopeValidator = domain.ScopeValidator

	UserRegisteredEvent  = domain.UserRegisteredEvent
	UserActivatedEvent   = domain.UserActivatedEvent
	PasswordChangedEvent = domain.PasswordChangedEvent
	ProfileUpdatedEvent  = domain.ProfileUpdatedEvent
)

// User status constants re-exported for SDK consumers.
const (
	UserStatusActive   = domain.UserStatusActive
	UserStatusDisabled = domain.UserStatusDisabled
	UserStatusLocked   = domain.UserStatusLocked
)

// Domain event names re-exported for SDK subscribers.
const (
	EventUserRegistered  = domain.EventUserRegistered
	EventUserActivated   = domain.EventUserActivated
	EventPasswordChanged = domain.EventPasswordChanged
	EventProfileUpdated  = domain.EventProfileUpdated
)

// Domain sentinel errors re-exported so SDK callers can errors.Is
// against them without importing internal packages.
var (
	ErrUserNotFound         = domain.ErrUserNotFound
	ErrUserAlreadyExists    = domain.ErrUserAlreadyExists
	ErrEmailAlreadyTaken    = domain.ErrEmailAlreadyTaken
	ErrInvalidEmail         = domain.ErrInvalidEmail
	ErrPasswordTooShort     = domain.ErrPasswordTooShort
	ErrInvalidPassword      = domain.ErrInvalidPassword
	ErrUserAlreadyActivated = domain.ErrUserAlreadyActivated
	ErrUserDisabled         = domain.ErrUserDisabled
	ErrUserLocked           = domain.ErrUserLocked
)
