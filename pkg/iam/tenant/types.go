// Package tenant is the public SDK surface for the IAM tenant module:
// tenant + application directory plus the cross-module adapters other
// modules consume (authn AppDirectory, identity ScopeValidator, authz
// SubjectExistence partial).
//
// Phase 2d lifts the public types and Builder API; canonical
// implementations stay under internal/tenant until Phase 5.
package tenant

import (
	shared "openiam/internal/shared/domain"
	"openiam/internal/tenant/domain"
)

// Identifier aliases.
type (
	TenantID = shared.TenantID
	AppID    = shared.AppID
	UserID   = shared.UserID
)

// Domain types re-exported for SDK consumers.
type (
	Tenant      = domain.Tenant
	Application = domain.Application

	TenantCreatedEvent      = domain.TenantCreatedEvent
	ApplicationCreatedEvent = domain.ApplicationCreatedEvent
	ApplicationUpdatedEvent = domain.ApplicationUpdatedEvent
)

// Domain event names re-exported for SDK subscribers.
const (
	EventTenantCreated      = domain.EventTenantCreated
	EventApplicationCreated = domain.EventApplicationCreated
	EventApplicationUpdated = domain.EventApplicationUpdated
)

// Domain sentinel errors re-exported.
var (
	ErrTenantNotFound      = domain.ErrTenantNotFound
	ErrTenantAlreadyExists = domain.ErrTenantAlreadyExists
	ErrAppNotFound         = domain.ErrAppNotFound
	ErrAppAlreadyExists    = domain.ErrAppAlreadyExists
	ErrClientIDTaken       = domain.ErrClientIDTaken
)
