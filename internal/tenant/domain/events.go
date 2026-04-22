package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

const (
	EventTenantCreated      = "tenant.created"
	EventApplicationCreated = "application.created"
	EventApplicationUpdated = "application.updated"
)

type TenantCreatedEvent struct {
	TenantID  shared.TenantID
	Name      string
	Timestamp time.Time
}

func (e TenantCreatedEvent) EventName() string     { return EventTenantCreated }
func (e TenantCreatedEvent) OccurredAt() time.Time { return e.Timestamp }
func (e TenantCreatedEvent) AggregateID() string   { return e.TenantID.String() }

type ApplicationCreatedEvent struct {
	AppID     shared.AppID
	TenantID  shared.TenantID
	Name      string
	CreatedBy shared.UserID
	Timestamp time.Time
}

func (e ApplicationCreatedEvent) EventName() string     { return EventApplicationCreated }
func (e ApplicationCreatedEvent) OccurredAt() time.Time { return e.Timestamp }
func (e ApplicationCreatedEvent) AggregateID() string   { return e.AppID.String() }
func (e ApplicationCreatedEvent) GetAppID() shared.AppID       { return e.AppID }
func (e ApplicationCreatedEvent) GetTenantID() shared.TenantID { return e.TenantID }
func (e ApplicationCreatedEvent) GetCreatedBy() shared.UserID  { return e.CreatedBy }

type ApplicationUpdatedEvent struct {
	AppID        shared.AppID
	TenantID     shared.TenantID
	Name         string
	RedirectURIs []string
	Scopes       []string
	Timestamp    time.Time
}

func (e ApplicationUpdatedEvent) EventName() string             { return EventApplicationUpdated }
func (e ApplicationUpdatedEvent) OccurredAt() time.Time         { return e.Timestamp }
func (e ApplicationUpdatedEvent) AggregateID() string           { return e.AppID.String() }
func (e ApplicationUpdatedEvent) GetAppID() shared.AppID        { return e.AppID }
func (e ApplicationUpdatedEvent) GetTenantID() shared.TenantID  { return e.TenantID }
