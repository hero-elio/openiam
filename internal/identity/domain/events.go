package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

const (
	EventUserRegistered  = "user.registered"
	EventUserActivated   = "user.activated"
	EventPasswordChanged = "user.password_changed"
)

type UserRegisteredEvent struct {
	UserID       shared.UserID
	AppID        shared.AppID
	Provider     string
	Email        string
	PasswordHash string
	TenantID     shared.TenantID
	Timestamp    time.Time
}

func (e UserRegisteredEvent) EventName() string     { return EventUserRegistered }
func (e UserRegisteredEvent) OccurredAt() time.Time  { return e.Timestamp }
func (e UserRegisteredEvent) AggregateID() string    { return e.UserID.String() }
func (e UserRegisteredEvent) GetUserID() shared.UserID     { return e.UserID }
func (e UserRegisteredEvent) GetAppID() shared.AppID       { return e.AppID }
func (e UserRegisteredEvent) GetProvider() string          { return e.Provider }
func (e UserRegisteredEvent) GetEmail() string             { return e.Email }
func (e UserRegisteredEvent) GetPasswordHash() string      { return e.PasswordHash }
func (e UserRegisteredEvent) GetTenantID() shared.TenantID { return e.TenantID }

type UserActivatedEvent struct {
	UserID    shared.UserID
	Timestamp time.Time
}

func (e UserActivatedEvent) EventName() string     { return EventUserActivated }
func (e UserActivatedEvent) OccurredAt() time.Time  { return e.Timestamp }
func (e UserActivatedEvent) AggregateID() string    { return e.UserID.String() }

type PasswordChangedEvent struct {
	UserID    shared.UserID
	Timestamp time.Time
}

func (e PasswordChangedEvent) EventName() string     { return EventPasswordChanged }
func (e PasswordChangedEvent) OccurredAt() time.Time  { return e.Timestamp }
func (e PasswordChangedEvent) AggregateID() string    { return e.UserID.String() }
