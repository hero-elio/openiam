package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

const (
	EventUserLoggedIn   = "authn.user_logged_in"
	EventUserLoggedOut  = "authn.user_logged_out"
	EventTokenRefreshed = "authn.token_refreshed"
)

type UserLoggedInEvent struct {
	UserID    shared.UserID
	AppID     shared.AppID
	Provider  string
	SessionID shared.SessionID
	Timestamp time.Time
}

func (e UserLoggedInEvent) EventName() string    { return EventUserLoggedIn }
func (e UserLoggedInEvent) OccurredAt() time.Time { return e.Timestamp }
func (e UserLoggedInEvent) AggregateID() string   { return e.UserID.String() }

type UserLoggedOutEvent struct {
	UserID    shared.UserID
	SessionID shared.SessionID
	Timestamp time.Time
}

func (e UserLoggedOutEvent) EventName() string    { return EventUserLoggedOut }
func (e UserLoggedOutEvent) OccurredAt() time.Time { return e.Timestamp }
func (e UserLoggedOutEvent) AggregateID() string   { return e.UserID.String() }

type TokenRefreshedEvent struct {
	UserID    shared.UserID
	SessionID shared.SessionID
	Timestamp time.Time
}

func (e TokenRefreshedEvent) EventName() string    { return EventTokenRefreshed }
func (e TokenRefreshedEvent) OccurredAt() time.Time { return e.Timestamp }
func (e TokenRefreshedEvent) AggregateID() string   { return e.UserID.String() }
