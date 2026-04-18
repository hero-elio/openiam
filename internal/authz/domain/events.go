package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

const (
	EventRoleCreated       = "role.created"
	EventPermissionGranted = "role.permission_granted"
	EventRoleAssigned      = "role.assigned"
)

type RoleCreatedEvent struct {
	RoleID    shared.RoleID
	AppID     shared.AppID
	TenantID  shared.TenantID
	Name      string
	Timestamp time.Time
}

func (e RoleCreatedEvent) EventName() string     { return EventRoleCreated }
func (e RoleCreatedEvent) OccurredAt() time.Time { return e.Timestamp }
func (e RoleCreatedEvent) AggregateID() string   { return e.RoleID.String() }

type PermissionGrantedEvent struct {
	RoleID    shared.RoleID
	Resource  string
	Action    string
	Timestamp time.Time
}

func (e PermissionGrantedEvent) EventName() string     { return EventPermissionGranted }
func (e PermissionGrantedEvent) OccurredAt() time.Time { return e.Timestamp }
func (e PermissionGrantedEvent) AggregateID() string   { return e.RoleID.String() }

type RoleAssignedEvent struct {
	UserID    shared.UserID
	AppID     shared.AppID
	RoleID    shared.RoleID
	TenantID  shared.TenantID
	Timestamp time.Time
}

func (e RoleAssignedEvent) EventName() string     { return EventRoleAssigned }
func (e RoleAssignedEvent) OccurredAt() time.Time { return e.Timestamp }
func (e RoleAssignedEvent) AggregateID() string   { return e.RoleID.String() }
