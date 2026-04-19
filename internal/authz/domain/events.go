package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

const (
	EventRoleCreated               = "role.created"
	EventPermissionGranted         = "role.permission_granted"
	EventPermissionRevoked         = "role.permission_revoked"
	EventRoleAssigned              = "role.assigned"
	EventResourcePermissionGranted = "resource_permission.granted"
	EventResourcePermissionRevoked = "resource_permission.revoked"
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

type PermissionRevokedEvent struct {
	RoleID    shared.RoleID
	Resource  string
	Action    string
	Timestamp time.Time
}

func (e PermissionRevokedEvent) EventName() string     { return EventPermissionRevoked }
func (e PermissionRevokedEvent) OccurredAt() time.Time { return e.Timestamp }
func (e PermissionRevokedEvent) AggregateID() string   { return e.RoleID.String() }

type ResourcePermissionGrantedEvent struct {
	UserID       shared.UserID
	AppID        shared.AppID
	ResourceType string
	ResourceID   string
	Action       string
	GrantedBy    shared.UserID
	Timestamp    time.Time
}

func (e ResourcePermissionGrantedEvent) EventName() string     { return EventResourcePermissionGranted }
func (e ResourcePermissionGrantedEvent) OccurredAt() time.Time { return e.Timestamp }
func (e ResourcePermissionGrantedEvent) AggregateID() string   { return e.UserID.String() }

type ResourcePermissionRevokedEvent struct {
	UserID       shared.UserID
	AppID        shared.AppID
	ResourceType string
	ResourceID   string
	Action       string
	Timestamp    time.Time
}

func (e ResourcePermissionRevokedEvent) EventName() string     { return EventResourcePermissionRevoked }
func (e ResourcePermissionRevokedEvent) OccurredAt() time.Time { return e.Timestamp }
func (e ResourcePermissionRevokedEvent) AggregateID() string   { return e.UserID.String() }
