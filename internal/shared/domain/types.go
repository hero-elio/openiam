package domain

import "github.com/google/uuid"

type UserID string
type TenantID string
type RoleID string
type AppID string
type SessionID string
type CredentialID string

func NewUserID() UserID             { return UserID(uuid.New().String()) }
func NewTenantID() TenantID         { return TenantID(uuid.New().String()) }
func NewRoleID() RoleID             { return RoleID(uuid.New().String()) }
func NewAppID() AppID               { return AppID(uuid.New().String()) }
func NewSessionID() SessionID       { return SessionID(uuid.New().String()) }
func NewCredentialID() CredentialID { return CredentialID(uuid.New().String()) }

func (id UserID) String() string       { return string(id) }
func (id UserID) IsEmpty() bool        { return id == "" }
func (id TenantID) String() string     { return string(id) }
func (id TenantID) IsEmpty() bool      { return id == "" }
func (id RoleID) String() string       { return string(id) }
func (id AppID) String() string        { return string(id) }
func (id SessionID) String() string    { return string(id) }
func (id CredentialID) String() string { return string(id) }
