package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

type UserStatus string

const (
	UserStatusPending  UserStatus = "pending"
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
	UserStatusLocked   UserStatus = "locked"
)

type User struct {
	shared.AggregateRoot
	ID        shared.UserID
	Email     Email
	Password  Password
	Profile   Profile
	Status    UserStatus
	TenantID  shared.TenantID
	CreatedAt time.Time
	UpdatedAt time.Time
}

func NewUser(email Email, rawPassword string, tenantID shared.TenantID, appID shared.AppID, provider string) (*User, error) {
	password, err := NewPassword(rawPassword)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	u := &User{
		ID:        shared.NewUserID(),
		Email:     email,
		Password:  password,
		Status:    UserStatusActive,
		TenantID:  tenantID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	u.RecordEvent(UserRegisteredEvent{
		UserID:       u.ID,
		AppID:        appID,
		Provider:     provider,
		Email:        email.String(),
		PasswordHash: password.Hash(),
		TenantID:     tenantID,
		Timestamp:    now,
	})
	return u, nil
}

func (u *User) Activate() error {
	if u.Status != UserStatusPending {
		return shared.ErrUserAlreadyActivated
	}
	u.Status = UserStatusActive
	u.UpdatedAt = time.Now()
	u.RecordEvent(UserActivatedEvent{UserID: u.ID, Timestamp: u.UpdatedAt})
	return nil
}

func (u *User) ChangePassword(oldRaw, newRaw string) error {
	if !u.Password.Verify(oldRaw) {
		return shared.ErrInvalidPassword
	}
	newPwd, err := NewPassword(newRaw)
	if err != nil {
		return err
	}
	u.Password = newPwd
	u.UpdatedAt = time.Now()
	u.RecordEvent(PasswordChangedEvent{UserID: u.ID, Timestamp: u.UpdatedAt})
	return nil
}

func (u *User) UpdateProfile(profile Profile) {
	u.Profile = profile
	u.UpdatedAt = time.Now()
}

func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}
