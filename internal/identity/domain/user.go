package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
		UserID:            u.ID,
		AppID:             appID,
		Provider:          provider,
		CredentialSubject: email.String(),
		Secret:            password.Hash(),
		TenantID:          tenantID,
		Timestamp:         now,
	})
	return u, nil
}

// NewExternalUser creates a user from an external identity (e.g. wallet address).
// No password is set. The credential subject is used as the identity anchor.
func NewExternalUser(tenantID shared.TenantID, appID shared.AppID, provider, credentialSubject, publicKey string) *User {
	now := time.Now()
	hash := sha256.Sum256([]byte(provider + ":" + credentialSubject))
	placeholderEmail := NewEmailFromTrusted(fmt.Sprintf("%s@external.openiam.local", hex.EncodeToString(hash[:8])))
	u := &User{
		ID:        shared.NewUserID(),
		Email:     placeholderEmail,
		Status:    UserStatusActive,
		TenantID:  tenantID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	u.RecordEvent(UserRegisteredEvent{
		UserID:            u.ID,
		AppID:             appID,
		Provider:          provider,
		CredentialSubject: credentialSubject,
		PublicKey:         publicKey,
		TenantID:          tenantID,
		Timestamp:         now,
	})
	return u
}

func (u *User) Activate() error {
	if u.Status != UserStatusPending {
		return ErrUserAlreadyActivated
	}
	u.Status = UserStatusActive
	u.UpdatedAt = time.Now()
	u.RecordEvent(UserActivatedEvent{UserID: u.ID, Timestamp: u.UpdatedAt})
	return nil
}

func (u *User) ChangePassword(oldRaw, newRaw string) error {
	if !u.Password.Verify(oldRaw) {
		return ErrInvalidPassword
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
	u.RecordEvent(ProfileUpdatedEvent{
		UserID:      u.ID,
		TenantID:    u.TenantID,
		DisplayName: profile.DisplayName,
		AvatarURL:   profile.AvatarURL,
		Timestamp:   u.UpdatedAt,
	})
}

func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}
