package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

type Tenant struct {
	shared.AggregateRoot
	ID        shared.TenantID
	Name      string
	Status    string
	CreatedAt time.Time
}

func NewTenant(name string) *Tenant {
	now := time.Now()
	t := &Tenant{
		ID:        shared.NewTenantID(),
		Name:      name,
		Status:    "active",
		CreatedAt: now,
	}
	t.RecordEvent(TenantCreatedEvent{
		TenantID:  t.ID,
		Name:      name,
		Timestamp: now,
	})
	return t
}
