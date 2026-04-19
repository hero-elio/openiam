package domain

import (
	"context"
	"time"
)

type DomainEvent interface {
	EventName() string
	OccurredAt() time.Time
	AggregateID() string
}

type EventHandler func(ctx context.Context, event DomainEvent) error

type EventBus interface {
	Publish(ctx context.Context, events ...DomainEvent) error
	Subscribe(eventName string, handler EventHandler) error
}

// TxManager abstracts unit-of-work execution so application services
// do not depend on any specific persistence infrastructure.
type TxManager interface {
	Execute(ctx context.Context, fn func(txCtx context.Context) error) error
}
