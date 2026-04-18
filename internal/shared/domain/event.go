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
