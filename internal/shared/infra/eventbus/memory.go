package eventbus

import (
	"context"
	"log/slog"
	"sync"

	"openiam/internal/shared/domain"
)

type MemoryEventBus struct {
	mu       sync.RWMutex
	handlers map[string][]domain.EventHandler
	logger   *slog.Logger
}

func NewMemoryEventBus(logger *slog.Logger) *MemoryEventBus {
	if logger == nil {
		logger = slog.Default()
	}
	return &MemoryEventBus{
		handlers: make(map[string][]domain.EventHandler),
		logger:   logger,
	}
}

func (b *MemoryEventBus) Publish(ctx context.Context, events ...domain.DomainEvent) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, event := range events {
		handlers := b.handlers[event.EventName()]
		for _, handler := range handlers {
			if err := handler(ctx, event); err != nil {
				b.logger.Error("event handler failed",
					"event", event.EventName(),
					"aggregate_id", event.AggregateID(),
					"error", err,
				)
				return err
			}
		}
	}
	return nil
}

func (b *MemoryEventBus) Subscribe(eventName string, handler domain.EventHandler) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventName] = append(b.handlers[eventName], handler)
	return nil
}
