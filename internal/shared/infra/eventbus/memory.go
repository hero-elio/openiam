package eventbus

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"openiam/internal/shared/domain"
)

// MemoryEventBus is an in-process synchronous event bus.
//
// Delivery semantics:
//   - Handlers are dispatched outside the bus mutex so a handler may safely
//     Subscribe (or republish) without deadlocking against itself.
//   - All handlers for all events are attempted; failures are accumulated
//     and returned as a single joined error instead of short-circuiting and
//     leaving later events undelivered.
//   - Best-effort, in-memory only. Reliable cross-process delivery requires
//     an outbox/broker; that is intentionally outside this type's scope.
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
	if len(events) == 0 {
		return nil
	}

	type dispatch struct {
		event   domain.DomainEvent
		handler domain.EventHandler
	}

	// Snapshot handlers under the read lock, then release before invoking
	// them — handlers may take other locks (including this bus's write lock
	// when subscribing) and must not be called while we hold ours.
	b.mu.RLock()
	plan := make([]dispatch, 0, len(events))
	for _, ev := range events {
		for _, h := range b.handlers[ev.EventName()] {
			plan = append(plan, dispatch{event: ev, handler: h})
		}
	}
	b.mu.RUnlock()

	var errs []error
	for _, d := range plan {
		if err := d.handler(ctx, d.event); err != nil {
			b.logger.Error("event handler failed",
				"event", d.event.EventName(),
				"aggregate_id", d.event.AggregateID(),
				"error", err,
			)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (b *MemoryEventBus) Subscribe(eventName string, handler domain.EventHandler) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventName] = append(b.handlers[eventName], handler)
	return nil
}
