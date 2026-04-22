package eventbus

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"openiam/internal/shared/domain"
)

type stubEvent struct {
	name string
	id   string
}

func (e stubEvent) EventName() string      { return e.name }
func (e stubEvent) AggregateID() string    { return e.id }
func (e stubEvent) OccurredAt() time.Time  { return time.Time{} }

func newQuietBus() *MemoryEventBus {
	return NewMemoryEventBus(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestPublish_AggregatesHandlerErrorsWithoutShortCircuit(t *testing.T) {
	bus := newQuietBus()

	var aCalled, bCalled, cCalled atomic.Int32
	errA := errors.New("a failed")
	errB := errors.New("b failed")

	_ = bus.Subscribe("evt", func(context.Context, domain.DomainEvent) error {
		aCalled.Add(1)
		return errA
	})
	_ = bus.Subscribe("evt", func(context.Context, domain.DomainEvent) error {
		bCalled.Add(1)
		return errB
	})
	_ = bus.Subscribe("other", func(context.Context, domain.DomainEvent) error {
		cCalled.Add(1)
		return nil
	})

	err := bus.Publish(context.Background(), stubEvent{name: "evt", id: "1"}, stubEvent{name: "other", id: "2"})

	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Fatalf("expected joined error to wrap both handler errors, got %v", err)
	}
	if aCalled.Load() != 1 || bCalled.Load() != 1 {
		t.Fatalf("both failing handlers must run; got a=%d b=%d", aCalled.Load(), bCalled.Load())
	}
	if cCalled.Load() != 1 {
		t.Fatal("later events must still be delivered after earlier handlers fail")
	}
}

func TestPublish_HandlerCanSubscribeWithoutDeadlock(t *testing.T) {
	bus := newQuietBus()

	done := make(chan struct{})
	_ = bus.Subscribe("evt", func(context.Context, domain.DomainEvent) error {
		// Re-subscribing inside a handler used to deadlock when Publish
		// held the read lock; this guards against regressing to that.
		err := bus.Subscribe("evt", func(context.Context, domain.DomainEvent) error { return nil })
		close(done)
		return err
	})

	go func() { _ = bus.Publish(context.Background(), stubEvent{name: "evt"}) }()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler blocked — Publish is still holding the bus lock during dispatch")
	}
}
