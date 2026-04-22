// Package eventbus is the public SDK surface for IAM's event bus
// implementations: an in-process MemoryEventBus and the transactional
// OutboxEventBus that persists every event to the domain_events table
// before dispatching to in-process subscribers.
//
// Phase 2e of the SDK refactor lifts the public API; concrete
// implementations stay under internal/shared/infra/eventbus until
// Phase 5 collapses them.
package eventbus

import (
	"log/slog"

	"github.com/jmoiron/sqlx"

	shared "openiam/internal/shared/domain"
	internalbus "openiam/internal/shared/infra/eventbus"
)

// Bus is the public name for the cross-context event bus interface.
// Defined upstream in internal/shared/domain so domain-layer events can
// publish without depending on any specific bus implementation.
type Bus = shared.EventBus

// EventHandler is the function signature subscribers register against.
type EventHandler = shared.EventHandler

// DomainEvent is the marker every published event implements.
type DomainEvent = shared.DomainEvent

// MemoryBus is a synchronous in-process bus useful for tests, embedded
// use, and any deployment that does not require cross-process delivery.
type MemoryBus = internalbus.MemoryEventBus

// OutboxBus persists every published event into the domain_events
// table inside the caller's transaction and then synchronously
// dispatches the same events to in-process subscribers. See the
// internal docs for the full delivery / failure semantics.
type OutboxBus = internalbus.OutboxEventBus

// NewMemory returns a MemoryBus with the given logger; nil falls back
// to slog.Default().
func NewMemory(logger *slog.Logger) *MemoryBus {
	return internalbus.NewMemoryEventBus(logger)
}

// NewOutbox returns an OutboxBus that piggy-backs on db. The bus
// requires the domain_events table (see migrations).
func NewOutbox(db *sqlx.DB, logger *slog.Logger) *OutboxBus {
	return internalbus.NewOutboxEventBus(db, logger)
}
