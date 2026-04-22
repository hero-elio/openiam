package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"openiam/internal/shared/domain"
	"openiam/internal/shared/infra/persistence"
)

// OutboxEventBus persists every published event into the domain_events
// table inside the caller's transaction and then synchronously dispatches
// the same events to in-process subscribers.
//
// Why both:
//
//   - Persisting in the caller's tx makes "the aggregate write happened
//     and the event was recorded" atomic. If the surrounding business tx
//     rolls back, the event row goes with it — no phantom events.
//   - Synchronous in-process dispatch preserves the existing semantics this
//     codebase relies on: a failed subscriber rolls back the originating
//     write (e.g. credential creation failing aborts user registration).
//
// Lifecycle of a row:
//
//  1. INSERT with published = false (caller's tx).
//  2. Dispatch to in-process handlers (caller's tx).
//  3. If dispatch succeeds, batch UPDATE the rows to published = true
//     (caller's tx). If any handler fails, the error propagates and the
//     surrounding tx rolls back, taking the inserted rows with it.
//
// When external sinks (Kafka, webhooks, …) get added later, the meaning
// of the `published` column can be split per-sink without changing this
// type's public surface — the only invariant readers should rely on is
// "row exists ⇒ event durably happened".
type OutboxEventBus struct {
	db        *sqlx.DB
	inProcess *MemoryEventBus
	logger    *slog.Logger
}

// NewOutboxEventBus wires an OutboxEventBus around a sqlx.DB. The
// in-process delivery side reuses MemoryEventBus so existing handler
// registration and goroutine-safety properties are unchanged.
func NewOutboxEventBus(db *sqlx.DB, logger *slog.Logger) *OutboxEventBus {
	if logger == nil {
		logger = slog.Default()
	}
	return &OutboxEventBus{
		db:        db,
		inProcess: NewMemoryEventBus(logger),
		logger:    logger,
	}
}

// Subscribe delegates to the underlying in-process bus. External sinks
// would be wired through a separate publisher worker, not via this method.
func (b *OutboxEventBus) Subscribe(eventName string, handler domain.EventHandler) error {
	return b.inProcess.Subscribe(eventName, handler)
}

// Publish persists the events to the outbox table and then dispatches them
// to in-process subscribers. All work happens on the connection carried by
// ctx (a transaction, when present), so the caller controls commit/rollback.
func (b *OutboxEventBus) Publish(ctx context.Context, events ...domain.DomainEvent) error {
	if len(events) == 0 {
		return nil
	}

	conn := persistence.Conn(ctx, b.db)

	ids := make([]string, 0, len(events))
	for _, ev := range events {
		payload, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("marshal event %s: %w", ev.EventName(), err)
		}

		id := uuid.NewString()
		if _, err := conn.ExecContext(ctx, `
			INSERT INTO domain_events
				(id, aggregate_id, aggregate_type, event_type, payload, published, occurred_at)
			VALUES ($1, $2, $3, $4, $5, false, $6)
		`,
			id,
			ev.AggregateID(),
			aggregateTypeFromEventName(ev.EventName()),
			ev.EventName(),
			payload,
			ev.OccurredAt(),
		); err != nil {
			return fmt.Errorf("persist event %s: %w", ev.EventName(), err)
		}
		ids = append(ids, id)
	}

	// Dispatch BEFORE marking published. A handler failure here returns
	// the error up to the caller, whose tx will roll back and discard the
	// rows we just inserted — matching the pre-outbox guarantee that an
	// in-tx subscriber failure undoes the originating aggregate write.
	if err := b.inProcess.Publish(ctx, events...); err != nil {
		return err
	}

	if _, err := conn.ExecContext(ctx,
		`UPDATE domain_events SET published = true WHERE id = ANY($1)`,
		pq.Array(ids),
	); err != nil {
		return fmt.Errorf("mark events published: %w", err)
	}

	return nil
}

// aggregateTypeFromEventName extracts the aggregate prefix from an event
// name following the project convention "<aggregate>.<verb>" (e.g.
// "user.registered" → "user", "application.created" → "application"). The
// schema column is NOT NULL, so events that don't follow the convention
// fall back to "unknown" rather than panicking.
func aggregateTypeFromEventName(name string) string {
	if i := strings.Index(name, "."); i > 0 {
		return name[:i]
	}
	return "unknown"
}
