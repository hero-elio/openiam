package eventbus_test

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	shared "openiam/internal/shared/domain"
	"openiam/internal/shared/infra/eventbus"
	sharedPersistence "openiam/internal/shared/infra/persistence"
)

// stubEvent is the minimum DomainEvent we need to exercise the outbox; the
// JSON payload doesn't need to be rich, just round-trippable.
type stubEvent struct {
	Name        string    `json:"name"`
	Aggregate   string    `json:"aggregate"`
	OccurredAtT time.Time `json:"occurred_at"`
	Detail      string    `json:"detail"`
}

func (e stubEvent) EventName() string      { return e.Name }
func (e stubEvent) AggregateID() string    { return e.Aggregate }
func (e stubEvent) OccurredAt() time.Time  { return e.OccurredAtT }

func setupPostgres(t *testing.T) *sqlx.DB {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("iam_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	migrationsPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "migration")
	abs, err := filepath.Abs(migrationsPath)
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	m, err := migrate.New("file://"+abs, dsn)
	if err != nil {
		t.Fatalf("create migrator: %v", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("run migrations: %v", err)
	}
	if srcErr, dbErr := m.Close(); srcErr != nil || dbErr != nil {
		t.Fatalf("close migrator: src=%v db=%v", srcErr, dbErr)
	}

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOutboxEventBus_PersistsAndDispatches(t *testing.T) {
	db := setupPostgres(t)

	bus := eventbus.NewOutboxEventBus(db, nil)

	delivered := []shared.DomainEvent{}
	if err := bus.Subscribe("user.registered", func(_ context.Context, ev shared.DomainEvent) error {
		delivered = append(delivered, ev)
		return nil
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	ev := stubEvent{Name: "user.registered", Aggregate: "agg-1", OccurredAtT: now, Detail: "hello"}

	tm := sharedPersistence.NewTxManager(db)
	if err := tm.Execute(context.Background(), func(ctx context.Context) error {
		return bus.Publish(ctx, ev)
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if len(delivered) != 1 || delivered[0].EventName() != "user.registered" {
		t.Fatalf("expected one in-process delivery, got %#v", delivered)
	}

	var (
		count          int
		aggregateType  string
		published      bool
	)
	row := db.QueryRow(`SELECT COUNT(*), MAX(aggregate_type), bool_and(published) FROM domain_events`)
	if err := row.Scan(&count, &aggregateType, &published); err != nil {
		t.Fatalf("query domain_events: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 row, got %d", count)
	}
	if aggregateType != "user" {
		t.Fatalf("expected aggregate_type=user, got %q", aggregateType)
	}
	if !published {
		t.Fatalf("expected row to be marked published after successful dispatch")
	}
}

func TestOutboxEventBus_HandlerFailureRollsBackInsert(t *testing.T) {
	db := setupPostgres(t)

	bus := eventbus.NewOutboxEventBus(db, nil)

	wantErr := errors.New("subscriber boom")
	if err := bus.Subscribe("tenant.created", func(_ context.Context, _ shared.DomainEvent) error {
		return wantErr
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	tm := sharedPersistence.NewTxManager(db)
	gotErr := tm.Execute(context.Background(), func(ctx context.Context) error {
		return bus.Publish(ctx, stubEvent{
			Name:        "tenant.created",
			Aggregate:   "agg-2",
			OccurredAtT: time.Now(),
		})
	})
	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("expected subscriber error to propagate, got %v", gotErr)
	}

	// The whole tx must have rolled back: no event row should remain.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM domain_events`).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 rows after rollback, got %d", count)
	}
}

func TestOutboxEventBus_NoEventsIsNoop(t *testing.T) {
	db := setupPostgres(t)
	bus := eventbus.NewOutboxEventBus(db, nil)
	if err := bus.Publish(context.Background()); err != nil {
		t.Fatalf("publish empty: %v", err)
	}
}

func TestOutboxEventBus_UnknownEventNameMapsToUnknownAggregate(t *testing.T) {
	db := setupPostgres(t)
	bus := eventbus.NewOutboxEventBus(db, nil)

	tm := sharedPersistence.NewTxManager(db)
	if err := tm.Execute(context.Background(), func(ctx context.Context) error {
		return bus.Publish(ctx, stubEvent{
			Name:        "no_dot_in_name",
			Aggregate:   "agg-3",
			OccurredAtT: time.Now(),
		})
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	var aggregateType string
	if err := db.QueryRow(`SELECT aggregate_type FROM domain_events WHERE aggregate_id = 'agg-3'`).Scan(&aggregateType); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if aggregateType != "unknown" {
		t.Fatalf("expected aggregate_type=unknown, got %q", aggregateType)
	}
}
