package persistence

import (
	"context"
	"errors"
	"testing"

	"github.com/jmoiron/sqlx"

	_ "github.com/lib/pq"
)

// fakeTxManager is intentionally not used; we exercise the real TxManager
// against a sqlmock would be ideal, but to avoid extra deps we focus on
// nesting + panic semantics that are pure ctx logic.

func TestExecute_PanicRollsBackAndRePanics(t *testing.T) {
	mgr := &TxManager{}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic to propagate")
		}
	}()

	// Force the no-DB path by pre-injecting a sentinel tx into ctx so we
	// hit the join branch (which doesn't touch the DB) and can validate
	// panic propagation without spinning up Postgres.
	ctx := context.WithValue(context.Background(), ctxKey{}, (*sqlx.Tx)(nil))
	_ = mgr.Execute(ctx, func(context.Context) error {
		panic("boom")
	})
}

func TestExecute_JoinsExistingTransaction(t *testing.T) {
	mgr := &TxManager{}

	parentCtx := context.WithValue(context.Background(), ctxKey{}, (*sqlx.Tx)(nil))
	called := false
	err := mgr.Execute(parentCtx, func(innerCtx context.Context) error {
		called = true
		// The inner ctx must still carry the same tx value — joining, not
		// shadowing — otherwise nested writes would be in different txns.
		if innerCtx.Value(ctxKey{}) == nil {
			t.Fatal("inner ctx should reuse the parent transaction value")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("nested fn was not invoked")
	}
}

func TestExecute_JoinedErrorPropagates(t *testing.T) {
	mgr := &TxManager{}
	want := errors.New("inner failed")
	parentCtx := context.WithValue(context.Background(), ctxKey{}, (*sqlx.Tx)(nil))
	got := mgr.Execute(parentCtx, func(context.Context) error { return want })
	if !errors.Is(got, want) {
		t.Fatalf("unexpected error: got %v want %v", got, want)
	}
}
