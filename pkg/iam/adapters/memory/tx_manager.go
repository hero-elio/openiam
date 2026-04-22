package memory

import (
	"context"

	shared "openiam/internal/shared/domain"
)

// TxManager is the in-process implementation of shared.TxManager.
//
// There is no real transaction here: in-memory adapters mutate maps
// under their own locks, so nesting and rollback semantics are
// unnecessary. Execute simply runs fn with the provided context and
// returns its error, which is enough for application services that
// only require the unit-of-work shape.
type TxManager struct{}

// NewTxManager returns the no-op TxManager. It carries no state, so
// callers may share a single instance across modules.
func NewTxManager() TxManager {
	return TxManager{}
}

// Execute runs fn with ctx unchanged. Errors propagate verbatim;
// panics are not caught (consistent with the in-memory "everything is
// best-effort" contract).
func (TxManager) Execute(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

var _ shared.TxManager = TxManager{}
