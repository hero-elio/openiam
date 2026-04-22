package persistence

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
)

type ctxKey struct{}

type TxManager struct {
	db *sqlx.DB
}

func NewTxManager(db *sqlx.DB) *TxManager {
	return &TxManager{db: db}
}

// Execute runs fn inside a database transaction.
//
// Nesting semantics: if ctx already carries a transaction (e.g. a synchronous
// event handler invoked from within an outer Execute), the inner call joins
// the existing transaction instead of opening a new one. This guarantees the
// outer aggregate write and any handler-side writes commit atomically — or
// roll back together when the outer caller fails.
//
// A panic inside fn rolls the transaction back before re-raising the panic.
func (m *TxManager) Execute(ctx context.Context, fn func(txCtx context.Context) error) (err error) {
	if _, ok := GetTx(ctx); ok {
		// Join the surrounding transaction; let the outermost owner commit/rollback.
		return fn(ctx)
	}

	tx, beginErr := m.db.BeginTxx(ctx, &sql.TxOptions{})
	if beginErr != nil {
		return beginErr
	}

	txCtx := context.WithValue(ctx, ctxKey{}, tx)

	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
			panic(r)
		}
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && rbErr != sql.ErrTxDone {
				err = fmt.Errorf("%w (rollback: %v)", err, rbErr)
			}
			return
		}
		if cmErr := tx.Commit(); cmErr != nil {
			err = cmErr
		}
	}()

	err = fn(txCtx)
	return
}

func GetTx(ctx context.Context) (*sqlx.Tx, bool) {
	tx, ok := ctx.Value(ctxKey{}).(*sqlx.Tx)
	return tx, ok
}

func Conn(ctx context.Context, fallback *sqlx.DB) sqlx.ExtContext {
	if tx, ok := GetTx(ctx); ok {
		return tx
	}
	return fallback
}
