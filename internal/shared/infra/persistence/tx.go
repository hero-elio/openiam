package persistence

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
)

type ctxKey struct{}

type TxManager struct {
	db *sqlx.DB
}

func NewTxManager(db *sqlx.DB) *TxManager {
	return &TxManager{db: db}
}

func (m *TxManager) Execute(ctx context.Context, fn func(txCtx context.Context) error) error {
	tx, err := m.db.BeginTxx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}

	txCtx := context.WithValue(ctx, ctxKey{}, tx)
	if err := fn(txCtx); err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
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
