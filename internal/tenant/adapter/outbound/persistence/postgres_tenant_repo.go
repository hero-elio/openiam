package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"

	shared "openiam/internal/shared/domain"
	sharedPersistence "openiam/internal/shared/infra/persistence"
	"openiam/internal/tenant/domain"
)

type tenantRow struct {
	ID        string    `db:"id"`
	Name      string    `db:"name"`
	Status    string    `db:"status"`
	CreatedAt time.Time `db:"created_at"`
}

type PostgresTenantRepository struct {
	db *sqlx.DB
}

func NewPostgresTenantRepository(db *sqlx.DB) *PostgresTenantRepository {
	return &PostgresTenantRepository{db: db}
}

func (r *PostgresTenantRepository) Save(ctx context.Context, t *domain.Tenant) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	const q = `
		INSERT INTO tenants (id, name, status, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			status = EXCLUDED.status`

	_, err := conn.ExecContext(ctx, q,
		t.ID.String(), t.Name, t.Status, t.CreatedAt,
	)
	return err
}

func (r *PostgresTenantRepository) List(ctx context.Context, filter domain.ListTenantsFilter) ([]*domain.Tenant, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	const baseQuery = `SELECT id, name, status, created_at FROM tenants ORDER BY created_at DESC`

	limit := filter.Limit
	offset := filter.Offset
	if limit < 0 {
		limit = 0
	}
	if offset < 0 {
		offset = 0
	}

	var rows []tenantRow
	switch {
	case limit > 0 && offset > 0:
		err := sqlx.SelectContext(ctx, conn, &rows, baseQuery+` LIMIT $1 OFFSET $2`, limit, offset)
		if err != nil {
			return nil, err
		}
	case limit > 0:
		err := sqlx.SelectContext(ctx, conn, &rows, baseQuery+` LIMIT $1`, limit)
		if err != nil {
			return nil, err
		}
	case offset > 0:
		err := sqlx.SelectContext(ctx, conn, &rows, baseQuery+` OFFSET $1`, offset)
		if err != nil {
			return nil, err
		}
	default:
		if err := sqlx.SelectContext(ctx, conn, &rows, baseQuery); err != nil {
			return nil, err
		}
	}

	out := make([]*domain.Tenant, 0, len(rows))
	for _, row := range rows {
		out = append(out, &domain.Tenant{
			ID:        shared.TenantID(row.ID),
			Name:      row.Name,
			Status:    row.Status,
			CreatedAt: row.CreatedAt,
		})
	}
	return out, nil
}

func (r *PostgresTenantRepository) FindByID(ctx context.Context, id shared.TenantID) (*domain.Tenant, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row tenantRow
	err := sqlx.GetContext(ctx, conn, &row,
		`SELECT id, name, status, created_at FROM tenants WHERE id = $1`, id.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrTenantNotFound
		}
		return nil, err
	}

	return &domain.Tenant{
		ID:        shared.TenantID(row.ID),
		Name:      row.Name,
		Status:    row.Status,
		CreatedAt: row.CreatedAt,
	}, nil
}
