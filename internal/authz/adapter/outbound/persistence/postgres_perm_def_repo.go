package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"openiam/internal/authz/domain"
	shared "openiam/internal/shared/domain"
	sharedPersistence "openiam/internal/shared/infra/persistence"
)

type permDefRow struct {
	ID          string    `db:"id"`
	AppID       string    `db:"app_id"`
	Resource    string    `db:"resource"`
	Action      string    `db:"action"`
	Description string    `db:"description"`
	IsBuiltin   bool      `db:"is_builtin"`
	CreatedAt   time.Time `db:"created_at"`
}

type PostgresPermissionDefinitionRepository struct {
	db *sqlx.DB
}

func NewPostgresPermissionDefinitionRepository(db *sqlx.DB) *PostgresPermissionDefinitionRepository {
	return &PostgresPermissionDefinitionRepository{db: db}
}

func (r *PostgresPermissionDefinitionRepository) Upsert(ctx context.Context, pd *domain.PermissionDefinition) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	if pd.ID == "" {
		pd.ID = uuid.New().String()
	}

	const q = `
		INSERT INTO permission_definitions (id, app_id, resource, action, description, is_builtin, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (app_id, resource, action) DO UPDATE SET
			description = EXCLUDED.description,
			is_builtin = EXCLUDED.is_builtin`

	_, err := conn.ExecContext(ctx, q,
		pd.ID, pd.AppID.String(), pd.Resource, pd.Action,
		pd.Description, pd.IsBuiltin, pd.CreatedAt,
	)
	return err
}

func (r *PostgresPermissionDefinitionRepository) Delete(ctx context.Context, appID shared.AppID, resource, action string) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	_, err := conn.ExecContext(ctx,
		`DELETE FROM permission_definitions WHERE app_id = $1 AND resource = $2 AND action = $3 AND is_builtin = FALSE`,
		appID.String(), resource, action)
	return err
}

func (r *PostgresPermissionDefinitionRepository) ListByApp(ctx context.Context, appID shared.AppID) ([]*domain.PermissionDefinition, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var rows []permDefRow
	err := sqlx.SelectContext(ctx, conn, &rows,
		`SELECT * FROM permission_definitions WHERE app_id = $1 ORDER BY resource, action`, appID.String())
	if err != nil {
		return nil, err
	}

	defs := make([]*domain.PermissionDefinition, 0, len(rows))
	for _, row := range rows {
		defs = append(defs, rowToPermDef(row))
	}
	return defs, nil
}

func (r *PostgresPermissionDefinitionRepository) FindByKey(ctx context.Context, appID shared.AppID, resource, action string) (*domain.PermissionDefinition, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row permDefRow
	err := sqlx.GetContext(ctx, conn, &row,
		`SELECT * FROM permission_definitions WHERE app_id = $1 AND resource = $2 AND action = $3`,
		appID.String(), resource, action)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}

	return rowToPermDef(row), nil
}

func rowToPermDef(row permDefRow) *domain.PermissionDefinition {
	return &domain.PermissionDefinition{
		ID:          row.ID,
		AppID:       shared.AppID(row.AppID),
		Resource:    row.Resource,
		Action:      row.Action,
		Description: row.Description,
		IsBuiltin:   row.IsBuiltin,
		CreatedAt:   row.CreatedAt,
	}
}
