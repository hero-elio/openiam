package persistence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	shared "openiam/internal/shared/domain"
	sharedPersistence "openiam/internal/shared/infra/persistence"
	"openiam/internal/tenant/domain"
)

type stringSlice []string

func (s stringSlice) Value() (driver.Value, error) {
	if s == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(s)
}

func (s *stringSlice) Scan(src any) error {
	if src == nil {
		*s = []string{}
		return nil
	}
	b, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("stringSlice.Scan: unexpected type %T", src)
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Errorf("stringSlice.Scan: %w", err)
	}
	if out == nil {
		out = []string{}
	}
	*s = out
	return nil
}

type applicationRow struct {
	ID               string      `db:"id"`
	TenantID         string      `db:"tenant_id"`
	Name             string      `db:"name"`
	ClientID         string      `db:"client_id"`
	ClientSecretHash string      `db:"client_secret_hash"`
	RedirectURIs     stringSlice `db:"redirect_uris"`
	Scopes           stringSlice `db:"scopes"`
	Status           string      `db:"status"`
	CreatedAt        time.Time   `db:"created_at"`
}

const appColumns = `id, tenant_id, name, client_id, client_secret_hash, redirect_uris, scopes, status, created_at`

type PostgresApplicationRepository struct {
	db *sqlx.DB
}

func NewPostgresApplicationRepository(db *sqlx.DB) *PostgresApplicationRepository {
	return &PostgresApplicationRepository{db: db}
}

func (r *PostgresApplicationRepository) Save(ctx context.Context, app *domain.Application) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	const q = `
		INSERT INTO applications (id, tenant_id, name, client_id, client_secret_hash, redirect_uris, scopes, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			redirect_uris = EXCLUDED.redirect_uris,
			scopes = EXCLUDED.scopes,
			status = EXCLUDED.status`

	_, err := conn.ExecContext(ctx, q,
		app.ID.String(),
		app.TenantID.String(),
		app.Name,
		app.ClientID,
		app.ClientSecretHash,
		stringSlice(app.RedirectURIs),
		stringSlice(app.Scopes),
		app.Status,
		app.CreatedAt,
	)
	return err
}

func (r *PostgresApplicationRepository) FindByID(ctx context.Context, id shared.AppID) (*domain.Application, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row applicationRow
	err := sqlx.GetContext(ctx, conn, &row,
		`SELECT `+appColumns+` FROM applications WHERE id = $1`, id.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrAppNotFound
		}
		return nil, err
	}

	return rowToApplication(row), nil
}

func (r *PostgresApplicationRepository) FindByClientID(ctx context.Context, clientID string) (*domain.Application, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row applicationRow
	err := sqlx.GetContext(ctx, conn, &row,
		`SELECT `+appColumns+` FROM applications WHERE client_id = $1`, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrAppNotFound
		}
		return nil, err
	}

	return rowToApplication(row), nil
}

func (r *PostgresApplicationRepository) ListByTenant(ctx context.Context, tenantID shared.TenantID) ([]*domain.Application, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var rows []applicationRow
	err := sqlx.SelectContext(ctx, conn, &rows,
		`SELECT `+appColumns+` FROM applications WHERE tenant_id = $1 ORDER BY name`, tenantID.String())
	if err != nil {
		return nil, err
	}

	apps := make([]*domain.Application, 0, len(rows))
	for _, row := range rows {
		apps = append(apps, rowToApplication(row))
	}
	return apps, nil
}

func rowToApplication(row applicationRow) *domain.Application {
	return &domain.Application{
		ID:               shared.AppID(row.ID),
		TenantID:         shared.TenantID(row.TenantID),
		Name:             row.Name,
		ClientID:         row.ClientID,
		ClientSecretHash: row.ClientSecretHash,
		RedirectURIs:     []string(row.RedirectURIs),
		Scopes:           []string(row.Scopes),
		Status:           row.Status,
		CreatedAt:        row.CreatedAt,
	}
}
