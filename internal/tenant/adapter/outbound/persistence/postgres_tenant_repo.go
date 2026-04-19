package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
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

type applicationRow struct {
	ID               string    `db:"id"`
	TenantID         string    `db:"tenant_id"`
	Name             string    `db:"name"`
	ClientID         string    `db:"client_id"`
	ClientSecretHash string    `db:"client_secret_hash"`
	RedirectURIs     []byte    `db:"redirect_uris"`
	Scopes           []byte    `db:"scopes"`
	Status           string    `db:"status"`
	CreatedAt        time.Time `db:"created_at"`
}

type PostgresTenantRepository struct {
	db *sqlx.DB
}

func NewPostgresTenantRepository(db *sqlx.DB) *PostgresTenantRepository {
	return &PostgresTenantRepository{db: db}
}

func (r *PostgresTenantRepository) SaveTenant(ctx context.Context, t *domain.Tenant) error {
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

func (r *PostgresTenantRepository) FindTenantByID(ctx context.Context, id shared.TenantID) (*domain.Tenant, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row tenantRow
	err := sqlx.GetContext(ctx, conn, &row, `SELECT * FROM tenants WHERE id = $1`, id.String())
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

func (r *PostgresTenantRepository) SaveApplication(ctx context.Context, app *domain.Application) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	redirectURIs, _ := json.Marshal(app.RedirectURIs)
	scopes, _ := json.Marshal(app.Scopes)

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
		redirectURIs,
		scopes,
		app.Status,
		app.CreatedAt,
	)
	return err
}

func (r *PostgresTenantRepository) FindApplicationByID(ctx context.Context, id shared.AppID) (*domain.Application, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row applicationRow
	err := sqlx.GetContext(ctx, conn, &row, `SELECT * FROM applications WHERE id = $1`, id.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrAppNotFound
		}
		return nil, err
	}

	return rowToApplication(row), nil
}

func (r *PostgresTenantRepository) FindApplicationByClientID(ctx context.Context, clientID string) (*domain.Application, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row applicationRow
	err := sqlx.GetContext(ctx, conn, &row, `SELECT * FROM applications WHERE client_id = $1`, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrAppNotFound
		}
		return nil, err
	}

	return rowToApplication(row), nil
}

func (r *PostgresTenantRepository) ListApplicationsByTenant(ctx context.Context, tenantID shared.TenantID) ([]*domain.Application, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var rows []applicationRow
	err := sqlx.SelectContext(ctx, conn, &rows,
		`SELECT * FROM applications WHERE tenant_id = $1 ORDER BY name`, tenantID.String())
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
	var redirectURIs []string
	_ = json.Unmarshal(row.RedirectURIs, &redirectURIs)
	if redirectURIs == nil {
		redirectURIs = []string{}
	}

	var scopes []string
	_ = json.Unmarshal(row.Scopes, &scopes)
	if scopes == nil {
		scopes = []string{}
	}

	return &domain.Application{
		ID:               shared.AppID(row.ID),
		TenantID:         shared.TenantID(row.TenantID),
		Name:             row.Name,
		ClientID:         row.ClientID,
		ClientSecretHash: row.ClientSecretHash,
		RedirectURIs:     redirectURIs,
		Scopes:           scopes,
		Status:           row.Status,
		CreatedAt:        row.CreatedAt,
	}
}
