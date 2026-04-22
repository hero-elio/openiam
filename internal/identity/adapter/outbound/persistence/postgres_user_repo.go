package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"openiam/internal/identity/domain"
	shared "openiam/internal/shared/domain"
	sharedPersistence "openiam/internal/shared/infra/persistence"
)

// pgUniqueViolation is the SQLSTATE code postgres returns for a violated
// UNIQUE constraint. We surface these as domain-level errors so callers
// (especially external-identity registration) can recognize a concurrent
// duplicate and recover by re-reading the existing row.
const pgUniqueViolation = "23505"

type userRow struct {
	ID           string    `db:"id"`
	TenantID     string    `db:"tenant_id"`
	Email        string    `db:"email"`
	PasswordHash string    `db:"password_hash"`
	DisplayName  string    `db:"display_name"`
	AvatarURL    string    `db:"avatar_url"`
	Status       string    `db:"status"`
	Version      int       `db:"version"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

type PostgresUserRepository struct {
	db *sqlx.DB
}

func NewPostgresUserRepository(db *sqlx.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) Save(ctx context.Context, user *domain.User) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	// Optimistic lock: the ON CONFLICT branch only fires when the persisted
	// row's version matches what we loaded ($7). A mismatch leaves the row
	// untouched, RowsAffected returns 0, and we surface ErrConcurrentUpdate
	// so the caller can retry against the latest snapshot instead of
	// silently overwriting somebody else's update.
	const upsert = `
		INSERT INTO users (id, tenant_id, email, password_hash, display_name, avatar_url, status, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			password_hash = EXCLUDED.password_hash,
			display_name = EXCLUDED.display_name,
			avatar_url = EXCLUDED.avatar_url,
			status = EXCLUDED.status,
			version = users.version + 1,
			updated_at = EXCLUDED.updated_at
		WHERE users.version = $8`

	res, err := conn.ExecContext(ctx, upsert,
		user.ID.String(),
		user.TenantID.String(),
		user.Email.String(),
		user.Password.Hash(),
		user.Profile.DisplayName,
		user.Profile.AvatarURL,
		string(user.Status),
		user.Version,
		user.Version+1,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && string(pgErr.Code) == pgUniqueViolation {
			return domain.ErrEmailAlreadyTaken
		}
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return shared.ErrConcurrentUpdate
	}
	user.Version++
	return nil
}

func (r *PostgresUserRepository) FindByID(ctx context.Context, id shared.UserID) (*domain.User, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row userRow
	err := sqlx.GetContext(ctx, conn, &row, `SELECT * FROM users WHERE id = $1`, id.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return rowToUser(row), nil
}

func (r *PostgresUserRepository) FindByEmail(ctx context.Context, tenantID shared.TenantID, email domain.Email) (*domain.User, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row userRow
	err := sqlx.GetContext(ctx, conn, &row,
		`SELECT * FROM users WHERE tenant_id = $1 AND email = $2`,
		tenantID.String(), email.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return rowToUser(row), nil
}

func (r *PostgresUserRepository) ExistsByEmail(ctx context.Context, tenantID shared.TenantID, email domain.Email) (bool, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var exists bool
	err := sqlx.GetContext(ctx, conn, &exists,
		`SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id = $1 AND email = $2)`,
		tenantID.String(), email.String())
	return exists, err
}

func rowToUser(row userRow) *domain.User {
	u := &domain.User{
		ID:       shared.UserID(row.ID),
		Email:    domain.NewEmailFromTrusted(row.Email),
		Password: domain.NewPasswordFromHash(row.PasswordHash),
		Profile: domain.Profile{
			DisplayName: row.DisplayName,
			AvatarURL:   row.AvatarURL,
		},
		Status:    domain.UserStatus(row.Status),
		TenantID:  shared.TenantID(row.TenantID),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
	u.Version = row.Version
	return u
}
