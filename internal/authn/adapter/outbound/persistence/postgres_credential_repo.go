package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
	sharedpersistence "openiam/internal/shared/infra/persistence"
)

// pgUniqueViolation is the SQLSTATE code postgres returns when a UNIQUE
// constraint is violated. We map it to a domain error so callers can
// surface "this credential is already bound" instead of leaking the raw
// driver error.
const pgUniqueViolation = "23505"

type PostgresCredentialRepo struct {
	db *sqlx.DB
}

func NewPostgresCredentialRepo(db *sqlx.DB) *PostgresCredentialRepo {
	return &PostgresCredentialRepo{db: db}
}

type credentialRow struct {
	ID                string         `db:"id"`
	UserID            string         `db:"user_id"`
	AppID             string         `db:"app_id"`
	Type              string         `db:"type"`
	Provider          string         `db:"provider"`
	CredentialSubject string         `db:"credential_subject"`
	Secret            sql.NullString `db:"secret"`
	PublicKey         sql.NullString `db:"public_key"`
	Metadata          []byte         `db:"metadata"`
	CreatedAt         time.Time      `db:"created_at"`
	// last_used_at is nullable in the schema (a freshly issued credential
	// has never been used). A bare time.Time would Scan-fail on NULL.
	LastUsedAt sql.NullTime `db:"last_used_at"`
}

const credentialColumns = `id, user_id, app_id, type, provider, credential_subject, secret, public_key, metadata, created_at, last_used_at`

func (r *PostgresCredentialRepo) Save(ctx context.Context, cred *domain.Credential) error {
	conn := sharedpersistence.Conn(ctx, r.db)
	meta, err := json.Marshal(cred.Metadata)
	if err != nil {
		return err
	}

	const q = `INSERT INTO credentials (id, user_id, app_id, type, provider, credential_subject, secret, public_key, metadata, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err = conn.ExecContext(ctx, q,
		cred.ID.String(),
		cred.UserID.String(),
		cred.AppID.String(),
		string(cred.Type),
		cred.Provider,
		cred.CredentialSubject,
		toNullString(cred.Secret),
		toNullString(cred.PublicKey),
		meta,
		cred.CreatedAt,
		nullTime(cred.LastUsedAt),
	)
	if err != nil {
		// (app_id, credential_subject, type) is UNIQUE — a concurrent
		// SIWE/WebAuthn registration for the same address could race past
		// our application-level check and reach here. Surface it as a
		// domain error so callers can treat the duplicate as already-bound
		// instead of leaking the raw pq error.
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && string(pgErr.Code) == pgUniqueViolation {
			return domain.ErrCredentialAlreadyBound
		}
		return err
	}
	return nil
}

func (r *PostgresCredentialRepo) FindByID(ctx context.Context, id shared.CredentialID) (*domain.Credential, error) {
	conn := sharedpersistence.Conn(ctx, r.db)
	var row credentialRow
	err := sqlx.GetContext(ctx, conn, &row,
		`SELECT `+credentialColumns+` FROM credentials WHERE id = $1`, id.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrCredentialNotFound
		}
		return nil, err
	}
	return rowToCredential(row)
}

func (r *PostgresCredentialRepo) FindByUserAndType(ctx context.Context, userID shared.UserID, appID shared.AppID, credType domain.CredentialType) (*domain.Credential, error) {
	conn := sharedpersistence.Conn(ctx, r.db)
	var row credentialRow
	err := sqlx.GetContext(ctx, conn, &row,
		`SELECT `+credentialColumns+` FROM credentials WHERE user_id = $1 AND app_id = $2 AND type = $3`,
		userID.String(), appID.String(), string(credType))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrCredentialNotFound
		}
		return nil, err
	}
	return rowToCredential(row)
}

func (r *PostgresCredentialRepo) FindBySubjectAndType(ctx context.Context, subject string, appID shared.AppID, credType domain.CredentialType) (*domain.Credential, error) {
	conn := sharedpersistence.Conn(ctx, r.db)
	var row credentialRow
	err := sqlx.GetContext(ctx, conn, &row,
		`SELECT `+credentialColumns+` FROM credentials WHERE credential_subject = $1 AND app_id = $2 AND type = $3`,
		subject, appID.String(), string(credType))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrCredentialNotFound
		}
		return nil, err
	}
	return rowToCredential(row)
}

func (r *PostgresCredentialRepo) Update(ctx context.Context, cred *domain.Credential) error {
	conn := sharedpersistence.Conn(ctx, r.db)
	meta, err := json.Marshal(cred.Metadata)
	if err != nil {
		return err
	}

	const q = `UPDATE credentials SET secret = $1, public_key = $2, metadata = $3, last_used_at = $4 WHERE id = $5`
	_, err = conn.ExecContext(ctx, q,
		toNullString(cred.Secret),
		toNullString(cred.PublicKey),
		meta,
		nullTime(cred.LastUsedAt),
		cred.ID.String(),
	)
	return err
}

func (r *PostgresCredentialRepo) Delete(ctx context.Context, id shared.CredentialID) error {
	conn := sharedpersistence.Conn(ctx, r.db)
	_, err := conn.ExecContext(ctx, `DELETE FROM credentials WHERE id = $1`, id.String())
	return err
}

func (r *PostgresCredentialRepo) ListByUser(ctx context.Context, userID shared.UserID) ([]*domain.Credential, error) {
	conn := sharedpersistence.Conn(ctx, r.db)
	var rows []credentialRow
	err := sqlx.SelectContext(ctx, conn, &rows,
		`SELECT `+credentialColumns+` FROM credentials WHERE user_id = $1 ORDER BY created_at`, userID.String())
	if err != nil {
		return nil, err
	}

	creds := make([]*domain.Credential, 0, len(rows))
	for _, row := range rows {
		c, err := rowToCredential(row)
		if err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}

func rowToCredential(row credentialRow) (*domain.Credential, error) {
	cred := &domain.Credential{
		ID:                shared.CredentialID(row.ID),
		UserID:            shared.UserID(row.UserID),
		AppID:             shared.AppID(row.AppID),
		Type:              domain.CredentialType(row.Type),
		Provider:          row.Provider,
		CredentialSubject: row.CredentialSubject,
		CreatedAt:         row.CreatedAt,
	}
	if row.LastUsedAt.Valid {
		cred.LastUsedAt = row.LastUsedAt.Time
	}
	if row.Secret.Valid {
		cred.Secret = &row.Secret.String
	}
	if row.PublicKey.Valid {
		cred.PublicKey = &row.PublicKey.String
	}
	if row.Metadata != nil {
		if err := json.Unmarshal(row.Metadata, &cred.Metadata); err != nil {
			return nil, err
		}
	}
	if cred.Metadata == nil {
		cred.Metadata = make(map[string]any)
	}
	return cred, nil
}

func toNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

// nullTime maps a zero time.Time to SQL NULL so a freshly-issued
// credential persists as last_used_at IS NULL instead of "0001-01-01",
// keeping the on-disk representation consistent with what readers
// observe via sql.NullTime.
func nullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t, Valid: true}
}
