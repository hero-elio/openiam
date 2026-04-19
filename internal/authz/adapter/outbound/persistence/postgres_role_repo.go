package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"

	"openiam/internal/authz/domain"
	shared "openiam/internal/shared/domain"
	sharedPersistence "openiam/internal/shared/infra/persistence"
)

type roleRow struct {
	ID          string    `db:"id"`
	AppID       string    `db:"app_id"`
	TenantID    string    `db:"tenant_id"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
	IsSystem    bool      `db:"is_system"`
	Version     int       `db:"version"`
	CreatedAt   time.Time `db:"created_at"`
}

type permissionRow struct {
	RoleID   string `db:"role_id"`
	Resource string `db:"resource"`
	Action   string `db:"action"`
}

type userAppRoleRow struct {
	UserID     string    `db:"user_id"`
	AppID      string    `db:"app_id"`
	RoleID     string    `db:"role_id"`
	TenantID   string    `db:"tenant_id"`
	AssignedAt time.Time `db:"assigned_at"`
}

type PostgresRoleRepository struct {
	db *sqlx.DB
}

func NewPostgresRoleRepository(db *sqlx.DB) *PostgresRoleRepository {
	return &PostgresRoleRepository{db: db}
}

func (r *PostgresRoleRepository) Save(ctx context.Context, role *domain.Role) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	const upsertRole = `
		INSERT INTO roles (id, app_id, tenant_id, name, description, is_system, version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			version = EXCLUDED.version`

	if _, err := conn.ExecContext(ctx, upsertRole,
		role.ID.String(),
		role.AppID.String(),
		role.TenantID.String(),
		role.Name,
		role.Description,
		role.IsSystem,
		role.Version+1,
		role.CreatedAt,
	); err != nil {
		return err
	}

	if _, err := conn.ExecContext(ctx,
		`DELETE FROM role_permissions WHERE role_id = $1`, role.ID.String(),
	); err != nil {
		return err
	}

	for _, p := range role.Permissions {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO role_permissions (role_id, resource, action) VALUES ($1, $2, $3)`,
			role.ID.String(), p.Resource, p.Action,
		); err != nil {
			return err
		}
	}

	return nil
}

func (r *PostgresRoleRepository) FindByID(ctx context.Context, id shared.RoleID) (*domain.Role, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row roleRow
	err := sqlx.GetContext(ctx, conn, &row, `SELECT * FROM roles WHERE id = $1`, id.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrRoleNotFound
		}
		return nil, err
	}

	perms, err := r.loadPermissions(ctx, conn, id.String())
	if err != nil {
		return nil, err
	}

	return rowToRole(row, perms), nil
}

func (r *PostgresRoleRepository) FindByName(ctx context.Context, appID shared.AppID, name string) (*domain.Role, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var row roleRow
	err := sqlx.GetContext(ctx, conn, &row,
		`SELECT * FROM roles WHERE app_id = $1 AND name = $2`,
		appID.String(), name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrRoleNotFound
		}
		return nil, err
	}

	perms, err := r.loadPermissions(ctx, conn, row.ID)
	if err != nil {
		return nil, err
	}

	return rowToRole(row, perms), nil
}

func (r *PostgresRoleRepository) FindByUserAndApp(ctx context.Context, userID shared.UserID, appID shared.AppID) ([]*domain.Role, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var rows []roleRow
	err := sqlx.SelectContext(ctx, conn, &rows, `
		SELECT r.* FROM roles r
		JOIN user_app_roles uar ON uar.role_id = r.id
		WHERE uar.user_id = $1 AND uar.app_id = $2`,
		userID.String(), appID.String())
	if err != nil {
		return nil, err
	}

	return r.hydrateRoles(ctx, conn, rows)
}

func (r *PostgresRoleRepository) ListByApp(ctx context.Context, appID shared.AppID) ([]*domain.Role, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var rows []roleRow
	err := sqlx.SelectContext(ctx, conn, &rows,
		`SELECT * FROM roles WHERE app_id = $1 ORDER BY name`, appID.String())
	if err != nil {
		return nil, err
	}

	return r.hydrateRoles(ctx, conn, rows)
}

func (r *PostgresRoleRepository) Delete(ctx context.Context, id shared.RoleID) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	if _, err := conn.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, id.String()); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM user_app_roles WHERE role_id = $1`, id.String()); err != nil {
		return err
	}
	_, err := conn.ExecContext(ctx, `DELETE FROM roles WHERE id = $1`, id.String())
	return err
}

func (r *PostgresRoleRepository) SaveUserAppRole(ctx context.Context, uar *domain.UserAppRole) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	const q = `
		INSERT INTO user_app_roles (user_id, app_id, role_id, tenant_id, assigned_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, app_id, role_id) DO NOTHING`

	_, err := conn.ExecContext(ctx, q,
		uar.UserID.String(),
		uar.AppID.String(),
		uar.RoleID.String(),
		uar.TenantID.String(),
		uar.AssignedAt,
	)
	return err
}

func (r *PostgresRoleRepository) DeleteUserAppRole(ctx context.Context, userID shared.UserID, appID shared.AppID, roleID shared.RoleID) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	_, err := conn.ExecContext(ctx,
		`DELETE FROM user_app_roles WHERE user_id = $1 AND app_id = $2 AND role_id = $3`,
		userID.String(), appID.String(), roleID.String())
	return err
}

func (r *PostgresRoleRepository) FindUserAppRoles(ctx context.Context, userID shared.UserID, appID shared.AppID) ([]*domain.UserAppRole, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var rows []userAppRoleRow
	err := sqlx.SelectContext(ctx, conn, &rows,
		`SELECT * FROM user_app_roles WHERE user_id = $1 AND app_id = $2`,
		userID.String(), appID.String())
	if err != nil {
		return nil, err
	}

	uars := make([]*domain.UserAppRole, 0, len(rows))
	for _, row := range rows {
		uars = append(uars, &domain.UserAppRole{
			UserID:     shared.UserID(row.UserID),
			AppID:      shared.AppID(row.AppID),
			RoleID:     shared.RoleID(row.RoleID),
			TenantID:   shared.TenantID(row.TenantID),
			AssignedAt: row.AssignedAt,
		})
	}
	return uars, nil
}

func (r *PostgresRoleRepository) loadPermissions(ctx context.Context, conn sqlx.ExtContext, roleID string) ([]domain.Permission, error) {
	var rows []permissionRow
	err := sqlx.SelectContext(ctx, conn, &rows,
		`SELECT * FROM role_permissions WHERE role_id = $1`, roleID)
	if err != nil {
		return nil, err
	}

	perms := make([]domain.Permission, 0, len(rows))
	for _, row := range rows {
		perms = append(perms, domain.Permission{Resource: row.Resource, Action: row.Action})
	}
	return perms, nil
}

func (r *PostgresRoleRepository) hydrateRoles(ctx context.Context, conn sqlx.ExtContext, rows []roleRow) ([]*domain.Role, error) {
	roles := make([]*domain.Role, 0, len(rows))
	for _, row := range rows {
		perms, err := r.loadPermissions(ctx, conn, row.ID)
		if err != nil {
			return nil, err
		}
		roles = append(roles, rowToRole(row, perms))
	}
	return roles, nil
}

func rowToRole(row roleRow, perms []domain.Permission) *domain.Role {
	r := &domain.Role{
		ID:          shared.RoleID(row.ID),
		AppID:       shared.AppID(row.AppID),
		TenantID:    shared.TenantID(row.TenantID),
		Name:        row.Name,
		Description: row.Description,
		Permissions: perms,
		IsSystem:    row.IsSystem,
		CreatedAt:   row.CreatedAt,
	}
	r.Version = row.Version
	return r
}
