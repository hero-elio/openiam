package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"openiam/internal/authz/domain"
	shared "openiam/internal/shared/domain"
	sharedPersistence "openiam/internal/shared/infra/persistence"
)

type roleRow struct {
	ID                  string    `db:"id"`
	AppID               string    `db:"app_id"`
	TenantID            string    `db:"tenant_id"`
	Name                string    `db:"name"`
	Description         string    `db:"description"`
	IsSystem            bool      `db:"is_system"`
	IsTemplate          bool      `db:"is_template"`
	IsDefaultForCreator bool      `db:"is_default_for_creator"`
	Version             int       `db:"version"`
	CreatedAt           time.Time `db:"created_at"`
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

	// Optimistic lock: ON CONFLICT only updates when the persisted version
	// matches the loaded snapshot ($9). Stale writes get 0 rows affected
	// and we report ErrConcurrentUpdate instead of silently clobbering
	// concurrent permission changes on the same role.
	const upsertRole = `
		INSERT INTO roles (id, app_id, tenant_id, name, description, is_system, is_template, is_default_for_creator, version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			is_template = EXCLUDED.is_template,
			is_default_for_creator = EXCLUDED.is_default_for_creator,
			version = roles.version + 1
		WHERE roles.version = $9`

	res, err := conn.ExecContext(ctx, upsertRole,
		role.ID.String(),
		role.AppID.String(),
		role.TenantID.String(),
		role.Name,
		role.Description,
		role.IsSystem,
		role.IsTemplate,
		role.IsDefaultForCreator,
		role.Version,
		role.Version+1,
		role.CreatedAt,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return shared.ErrConcurrentUpdate
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

	role.Version++
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

func (r *PostgresRoleRepository) FindByName(ctx context.Context, appID shared.AppID, tenantID shared.TenantID, name string) (*domain.Role, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	// The unique constraint is (app_id, tenant_id, name); searching by
	// (app_id, name) alone could return multiple rows across tenants.
	var row roleRow
	err := sqlx.GetContext(ctx, conn, &row,
		`SELECT * FROM roles WHERE app_id = $1 AND tenant_id = $2 AND name = $3`,
		appID.String(), tenantID.String(), name)
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
		WHERE uar.user_id = $1 AND uar.app_id = $2 AND r.app_id = uar.app_id`,
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
		`SELECT * FROM roles WHERE app_id = $1 AND is_template = false ORDER BY name`, appID.String())
	if err != nil {
		return nil, err
	}

	return r.hydrateRoles(ctx, conn, rows)
}

func (r *PostgresRoleRepository) FindTemplates(ctx context.Context, tenantID shared.TenantID) ([]*domain.Role, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	// Tenant-scoped templates take priority over global ones.
	var rows []roleRow
	err := sqlx.SelectContext(ctx, conn, &rows,
		`SELECT * FROM roles WHERE is_template = true AND tenant_id = $1 ORDER BY name`,
		tenantID.String())
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 {
		return r.hydrateRoles(ctx, conn, rows)
	}

	// Fall back to global templates (tenant_id = '').
	err = sqlx.SelectContext(ctx, conn, &rows,
		`SELECT * FROM roles WHERE is_template = true AND tenant_id = '' ORDER BY name`)
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
		SELECT $1::varchar, $2::varchar, $3::varchar, $4::varchar, $5::timestamptz
		WHERE EXISTS (SELECT 1 FROM roles WHERE id = $3::varchar AND app_id = $2::varchar)
		ON CONFLICT (user_id, app_id, role_id) DO NOTHING`

	res, err := conn.ExecContext(ctx, q,
		uar.UserID.String(),
		uar.AppID.String(),
		uar.RoleID.String(),
		uar.TenantID.String(),
		uar.AssignedAt,
	)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}

	// Idempotent path: assignment already exists.
	var exists bool
	if err := sqlx.GetContext(ctx, conn, &exists, `
		SELECT EXISTS (
			SELECT 1 FROM user_app_roles
			WHERE user_id = $1 AND app_id = $2 AND role_id = $3
		)`,
		uar.UserID.String(), uar.AppID.String(), uar.RoleID.String()); err != nil {
		return err
	}
	if exists {
		return nil
	}

	// Role exists but app mismatch should surface as business error.
	if err := sqlx.GetContext(ctx, conn, &exists, `SELECT EXISTS (SELECT 1 FROM roles WHERE id = $1)`, uar.RoleID.String()); err != nil {
		return err
	}
	if exists {
		return domain.ErrRoleAppMismatch
	}
	return domain.ErrRoleNotFound
}

func (r *PostgresRoleRepository) DeleteUserAppRole(ctx context.Context, userID shared.UserID, appID shared.AppID, roleID shared.RoleID) (bool, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	res, err := conn.ExecContext(ctx,
		`DELETE FROM user_app_roles WHERE user_id = $1 AND app_id = $2 AND role_id = $3`,
		userID.String(), appID.String(), roleID.String())
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
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

// hydrateRoles attaches permissions to a batch of roles in a single
// round-trip. The previous implementation issued one SELECT per role,
// which made the per-request authorization check (FindByUserAndApp)
// scale linearly with the user's role count — e.g. an admin with 20
// roles cost 21 queries on every IsAllowed call.
func (r *PostgresRoleRepository) hydrateRoles(ctx context.Context, conn sqlx.ExtContext, rows []roleRow) ([]*domain.Role, error) {
	if len(rows) == 0 {
		return []*domain.Role{}, nil
	}

	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}

	var permRows []permissionRow
	if err := sqlx.SelectContext(ctx, conn, &permRows,
		`SELECT role_id, resource, action FROM role_permissions WHERE role_id = ANY($1)`,
		pq.Array(ids),
	); err != nil {
		return nil, err
	}

	permsByRole := make(map[string][]domain.Permission, len(rows))
	for _, p := range permRows {
		permsByRole[p.RoleID] = append(permsByRole[p.RoleID], domain.Permission{
			Resource: p.Resource,
			Action:   p.Action,
		})
	}

	roles := make([]*domain.Role, 0, len(rows))
	for _, row := range rows {
		roles = append(roles, rowToRole(row, permsByRole[row.ID]))
	}
	return roles, nil
}

func rowToRole(row roleRow, perms []domain.Permission) *domain.Role {
	r := &domain.Role{
		ID:                  shared.RoleID(row.ID),
		AppID:               shared.AppID(row.AppID),
		TenantID:            shared.TenantID(row.TenantID),
		Name:                row.Name,
		Description:         row.Description,
		Permissions:         perms,
		IsSystem:            row.IsSystem,
		IsTemplate:          row.IsTemplate,
		IsDefaultForCreator: row.IsDefaultForCreator,
		CreatedAt:           row.CreatedAt,
	}
	r.Version = row.Version
	return r
}
