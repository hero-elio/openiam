package persistence

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"openiam/internal/authz/domain"
	shared "openiam/internal/shared/domain"
	sharedPersistence "openiam/internal/shared/infra/persistence"
)

type resourcePermRow struct {
	ID           string    `db:"id"`
	UserID       string    `db:"user_id"`
	AppID        string    `db:"app_id"`
	TenantID     string    `db:"tenant_id"`
	ResourceType string    `db:"resource_type"`
	ResourceID   string    `db:"resource_id"`
	Action       string    `db:"action"`
	GrantedAt    time.Time `db:"granted_at"`
	GrantedBy    string    `db:"granted_by"`
}

type PostgresResourcePermissionRepository struct {
	db *sqlx.DB
}

func NewPostgresResourcePermissionRepository(db *sqlx.DB) *PostgresResourcePermissionRepository {
	return &PostgresResourcePermissionRepository{db: db}
}

func (r *PostgresResourcePermissionRepository) Save(ctx context.Context, rp *domain.ResourcePermission) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	if rp.ID == "" {
		rp.ID = uuid.New().String()
	}

	const q = `
		INSERT INTO user_resource_permissions (id, user_id, app_id, tenant_id, resource_type, resource_id, action, granted_at, granted_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (user_id, app_id, resource_type, resource_id, action) DO NOTHING`

	_, err := conn.ExecContext(ctx, q,
		rp.ID,
		rp.UserID.String(),
		rp.AppID.String(),
		rp.TenantID.String(),
		rp.ResourceType,
		rp.ResourceID,
		rp.Action,
		rp.GrantedAt,
		rp.GrantedBy.String(),
	)
	return err
}

func (r *PostgresResourcePermissionRepository) Delete(ctx context.Context, userID shared.UserID, appID shared.AppID, resourceType, resourceID, action string) error {
	conn := sharedPersistence.Conn(ctx, r.db)

	_, err := conn.ExecContext(ctx,
		`DELETE FROM user_resource_permissions WHERE user_id = $1 AND app_id = $2 AND resource_type = $3 AND resource_id = $4 AND action = $5`,
		userID.String(), appID.String(), resourceType, resourceID, action)
	return err
}

func (r *PostgresResourcePermissionRepository) FindByUserAndResource(ctx context.Context, userID shared.UserID, appID shared.AppID, resourceType, resourceID string) ([]*domain.ResourcePermission, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var rows []resourcePermRow
	err := sqlx.SelectContext(ctx, conn, &rows,
		`SELECT * FROM user_resource_permissions WHERE user_id = $1 AND app_id = $2 AND resource_type = $3 AND resource_id = $4`,
		userID.String(), appID.String(), resourceType, resourceID)
	if err != nil {
		return nil, err
	}

	return rowsToResourcePerms(rows), nil
}

func (r *PostgresResourcePermissionRepository) HasPermission(ctx context.Context, userID shared.UserID, appID shared.AppID, resourceType, resourceID, action string) (bool, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var count int
	err := sqlx.GetContext(ctx, conn, &count,
		`SELECT COUNT(*) FROM user_resource_permissions WHERE user_id = $1 AND app_id = $2 AND resource_type = $3 AND resource_id = $4 AND action = $5`,
		userID.String(), appID.String(), resourceType, resourceID, action)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *PostgresResourcePermissionRepository) ListByUser(ctx context.Context, userID shared.UserID, appID shared.AppID) ([]*domain.ResourcePermission, error) {
	conn := sharedPersistence.Conn(ctx, r.db)

	var rows []resourcePermRow
	err := sqlx.SelectContext(ctx, conn, &rows,
		`SELECT * FROM user_resource_permissions WHERE user_id = $1 AND app_id = $2 ORDER BY resource_type, resource_id`,
		userID.String(), appID.String())
	if err != nil {
		return nil, err
	}

	return rowsToResourcePerms(rows), nil
}

func rowsToResourcePerms(rows []resourcePermRow) []*domain.ResourcePermission {
	result := make([]*domain.ResourcePermission, 0, len(rows))
	for _, row := range rows {
		result = append(result, &domain.ResourcePermission{
			ID:           row.ID,
			UserID:       shared.UserID(row.UserID),
			AppID:        shared.AppID(row.AppID),
			TenantID:     shared.TenantID(row.TenantID),
			ResourceType: row.ResourceType,
			ResourceID:   row.ResourceID,
			Action:       row.Action,
			GrantedAt:    row.GrantedAt,
			GrantedBy:    shared.UserID(row.GrantedBy),
		})
	}
	return result
}
