// Package postgres bundles every Postgres-backed port implementation
// IAM ships with into a single fixture struct.
//
// Typical use:
//
//	pg := postgres.Adapters(db)
//	authnMod, _ := authn.New(authnCfg, authn.Deps{
//	    CredentialStore: pg.Credentials,
//	    SessionStore:    redisSessions, // separate adapter for Redis
//	    // ...
//	})
//	identityMod, _ := identity.New(identity.Deps{Users: pg.Users})
//	authzMod, _   := authz.New(authz.Deps{
//	    Roles:               pg.Roles,
//	    ResourcePermissions: pg.ResourcePermissions,
//	    PermissionDefs:      pg.PermissionDefinitions,
//	})
//	tenantMod, _  := tenant.New(tenant.Deps{
//	    Tenants:      pg.Tenants,
//	    Applications: pg.Applications,
//	})
//
// The fixture deliberately exposes only the persistent stores. Redis
// and JWT adapters live in sibling packages (pkg/iam/adapters/redis,
// pkg/iam/adapters/jwt) so SDK consumers can mix and match.
package postgres

import (
	"github.com/jmoiron/sqlx"

	authnPersistence "openiam/internal/authn/adapter/outbound/persistence"
	authzPersistence "openiam/internal/authz/adapter/outbound/persistence"
	identityPersistence "openiam/internal/identity/adapter/outbound/persistence"
	tenantPersistence "openiam/internal/tenant/adapter/outbound/persistence"

	"openiam/pkg/iam/authn"
	"openiam/pkg/iam/authz"
	"openiam/pkg/iam/identity"
	"openiam/pkg/iam/tenant"
)

// AdapterSet is the set of Postgres-backed port implementations that
// satisfy the IAM module Deps. Each field is the public port type from
// the corresponding pkg/iam/<module> package, so wiring the module
// from this struct is straightforward and type-checked.
type AdapterSet struct {
	// authn
	Credentials authn.CredentialStore

	// identity
	Users identity.UserStore

	// authz
	Roles                 authz.RoleStore
	ResourcePermissions   authz.ResourcePermissionStore
	PermissionDefinitions authz.PermissionDefinitionStore

	// tenant
	Tenants      tenant.TenantStore
	Applications tenant.ApplicationStore
}

// Adapters returns the canonical AdapterSet bound to db. The function
// performs no I/O; the underlying repositories are lazy and only touch
// the database when a Service method is invoked.
func Adapters(db *sqlx.DB) AdapterSet {
	return AdapterSet{
		Credentials: authnPersistence.NewPostgresCredentialRepo(db),

		Users: identityPersistence.NewPostgresUserRepository(db),

		Roles:                 authzPersistence.NewPostgresRoleRepository(db),
		ResourcePermissions:   authzPersistence.NewPostgresResourcePermissionRepository(db),
		PermissionDefinitions: authzPersistence.NewPostgresPermissionDefinitionRepository(db),

		Tenants:      tenantPersistence.NewPostgresTenantRepository(db),
		Applications: tenantPersistence.NewPostgresApplicationRepository(db),
	}
}
