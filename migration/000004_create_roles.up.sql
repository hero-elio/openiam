CREATE TABLE roles (
    id VARCHAR(36) PRIMARY KEY,
    app_id VARCHAR(36) NOT NULL,
    tenant_id VARCHAR(36) NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (app_id, tenant_id, name)
);

CREATE TABLE role_permissions (
    role_id VARCHAR(36) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    PRIMARY KEY (role_id, resource, action)
);

CREATE INDEX idx_roles_tenant_id ON roles(tenant_id);
CREATE INDEX idx_roles_app_id ON roles(app_id);
