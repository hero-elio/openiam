CREATE TABLE user_app_roles (
    user_id VARCHAR(36) NOT NULL,
    app_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    tenant_id VARCHAR(36) NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, app_id, role_id)
);

CREATE INDEX idx_user_app_roles_tenant_id ON user_app_roles(tenant_id);
CREATE INDEX idx_user_app_roles_role_id ON user_app_roles(role_id);
