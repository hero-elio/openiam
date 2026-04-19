CREATE TABLE roles (
    id VARCHAR(36) PRIMARY KEY,
    app_id VARCHAR(36) NOT NULL DEFAULT '',
    tenant_id VARCHAR(36) NOT NULL DEFAULT '',
    name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    is_template BOOLEAN NOT NULL DEFAULT FALSE,
    is_default_for_creator BOOLEAN NOT NULL DEFAULT FALSE,
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
CREATE INDEX idx_roles_template ON roles(is_template, tenant_id) WHERE is_template = true;

-- Seed built-in global template roles.
INSERT INTO roles (id, app_id, tenant_id, name, description, is_system, is_template, is_default_for_creator, version)
VALUES
('tmpl-super-admin', '', '', 'super_admin', 'Super administrator with all permissions', true, true, true, 1),
('tmpl-admin', '', '', 'admin', 'Administrator with user and role management permissions', true, true, false, 1),
('tmpl-member', '', '', 'member', 'Basic member role (auto-assigned on registration)', true, true, false, 1);

INSERT INTO role_permissions (role_id, resource, action) VALUES
('tmpl-super-admin', '*', '*'),
('tmpl-admin', 'users', 'read'),
('tmpl-admin', 'users', 'update'),
('tmpl-admin', 'roles', '*'),
('tmpl-admin', 'permissions', 'check');
