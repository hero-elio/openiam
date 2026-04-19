CREATE TABLE user_resource_permissions (
    id            VARCHAR(36)  PRIMARY KEY,
    user_id       VARCHAR(36)  NOT NULL,
    app_id        VARCHAR(36)  NOT NULL,
    tenant_id     VARCHAR(36)  NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id   VARCHAR(255) NOT NULL,
    action        VARCHAR(100) NOT NULL,
    granted_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    granted_by    VARCHAR(36),
    UNIQUE (user_id, app_id, resource_type, resource_id, action)
);

CREATE INDEX idx_urp_user_app ON user_resource_permissions(user_id, app_id);
CREATE INDEX idx_urp_resource ON user_resource_permissions(resource_type, resource_id);
