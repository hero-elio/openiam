CREATE TABLE permission_definitions (
    id          VARCHAR(36)  PRIMARY KEY,
    app_id      VARCHAR(36)  NOT NULL,
    resource    VARCHAR(255) NOT NULL,
    action      VARCHAR(100) NOT NULL,
    description TEXT         NOT NULL DEFAULT '',
    is_builtin  BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (app_id, resource, action)
);

CREATE INDEX idx_perm_def_app_id ON permission_definitions(app_id);
