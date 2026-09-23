PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'retired')),
    created_at TEXT NOT NULL,
    UNIQUE (database_id, version)
);

CREATE TABLE IF NOT EXISTS databases (
    id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL UNIQUE,
    display_label TEXT,
    mode TEXT NOT NULL CHECK (mode IN ('unconfigured', 'enabled', 'disabled')),
    active_policy_id TEXT REFERENCES policies(id),
    active_cache_version INTEGER,
    mapping_ttl_seconds INTEGER NOT NULL DEFAULT 86400 CHECK (mapping_ttl_seconds > 0),
    history_ttl_seconds INTEGER NOT NULL DEFAULT 86400 CHECK (history_ttl_seconds > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_classifications (
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    class TEXT NOT NULL CHECK (class IN ('data-mask', 'metadata-bypass', 'deny-pending-review')),
    reviewer TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (database_id, tool_name)
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    selector_kind TEXT NOT NULL CHECK (selector_kind IN ('source_path', 'name', 'type', 'dictionary', 'regex')),
    selector_value TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('keep', 'mask', 'secret')),
    category TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS policy_rules_policy_idx ON policy_rules(policy_id, enabled, selector_kind, priority);

CREATE TABLE IF NOT EXISTS dictionary_configs (
    id TEXT PRIMARY KEY,
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('all', 'part')),
    source_paths_json TEXT NOT NULL DEFAULT '[]',
    filter_ast_json TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE (database_id)
);

CREATE TABLE IF NOT EXISTS cache_generations (
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('building', 'active', 'failed')),
    metadata_count INTEGER NOT NULL DEFAULT 0,
    dictionary_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    activated_at TEXT,
    PRIMARY KEY (database_id, version)
);

CREATE TABLE IF NOT EXISTS history (
    id TEXT PRIMARY KEY,
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    chat_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    outcome TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    mask_reasons_json TEXT NOT NULL,
    public_result_json TEXT NOT NULL,
    report_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    mapping_batch_id TEXT,
    UNIQUE (database_id, chat_id, call_id)
);
CREATE INDEX IF NOT EXISTS history_expires_idx ON history(expires_at);
CREATE INDEX IF NOT EXISTS history_chat_idx ON history(database_id, chat_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_kind TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    database_id TEXT,
    chat_id TEXT,
    history_id TEXT,
    outcome TEXT NOT NULL,
    code TEXT,
    correlation_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_events(created_at);

CREATE TABLE IF NOT EXISTS feed_jobs (
    id TEXT PRIMARY KEY,
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    target_version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'receiving', 'ready', 'active', 'failed')),
    expected_count INTEGER,
    digest TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    normalized_login TEXT NOT NULL UNIQUE,
    display_login TEXT NOT NULL,
    password_hash TEXT,
    role TEXT NOT NULL CHECK (role IN ('Admin', 'Viewer')),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    auth_epoch INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activation_capabilities (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_hash BLOB NOT NULL,
    idle_expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    revoked_at TEXT,
    auth_epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id, revoked_at);

CREATE TABLE IF NOT EXISTS service_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    bootstrap_completed_at TEXT,
    audit_retention_seconds INTEGER NOT NULL DEFAULT 7776000
);
INSERT OR IGNORE INTO service_state(singleton) VALUES (1);
