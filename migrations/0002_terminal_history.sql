CREATE TABLE IF NOT EXISTS unscoped_terminal_events (
    id TEXT PRIMARY KEY,
    call_id TEXT NOT NULL UNIQUE,
    correlation_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    error_code TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS unscoped_terminal_expires_idx
    ON unscoped_terminal_events(expires_at);
