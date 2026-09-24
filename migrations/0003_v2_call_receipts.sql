--++agent TASK-221 [23.09.2026 20:15:00]
-- Identity живёт дольше history: очистка payload не разрешает повторный dispatch.
CREATE TABLE IF NOT EXISTS v2_call_receipts (
    call_id TEXT PRIMARY KEY,
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    database_instance_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    connection_generation TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    service_epoch TEXT NOT NULL,
    lease_id TEXT NOT NULL UNIQUE,
    policy_version INTEGER NOT NULL,
    policy_digest TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    issued_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('issued', 'completed')),
    terminal_code TEXT,
    history_id TEXT REFERENCES history(id) ON DELETE SET NULL,
    CHECK (expires_at_ms > issued_at_ms)
);
CREATE INDEX IF NOT EXISTS v2_receipts_database_idx ON v2_call_receipts(database_id);
--++agent TASK-221
