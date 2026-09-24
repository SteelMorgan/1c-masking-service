--++agent TASK-221 [23.09.2026 20:48:00]
-- Cache values остаются RAM-only; durable generation не объявляет restart ready.
CREATE TABLE IF NOT EXISTS v2_active_snapshots (
    database_id TEXT PRIMARY KEY REFERENCES databases(id) ON DELETE CASCADE,
    policy_digest TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    metadata_generation TEXT NOT NULL,
    dictionary_generation TEXT NOT NULL,
    activated_at TEXT NOT NULL
);
--++agent TASK-221
