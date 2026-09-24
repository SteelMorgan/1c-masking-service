--++agent TASK-221 [24.09.2026 00:40:00]
CREATE TABLE IF NOT EXISTS v2_refresh_intents (
    database_id TEXT PRIMARY KEY REFERENCES databases(id) ON DELETE CASCADE,
    phase TEXT NOT NULL CHECK (phase IN ('full', 'dictionary')),
    reason TEXT,
    actor_id TEXT,
    created_at TEXT NOT NULL
);
ALTER TABLE cache_generations ADD COLUMN selectors_json TEXT;
--++agent TASK-221
