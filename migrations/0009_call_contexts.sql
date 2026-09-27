--++agent TASK-224 [08.10.2026] итерация 4
-- Контекст вызова preflight→finalize: текст запроса/описание аргументов,
-- зачищенный engine secret-cut до записи (ревью R1: сырые литералы
-- секретов в arguments возможны — durable-форма только sanitized). Живёт
-- не дольше min(history_ttl, mapping_ttl) и удаляется вместе с историей
-- на старте — без RAM mapping записи всё равно нераскрываемы.
CREATE TABLE IF NOT EXISTS call_contexts (
    call_id TEXT PRIMARY KEY,
    database_id TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    title TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS call_contexts_expires_idx ON call_contexts(expires_at);
--++agent TASK-224
