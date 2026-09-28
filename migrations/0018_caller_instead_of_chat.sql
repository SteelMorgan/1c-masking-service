-- Миграция 0018: вызовы без понятия «разговора».
--
-- chat_id больше не участвует ни в ключах, ни в уникальности: история и
-- контексты вызовов адресуются парой (database_id, call_id), а вызывающий
-- хранится только как атрибут аудита caller_label (самоназвание клиента,
-- не механизм доступа).
--
-- Прежние записи, привязанные к chat_id, не переносятся: history,
-- call_contexts и unscoped_terminal_events очищаются полностью,
-- выведенная из употребления v2_call_receipts (см. 0008) удаляется,
-- у audit_events колонка переименовывается и обнуляется.
-- Таблица соответствий токенов живёт только в памяти процесса, поэтому
-- после рестарта старые записи истории всё равно нераскрываемы.
--
-- Файл разбит на секции `-- == NAME ==`. Каждая секция применяется
-- в SqliteStorage::initialize только если в таблице фактически есть
-- колонка chat_id (pragma_table_info), а не по записи version=18:
-- частично мигрированная схема достраивается по месту, повторный старт
-- на мигрированной схеме — no-op. Порядок: receipts до history (ссылка
-- history_id), затем пересоздание history.
--
-- == RECEIPTS-DROP ==
DROP TABLE IF EXISTS v2_call_receipts;

-- == HISTORY-RECREATE ==
DROP TABLE history;
CREATE TABLE history (
    id TEXT PRIMARY KEY,
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    caller_label TEXT,
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
    mask_detail_json TEXT,
    field_sources_json TEXT,
    policy_id TEXT,
    UNIQUE (database_id, call_id)
);
CREATE INDEX IF NOT EXISTS history_expires_idx ON history(expires_at);
CREATE INDEX IF NOT EXISTS history_db_created_idx ON history(database_id, created_at DESC);

-- == CONTEXTS-RECREATE ==
DROP TABLE call_contexts;
CREATE TABLE call_contexts (
    call_id TEXT PRIMARY KEY,
    database_id TEXT NOT NULL,
    caller_label TEXT,
    tool_name TEXT NOT NULL,
    title TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    had_mask_tokens INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS call_contexts_expires_idx ON call_contexts(expires_at);

-- == AUDIT-RENAME ==
ALTER TABLE audit_events RENAME COLUMN chat_id TO caller_label;
UPDATE audit_events SET caller_label = NULL;
DELETE FROM unscoped_terminal_events;
