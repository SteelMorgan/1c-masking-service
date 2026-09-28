-- Миграция 0018: вызовы без понятия «разговора».
--
-- chat_id больше не участвует ни в ключах, ни в уникальности: история и
-- контексты вызовов адресуются парой (database_id, call_id), а вызывающий
-- хранится только как атрибут аудита caller_label (самоназвание клиента,
-- не механизм доступа).
--
-- Данные вызовов не переносятся: таблица соответствий токенов живёт
-- только в памяти процесса, поэтому прежняя история всё равно
-- нераскрываема. Миграция безусловно пересоздаёт пустыми все таблицы
-- вызовов: history, call_contexts, unscoped_terminal_events,
-- audit_events; выведенная из употребления v2_call_receipts (см. 0008)
-- удаляется. Сохраняются только настройки: базы, политики и правила,
-- словари, классификации инструментов, пользователи и доступы, журнал
-- импорта настроек, кэш поколений, сессии входа.
--
-- Применяется целиком одной транзакцией вместе с записью version=18
-- (guard — запись version=18): промежуточного состояния не бывает,
-- повторный старт — no-op.

DROP TABLE IF EXISTS v2_call_receipts;

DROP TABLE IF EXISTS history;
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

DROP TABLE IF EXISTS call_contexts;
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

DROP TABLE IF EXISTS unscoped_terminal_events;
CREATE TABLE unscoped_terminal_events (
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

DROP TABLE IF EXISTS audit_events;
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_kind TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    database_id TEXT,
    caller_label TEXT,
    history_id TEXT,
    outcome TEXT NOT NULL,
    code TEXT,
    correlation_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    target_user_id TEXT
);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_events(created_at);
