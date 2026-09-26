--++agent TASK-225 [26.09.2026]
-- Миграция версий настройки (spec §2.2): policies несут снимок словаря
-- (dictionary_json) и режимов инструментов (tools_json), журналы
-- setup_imports/setup_journal, детализация причин маскирования в history
-- (§6), колонки устойчивости pull для t226 (§8) и статистика источников
-- последнего pull (§5a.3). Все ALTER применяются поколоночно — порядок
-- прихода миграций на merge не гарантирован, колонки частично пересекаются
-- с 0011. Внимание: в комментариях файла точки с запятой не используются
-- — апплаер разбирает файл по точке с запятой.

ALTER TABLE policies ADD COLUMN dictionary_json TEXT;
ALTER TABLE policies ADD COLUMN tools_json TEXT;
ALTER TABLE policies ADD COLUMN origin TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE policies ADD COLUMN origin_ref TEXT;
ALTER TABLE policies ADD COLUMN created_by TEXT;
ALTER TABLE policies ADD COLUMN updated_at TEXT;
ALTER TABLE policies ADD COLUMN content_hash TEXT;
ALTER TABLE policies ADD COLUMN activated_at TEXT;
ALTER TABLE policies ADD COLUMN activated_by TEXT;
ALTER TABLE policies ADD COLUMN comment TEXT;
ALTER TABLE policies ADD COLUMN discarded_at TEXT;

ALTER TABLE policy_rules ADD COLUMN reason TEXT;
ALTER TABLE policy_rules ADD COLUMN tests_json TEXT;

CREATE TABLE IF NOT EXISTS setup_imports (
  id TEXT PRIMARY KEY,
  database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL,
  file_name TEXT,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  schema TEXT NOT NULL,
  generated_by_json TEXT,
  database_hint_json TEXT,
  result TEXT NOT NULL CHECK (result IN ('accepted','rejected')),
  error_codes_json TEXT,
  draft_policy_id TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS setup_journal (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  at TEXT NOT NULL,
  actor_kind TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL CHECK (action IN ('import','import_rejected','draft_create','draft_edit','draft_discard','activate','rollback','export','tool_mode','migration')),
  version INTEGER,
  file_name TEXT,
  sha256 TEXT,
  details_json TEXT
);
CREATE INDEX IF NOT EXISTS setup_journal_db_idx ON setup_journal(database_id, at DESC);

ALTER TABLE tool_classifications ADD COLUMN auto_added INTEGER NOT NULL DEFAULT 0 CHECK (auto_added IN (0,1));
ALTER TABLE tool_classifications ADD COLUMN first_seen_at TEXT;
ALTER TABLE tool_classifications ADD COLUMN denied_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tool_classifications ADD COLUMN last_denied_at TEXT;

ALTER TABLE history ADD COLUMN mask_detail_json TEXT;
ALTER TABLE history ADD COLUMN field_sources_json TEXT;
ALTER TABLE history ADD COLUMN policy_id TEXT;

ALTER TABLE v2_refresh_intents ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE v2_refresh_intents ADD COLUMN next_attempt_at TEXT;
ALTER TABLE v2_refresh_intents ADD COLUMN state TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE v2_refresh_intents ADD COLUMN last_error_code TEXT;
ALTER TABLE v2_refresh_intents ADD COLUMN last_error_at TEXT;
ALTER TABLE v2_refresh_intents ADD COLUMN first_failed_at TEXT;

ALTER TABLE databases ADD COLUMN last_refresh_ok_at TEXT;
ALTER TABLE databases ADD COLUMN last_refresh_error_code TEXT;
ALTER TABLE databases ADD COLUMN last_refresh_error_at TEXT;

ALTER TABLE cache_generations ADD COLUMN source_stats_json TEXT;

-- == POST-DATA ==
-- Уникальные индексы создаются ПОСЛЕ переноса данных §2.3 (несколько
-- draft у базы сначала нормализуются до одного) в той же транзакции.
CREATE UNIQUE INDEX IF NOT EXISTS policies_one_draft ON policies(database_id) WHERE status='draft';
CREATE UNIQUE INDEX IF NOT EXISTS policies_one_active ON policies(database_id) WHERE status='active';
--++agent TASK-225
