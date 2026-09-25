-- TASK-225 (фаза «все вызовы через маскировщик»): автодобавление неизвестных
-- инструментов в tool_classifications. Все инструменты по умолчанию идут через
-- сервис маскирования, неизвестные отклоняются как deny-pending-review и должны
-- быть видны администратору в очереди на классификацию.
--
-- Колонки совпадают по форме с миграцией 0010 (основная спека TASK-225):
-- применяются ПОКОЛОНОЧНО из Rust (PRAGMA table_info), т.к. порядок прихода
-- 0010/0011 на merge не гарантирован — см. SqliteStorage::initialize.
ALTER TABLE tool_classifications ADD COLUMN auto_added INTEGER NOT NULL DEFAULT 0 CHECK (auto_added IN (0,1));
ALTER TABLE tool_classifications ADD COLUMN first_seen_at TEXT;
ALTER TABLE tool_classifications ADD COLUMN denied_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tool_classifications ADD COLUMN last_denied_at TEXT;
