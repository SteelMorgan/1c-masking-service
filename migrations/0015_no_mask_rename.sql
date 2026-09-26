--++agent TASK-225 [26.09.2026] раздел E
-- Переименование класса инструмента metadata-bypass -> no-mask.
-- SQLite не умеет изменять CHECK через ALTER — таблица пересобирается
-- с новым ограничением, значения class переводятся при копировании.
-- Снимки режимов в policies.tools_json — компактный serde_json
-- вида {"tool":…,"mode":"metadata-bypass","reason":…} — переводятся
-- REPLACE. Применяется execute_batch внутри IMMEDIATE-транзакции
-- initialize; колонки auto_added/first_seen_at/denied_count/
-- last_denied_at к этому моменту уже добавлены миграциями 0010/0011
DROP TABLE IF EXISTS tool_classifications_new;

CREATE TABLE tool_classifications_new (
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    class TEXT NOT NULL CHECK (class IN ('data-mask', 'no-mask', 'deny-pending-review')),
    reviewer TEXT,
    updated_at TEXT NOT NULL,
    auto_added INTEGER NOT NULL DEFAULT 0 CHECK (auto_added IN (0,1)),
    first_seen_at TEXT,
    denied_count INTEGER NOT NULL DEFAULT 0,
    last_denied_at TEXT,
    PRIMARY KEY (database_id, tool_name)
);

INSERT INTO tool_classifications_new
    (database_id, tool_name, class, reviewer, updated_at,
     auto_added, first_seen_at, denied_count, last_denied_at)
SELECT database_id, tool_name,
       CASE WHEN class='metadata-bypass' THEN 'no-mask' ELSE class END,
       reviewer, updated_at, auto_added, first_seen_at, denied_count, last_denied_at
FROM tool_classifications;

DROP TABLE tool_classifications;
ALTER TABLE tool_classifications_new RENAME TO tool_classifications;

UPDATE policies SET tools_json = REPLACE(tools_json, '"mode":"metadata-bypass"', '"mode":"no-mask"')
WHERE tools_json LIKE '%metadata-bypass%';
--++agent TASK-225
