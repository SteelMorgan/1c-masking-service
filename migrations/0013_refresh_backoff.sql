-- TASK-225 (t226) §8: устойчивость refresh + §5a.3 статистика источников.
-- Те же ALTER включены в 0010 основной фазы (spec §2.2), применение
-- поколоночное с пропуском существующих — порядок 0010/0013 на merge
-- не гарантирован, обе стороны идемпотентны. В комментариях точки с
-- запятой не используются: апплаер разбирает файл по ним.
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
