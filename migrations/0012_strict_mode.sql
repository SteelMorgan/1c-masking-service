-- TASK-225 (строгий режим lineage): настройка базы `strict_mode`.
-- Включено по умолчанию (решение пользователя: default ON после сервисной
-- части): колонки с маркером unverified возвращаются с полностью
-- маскированными значениями, при выключении — отказ как раньше.
--
-- Применяется ПОКОЛОНОЧНО из Rust (PRAGMA table_info), т.к. порядок
-- прихода миграций параллельных фаз на merge не гарантирован —
-- см. SqliteStorage::initialize. Комментарии в этом файле не должны
-- содержать разделителя операторов.
ALTER TABLE databases ADD COLUMN strict_mode INTEGER NOT NULL DEFAULT 1 CHECK (strict_mode IN (0,1));
