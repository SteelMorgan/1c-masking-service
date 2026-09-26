-- TASK-225 ревью-2 N-1: флаг «preflight расшифровал хотя бы один
-- mask-токен в аргументах». Finalize по нему гасит свободный текст
-- ошибки (QUERY_PARSE_ERROR уходит без message, только позиция) —
-- эхо текста запроса после резолва содержит исходные значения.
-- Поколоночное применение, INTEGER 0/1, default 0.
ALTER TABLE call_contexts ADD COLUMN had_mask_tokens INTEGER NOT NULL DEFAULT 0;
