-- Миграция 0016: идентичность базы — точный непрозрачный ключ
-- `instance_id` (раздел O2: `ras:<cluster_guid>:<infobase_guid>` после
-- RAS-резолюции менеджером либо `gen:<srvr>/<ref>` verbatim при
-- недоступном RAS). `cluster_server`/`infobase_name` — только
-- отображаемые координаты (Srvr/Ref) для админки. Источник ключа
-- (`ras`/`generated`) выводится из префикса и колонкой не хранится
-- (оставшаяся колонка `guid_source` в ранее применённых БД не
-- читается).
-- Никакой нормализации координат и координатных индексов: записи
-- различаются ключом, склейка баз невозможна по построению.
-- Этот файл применяется поколоночно (initialize).

ALTER TABLE databases ADD COLUMN cluster_server TEXT;
ALTER TABLE databases ADD COLUMN infobase_name TEXT;
