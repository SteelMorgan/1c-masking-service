-- Миграция 0017: права по базам (per-database RBAC).
--
-- Роль пользователя становится трёхступенчатой: SuperAdmin (все базы и
-- управление пользователями), Admin (только назначенные базы), Viewer
-- (просмотр назначенных баз). Доступ к базам хранится отдельно от роли
-- в user_database_access: у SuperAdmin строк нет — его доступ «все базы»
-- неявный и не снимается отзывом.
--
-- Файл разбит на секции `-- == NAME ==`; каждая применяется своей фазой
-- в SqliteStorage::initialize. Гард фазы 2 — фактическое состояние схемы
-- (наличие user_database_access в sqlite_master), а не запись version=17:
-- базы с чужой записью от ранней сборки достраиваются по месту.
--
-- == AUDIT-COLUMN ==
-- Колонка целевого пользователя для событий аудита: grant/revoke доступа
-- и user-мутации пишут target_user_id отдельным полем, а не только
-- фрагментом free-form code. Применяется поколоночно (как 0011/0012):
-- уже созданная колонка пропускается, конфликт типа — ошибка старта.
ALTER TABLE audit_events ADD COLUMN target_user_id TEXT;

-- == ACCESS-TABLE ==
-- Назначение баз пользователям Admin/Viewer. granted_by — id
-- супер-администратора, выдавшего доступ (NULL у миграционной выдачи).
CREATE TABLE IF NOT EXISTS user_database_access (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    granted_by TEXT,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, database_id)
);
CREATE INDEX IF NOT EXISTS uda_database_idx ON user_database_access(database_id);

-- == USERS-RECREATE ==
-- SQLite не умеет изменять CHECK через ALTER — users пересоздаётся со
-- ступенью SuperAdmin (тот же приём, что у 0015 для tool_classifications).
-- Выполняется отдельной транзакцией при PRAGMA foreign_keys=OFF: sessions,
-- activation_capabilities и user_database_access ссылаются на users, а
-- DROP родительской таблицы под включёнными FK не проходит. После коммита
-- initialize проверяет pragma_foreign_key_check — нарушение = ошибка
-- старта. Guard: запускается только когда в sqlite_master.sql таблицы
-- users нет 'SuperAdmin' (свежие БД получают новый CHECK уже из 0001).
-- Все существующие Admin становятся SuperAdmin — иначе у работающего
-- сервиса не осталось бы никого с полными правами.
CREATE TABLE users_new (
    id TEXT PRIMARY KEY,
    normalized_login TEXT NOT NULL UNIQUE,
    display_login TEXT NOT NULL,
    password_hash TEXT,
    role TEXT NOT NULL CHECK (role IN ('SuperAdmin', 'Admin', 'Viewer')),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    auth_epoch INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO users_new(id, normalized_login, display_login, password_hash, role, status, auth_epoch, created_at, updated_at)
SELECT id, normalized_login, display_login, password_hash,
       CASE role WHEN 'Admin' THEN 'SuperAdmin' ELSE role END,
       status, auth_epoch, created_at, updated_at
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
