use std::{path::Path, sync::Mutex};

use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use uuid::Uuid;

use crate::domain::{
    DatabaseIdentity, DatabaseMode, DatabaseSettings, HistoryForReveal, PolicyRule, RuleAction,
    RuleSelector, StoredHistory, ToolClass,
};

const MIGRATION: &str = include_str!("../../migrations/0001_core.sql");
const TERMINAL_HISTORY_MIGRATION: &str = include_str!("../../migrations/0002_terminal_history.sql");
//++agent TASK-221 [23.09.2026 20:15:00]
// Исторические миграции применяются для upgrade path существующих баз;
// созданные ими v2-таблицы удаляются миграцией 0008 (TASK-222).
const V2_CALL_MIGRATION: &str = include_str!("../../migrations/0003_v2_call_receipts.sql");
const V2_ACTIVATION_MIGRATION: &str = include_str!("../../migrations/0004_v2_active_snapshots.sql");
const V2_FEED_MIGRATION: &str = include_str!("../../migrations/0005_v2_feed_leases.sql");
const V2_FEED_PROOF_MIGRATION: &str =
    include_str!("../../migrations/0006_v2_feed_completion_proof.sql");
const V2_REFRESH_INTENTS_MIGRATION: &str =
    include_str!("../../migrations/0007_v2_refresh_intents.sql");
//++agent TASK-221
//++agent TASK-222 [05.10.2026]
const DROP_V2_FEED_MIGRATION: &str = include_str!("../../migrations/0008_drop_v2_feed.sql");
//++agent TASK-222
//++agent TASK-224 [08.10.2026] итерация 4
const CALL_CONTEXTS_MIGRATION: &str = include_str!("../../migrations/0009_call_contexts.sql");
//++agent TASK-224
//++agent TASK-225 [25.09.2026]
// DDL приведён для аудита; применяется поколоночно из initialize —
// миграция 0010 (основная фаза TASK-225) содержит те же ALTER, и порядок
// прихода миграций на merge не гарантирован.
const TOOL_AUTO_CLASS_MIGRATION: &str =
    include_str!("../../migrations/0011_tool_auto_classification.sql");
// Миграция 0012 (строгий режим lineage): колонка strict_mode в databases,
// тот же поколоночный контракт применения, что у 0011.
const STRICT_MODE_MIGRATION: &str = include_str!("../../migrations/0012_strict_mode.sql");
// Миграция 0010 (версии настройки, spec §2.2): ALTER поколоночно по всем
// таблицам (пересечение с 0011 и порядок merge не гарантированы),
// перенос данных §2.3, затем уникальные индексы части POST-DATA.
const SETUP_VERSIONS_MIGRATION: &str = include_str!("../../migrations/0010_setup_versions.sql");
// Миграция 0013 (§8 backoff + §5a.3 source stats): поколоночное применение,
// те же ALTER содержит 0010 основной фазы — пропуск существующих колонок.
const REFRESH_BACKOFF_MIGRATION: &str = include_str!("../../migrations/0013_refresh_backoff.sql");
// Миграция 0014 (ревью-2 N-1): флаг расшифрованных mask-токенов
// на записи контекста вызова.
const MASK_TOKEN_FLAG_MIGRATION: &str = include_str!("../../migrations/0014_mask_token_flag.sql");
// Миграция 0015 (раздел E): переименование класса инструмента
// metadata-bypass → no-mask — пересборка tool_classifications
// (CHECK не меняется ALTER'ом) и REPLACE в policies.tools_json.
const NO_MASK_RENAME_MIGRATION: &str = include_str!("../../migrations/0015_no_mask_rename.sql");
//++agent TASK-225
// Миграция 0016 (раздел O2): отображаемые координаты базы (Srvr/Ref)
// и источник ключа (`ras`|`generated`, выводится из префикса
// `instance_id`); идентичность — точный ключ `instance_id`.
const DATABASE_IDENTITY_MIGRATION: &str =
    include_str!("../../migrations/0016_database_identity.sql");
//++agent TASK-225
// Миграция 0017 (per-database RBAC): колонка audit_events.target_user_id
// (поколоночно), таблица user_database_access, пересоздание users с
// расширенным CHECK роли. Файл разбит на секции `-- == NAME ==`, фазы
// применения — в initialize.
const DATABASE_ACCESS_MIGRATION: &str =
    include_str!("../../migrations/0017_database_access.sql");

pub enum HistoryWrite {
    Inserted(Uuid),
    Existing(StoredHistory),
    Conflict,
}

//++agent TASK-225 [26.09.2026]
/// §6.1: детальная часть записи истории — причины по ячейкам, lineage
/// (без значений) и id версии политики. `None` у legacy-вызовов —
/// колонки остаются NULL, B9 отвечает `detailed:false`.
//++agent TASK-225
#[derive(Debug, Default, Clone, Copy)]
pub struct HistoryDetail<'a> {
    pub mask_detail_json: Option<&'a str>,
    pub field_sources_json: Option<&'a str>,
    pub policy_id: Option<Uuid>,
}

//++agent TASK-225 [26.09.2026]
/// B9/§6.3: запись истории для отчёта причин (без значений ячеек).
//++agent TASK-225
//++agent TASK-225 [26.09.2026]
/// §5: запись истории для сухого прогона (B6) — маскированный ответ,
/// lineage и привязка причин. Значения не покидают сервис.
//++agent TASK-225
#[derive(Debug)]
pub struct DryRunRecord {
    pub id: Uuid,
    pub created_at: String,
    pub tool_name: String,
    pub chat_id: String,
    pub call_id: Uuid,
    pub public_result: Value,
    pub mapping_batch_id: Option<Uuid>,
    pub field_sources: Option<String>,
    pub mask_detail: Option<String>,
}

#[derive(Debug)]
pub struct HistoryReasonsRow {
    pub database_id: Uuid,
    pub expires_at: String,
    pub policy_version: i64,
    pub policy_id: Option<Uuid>,
    pub mask_detail_json: Option<String>,
    pub mask_reasons_json: Option<String>,
    pub report: Value,
    pub tool_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalWrite {
    Inserted,
    Existing,
    Conflict,
}

pub struct SqliteStorage {
    connection: Mutex<Connection>,
}

impl SqliteStorage {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        Self::initialize(Connection::open(path)?)
    }

    pub fn in_memory() -> rusqlite::Result<Self> {
        Self::initialize(Connection::open_in_memory()?)
    }

    fn initialize(mut connection: Connection) -> rusqlite::Result<Self> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        // Миграция 0017, фаза 1: пересоздание users со старым CHECK ролей
        // нельзя выполнить внутри транзакции — foreign_keys переключается
        // только вне её, а DROP родителя sessions/capabilities требует
        // выключенных FK. Guard по тексту DDL: свежая БД (users ещё нет)
        // и уже мигрированная (CHECK содержит 'SuperAdmin') пропускаются.
        migrate_users_role_check(&mut connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(MIGRATION)?;
        transaction.execute_batch(TERMINAL_HISTORY_MIGRATION)?;
        //++agent TASK-221 [23.09.2026 20:15:00]
        transaction.execute_batch(V2_CALL_MIGRATION)?;
        transaction.execute_batch(V2_ACTIVATION_MIGRATION)?;
        transaction.execute_batch(V2_FEED_MIGRATION)?;
        let has_feed_proof: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=6)",
            [],
            |row| row.get(0),
        )?;
        if !has_feed_proof {
            transaction.execute_batch(V2_FEED_PROOF_MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (6, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        let has_refresh_intents: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=7)",
            [],
            |row| row.get(0),
        )?;
        if !has_refresh_intents {
            transaction.execute_batch(V2_REFRESH_INTENTS_MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (7, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        //++agent TASK-222 [05.10.2026]
        let has_v2_drop: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=8)",
            [],
            |row| row.get(0),
        )?;
        if !has_v2_drop {
            transaction.execute_batch(DROP_V2_FEED_MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (8, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        //++agent TASK-222
        //++agent TASK-224 [08.10.2026] итерация 4
        let has_call_contexts: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=9)",
            [],
            |row| row.get(0),
        )?;
        if !has_call_contexts {
            transaction.execute_batch(CALL_CONTEXTS_MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (9, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        //++agent TASK-224
        //++agent TASK-225 [25.09.2026]
        // Миграция 0010 (версии настройки): поколоночные ALTER по всем
        // затронутым таблицам, затем перенос данных §2.3, затем уникальные
        // индексы — всё внутри этой же IMMEDIATE-транзакции initialize.
        let has_setup_versions: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=10)",
            [],
            |row| row.get(0),
        )?;
        if !has_setup_versions {
            apply_setup_versions_migration(&transaction, SETUP_VERSIONS_MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (10, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        // Миграция 0011 применяется поколоночно: те же колонки объявлены в
        // миграции 0010 основной фазы TASK-225, а порядок прихода на merge
        // не гарантирован — увидев уже созданную колонку, пропускаем её,
        // но проверяем тип (тип, несовместимый со спекой, — громкая ошибка
        // на старте, а не тихая поломка tool_class).
        let has_tool_auto_class: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=11)",
            [],
            |row| row.get(0),
        )?;
        if !has_tool_auto_class {
            apply_add_column_migration(
                &transaction,
                "tool_classifications",
                TOOL_AUTO_CLASS_MIGRATION,
            )?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (11, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        // Миграция 0012 (строгий режим): та же поколоночная стратегия —
        // пропустить существующую колонку strict_mode, громко упасть при
        // несовместимом типе. default 1 соответствует решению «default ON».
        let has_strict_mode: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=12)",
            [],
            |row| row.get(0),
        )?;
        if !has_strict_mode {
            apply_add_column_migration(&transaction, "databases", STRICT_MODE_MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (12, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        // Миграция 0013 (§8 backoff refresh + статистика источников §5a.3):
        // мульти-табличный вариант поколоночного применения — целевая таблица
        // разбирается из каждого ALTER-оператора, существующие колонки
        // пропускаются, несовместимый тип — ошибка старта.
        let has_refresh_backoff: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=13)",
            [],
            |row| row.get(0),
        )?;
        if !has_refresh_backoff {
            apply_add_column_migration_set(&transaction, REFRESH_BACKOFF_MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (13, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        //++agent TASK-225 [26.09.2026] ревью-2 N-1
        // Миграция 0014 (флаг расшифрованных mask-токенов на контексте
        // вызова): та же поколоночная стратегия.
        let has_mask_token_flag: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=14)",
            [],
            |row| row.get(0),
        )?;
        if !has_mask_token_flag {
            apply_add_column_migration(&transaction, "call_contexts", MASK_TOKEN_FLAG_MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (14, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        // Миграция 0015 (раздел E): класс metadata-bypass → no-mask.
        // Пересборка tool_classifications с новым CHECK и перевод
        // снимков режимов в policies.tools_json — в той же
        // IMMEDIATE-транзакции, идемпотентна (помечена версией).
        let has_no_mask_rename: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=15)",
            [],
            |row| row.get(0),
        )?;
        if !has_no_mask_rename {
            transaction.execute_batch(NO_MASK_RENAME_MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (15, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        // Миграция 0016 (раздел O2): отображаемые координаты базы.
        // Идентичность — точный ключ `instance_id` (`ras:`/`gen:`),
        // координатных индексов и сравнений нет.
        let has_database_identity: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=16)",
            [],
            |row| row.get(0),
        )?;
        if !has_database_identity {
            apply_add_column_migration(&transaction, "databases", DATABASE_IDENTITY_MIGRATION)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (16, ?1)",
                [Utc::now().to_rfc3339()],
            )?;
        }
        // Миграция 0017, фаза 2 (в основной транзакции): колонка аудита и
        // таблица доступов. Гард — фактическое состояние схемы, а не запись
        // schema_migrations: база с чужой записью version=17 от ранней
        // сборки (таблицы нет) достраивается, а не застревает наполовину.
        // Колонка аудита применяется поколоночно и идемпотентна —
        // вызывается всегда; таблица и миграционная выдача — только при её
        // отсутствии. Действующие Viewer получают все существующие базы —
        // иначе обновление молча отняло бы им выдачу; доступ новых баз
        // дальше выдаётся только явно. granted_by=NULL — выдала миграция,
        // а не администратор.
        apply_add_column_migration(
            &transaction,
            "audit_events",
            migration_section(DATABASE_ACCESS_MIGRATION, "AUDIT-COLUMN")?,
        )?;
        let has_database_access: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master
             WHERE type='table' AND name='user_database_access')",
            [],
            |row| row.get(0),
        )?;
        if !has_database_access {
            transaction.execute_batch(migration_section(
                DATABASE_ACCESS_MIGRATION,
                "ACCESS-TABLE",
            )?)?;
            transaction.execute(
                "INSERT OR IGNORE INTO user_database_access(user_id, database_id, granted_by, granted_at)
                 SELECT u.id, d.id, NULL, ?1 FROM users u CROSS JOIN databases d WHERE u.role='Viewer'",
                [Utc::now().to_rfc3339()],
            )?;
        }
        transaction.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (17, ?1)",
            [Utc::now().to_rfc3339()],
        )?;
        //++agent TASK-225
        transaction.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (5, ?1)",
            [Utc::now().to_rfc3339()],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (4, ?1)",
            [Utc::now().to_rfc3339()],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (3, ?1)",
            [Utc::now().to_rfc3339()],
        )?;
        //++agent TASK-221
        transaction.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, ?1)",
            [Utc::now().to_rfc3339()],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (2, ?1)",
            [Utc::now().to_rfc3339()],
        )?;
        let user_count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
        if user_count == 0 {
            let now = Utc::now().to_rfc3339();
            transaction.execute(
                "INSERT INTO users(id, normalized_login, display_login, password_hash, role, status, auth_epoch, created_at, updated_at)
                 VALUES (?1, 'admin', 'Admin', NULL, 'SuperAdmin', 'active', 0, ?2, ?2)",
                params![Uuid::new_v4().to_string(), now],
            )?;
        }
        transaction.commit()?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Executes one short serialized operation. Adapters must never persist raw
    /// business values through this escape hatch.
    pub fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        operation(&mut connection)
    }

    //++agent TASK-225 [26.09.2026] O2
    /// Резолюция записи базы — только точное совпадение `instance_id`:
    /// ключ есть → та же запись; ключа нет → новая `unconfigured` запись.
    /// Координатных фолбэков, нормализации и переносов generated→ras нет:
    /// склейка баз исключена по построению, а переход ключа создаёт
    /// отдельную запись (настройки переносятся export/import).
    ///
    /// Возвращает (id записи, настройки, создана ли в этом вызове).
    pub fn ensure_database(
        &self,
        identity: &DatabaseIdentity,
    ) -> rusqlite::Result<(Uuid, DatabaseSettings, bool)> {
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some((database_id, settings)) = find_database(&transaction, identity)? {
                transaction.commit()?;
                return Ok((database_id, settings, false));
            }
            let database_id = Uuid::new_v4();
            insert_database(&transaction, database_id, identity)?;
            let settings = load_database(&transaction, database_id)?.expect("database inserted");
            transaction.commit()?;
            Ok((database_id, settings, true))
        })
    }

    /// Посадка записи с заданным id и ключом — миграция deployment-записей
    /// и тестовые фикстуры. Существующая запись не трогается: ключ не
    /// перепривязывается (точный матч — единственная семантика).
    pub fn insert_database(
        &self,
        database_id: Uuid,
        identity: &DatabaseIdentity,
    ) -> rusqlite::Result<DatabaseSettings> {
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if load_database(&transaction, database_id)?.is_none() {
                insert_database(&transaction, database_id, identity)?;
            }
            let settings = load_database(&transaction, database_id)?.expect("database inserted");
            transaction.commit()?;
            Ok(settings)
        })
    }

    /// Read-only резолюция записи по ключу (без создания) — для
    /// internal-экспорта и read-путей.
    pub fn lookup_database(
        &self,
        identity: &DatabaseIdentity,
    ) -> rusqlite::Result<Option<(Uuid, DatabaseSettings)>> {
        self.with_connection(|connection| find_database(connection, identity))
    }
    //++agent TASK-225

    pub fn set_database_mode(
        &self,
        database_id: Uuid,
        mode: DatabaseMode,
    ) -> rusqlite::Result<bool> {
        self.with_connection(|connection| {
            Ok(connection.execute(
                "UPDATE databases SET mode=?2, updated_at=?3 WHERE id=?1",
                params![
                    database_id.to_string(),
                    mode.as_str(),
                    Utc::now().to_rfc3339()
                ],
            )? == 1)
        })
    }

    pub fn set_tool_classification(
        &self,
        database_id: Uuid,
        tool_name: &str,
        class: ToolClass,
        reviewer: &str,
    ) -> rusqlite::Result<()> {
        if tool_name.is_empty()
            || tool_name.len() > 128
            || reviewer.is_empty()
            || reviewer.len() > 128
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        self.with_connection(|connection| {
            //++agent TASK-225 [25.09.2026]
            // Решение администратора снимает auto_added=0 и сохраняет
            // счётчик отказов/first_seen_at (спека §7): INSERT ветвь —
            // свежая строка без истории отказов; ON CONFLICT ветвь —
            // denied_count/first_seen_at/last_denied_at не трогаем.
            //++agent TASK-225
            connection.execute(
                "INSERT INTO tool_classifications(database_id,tool_name,class,reviewer,updated_at,auto_added)
                 VALUES (?1,?2,?3,?4,?5,0)
                 ON CONFLICT(database_id,tool_name) DO UPDATE SET class=excluded.class,reviewer=excluded.reviewer,updated_at=excluded.updated_at,auto_added=0",
                params![database_id.to_string(), tool_name, class.as_str(), reviewer, Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })
    }

    pub fn install_policy(
        &self,
        database_id: Uuid,
        version: i64,
        rules: &[PolicyRule],
    ) -> rusqlite::Result<String> {
        if version < 1 || rules.len() > 1_000 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        for rule in rules {
            if rule.pattern.is_empty()
                || rule.pattern.len() > 1024
                || rule.category.is_empty()
                || rule.category.len() > 32
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            if rule.selector == RuleSelector::Regex && regex::Regex::new(&rule.pattern).is_err() {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let policy_id = Uuid::new_v4().to_string();
            let now = Utc::now().to_rfc3339();
            //++agent TASK-225 [26.09.2026]
            // §2.2: частичный уникальный индекс одной активной версии —
            // старая снимается ДО вставки новой, иначе INSERT упирается в
            // индекс (INSERT до retire не проходит при непустом active).
            //++agent TASK-225
            transaction.execute("UPDATE policies SET status='retired' WHERE id=(SELECT active_policy_id FROM databases WHERE id=?1)", [database_id.to_string()])?;
            transaction.execute(
                "INSERT INTO policies(id,database_id,version,status,created_at) VALUES (?1,?2,?3,'active',?4)",
                params![policy_id, database_id.to_string(), version, now],
            )?;
            for rule in rules {
                transaction.execute(
                    "INSERT INTO policy_rules(id,policy_id,selector_kind,selector_value,action,category,priority,enabled,created_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,1,?8)",
                    params![Uuid::new_v4().to_string(), policy_id, selector_name(rule.selector), rule.pattern,
                        action_name(rule.action), rule.category, rule.priority, now],
                )?;
            }
            transaction.execute(
                "UPDATE databases SET active_policy_id=?2,updated_at=?3 WHERE id=?1",
                params![database_id.to_string(), policy_id, now],
            )?;
            transaction.commit()?;
            Ok(policy_id)
        })
    }

    pub fn set_dictionary_config(
        &self,
        database_id: Uuid,
        mode: &str,
        selectors: &[Value],
    ) -> rusqlite::Result<()> {
        if !matches!(mode, "all" | "part")
            || selectors.len() > 100
            || !selectors.iter().all(valid_dictionary_selector)
            || (mode == "all"
                && (selectors.len() != 1
                    || selectors[0].get("source_path").and_then(Value::as_str) != Some("*")))
            || (mode == "part"
                && selectors.iter().any(|selector| {
                    selector.get("source_path").and_then(Value::as_str) == Some("*")
                }))
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO dictionary_configs(id,database_id,mode,source_paths_json,filter_ast_json,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(database_id) DO UPDATE SET mode=excluded.mode,source_paths_json=excluded.source_paths_json,
                 filter_ast_json=excluded.filter_ast_json,updated_at=excluded.updated_at",
                params![Uuid::new_v4().to_string(), database_id.to_string(), mode,
                    serde_json::to_string(selectors).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    Option::<String>::None,
                    Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })
    }

    pub fn database_settings(
        &self,
        database_id: Uuid,
    ) -> rusqlite::Result<Option<DatabaseSettings>> {
        self.with_connection(|connection| load_database(connection, database_id))
    }

    pub fn tool_class(&self, database_id: Uuid, tool_name: &str) -> rusqlite::Result<ToolClass> {
        self.with_connection(|connection| {
            let class: Option<String> = connection
                .query_row(
                    "SELECT class FROM tool_classifications WHERE database_id=?1 AND tool_name=?2",
                    params![database_id.to_string(), tool_name],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(class
                .as_deref()
                .and_then(|value| ToolClass::try_from(value).ok())
                .unwrap_or(ToolClass::DenyPendingReview))
        })
    }

    pub fn policy_rules(&self, policy_id: Option<&str>) -> rusqlite::Result<Vec<PolicyRule>> {
        let Some(policy_id) = policy_id else {
            return Ok(Vec::new());
        };
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT selector_kind, selector_value, action, category, priority, id
                 FROM policy_rules WHERE policy_id=?1 AND enabled=1 ORDER BY priority, id",
            )?;
            let rules = statement
                .query_map([policy_id], read_policy_rule)?
                .collect();
            rules
        })
    }

    pub fn active_policy(
        &self,
        database_id: Uuid,
        policy_id: &str,
    ) -> rusqlite::Result<Option<(i64, Vec<PolicyRule>)>> {
        self.with_connection(|connection| {
            let version = connection
                .query_row(
                    "SELECT version FROM policies WHERE id=?1 AND database_id=?2 AND status='active'",
                    params![policy_id, database_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            let Some(version) = version else {
                return Ok(None);
            };
            let mut statement = connection.prepare(
                "SELECT selector_kind,selector_value,action,category,priority,id
                 FROM policy_rules WHERE policy_id=?1 AND enabled=1 ORDER BY priority,id",
            )?;
            let rules = statement
                .query_map([policy_id], read_policy_rule)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Some((version, rules)))
        })
    }

    pub fn load_history(
        &self,
        database_id: Uuid,
        chat_id: &str,
        call_id: Uuid,
    ) -> rusqlite::Result<Option<StoredHistory>> {
        self.with_connection(|connection| {
            load_history_from(connection, database_id, chat_id, call_id)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write_history(
        &self,
        database_id: Uuid,
        chat_id: &str,
        call_id: Uuid,
        tool_name: &str,
        outcome: &str,
        public_result: &Value,
        report: &Value,
        policy_version: i64,
        mask_reasons: &[String],
        history_ttl_seconds: u64,
        mapping_batch_id: Option<Uuid>,
        correlation_id: Uuid,
        //++agent TASK-225 [26.09.2026] §6.1: детальная запись.
        detail: Option<&HistoryDetail>,
        //++agent TASK-225
    ) -> rusqlite::Result<HistoryWrite> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let unscoped_exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM unscoped_terminal_events WHERE call_id=?1)",
                [call_id.to_string()],
                |row| row.get(0),
            )?;
            if unscoped_exists {
                transaction.commit()?;
                return Ok(HistoryWrite::Conflict);
            }
            let matching_call_count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM history WHERE call_id=?1",
                [call_id.to_string()],
                |row| row.get(0),
            )?;
            if matching_call_count > 1 {
                transaction.commit()?;
                return Ok(HistoryWrite::Conflict);
            }
            if matching_call_count == 1 {
                let existing_scope: (String, String) = transaction.query_row(
                    "SELECT database_id,chat_id FROM history WHERE call_id=?1",
                    [call_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                if existing_scope != (database_id.to_string(), chat_id.to_owned()) {
                    transaction.commit()?;
                    return Ok(HistoryWrite::Conflict);
                }
                let existing = load_history_from(&transaction, database_id, chat_id, call_id)?
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                transaction.commit()?;
                return Ok(HistoryWrite::Existing(existing));
            }
            let id = Uuid::new_v4();
            let created_at = Utc::now();
            let expires_at = created_at + Duration::seconds(history_ttl_seconds.min(i64::MAX as u64) as i64);
            transaction.execute(
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,mask_reasons_json,public_result_json,report_json,created_at,expires_at,mapping_batch_id,mask_detail_json,field_sources_json,policy_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                params![id.to_string(), database_id.to_string(), chat_id, call_id.to_string(), tool_name, outcome,
                    policy_version,
                    serde_json::to_string(mask_reasons).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    serde_json::to_string(public_result).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    serde_json::to_string(report).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    created_at.to_rfc3339(), expires_at.to_rfc3339(), mapping_batch_id.map(|id| id.to_string()),
                    //++agent TASK-225 [26.09.2026] §6.1
                    detail.and_then(|d| d.mask_detail_json),
                    detail.and_then(|d| d.field_sources_json),
                    detail.and_then(|d| d.policy_id).map(|id| id.to_string())],
                //++agent TASK-225
            )?;
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,chat_id,history_id,outcome,code,correlation_id,created_at)
                 VALUES ('service',NULL,'call.finalize',?1,?2,?3,'success',NULL,?4,?5)",
                params![database_id.to_string(), chat_id, id.to_string(), correlation_id.to_string(), created_at.to_rfc3339()],
            )?;
            transaction.commit()?;
            Ok(HistoryWrite::Inserted(id))
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write_scoped_terminal(
        &self,
        database_id: Uuid,
        chat_id: &str,
        call_id: Uuid,
        tool_name: &str,
        error_code: &str,
        public_result: &Value,
        report: &Value,
        history_ttl_seconds: u64,
        correlation_id: Uuid,
    ) -> rusqlite::Result<TerminalWrite> {
        //++agent TASK-225 [25.09.2026]
        // Тело вынесено в write_scoped_terminal_tx — та же tx-логика
        // переиспользуется write_tool_pending_review (учёт классификации
        // и запись отказа живут в одной IMMEDIATE-транзакции, спека §7).
        //++agent TASK-225
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let write = write_scoped_terminal_tx(
                &transaction,
                database_id,
                chat_id,
                call_id,
                tool_name,
                error_code,
                public_result,
                report,
                history_ttl_seconds,
                correlation_id,
            )?;
            transaction.commit()?;
            Ok(write)
        })
    }

    //++agent TASK-225 [25.09.2026]
    /// Отказ `deny-pending-review` (спека §7): в одной IMMEDIATE-транзакции
    /// фиксирует terminal-запись истории И учёт инструмента в
    /// `tool_classifications` (новое имя → строка auto_added=1 с
    /// first_seen_at/denied_count; повторный отказ → denied_count+1).
    /// Сбой учёта не меняет решение — запись отказа в историю коммитится
    /// в любом случае (ошибка логируется, не пробрасывается).
    #[allow(clippy::too_many_arguments)]
    pub fn write_tool_pending_review(
        &self,
        database_id: Uuid,
        chat_id: &str,
        call_id: Uuid,
        tool_name: &str,
        public_result: &Value,
        report: &Value,
        history_ttl_seconds: u64,
        correlation_id: Uuid,
    ) -> rusqlite::Result<TerminalWrite> {
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let write = write_scoped_terminal_tx(
                &transaction,
                database_id,
                chat_id,
                call_id,
                tool_name,
                "TOOL_PENDING_REVIEW",
                public_result,
                report,
                history_ttl_seconds,
                correlation_id,
            )?;
            if let Err(error) = account_pending_review_denial(
                &transaction,
                database_id,
                chat_id,
                tool_name,
                correlation_id,
                write,
            ) {
                tracing::warn!(
                    tool_name = %tool_name,
                    error = %error,
                    "tool auto-classification accounting failed; denial kept"
                );
            }
            transaction.commit()?;
            Ok(write)
        })
    }
    //++agent TASK-225

    pub fn write_unscoped_terminal(
        &self,
        call_id: Uuid,
        correlation_id: Uuid,
        tool_name: &str,
        error_code: &str,
        retention_seconds: u64,
    ) -> rusqlite::Result<TerminalWrite> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let scoped_exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM history WHERE call_id=?1)",
                [call_id.to_string()],
                |row| row.get(0),
            )?;
            if scoped_exists {
                transaction.commit()?;
                return Ok(TerminalWrite::Conflict);
            }
            let existing = transaction
                .query_row(
                    "SELECT correlation_id,tool_name,error_code
                     FROM unscoped_terminal_events WHERE call_id=?1",
                    [call_id.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((stored_correlation, stored_tool, stored_code)) = existing {
                transaction.commit()?;
                return Ok(if stored_correlation == correlation_id.to_string()
                    && stored_tool == tool_name
                    && stored_code == error_code
                {
                    TerminalWrite::Existing
                } else {
                    TerminalWrite::Conflict
                });
            }
            let id = Uuid::new_v4();
            let created_at = Utc::now();
            let expires_at = created_at
                + Duration::seconds(retention_seconds.min(i64::MAX as u64) as i64);
            transaction.execute(
                "INSERT INTO unscoped_terminal_events(id,call_id,correlation_id,tool_name,error_code,created_at,expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id.to_string(),
                    call_id.to_string(),
                    correlation_id.to_string(),
                    tool_name,
                    error_code,
                    created_at.to_rfc3339(),
                    expires_at.to_rfc3339()
                ],
            )?;
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,chat_id,history_id,outcome,code,correlation_id,created_at)
                 VALUES ('service',NULL,'call.terminal.unscoped',NULL,NULL,NULL,'denied',?1,?2,?3)",
                params![error_code, correlation_id.to_string(), created_at.to_rfc3339()],
            )?;
            transaction.commit()?;
            Ok(TerminalWrite::Inserted)
        })
    }

    pub fn audit_denial(
        &self,
        database_id: Uuid,
        chat_id: &str,
        correlation_id: Uuid,
        code: &str,
    ) -> rusqlite::Result<()> {
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO audit_events(actor_kind,action,database_id,chat_id,outcome,code,correlation_id,created_at)
                 VALUES ('service','call.denied',?1,?2,'denied',?3,?4,?5)",
                params![database_id.to_string(), chat_id, code, correlation_id.to_string(), Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })
    }

    pub fn cleanup_history(&self, limit: usize) -> rusqlite::Result<usize> {
        self.with_connection(|connection| {
            //++agent TASK-224 [08.10.2026] итерация 4: контексты вызовов —
            // тот же жизненный цикл, что у истории.
            connection.execute(
                "DELETE FROM call_contexts WHERE expires_at <= ?1",
                [Utc::now().to_rfc3339()],
            )?;
            //--agent TASK-224
            connection.execute(
            "DELETE FROM history WHERE id IN (SELECT id FROM history WHERE expires_at <= ?1 ORDER BY expires_at LIMIT ?2)",
            params![Utc::now().to_rfc3339(), limit.min(500) as i64],
        )})
    }

    //++agent TASK-224 [08.10.2026] итерация 4
    /// Контекст вызова записывается на preflight; `title` приходит уже
    /// зачищенным engine-ом (secret-cut до durable-записи, ревью R1).
    /// Повторный preflight того же call_id — идемпотентный no-op
    /// (first-write-wins): отчёт ретрая должен
    /// совпадать с первым, иначе denial-запись ломала бы equality в
    /// write_scoped_terminal. TTL — effective history TTL (min истории/маппинга).
    pub fn write_call_context(
        &self,
        call_id: Uuid,
        database_id: Uuid,
        chat_id: &str,
        tool_name: &str,
        title: Option<&str>,
        ttl_seconds: u64,
    ) -> rusqlite::Result<()> {
        self.with_connection(|connection| {
            let now = Utc::now();
            connection.execute(
                "INSERT INTO call_contexts(call_id,database_id,chat_id,tool_name,title,created_at,expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(call_id) DO NOTHING",
                params![
                    call_id.to_string(),
                    database_id.to_string(),
                    chat_id,
                    tool_name,
                    title,
                    now.to_rfc3339(),
                    (now + Duration::seconds(ttl_seconds.min(i64::MAX as u64) as i64)).to_rfc3339()
                ],
            )?;
            Ok(())
        })
    }

    /// Текст запроса/описание вызова для заголовка отчёта истории; просроченные
    /// контексты не возвращаются (их TTL тот же, что у записи истории).
    pub fn call_context_text(&self, call_id: Uuid) -> rusqlite::Result<Option<String>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT title FROM call_contexts WHERE call_id=?1 AND expires_at>?2",
                    params![call_id.to_string(), Utc::now().to_rfc3339()],
                    |row| row.get(0),
                )
                .optional()
        })
    }

    //++agent TASK-225 [26.09.2026] ревью-2 N-1
    /// Флаг «preflight расшифровал ≥1 mask-токен» на контексте вызова.
    /// Возвращает false, если UPDATE не затронул строку (контекст не
    /// записан/просрочен): вызывающий при резолве токенов обязан
    /// отказаться fail-closed — без записанного флага finalize не узнает
    /// о необходимости гасить свободный текст ошибки.
    pub fn mark_call_context_mask_tokens(&self, call_id: Uuid) -> rusqlite::Result<bool> {
        self.with_connection(|connection| {
            Ok(connection.execute(
                "UPDATE call_contexts SET had_mask_tokens=1 WHERE call_id=?1",
                params![call_id.to_string()],
            )? > 0)
        })
    }

    /// Чтение флага расшифрованных mask-токенов. В отличие от title,
    /// флаг читается без TTL-фильтра: истёкший, но ещё не вытертый
    /// контекст всё равно говорит правду — flag=1 значит «токены
    /// резолвились, текст гасить», а его отсутствие при истёкшем TTL
    /// заставило бы принимать «нет записи» за «нет токенов».
    pub fn call_context_mask_tokens(&self, call_id: Uuid) -> rusqlite::Result<Option<bool>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT had_mask_tokens FROM call_contexts WHERE call_id=?1",
                    params![call_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map(|flag| flag.map(|value| value != 0))
        })
    }
    //++agent TASK-225

    /// Startup-очистка: mapping store живёт в RAM, поэтому после рестарта ни
    /// одна запись истории не раскрывается — таблицы history и call_contexts
    /// очищаются полностью. Ошибка fail-soft (maintenance tick доберёт).
    pub fn purge_ephemeral_history(&self) -> rusqlite::Result<()> {
        self.with_connection(|connection| {
            connection.execute("DELETE FROM history", [])?;
            connection.execute("DELETE FROM call_contexts", [])?;
            Ok(())
        })
    }
    //--agent TASK-224

    pub fn cleanup_unscoped_terminal(&self, limit: usize) -> rusqlite::Result<usize> {
        self.with_connection(|connection| {
            connection.execute(
                "DELETE FROM unscoped_terminal_events
                 WHERE id IN (SELECT id FROM unscoped_terminal_events
                              WHERE expires_at <= ?1 ORDER BY expires_at LIMIT ?2)",
                params![Utc::now().to_rfc3339(), limit.min(500) as i64],
            )
        })
    }

    pub fn cleanup_audit(&self, limit: usize) -> rusqlite::Result<usize> {
        self.with_connection(|connection| {
            let retention: i64 = connection.query_row(
                "SELECT audit_retention_seconds FROM service_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            let cutoff = Utc::now() - Duration::seconds(retention.max(1));
            connection.execute(
                "DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE created_at<=?1 ORDER BY created_at LIMIT ?2)",
                params![cutoff.to_rfc3339(), limit.min(500) as i64],
            )
        })
    }

    //++agent TASK-225 [26.09.2026]
    /// §5.1: ≤limit последних tool_result-записей с lineage — выборка
    /// сухого прогона B6.
    pub fn dry_run_records(
        &self,
        database_id: Uuid,
        limit: u32,
    ) -> rusqlite::Result<Vec<DryRunRecord>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id,created_at,tool_name,chat_id,call_id,public_result_json,
                        mapping_batch_id,field_sources_json,mask_detail_json
                 FROM history
                 WHERE database_id=?1 AND outcome='tool_result'
                   AND field_sources_json IS NOT NULL
                 ORDER BY created_at DESC LIMIT ?2",
            )?;
            let rows =
                statement.query_map(params![database_id.to_string(), limit as i64], |row| {
                    let public: String = row.get(5)?;
                    Ok(DryRunRecord {
                        id: Uuid::parse_str(&row.get::<_, String>(0)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        created_at: row.get(1)?,
                        tool_name: row.get(2)?,
                        chat_id: row.get(3)?,
                        call_id: Uuid::parse_str(&row.get::<_, String>(4)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        public_result: serde_json::from_str(&public)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        mapping_batch_id: row
                            .get::<_, Option<String>>(6)?
                            .and_then(|v| Uuid::parse_str(&v).ok()),
                        field_sources: row.get(7)?,
                        mask_detail: row.get(8)?,
                    })
                })?;
            rows.collect()
        })
    }

    //++agent TASK-225 [26.09.2026]
    /// §5.1: есть ли вообще записи `tool_result` — различает причины
    /// пустого сухого прогона (`no_records` / `no_lineage`).
    pub fn has_tool_result_records(&self, database_id: Uuid) -> rusqlite::Result<bool> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM history
                 WHERE database_id=?1 AND outcome='tool_result')",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
    }
    //++agent TASK-225

    /// B9/§6.3: запись истории для отчёта причин — без фильтра срока
    /// (истёкшая отличается кодом HISTORY_EXPIRED), без chat-scope
    /// (role-based доступ на уровне API — как reveal).
    pub fn history_reasons_record(
        &self,
        history_id: Uuid,
    ) -> rusqlite::Result<Option<HistoryReasonsRow>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT database_id,expires_at,policy_version,policy_id,mask_detail_json,mask_reasons_json,report_json,tool_name
                     FROM history WHERE id=?1",
                    [history_id.to_string()],
                    |row| {
                        let report: String = row.get(6)?;
                        Ok(HistoryReasonsRow {
                            database_id: Uuid::parse_str(&row.get::<_, String>(0)?)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                            expires_at: row.get(1)?,
                            policy_version: row.get(2)?,
                            policy_id: row
                                .get::<_, Option<String>>(3)?
                                .and_then(|v| Uuid::parse_str(&v).ok()),
                            mask_detail_json: row.get(4)?,
                            mask_reasons_json: row.get(5)?,
                            report: serde_json::from_str(&report)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                            tool_name: row.get(7)?,
                        })
                    },
                )
                .optional()
        })
    }
    //++agent TASK-225

    pub fn history_for_reveal(
        &self,
        history_id: Uuid,
        database_id: Uuid,
        chat_id: &str,
    ) -> rusqlite::Result<Option<HistoryForReveal>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT report_json,mapping_batch_id FROM history
                 WHERE id=?1 AND database_id=?2 AND chat_id=?3 AND expires_at>?4",
                    params![
                        history_id.to_string(),
                        database_id.to_string(),
                        chat_id,
                        Utc::now().to_rfc3339()
                    ],
                    |row| {
                        let report: String = row.get(0)?;
                        let batch: Option<String> = row.get(1)?;
                        Ok(HistoryForReveal {
                            report: serde_json::from_str(&report)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                            mapping_batch_id: batch
                                .map(|value| {
                                    Uuid::parse_str(&value)
                                        .map_err(|_| rusqlite::Error::InvalidQuery)
                                })
                                .transpose()?,
                        })
                    },
                )
                .optional()
        })
    }
}

fn read_policy_rule(row: &rusqlite::Row<'_>) -> rusqlite::Result<PolicyRule> {
    let selector: String = row.get(0)?;
    let action: String = row.get(2)?;
    Ok(PolicyRule {
        selector: match selector.as_str() {
            "source_path" => RuleSelector::SourcePath,
            "name" => RuleSelector::Name,
            "type" => RuleSelector::Type,
            "dictionary" => RuleSelector::Dictionary,
            _ => RuleSelector::Regex,
        },
        pattern: row.get(1)?,
        action: match action.as_str() {
            "secret" => RuleAction::Secret,
            "mask" => RuleAction::Mask,
            _ => RuleAction::Keep,
        },
        category: row.get(3)?,
        priority: row.get(4)?,
        //++agent TASK-225 [26.09.2026] §6.1: id правила — ссылка причины.
        rule_id: Uuid::parse_str(&row.get::<_, String>(5)?).ok(),
    })
}

//++agent TASK-225 [26.09.2026] N
const DATABASE_COLUMNS: &str = "id,mode,mapping_ttl_seconds,history_ttl_seconds,active_policy_id,active_cache_version,strict_mode,instance_id,cluster_server,infobase_name";

fn database_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Uuid, DatabaseSettings)> {
    let id =
        Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let mode: String = row.get(1)?;
    Ok((
        id,
        DatabaseSettings {
            mode: DatabaseMode::try_from(mode.as_str())
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            mapping_ttl_seconds: row.get::<_, i64>(2)?.max(1) as u64,
            history_ttl_seconds: row.get::<_, i64>(3)?.max(1) as u64,
            active_policy_id: row.get(4)?,
            active_cache_version: row
                .get::<_, Option<i64>>(5)?
                .map(|value| value.max(0) as u64),
            strict_mode: row.get::<_, i64>(6)? != 0,
            instance_id: row.get(7)?,
            cluster_server: row.get(8)?,
            infobase_name: row.get(9)?,
        },
    ))
}

fn load_database(
    connection: &Connection,
    database_id: Uuid,
) -> rusqlite::Result<Option<DatabaseSettings>> {
    connection
        .query_row(
            &format!("SELECT {DATABASE_COLUMNS} FROM databases WHERE id=?1"),
            [database_id.to_string()],
            database_row,
        )
        .optional()
        .map(|row| row.map(|(_, settings)| settings))
}

//++agent TASK-225 [26.09.2026] O2
fn insert_database(
    connection: &Connection,
    database_id: Uuid,
    identity: &DatabaseIdentity,
) -> rusqlite::Result<()> {
    let now = Utc::now().to_rfc3339();
    connection.execute(
        "INSERT INTO databases(id, instance_id, display_label, mode,
            cluster_server, infobase_name, created_at, updated_at)
         VALUES (?1, ?2, ?3, 'unconfigured', ?4, ?5, ?6, ?6)",
        params![
            database_id.to_string(),
            identity.instance_id,
            identity.infobase_name,
            identity.cluster_server,
            identity.infobase_name,
            now
        ],
    )?;
    for (tool, class) in default_tool_classes() {
        connection.execute(
            "INSERT INTO tool_classifications(database_id, tool_name, class, reviewer, updated_at)
             VALUES (?1, ?2, ?3, 'built-in-v1', ?4)",
            params![database_id.to_string(), tool, class.as_str(), now],
        )?;
    }
    Ok(())
}

/// Поиск записи — только точное совпадение `instance_id` (раздел O2):
/// ключ непрозрачен, координатных фолбэков и нормализации нет.
fn find_database(
    connection: &Connection,
    identity: &DatabaseIdentity,
) -> rusqlite::Result<Option<(Uuid, DatabaseSettings)>> {
    connection
        .query_row(
            &format!("SELECT {DATABASE_COLUMNS} FROM databases WHERE instance_id=?1"),
            [&identity.instance_id],
            database_row,
        )
        .optional()
}
//++agent TASK-225

fn load_history_from(
    connection: &Connection,
    database_id: Uuid,
    chat_id: &str,
    call_id: Uuid,
) -> rusqlite::Result<Option<StoredHistory>> {
    connection
        .query_row(
            "SELECT id,public_result_json FROM history
         WHERE database_id=?1 AND chat_id=?2 AND call_id=?3 AND expires_at>?4",
            params![
                database_id.to_string(),
                chat_id,
                call_id.to_string(),
                Utc::now().to_rfc3339()
            ],
            |row| {
                let id: String = row.get(0)?;
                let public_result: String = row.get(1)?;
                Ok(StoredHistory {
                    id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    public_result: serde_json::from_str(&public_result)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                })
            },
        )
        .optional()
}

fn default_tool_classes() -> [(&'static str, ToolClass); 6] {
    [
        ("execute_query", ToolClass::DataMask),
        ("find_references_to_object", ToolClass::DataMask),
        ("get_object_by_link", ToolClass::DataMask),
        ("get_metadata", ToolClass::NoMask),
        ("get_access_rights", ToolClass::NoMask),
        ("get_link_of_object", ToolClass::NoMask),
    ]
}

fn selector_name(selector: RuleSelector) -> &'static str {
    match selector {
        RuleSelector::SourcePath => "source_path",
        RuleSelector::Name => "name",
        RuleSelector::Type => "type",
        RuleSelector::Dictionary => "dictionary",
        RuleSelector::Regex => "regex",
    }
}

fn action_name(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Keep => "keep",
        RuleAction::Mask => "mask",
        RuleAction::Secret => "secret",
    }
}

fn valid_dictionary_selector(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let path = object
        .get("source_path")
        .and_then(Value::as_str)
        .unwrap_or("");
    let category = object.get("category").and_then(Value::as_str).unwrap_or("");
    !path.is_empty()
        && path.len() <= 512
        && !category.is_empty()
        && category.len() <= 32
        && object
            .keys()
            .all(|key| matches!(key.as_str(), "source_path" | "category" | "filter_ast"))
        && object
            .get("filter_ast")
            .is_none_or(|value| value.is_null() || valid_filter_ast(value))
}

pub(crate) fn valid_filter_ast(value: &Value) -> bool {
    let mut nodes = 0usize;
    valid_filter_ast_node(value, 0, &mut nodes)
}

fn valid_filter_ast_node(value: &Value, depth: usize, nodes: &mut usize) -> bool {
    if depth > 16 {
        return false;
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > 1024 {
        return false;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    let Some(operator) = object.get("op").and_then(Value::as_str) else {
        return false;
    };
    match operator {
        "and" | "or" => {
            object.len() == 2
                && object
                    .get("args")
                    .and_then(Value::as_array)
                    .is_some_and(|args| {
                        !args.is_empty()
                            && args.len() <= 32
                            && args
                                .iter()
                                .all(|item| valid_filter_ast_node(item, depth + 1, nodes))
                    })
        }
        "not" => {
            object.len() == 2
                && object
                    .get("arg")
                    .is_some_and(|item| valid_filter_ast_node(item, depth + 1, nodes))
        }
        "eq" | "ne" => {
            if object.len() != 3 {
                return false;
            }
            object.get("field").is_some_and(valid_filter_field)
                && object.get("value").is_some_and(|operand| {
                    valid_filter_scalar(operand) && valid_filter_operand(operand)
                })
        }
        "in" => {
            if object.len() != 3 {
                return false;
            }
            object.get("field").is_some_and(valid_filter_field)
                && object.get("values").is_some_and(|values| {
                    values.as_array().is_some_and(|items| {
                        items.len() <= 100 && items.iter().all(valid_filter_scalar)
                    }) && valid_filter_operand(values)
                })
        }
        _ => false,
    }
}

fn valid_filter_field(value: &Value) -> bool {
    let Some(field) = value.as_str() else {
        return false;
    };
    if field.is_empty() || field.len() > 256 {
        return false;
    }
    let mut characters = field.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_alphabetic())
        && characters.all(|character| character == '_' || character.is_alphanumeric())
}

fn valid_filter_scalar(value: &Value) -> bool {
    value.is_null()
        || value.is_boolean()
        || value.is_number()
        || value.as_str().is_some_and(|text| text.len() <= 1024)
}

//++agent TASK-221 [23.09.2026 23:05:00]
/// C2-04 spec bound: serialized operand payload ОДНОГО узла ≤4096 байт —
/// `value` для eq/ne, массив `values` для in. Per-scalar bound один
/// недостаточен: `in` из 100 строк по 1024B формально валиден, а operand
/// выходит за 4KiB. Value уже распарсен — `to_string` не может упасть.
//--agent TASK-221
fn valid_filter_operand(value: &Value) -> bool {
    serde_json::to_string(value).is_ok_and(|json| json.len() <= 4096)
}

//++agent TASK-225 [25.09.2026]
/// Тело `write_scoped_terminal` на уровне открытой транзакции — позволяет
/// `write_tool_pending_review` дописать учёт классификации в ту же tx.
#[allow(clippy::too_many_arguments)]
fn write_scoped_terminal_tx(
    transaction: &rusqlite::Transaction<'_>,
    database_id: Uuid,
    chat_id: &str,
    call_id: Uuid,
    tool_name: &str,
    error_code: &str,
    public_result: &Value,
    report: &Value,
    history_ttl_seconds: u64,
    correlation_id: Uuid,
) -> rusqlite::Result<TerminalWrite> {
    let unscoped_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM unscoped_terminal_events WHERE call_id=?1)",
        [call_id.to_string()],
        |row| row.get(0),
    )?;
    if unscoped_exists {
        return Ok(TerminalWrite::Conflict);
    }
    let existing = transaction
        .query_row(
            "SELECT h.database_id,h.chat_id,h.tool_name,h.outcome,
                    h.public_result_json,h.report_json,a.code,a.correlation_id
             FROM history h
             LEFT JOIN audit_events a ON a.history_id=h.id AND a.action='call.denied'
             WHERE h.call_id=?1",
            [call_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?;
    let matching_call_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM history WHERE call_id=?1",
        [call_id.to_string()],
        |row| row.get(0),
    )?;
    if matching_call_count > 1 {
        return Ok(TerminalWrite::Conflict);
    }
    let public_json =
        serde_json::to_string(public_result).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let report_json = serde_json::to_string(report).map_err(|_| rusqlite::Error::InvalidQuery)?;
    if let Some((
        stored_db,
        stored_chat,
        stored_tool,
        outcome,
        stored_public,
        stored_report,
        code,
        correlation,
    )) = existing
    {
        let expected_correlation = correlation_id.to_string();
        return Ok(
            if stored_db == database_id.to_string()
                && stored_chat == chat_id
                && stored_tool == tool_name
                && outcome == "terminal_denial"
                && stored_public == public_json
                && stored_report == report_json
                && code.as_deref() == Some(error_code)
                && correlation.as_deref() == Some(expected_correlation.as_str())
            {
                TerminalWrite::Existing
            } else {
                TerminalWrite::Conflict
            },
        );
    }
    let id = Uuid::new_v4();
    let created_at = Utc::now();
    let expires_at =
        created_at + Duration::seconds(history_ttl_seconds.min(i64::MAX as u64) as i64);
    let reasons = serde_json::to_string(&[format!("service:terminal:{error_code}")])
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    transaction.execute(
        "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,mask_reasons_json,public_result_json,report_json,created_at,expires_at,mapping_batch_id)
         VALUES (?1,?2,?3,?4,?5,'terminal_denial',0,?6,?7,?8,?9,?10,NULL)",
        params![
            id.to_string(),
            database_id.to_string(),
            chat_id,
            call_id.to_string(),
            tool_name,
            reasons,
            public_json,
            report_json,
            created_at.to_rfc3339(),
            expires_at.to_rfc3339()
        ],
    )?;
    transaction.execute(
        "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,chat_id,history_id,outcome,code,correlation_id,created_at)
         VALUES ('service',NULL,'call.denied',?1,?2,?3,'denied',?4,?5,?6)",
        params![
            database_id.to_string(),
            chat_id,
            id.to_string(),
            error_code,
            correlation_id.to_string(),
            created_at.to_rfc3339()
        ],
    )?;
    Ok(TerminalWrite::Inserted)
}

/// Учёт отказа `deny-pending-review` в `tool_classifications` (спека §7):
/// `counted` — это новый отказ (Insert), а не идемпотентный ретрай
/// существующего call_id (Existing): повторная доставка не считается дважды.
/// Обновление предикатировано `class='deny-pending-review'` — не затирает
/// параллельно принятую классификацию администратора. Имя вне авто-алфавита
/// и превышение лимита 500 — отказ фиксируется в истории в любом случае,
/// а в учёте отражается только audit-событие со спец-кодом.
fn account_pending_review_denial(
    transaction: &rusqlite::Transaction<'_>,
    database_id: Uuid,
    chat_id: &str,
    tool_name: &str,
    correlation_id: Uuid,
    counted: TerminalWrite,
) -> rusqlite::Result<()> {
    let counted = counted == TerminalWrite::Inserted;
    let now = Utc::now().to_rfc3339();
    if !valid_auto_tool_name(tool_name) {
        if counted {
            audit_call_denied(
                transaction,
                database_id,
                chat_id,
                "TOOL_NAME_INVALID",
                correlation_id,
            )?;
        }
        return Ok(());
    }
    let existing: Option<String> = transaction
        .query_row(
            "SELECT class FROM tool_classifications WHERE database_id=?1 AND tool_name=?2",
            params![database_id.to_string(), tool_name],
            |row| row.get(0),
        )
        .optional()?;
    match existing.as_deref() {
        Some("deny-pending-review") if counted => {
            transaction.execute(
                "UPDATE tool_classifications
                 SET denied_count=denied_count+1, last_denied_at=?3
                 WHERE database_id=?1 AND tool_name=?2 AND class='deny-pending-review'",
                params![database_id.to_string(), tool_name, now],
            )?;
        }
        Some(_) => {}
        None => {
            let auto_count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM tool_classifications WHERE database_id=?1 AND auto_added=1",
                [database_id.to_string()],
                |row| row.get(0),
            )?;
            if auto_count >= 500 {
                if counted {
                    audit_call_denied(
                        transaction,
                        database_id,
                        chat_id,
                        "TOOL_AUTOADD_LIMIT",
                        correlation_id,
                    )?;
                }
            } else {
                transaction.execute(
                    "INSERT INTO tool_classifications(database_id,tool_name,class,reviewer,updated_at,auto_added,first_seen_at,denied_count,last_denied_at)
                     VALUES (?1,?2,'deny-pending-review',NULL,?3,1,?3,1,?3)",
                    params![database_id.to_string(), tool_name, now],
                )?;
            }
        }
    }
    Ok(())
}

/// Спека §7: имя инструмента для авто-регистрации ограничено
/// `[A-Za-z0-9_.:-]{1,128}` — сужение публичного набора, запрещающее
/// вставку управляющих/мусорных имён в справочник классификации.
fn valid_auto_tool_name(tool_name: &str) -> bool {
    !tool_name.is_empty()
        && tool_name.len() <= 128
        && tool_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

/// audit-событие отказа вызова (call.denied) внутри открытой транзакции —
/// зеркало `audit_denial`, но без подмены outcome по существующему ответу:
/// используется для спец-кодов TOOL_NAME_INVALID/TOOL_AUTOADD_LIMIT,
/// не привязанных к history-записи.
fn audit_call_denied(
    transaction: &rusqlite::Transaction<'_>,
    database_id: Uuid,
    chat_id: &str,
    code: &str,
    correlation_id: Uuid,
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,chat_id,history_id,outcome,code,correlation_id,created_at)
         VALUES ('service',NULL,'call.denied',?1,?2,NULL,'denied',?3,?4,?5)",
        params![
            database_id.to_string(),
            chat_id,
            code,
            correlation_id.to_string(),
            Utc::now().to_rfc3339()
        ],
    )?;
    Ok(())
}
//++agent TASK-225

//++agent TASK-225 [25.09.2026]
/// Поколоночное применение миграций вида `ALTER TABLE <table>
/// ADD COLUMN ...` (файлы 0011/0012): колонки, уже созданные
/// параллельной миграцией (порядок прихода миграций на merge не
/// гарантирован), пропускаются; колонка с несовпадающим типом —
/// ошибка запуска сервиса, а не тихий пропуск. Имя таблицы —
/// внутренняя константа вызова, не ввод пользователя.
fn apply_add_column_migration(
    transaction: &rusqlite::Transaction<'_>,
    table: &str,
    ddl: &str,
) -> rusqlite::Result<()> {
    let mut existing = std::collections::HashMap::new();
    {
        let mut statement = transaction.prepare(&format!(
            "SELECT name, type FROM pragma_table_info('{table}')"
        ))?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (name, declared_type) in rows {
            existing.insert(name, declared_type);
        }
    }
    for statement in ddl.split(';') {
        let statement = statement
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        // Форма оператора зафиксирована файлом миграции:
        // `ALTER TABLE <table> ADD COLUMN <name> <type> ...`
        let mut words = statement.split_whitespace();
        let column = words
            .find(|word| word.eq_ignore_ascii_case("column"))
            .and_then(|_| words.next())
            .ok_or(rusqlite::Error::InvalidQuery)?;
        let declared_type = words.next().ok_or(rusqlite::Error::InvalidQuery)?;
        match existing.get(column) {
            Some(actual) if !actual.eq_ignore_ascii_case(declared_type) => {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Some(_) => {}
            None => transaction.execute_batch(statement)?,
        }
    }
    Ok(())
}

/// Мульти-табличный вариант `apply_add_column_migration` (файл 0013):
/// целевая таблица разбирается из оператора `ALTER TABLE <table>
/// ADD COLUMN ...`, операторы группируются по таблице и применяются
/// поколоночно с теми же гарантиями (пропуск существующих, конфликт
/// типов — ошибка). Форма операторов зафиксирована файлом миграции.
fn apply_add_column_migration_set(
    transaction: &rusqlite::Transaction<'_>,
    ddl: &str,
) -> rusqlite::Result<()> {
    let mut grouped: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for statement in ddl.split(';') {
        let statement = statement
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        let mut words = statement.split_whitespace();
        if !words
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("alter"))
            || !words
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("table"))
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let table = words.next().ok_or(rusqlite::Error::InvalidQuery)?;
        grouped
            .entry(table.to_string())
            .or_default()
            .push(statement.to_string());
    }
    for (table, statements) in grouped {
        apply_add_column_migration(transaction, &table, &statements.join(";\n"))?;
    }
    Ok(())
}

/// Вырезает секцию `-- == NAME ==` из файла миграции, размеченного
/// такими маркерами (многофазные миграции вроде 0017). Отсутствие метки —
/// ошибка файла, а не пустая миграция.
fn migration_section<'a>(ddl: &'a str, name: &str) -> rusqlite::Result<&'a str> {
    let marker = format!("-- == {name} ==");
    let Some(start) = ddl.find(&marker) else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    let rest = &ddl[start + marker.len()..];
    let end = rest.find("-- ==").unwrap_or(rest.len());
    Ok(rest[..end].trim())
}

/// Миграция 0017, фаза 1: пересоздание `users`, когда её CHECK не знает
/// ступень SuperAdmin (БД, созданные до 0017). Свежая схема 0001 уже
/// содержит новый CHECK, таблица может ещё не существовать — обе ситуации
/// пропускаются по тексту sqlite_master. `foreign_keys` выключается вне
/// транзакции (SQLite игнорирует переключение внутри), после коммита
/// сверяется `pragma_foreign_key_check`: сиротские ссылки — ошибка старта.
fn migrate_users_role_check(connection: &mut Connection) -> rusqlite::Result<()> {
    let legacy: bool = connection
        .query_row(
            "SELECT sql NOT LIKE '%SuperAdmin%' FROM sqlite_master
             WHERE type='table' AND name='users'",
            [],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(false);
    if !legacy {
        return Ok(());
    }
    connection.pragma_update(None, "foreign_keys", "OFF")?;
    let outcome = (|| {
        let transaction =
            connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(migration_section(
            DATABASE_ACCESS_MIGRATION,
            "USERS-RECREATE",
        )?)?;
        transaction.commit()
    })();
    // Реальная ошибка миграции важнее сбоя восстановления pragma —
    // возвращаем её первой. Но если миграция прошла, а FK включить
    // не удалось — это ошибка старта: работать с молча отключёнными
    // каскадами недопустимо.
    if let Err(pragma_error) = connection.pragma_update(None, "foreign_keys", "ON") {
        if outcome.is_ok() {
            return Err(pragma_error);
        }
        tracing::warn!(event = "foreign_keys_restore_failed", error = %pragma_error);
    }
    outcome?;
    let violations: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if violations > 0 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

/// Применение миграции 0010 (версии настройки, spec §2.2–§2.3):
/// часть до метки `-- == POST-DATA ==` — поколоночные ALTER (любых
/// таблиц — переиспользуется `apply_add_column_migration_set`) и
/// CREATE TABLE/INDEX как есть; затем перенос данных §2.3
/// (`migrate_setup_data`); затем операторы после метки — частичные
/// уникальные индексы, которым нужна уже нормализованная таблица
/// `policies`. Всё — в открытой IMMEDIATE-транзакции initialize.
fn apply_setup_versions_migration(
    transaction: &rusqlite::Transaction<'_>,
    ddl: &str,
) -> rusqlite::Result<()> {
    let mut parts = ddl.splitn(2, "-- == POST-DATA ==");
    let schema_ddl = parts.next().unwrap_or_default();
    let post_ddl = parts.next().unwrap_or_default();
    let mut alters = String::new();
    for statement in schema_ddl.split(';') {
        let statement = statement
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        if statement
            .split_whitespace()
            .take(2)
            .map(str::to_ascii_uppercase)
            .collect::<Vec<_>>()
            .as_slice()
            == ["ALTER", "TABLE"]
        {
            alters.push_str(statement);
            alters.push_str(";\n");
        } else {
            transaction.execute_batch(statement)?;
        }
    }
    apply_add_column_migration_set(transaction, &alters)?;
    super::setup::migrate_setup_data(transaction)?;
    transaction.execute_batch(post_ddl)?;
    Ok(())
}
//++agent TASK-225
