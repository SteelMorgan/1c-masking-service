use std::{path::Path, sync::Mutex};

use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use uuid::Uuid;

use crate::domain::{
    DatabaseMode, DatabaseSettings, FeedJob, HistoryForReveal, PolicyRule, RuleAction,
    RuleSelector, StoredHistory, ToolClass,
};

const MIGRATION: &str = include_str!("../../migrations/0001_core.sql");
const TERMINAL_HISTORY_MIGRATION: &str = include_str!("../../migrations/0002_terminal_history.sql");

pub enum HistoryWrite {
    Inserted(Uuid),
    Existing(StoredHistory),
    Conflict,
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
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(MIGRATION)?;
        transaction.execute_batch(TERMINAL_HISTORY_MIGRATION)?;
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
                 VALUES (?1, 'admin', 'Admin', NULL, 'Admin', 'active', 0, ?2, ?2)",
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

    pub fn ensure_database(&self, database_id: Uuid) -> rusqlite::Result<(DatabaseSettings, bool)> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some(settings) = load_database(&transaction, database_id)? {
                transaction.commit()?;
                return Ok((settings, false));
            }
            let now = Utc::now().to_rfc3339();
            transaction.execute(
                "INSERT INTO databases(id, instance_id, mode, created_at, updated_at) VALUES (?1, ?1, 'unconfigured', ?2, ?2)",
                params![database_id.to_string(), now],
            )?;
            for (tool, class) in default_tool_classes() {
                transaction.execute(
                    "INSERT INTO tool_classifications(database_id, tool_name, class, reviewer, updated_at)
                     VALUES (?1, ?2, ?3, 'built-in-v1', ?4)",
                    params![database_id.to_string(), tool, class.as_str(), now],
                )?;
            }
            let settings = load_database(&transaction, database_id)?.expect("database inserted");
            transaction.commit()?;
            Ok((settings, true))
        })
    }

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
            connection.execute(
                "INSERT INTO tool_classifications(database_id,tool_name,class,reviewer,updated_at)
                 VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT(database_id,tool_name) DO UPDATE SET class=excluded.class,reviewer=excluded.reviewer,updated_at=excluded.updated_at",
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
            transaction.execute("UPDATE policies SET status='retired' WHERE id=(SELECT active_policy_id FROM databases WHERE id=?1)", [database_id.to_string()])?;
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
                "SELECT selector_kind, selector_value, action, category, priority
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
                "SELECT selector_kind,selector_value,action,category,priority
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
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,mask_reasons_json,public_result_json,report_json,created_at,expires_at,mapping_batch_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![id.to_string(), database_id.to_string(), chat_id, call_id.to_string(), tool_name, outcome,
                    policy_version,
                    serde_json::to_string(mask_reasons).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    serde_json::to_string(public_result).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    serde_json::to_string(report).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    created_at.to_rfc3339(), expires_at.to_rfc3339(), mapping_batch_id.map(|id| id.to_string())],
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
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let unscoped_exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM unscoped_terminal_events WHERE call_id=?1)",
                [call_id.to_string()],
                |row| row.get(0),
            )?;
            if unscoped_exists {
                transaction.commit()?;
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
                transaction.commit()?;
                return Ok(TerminalWrite::Conflict);
            }
            let public_json = serde_json::to_string(public_result)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let report_json =
                serde_json::to_string(report).map_err(|_| rusqlite::Error::InvalidQuery)?;
            if let Some((stored_db, stored_chat, stored_tool, outcome, stored_public, stored_report, code, correlation)) = existing
            {
                let expected_correlation = correlation_id.to_string();
                transaction.commit()?;
                return Ok(if stored_db == database_id.to_string()
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
                });
            }
            let id = Uuid::new_v4();
            let created_at = Utc::now();
            let expires_at = created_at
                + Duration::seconds(history_ttl_seconds.min(i64::MAX as u64) as i64);
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
            transaction.commit()?;
            Ok(TerminalWrite::Inserted)
        })
    }

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
        self.with_connection(|connection| connection.execute(
            "DELETE FROM history WHERE id IN (SELECT id FROM history WHERE expires_at <= ?1 ORDER BY expires_at LIMIT ?2)",
            params![Utc::now().to_rfc3339(), limit.min(500) as i64],
        ))
    }

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

    pub fn pending_feed_jobs(&self, limit: usize) -> rusqlite::Result<Vec<FeedJob>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT j.id,j.database_id,j.target_version,c.mode,c.source_paths_json,c.filter_ast_json
                 FROM feed_jobs j LEFT JOIN dictionary_configs c ON c.database_id=j.database_id
                 WHERE j.state IN ('pending','receiving') ORDER BY j.created_at LIMIT ?1",
            )?;
            let rows = statement.query_map([limit.clamp(1, 10) as i64], |row| {
                let job_id = parse_uuid(row.get::<_, String>(0)?)?;
                let database_id = parse_uuid(row.get::<_, String>(1)?)?;
                let mode: Option<String> = row.get(3)?;
                let configured: Vec<Value> = serde_json::from_str(&row.get::<_, Option<String>>(4)?.unwrap_or_else(|| "[]".to_owned()))
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let filter: Option<Value> = row.get::<_, Option<String>>(5)?
                    .map(|json| serde_json::from_str(&json).map_err(|_| rusqlite::Error::InvalidQuery)).transpose()?;
                if filter.is_some() || configured.len() > 100 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let selectors = configured.into_iter().enumerate().map(|(index, mut value)| {
                    let object = value.as_object_mut().ok_or(rusqlite::Error::InvalidQuery)?;
                    if !object.keys().all(|key| matches!(key.as_str(), "source_path" | "category" | "filter_ast")) {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    let source = object.get("source_path").and_then(Value::as_str).ok_or(rusqlite::Error::InvalidQuery)?;
                    let category = object.get("category").and_then(Value::as_str).ok_or(rusqlite::Error::InvalidQuery)?;
                    if source.is_empty() || source.len() > 512 || category.is_empty() || category.len() > 32 {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    object.entry("filter_ast").or_insert(Value::Null);
                    if object
                        .get("filter_ast")
                        .is_some_and(|filter| !filter.is_null() && !valid_filter_ast(filter))
                    {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    object.insert("selection_id".to_owned(), Value::String(Uuid::from_u128(job_id.as_u128() ^ ((index + 1) as u128)).to_string()));
                    object.insert("page_size".to_owned(), Value::from(1000));
                    Ok(value)
                }).collect::<rusqlite::Result<Vec<_>>>()?;
                match mode.as_deref() {
                    None if selectors.is_empty() => {}
                    Some("all") if selectors.len() == 1
                        && selectors[0].get("source_path").and_then(Value::as_str) == Some("*") => {}
                    Some("part") if selectors.iter().all(|selector| selector.get("source_path").and_then(Value::as_str) != Some("*")) => {}
                    _ => return Err(rusqlite::Error::InvalidQuery),
                }
                Ok(FeedJob {
                    job_id, database_id, target_version: row.get::<_, i64>(2)?.max(0) as u64,
                    max_chunk_bytes: 1024 * 1024,
                    metadata_selector: serde_json::json!({"mode":"all","page_size":1000}),
                    dictionary_selectors: selectors,
                    hard_limits: serde_json::json!({"max_source_paths":100,"max_total_values":1_000_000}),
                })
            })?;
            rows.collect()
        })
    }

    pub fn enqueue_startup_refresh_jobs(&self) -> rusqlite::Result<usize> {
        self.with_connection(|connection| {
            let now = Utc::now().to_rfc3339();
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            // Receiving chunks live only in RAM and cannot be resumed after a
            // process restart. Retire those jobs before queueing a generation.
            transaction.execute(
                "UPDATE feed_jobs SET state='failed',updated_at=?1 WHERE state='receiving'",
                [&now],
            )?;
            let inserted = transaction.execute(
                "INSERT INTO feed_jobs(id,database_id,target_version,state,created_at,updated_at)
                 SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
                        substr(lower(hex(randomblob(2))),2) || '-' ||
                        substr('89ab',abs(random()) % 4 + 1,1) ||
                        substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6))),
                        d.id,d.active_cache_version + 1,'pending',?1,?1
                 FROM databases d
                 WHERE d.mode='enabled' AND d.active_cache_version IS NOT NULL
                   AND NOT EXISTS (
                       SELECT 1 FROM feed_jobs j
                       WHERE j.database_id=d.id AND j.state='pending'
                   )",
                [&now],
            )?;
            transaction.commit()?;
            Ok(inserted)
        })
    }

    pub fn enqueue_feed_job(
        &self,
        database_id: Uuid,
        target_version: u64,
    ) -> rusqlite::Result<Uuid> {
        let job_id = Uuid::new_v4();
        self.with_connection(|connection| {
            let now = Utc::now().to_rfc3339();
            connection.execute(
                "INSERT INTO feed_jobs(id,database_id,target_version,state,created_at,updated_at)
                 VALUES (?1,?2,?3,'pending',?4,?4)",
                params![
                    job_id.to_string(),
                    database_id.to_string(),
                    target_version.min(i64::MAX as u64) as i64,
                    now
                ],
            )?;
            Ok(job_id)
        })
    }

    pub fn feed_job(&self, job_id: Uuid) -> rusqlite::Result<Option<FeedJob>> {
        Ok(self
            .pending_feed_jobs(10)?
            .into_iter()
            .find(|job| job.job_id == job_id))
    }

    pub fn mark_feed_receiving(&self, job_id: Uuid) -> rusqlite::Result<bool> {
        self.with_connection(|connection| Ok(connection.execute(
            "UPDATE feed_jobs SET state='receiving',updated_at=?2 WHERE id=?1 AND state IN ('pending','receiving')",
            params![job_id.to_string(), Utc::now().to_rfc3339()],
        )? == 1))
    }

    pub fn activate_feed_job(
        &self,
        job: &FeedJob,
        digest: &str,
        metadata_count: usize,
        dictionary_count: usize,
    ) -> rusqlite::Result<()> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now = Utc::now().to_rfc3339();
            let changed = transaction.execute(
                "UPDATE feed_jobs SET state='active',digest=?2,expected_count=?3,updated_at=?4
                 WHERE id=?1 AND database_id=?5 AND target_version=?6 AND state='receiving'",
                params![
                    job.job_id.to_string(),
                    digest,
                    (metadata_count + dictionary_count) as i64,
                    now,
                    job.database_id.to_string(),
                    job.target_version.min(i64::MAX as u64) as i64
                ],
            )?;
            if changed != 1 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            transaction.execute(
                "UPDATE cache_generations SET status='failed' WHERE database_id=?1 AND status='active'",
                [job.database_id.to_string()],
            )?;
            transaction.execute(
                "INSERT OR REPLACE INTO cache_generations(database_id,version,digest,status,metadata_count,dictionary_count,created_at,activated_at)
                 VALUES (?1,?2,?3,'active',?4,?5,?6,?6)",
                params![job.database_id.to_string(), job.target_version as i64, digest, metadata_count as i64, dictionary_count as i64, now],
            )?;
            transaction.execute(
                "UPDATE databases SET active_cache_version=?2,updated_at=?3 WHERE id=?1",
                params![job.database_id.to_string(), job.target_version as i64, now],
            )?;
            transaction.commit()
        })
    }

    pub fn fail_feed_job(
        &self,
        job_id: Uuid,
        reason_code: &str,
        correlation_id: Uuid,
    ) -> rusqlite::Result<bool> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = transaction.execute(
                "UPDATE feed_jobs SET state='failed',updated_at=?2 WHERE id=?1 AND state IN ('pending','receiving')",
                params![job_id.to_string(), Utc::now().to_rfc3339()],
            )?;
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,action,outcome,code,correlation_id,created_at)
                 VALUES ('service','feed.fail','failed',?1,?2,?3)",
                params![reason_code, correlation_id.to_string(), Utc::now().to_rfc3339()],
            )?;
            transaction.commit()?;
            Ok(changed == 1)
        })
    }
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)
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
    })
}

fn load_database(
    connection: &Connection,
    database_id: Uuid,
) -> rusqlite::Result<Option<DatabaseSettings>> {
    connection.query_row(
        "SELECT mode,mapping_ttl_seconds,history_ttl_seconds,active_policy_id,active_cache_version FROM databases WHERE id=?1",
        [database_id.to_string()], |row| {
            let mode: String = row.get(0)?;
            Ok(DatabaseSettings {
                mode: DatabaseMode::try_from(mode.as_str()).map_err(|_| rusqlite::Error::InvalidQuery)?,
                mapping_ttl_seconds: row.get::<_, i64>(1)?.max(1) as u64,
                history_ttl_seconds: row.get::<_, i64>(2)?.max(1) as u64,
                active_policy_id: row.get(3)?,
                active_cache_version: row.get::<_, Option<i64>>(4)?.map(|value| value.max(0) as u64),
            })
        },
    ).optional()
}

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
        ("get_metadata", ToolClass::MetadataBypass),
        ("get_access_rights", ToolClass::MetadataBypass),
        ("get_link_of_object", ToolClass::MetadataBypass),
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
                && object.get("value").is_some_and(valid_filter_scalar)
        }
        "in" => {
            if object.len() != 3 {
                return false;
            }
            object.get("field").is_some_and(valid_filter_field)
                && object
                    .get("values")
                    .and_then(Value::as_array)
                    .is_some_and(|values| {
                        values.len() <= 100 && values.iter().all(valid_filter_scalar)
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
