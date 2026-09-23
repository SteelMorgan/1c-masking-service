use std::{future::Future, pin::Pin, sync::Arc};

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::Principal,
    domain::{
        DatabaseMode, ErrorCode, MaskingService, PolicyRule, PolicySnapshot, RuleAction,
        RuleSelector, ToolClass,
    },
    storage::{valid_filter_ast, SqliteStorage},
};

use super::{
    AdminDatabasePatch, ChatSummary, CreatePolicyRequest, DatabaseSummary, DictionaryConfig,
    HistoryItem, HumanDataError, HumanDataStore, NeutralReport, PolicyRuleInput, PolicySummary,
    ToolClassification, ToolClassificationPatch,
};

pub struct SqliteHumanDataStore {
    storage: Arc<SqliteStorage>,
    masking: Arc<MaskingService>,
}

impl SqliteHumanDataStore {
    pub fn new(storage: Arc<SqliteStorage>, masking: Arc<MaskingService>) -> Self {
        Self { storage, masking }
    }
}

impl HumanDataStore for SqliteHumanDataStore {
    fn list_databases(&self) -> Result<Vec<DatabaseSummary>, HumanDataError> {
        self.storage.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id,COALESCE(display_label,id),mode,mapping_ttl_seconds,history_ttl_seconds FROM databases ORDER BY COALESCE(display_label,id)",
            )?;
            let rows = statement.query_map([], |row| {
                Ok(DatabaseSummary {
                    id: parse_uuid(row.get(0)?)?,
                    label: row.get(1)?,
                    mode: row.get(2)?,
                    mapping_ttl_seconds: row.get::<_, i64>(3)?.max(1) as u64,
                    history_ttl_seconds: row.get::<_, i64>(4)?.max(1) as u64,
                })
            })?.collect();
            rows
        }).map_err(|_| HumanDataError::Unavailable)
    }

    fn list_chats(&self, database_id: Uuid) -> Result<Vec<ChatSummary>, HumanDataError> {
        self.storage.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT chat_id,COUNT(*),MAX(created_at) FROM history
                 WHERE database_id=?1 AND expires_at>?2 GROUP BY chat_id ORDER BY MAX(created_at) DESC",
            )?;
            let rows = statement.query_map(params![database_id.to_string(), Utc::now().to_rfc3339()], |row| {
                Ok(ChatSummary {
                    chat_id: row.get(0)?,
                    message_count: row.get::<_, i64>(1)?.max(0) as u64,
                    last_message_at: parse_time(row.get(2)?)?,
                })
            })?.collect();
            rows
        }).map_err(|_| HumanDataError::Unavailable)
    }

    fn list_history(
        &self,
        database_id: Uuid,
        chat_id: &str,
        limit: u8,
    ) -> Result<Vec<HistoryItem>, HumanDataError> {
        if !(30..=50).contains(&limit) {
            return Err(HumanDataError::Conflict);
        }
        self.storage.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id,database_id,chat_id,tool_name,outcome,created_at,report_json FROM history
                 WHERE database_id=?1 AND chat_id=?2 AND expires_at>?3 ORDER BY created_at DESC LIMIT ?4",
            )?;
            let rows = statement.query_map(
                params![database_id.to_string(), chat_id, Utc::now().to_rfc3339(), limit as i64],
                |row| {
                    let report_json: String = row.get(6)?;
                    Ok(HistoryItem {
                        id: parse_uuid(row.get(0)?)?,
                        database_id: parse_uuid(row.get(1)?)?,
                        chat_id: row.get(2)?,
                        tool_name: row.get(3)?,
                        outcome: row.get(4)?,
                        created_at: parse_time(row.get(5)?)?,
                        report: serde_json::from_str(&report_json).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )?.collect();
            rows
        }).map_err(|_| HumanDataError::Unavailable)
    }

    fn reveal_history<'a>(
        &'a self,
        actor: &Principal,
        history_id: Uuid,
        correlation_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<NeutralReport, HumanDataError>> + Send + 'a>> {
        let actor_id = actor.user_id;
        Box::pin(async move {
            let scope =
                self.storage
                    .with_connection(|connection| {
                        connection.query_row(
                    "SELECT database_id,chat_id FROM history WHERE id=?1 AND expires_at>?2",
                    params![history_id.to_string(), Utc::now().to_rfc3339()],
                    |row| Ok((parse_uuid(row.get(0)?)?, row.get::<_, String>(1)?)),
                ).optional()
                    })
                    .map_err(|_| HumanDataError::Unavailable)?
                    .ok_or(HumanDataError::NotFound)?;

            let result = self
                .masking
                .reveal_history(history_id, scope.0, &scope.1)
                .await;
            let (outcome, code) = match &result {
                Ok(_) => ("success", None),
                Err(error) => ("denied", Some(error.code.as_str())),
            };
            self.storage.with_connection(|connection| {
                connection.execute(
                    "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,chat_id,history_id,outcome,code,correlation_id,created_at)
                     VALUES ('human',?1,'history.reveal',?2,?3,?4,?5,?6,?7,?8)",
                    params![actor_id.to_string(), scope.0.to_string(), scope.1, history_id.to_string(), outcome, code, correlation_id.to_string(), Utc::now().to_rfc3339()],
                )?;
                Ok(())
            }).map_err(|_| HumanDataError::Unavailable)?;

            let value = result.map_err(|error| match error.code {
                ErrorCode::MaskTokenInvalid
                | ErrorCode::HistoryUnavailable
                | ErrorCode::MappingUnavailable => HumanDataError::MappingUnavailable,
                _ => HumanDataError::Unavailable,
            })?;
            let report: NeutralReport =
                serde_json::from_value(value).map_err(|_| HumanDataError::Unavailable)?;
            report
                .is_safe()
                .then_some(report)
                .ok_or(HumanDataError::Unavailable)
        })
    }

    fn update_database(
        &self,
        actor: &Principal,
        database_id: Uuid,
        patch: AdminDatabasePatch,
        correlation_id: Uuid,
    ) -> Result<(), HumanDataError> {
        let mode = patch
            .mode
            .as_deref()
            .map(DatabaseMode::try_from)
            .transpose()
            .map_err(|_| HumanDataError::Conflict)?;
        self.storage.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = transaction.execute(
                "UPDATE databases SET mode=COALESCE(?1,mode),mapping_ttl_seconds=COALESCE(?2,mapping_ttl_seconds),history_ttl_seconds=COALESCE(?3,history_ttl_seconds),updated_at=?4 WHERE id=?5",
                params![mode.map(DatabaseMode::as_str), patch.mapping_ttl_seconds.map(|value| value as i64), patch.history_ttl_seconds.map(|value| value as i64), Utc::now().to_rfc3339(), database_id.to_string()],
            )?;
            if changed != 1 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,outcome,correlation_id,created_at)
                 VALUES ('human',?1,'database.update',?2,'success',?3,?4)",
                params![actor.user_id.to_string(), database_id.to_string(), correlation_id.to_string(), Utc::now().to_rfc3339()],
            )?;
            transaction.commit()
        }).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { HumanDataError::NotFound } else { HumanDataError::Unavailable })
    }

    fn refresh_database(
        &self,
        actor: &Principal,
        database_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(), HumanDataError> {
        self.storage.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let target_version: Option<i64> = transaction.query_row(
                "SELECT COALESCE(active_cache_version,0)+1 FROM databases WHERE id=?1",
                [database_id.to_string()],
                |row| row.get(0),
            ).optional()?;
            let Some(target_version) = target_version else {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            };
            let now = Utc::now().to_rfc3339();
            transaction.execute(
                "INSERT INTO feed_jobs(id,database_id,target_version,state,created_at,updated_at) VALUES (?1,?2,?3,'pending',?4,?4)",
                params![Uuid::new_v4().to_string(), database_id.to_string(), target_version, now],
            )?;
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,outcome,correlation_id,created_at)
                 VALUES ('human',?1,'database.refresh',?2,'accepted',?3,?4)",
                params![actor.user_id.to_string(), database_id.to_string(), correlation_id.to_string(), now],
            )?;
            transaction.commit()
        }).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { HumanDataError::NotFound } else { HumanDataError::Unavailable })
    }

    fn list_tool_classifications(
        &self,
        database_id: Uuid,
    ) -> Result<Vec<ToolClassification>, HumanDataError> {
        self.storage.with_connection(|c| { let mut s=c.prepare("SELECT tool_name,class FROM tool_classifications WHERE database_id=?1 ORDER BY tool_name")?; let rows=s.query_map([database_id.to_string()], |r| Ok(ToolClassification{tool_name:r.get(0)?,class:r.get(1)?}))?.collect(); rows }).map_err(|_| HumanDataError::Unavailable)
    }

    fn update_tool_classification(
        &self,
        actor: &Principal,
        database_id: Uuid,
        tool_name: &str,
        patch: ToolClassificationPatch,
        correlation_id: Uuid,
    ) -> Result<(), HumanDataError> {
        if tool_name.is_empty()
            || tool_name.len() > 128
            || ToolClass::try_from(patch.class.as_str()).is_err()
        {
            return Err(HumanDataError::Conflict);
        }
        self.storage.with_connection(|c| { let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?; let now=Utc::now().to_rfc3339(); tx.execute("INSERT INTO tool_classifications(database_id,tool_name,class,reviewer,updated_at) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(database_id,tool_name) DO UPDATE SET class=excluded.class,reviewer=excluded.reviewer,updated_at=excluded.updated_at",params![database_id.to_string(),tool_name,patch.class,actor.user_id.to_string(),now])?; audit(&tx,actor,"tool.update",database_id,correlation_id,&now)?; tx.commit() }).map_err(sql_error)
    }

    fn list_dictionary_configs(
        &self,
        database_id: Uuid,
    ) -> Result<Vec<DictionaryConfig>, HumanDataError> {
        self.storage
            .with_connection(|connection| {
                let mut statement = connection.prepare(
                    "SELECT id,mode,source_paths_json FROM dictionary_configs WHERE database_id=?1",
                )?;
                let rows = statement
                    .query_map([database_id.to_string()], |row| {
                        let selectors_json: String = row.get(2)?;
                        Ok(DictionaryConfig {
                            id: parse_uuid(row.get(0)?)?,
                            mode: row.get(1)?,
                            selectors: serde_json::from_str(&selectors_json)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        })
                    })?
                    .collect();
                rows
            })
            .map_err(|_| HumanDataError::Unavailable)
    }

    fn put_dictionary_config(
        &self,
        actor: &Principal,
        database_id: Uuid,
        config: DictionaryConfig,
        correlation_id: Uuid,
    ) -> Result<(), HumanDataError> {
        if !matches!(config.mode.as_str(), "all" | "part")
            || config.selectors.is_empty()
            || config.selectors.len() > 100
            || (config.mode == "all"
                && (config.selectors.len() != 1 || config.selectors[0].source_path != "*"))
            || (config.mode == "part"
                && config
                    .selectors
                    .iter()
                    .any(|selector| selector.source_path == "*"))
            || config.selectors.iter().any(|selector| {
                selector.source_path.is_empty()
                    || selector.source_path.len() > 512
                    || selector.category.is_empty()
                    || selector.category.len() > 32
                    || selector.category.chars().any(char::is_control)
                    || selector
                        .filter_ast
                        .as_ref()
                        .is_some_and(|value| !valid_filter_ast(value))
            })
        {
            return Err(HumanDataError::Conflict);
        }
        let selectors =
            serde_json::to_string(&config.selectors).map_err(|_| HumanDataError::Conflict)?;
        self.storage.with_connection(|connection| {
            let transaction=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now=Utc::now().to_rfc3339();
            transaction.execute(
                "INSERT INTO dictionary_configs(id,database_id,mode,source_paths_json,filter_ast_json,updated_at) VALUES (?1,?2,?3,?4,NULL,?5)
                 ON CONFLICT(database_id) DO UPDATE SET id=excluded.id,mode=excluded.mode,source_paths_json=excluded.source_paths_json,filter_ast_json=NULL,updated_at=excluded.updated_at",
                params![config.id.to_string(),database_id.to_string(),config.mode,selectors,now],
            )?;
            audit(&transaction,actor,"dictionary.update",database_id,correlation_id,&now)?;
            transaction.commit()
        }).map_err(sql_error)
    }

    fn list_policies(&self, database_id: Uuid) -> Result<Vec<PolicySummary>, HumanDataError> {
        self.storage
            .with_connection(|c| load_policies(c, database_id))
            .map_err(|_| HumanDataError::Unavailable)
    }

    fn create_policy(
        &self,
        actor: &Principal,
        database_id: Uuid,
        request: CreatePolicyRequest,
        correlation_id: Uuid,
    ) -> Result<PolicySummary, HumanDataError> {
        if request.rules.is_empty()
            || request.rules.len() > 1000
            || !request.rules.iter().all(valid_rule)
        {
            return Err(HumanDataError::Conflict);
        }
        self.storage.with_connection(|c| { let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?; let version:i64=tx.query_row("SELECT COALESCE(MAX(version),0)+1 FROM policies WHERE database_id=?1",[database_id.to_string()],|r|r.get(0))?; let id=Uuid::new_v4(); let now=Utc::now().to_rfc3339(); tx.execute("INSERT INTO policies(id,database_id,version,status,created_at) VALUES (?1,?2,?3,'draft',?4)",params![id.to_string(),database_id.to_string(),version,now])?; for rule in &request.rules { tx.execute("INSERT INTO policy_rules(id,policy_id,selector_kind,selector_value,action,category,priority,enabled,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,1,?8)",params![Uuid::new_v4().to_string(),id.to_string(),rule.selector_kind,rule.selector_value,rule.action,rule.category,rule.priority,now])?; } audit(&tx,actor,"policy.create",database_id,correlation_id,&now)?; tx.commit()?; Ok(PolicySummary{id,version:version as u64,status:"draft".into(),rules:request.rules}) }).map_err(sql_error)
    }

    fn activate_policy<'a>(
        &'a self,
        actor: &Principal,
        database_id: Uuid,
        policy_id: Uuid,
        correlation_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), HumanDataError>> + Send + 'a>> {
        let actor_id = actor.user_id;
        Box::pin(async move {
            //++agent TASK-221 2026-09-23
            // Пока менеджер не получает версионированную политику до вызова 1С,
            // произвольный Secret нельзя активировать без риска пропуска значения через него.
            let (version, rules) = self.storage.with_connection(|c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let version: i64 = tx.query_row(
                    "SELECT version FROM policies WHERE id=?1 AND database_id=?2",
                    params![policy_id.to_string(), database_id.to_string()],
                    |row| row.get(0),
                )?;
                let rules = load_rules(&tx, policy_id, database_id)?;
                if rules.iter().any(|rule| rule.action == "secret") {
                    return Ok(None);
                }
                let now = Utc::now().to_rfc3339();
                tx.execute("UPDATE policies SET status='retired' WHERE database_id=?1 AND status='active'",[database_id.to_string()])?;
                tx.execute("UPDATE policies SET status='active' WHERE id=?1 AND database_id=?2",params![policy_id.to_string(),database_id.to_string()])?;
                tx.execute("UPDATE databases SET active_policy_id=?1,updated_at=?2 WHERE id=?3",params![policy_id.to_string(),now,database_id.to_string()])?;
                let principal=Principal{user_id:actor_id,role:crate::auth::Role::Admin,auth_epoch:0};
                audit(&tx,&principal,"policy.activate",database_id,correlation_id,&now)?;
                tx.commit()?;
                Ok(Some((version, rules)))
            }).map_err(sql_error)?.ok_or(HumanDataError::SecretPolicyUnsupported)?;
            //--agent TASK-221
            self.masking
                .set_policy_snapshot(
                    database_id,
                    PolicySnapshot {
                        version,
                        rules: rules.into_iter().map(domain_rule).collect(),
                        ..PolicySnapshot::default()
                    },
                )
                .await;
            Ok(())
        })
    }
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn parse_time(value: String) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn sql_error(e: rusqlite::Error) -> HumanDataError {
    if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
        HumanDataError::NotFound
    } else {
        HumanDataError::Unavailable
    }
}
fn audit(
    tx: &rusqlite::Transaction<'_>,
    a: &Principal,
    action: &str,
    db: Uuid,
    corr: Uuid,
    now: &str,
) -> rusqlite::Result<()> {
    tx.execute("INSERT INTO audit_events(actor_kind,actor_id,action,database_id,outcome,correlation_id,created_at) VALUES ('human',?1,?2,?3,'success',?4,?5)",params![a.user_id.to_string(),action,db.to_string(),corr.to_string(),now])?;
    Ok(())
}
fn valid_rule(r: &PolicyRuleInput) -> bool {
    matches!(
        r.selector_kind.as_str(),
        "source_path" | "name" | "type" | "dictionary" | "regex"
    ) && matches!(r.action.as_str(), "keep" | "mask" | "secret")
        && !r.selector_value.is_empty()
        && r.selector_value.len() <= 4096
        && !r.category.is_empty()
        && r.category.len() <= 64
        && (r.selector_kind != "regex" || regex::Regex::new(&r.selector_value).is_ok())
}
fn load_rules(
    c: &rusqlite::Connection,
    id: Uuid,
    db: Uuid,
) -> rusqlite::Result<Vec<PolicyRuleInput>> {
    let exists: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM policies WHERE id=?1 AND database_id=?2)",
        params![id.to_string(), db.to_string()],
        |r| r.get(0),
    )?;
    if !exists {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    let mut s=c.prepare("SELECT selector_kind,selector_value,action,category,priority FROM policy_rules WHERE policy_id=?1 AND enabled=1 ORDER BY priority,id")?;
    let rows = s
        .query_map([id.to_string()], |r| {
            Ok(PolicyRuleInput {
                selector_kind: r.get(0)?,
                selector_value: r.get(1)?,
                action: r.get(2)?,
                category: r.get(3)?,
                priority: r.get(4)?,
            })
        })?
        .collect();
    rows
}
fn load_policies(c: &rusqlite::Connection, db: Uuid) -> rusqlite::Result<Vec<PolicySummary>> {
    let mut s = c.prepare(
        "SELECT id,version,status FROM policies WHERE database_id=?1 ORDER BY version DESC",
    )?;
    let h: Vec<(Uuid, u64, String)> = s
        .query_map([db.to_string()], |r| {
            Ok((
                parse_uuid(r.get(0)?)?,
                r.get::<_, i64>(1)?.max(0) as u64,
                r.get(2)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    h.into_iter()
        .map(|(id, version, status)| {
            Ok(PolicySummary {
                id,
                version,
                status,
                rules: load_rules(c, id, db)?,
            })
        })
        .collect()
}
fn domain_rule(r: PolicyRuleInput) -> PolicyRule {
    PolicyRule {
        selector: match r.selector_kind.as_str() {
            "source_path" => RuleSelector::SourcePath,
            "name" => RuleSelector::Name,
            "type" => RuleSelector::Type,
            "dictionary" => RuleSelector::Dictionary,
            _ => RuleSelector::Regex,
        },
        pattern: r.selector_value,
        action: match r.action.as_str() {
            "secret" => RuleAction::Secret,
            "mask" => RuleAction::Mask,
            _ => RuleAction::Keep,
        },
        category: r.category,
        priority: r.priority,
    }
}
