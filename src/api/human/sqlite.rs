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
    DictionaryConfigView, DictionarySelectorConfig, DictionarySelectorView, HistoryItem,
    HumanDataError, HumanDataStore, MetadataNode, MetadataNodesPage, NeutralReport,
    PolicyRuleInput, PolicySummary, ToolClassification, ToolClassificationPatch,
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
            //++agent TASK-222 [05.10.2026]
            // refresh_stage: живой durable intent ('full') — pull в работе;
            // иначе 'active' при активной cache_generations строке; NULL —
            // snapshot ещё не собран. Stage label без feed данных.
            //++agent TASK-225 [25.09.2026]
            // new_tools_count (B2): сколько инструментов базы авто-
            // добавлены как deny-pending-review и ждут классификации.
            //++agent TASK-225
            let mut statement = connection.prepare(
                "SELECT d.id,COALESCE(d.display_label,d.id),d.display_label,d.mode,d.mapping_ttl_seconds,d.history_ttl_seconds,
                        COALESCE(i.phase,CASE WHEN a.database_id IS NOT NULL THEN 'active' END),
                        (SELECT COUNT(*) FROM tool_classifications t WHERE t.database_id=d.id AND t.auto_added=1),
                        d.strict_mode
                 FROM databases d
                 LEFT JOIN v2_refresh_intents i ON i.database_id=d.id
                 LEFT JOIN (SELECT database_id FROM cache_generations WHERE status='active') a
                        ON a.database_id=d.id
                 ORDER BY COALESCE(d.display_label,d.id)",
            )?;
            let rows = statement.query_map([], |row| {
                Ok(DatabaseSummary {
                    id: parse_uuid(row.get(0)?)?,
                    label: row.get(1)?,
                    display_label: row.get(2)?,
                    mode: row.get(3)?,
                    mapping_ttl_seconds: row.get::<_, i64>(4)?.max(1) as u64,
                    history_ttl_seconds: row.get::<_, i64>(5)?.max(1) as u64,
                    refresh_stage: row.get(6)?,
                    new_tools_count: row.get(7)?,
                    //++agent TASK-225 [25.09.2026]
                    strict_mode: row.get::<_, i64>(8)? != 0,
                    //++agent TASK-225
                })
            })?.collect();
            //++agent TASK-222
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

    //++agent TASK-224 [24.09.2026] итерация 3
    // Reveal нарочно НЕ аудируется: раскрытие стало автоматическим при
    // открытии записи (решение пользователя) — событие выродилось бы в шум
    // «запись просмотрена». Аудируемыми остаются admin-мутации.
    //--agent TASK-224
    fn reveal_history<'a>(
        &'a self,
        _actor: &Principal,
        history_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<NeutralReport, HumanDataError>> + Send + 'a>> {
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

            let value = self
                .masking
                .reveal_history(history_id, scope.0, &scope.1)
                .await
                .map_err(|error| match error.code {
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
        //++agent TASK-224 [24.09.2026]
        // display_label — tri-state: Some(value)/Some("")/Some(None) пишут
        // (пустое → NULL), None — не трогаем. Пробелы по краям срезаются.
        let label_written = patch.display_label.is_some();
        let label_value = patch
            .display_label
            .as_ref()
            .and_then(|value| value.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        //--agent TASK-224
        //++agent TASK-222 [05.10.2026]
        // Pull-модель: мутация — чисто durable tx (config + intent + audit
        // атомарно). RAM snapshot пересобирается pull worker по intent;
        // TTL режим не затрагивает содержимое snapshot (читается per-call),
        // поэтому intent ставится только при переходе в enabled.
        self.storage.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let previous_mode: String = transaction.query_row(
                "SELECT mode FROM databases WHERE id=?1",
                [database_id.to_string()],
                |row| row.get(0),
            )?;
            let changed = transaction.execute(
                "UPDATE databases SET mode=COALESCE(?1,mode),mapping_ttl_seconds=COALESCE(?2,mapping_ttl_seconds),history_ttl_seconds=COALESCE(?3,history_ttl_seconds),display_label=CASE WHEN ?4=1 THEN ?5 ELSE display_label END,strict_mode=COALESCE(?6,strict_mode),updated_at=?7 WHERE id=?8",
                params![mode.map(DatabaseMode::as_str), patch.mapping_ttl_seconds.map(|value| value as i64), patch.history_ttl_seconds.map(|value| value as i64), i64::from(label_written), label_value, patch.strict_mode.map(i64::from), Utc::now().to_rfc3339(), database_id.to_string()],
            )?;
            if changed != 1 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let now = Utc::now().to_rfc3339();
            let effective_mode = mode.map(DatabaseMode::as_str).unwrap_or(&previous_mode);
            if effective_mode == "enabled" && previous_mode != "enabled" {
                upsert_intent_tx(&transaction, database_id, "admin_enable", Some(actor.user_id), &now)?;
            } else if effective_mode != "enabled" {
                // Disabled/unconfigured: pull пропускает такие базы — висящий
                // intent снимаем, чтобы не крутить Skipped-циклы.
                transaction.execute(
                    "DELETE FROM v2_refresh_intents WHERE database_id=?1",
                    [database_id.to_string()],
                )?;
            }
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,outcome,correlation_id,created_at)
                 VALUES ('human',?1,'database.update',?2,'success',?3,?4)",
                params![actor.user_id.to_string(), database_id.to_string(), correlation_id.to_string(), now],
            )?;
            transaction.commit()
        }).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { HumanDataError::NotFound } else { HumanDataError::Unavailable })
        //++agent TASK-222
    }

    fn refresh_database(
        &self,
        actor: &Principal,
        database_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(), HumanDataError> {
        //++agent TASK-222 [05.10.2026]
        // Refresh = durable intent 'full' + audit в одной tx — pull worker
        // пересобирает metadata+dictionary snapshot через manager UDS.
        self.storage.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM databases WHERE id=?1)",
                [database_id.to_string()],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let now = Utc::now().to_rfc3339();
            upsert_intent_tx(
                &transaction,
                database_id,
                "admin_refresh",
                Some(actor.user_id),
                &now,
            )?;
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,outcome,correlation_id,created_at)
                 VALUES ('human',?1,'database.refresh',?2,'accepted',?3,?4)",
                params![actor.user_id.to_string(), database_id.to_string(), correlation_id.to_string(), now],
            )?;
            transaction.commit()
        }).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { HumanDataError::NotFound } else { HumanDataError::Unavailable })
        //++agent TASK-222
    }

    fn list_tool_classifications(
        &self,
        database_id: Uuid,
    ) -> Result<Vec<ToolClassification>, HumanDataError> {
        //++agent TASK-225 [25.09.2026]
        // Полная форма по спеке B10 — администратор видит, какие строки
        // добавлены автоматически (auto_added) и сколько отказов набрано.
        //++agent TASK-225
        self.storage.with_connection(|c| { let mut s=c.prepare("SELECT tool_name,class,reviewer,updated_at,auto_added,first_seen_at,denied_count,last_denied_at FROM tool_classifications WHERE database_id=?1 ORDER BY tool_name")?; let rows=s.query_map([database_id.to_string()], |r| Ok(ToolClassification{tool_name:r.get(0)?,class:r.get(1)?,reviewer:r.get(2)?,updated_at:r.get(3)?,auto_added:r.get::<_,i64>(4)?!=0,first_seen_at:r.get(5)?,denied_count:r.get(6)?,last_denied_at:r.get(7)?}))?.collect(); rows }).map_err(|_| HumanDataError::Unavailable)
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
        //++agent TASK-222 [05.10.2026]
        // Tool class читается из durable-хранилища на каждый вызов — RAM
        // snapshot его не содержит, refresh intent не нужен.
        //++agent TASK-225 [25.09.2026]
        // PUT администратора: auto_added=0 (решение принято), denied_count/
        // first_seen_at/last_denied_at сохраняются (спека §7).
        //++agent TASK-225
        self.storage.with_connection(|c| { let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?; let now=Utc::now().to_rfc3339(); tx.execute("INSERT INTO tool_classifications(database_id,tool_name,class,reviewer,updated_at,auto_added) VALUES (?1,?2,?3,?4,?5,0) ON CONFLICT(database_id,tool_name) DO UPDATE SET class=excluded.class,reviewer=excluded.reviewer,updated_at=excluded.updated_at,auto_added=0",params![database_id.to_string(),tool_name,patch.class,actor.user_id.to_string(),now])?; audit(&tx,actor,"tool.update",database_id,correlation_id,&now)?; tx.commit() }).map_err(sql_error)
        //++agent TASK-222
    }

    fn list_dictionary_configs(
        &self,
        database_id: Uuid,
    ) -> Result<Vec<DictionaryConfigView>, HumanDataError> {
        //++agent TASK-224 [24.09.2026]
        // in_manifest — проверка пути по RAM manifest: None, когда manifest
        // не получен (UI тогда не маркирует «нет в конфигурации»).
        let manifest_paths = self
            .masking
            .metadata_manifest_view(database_id, |items| {
                items
                    .iter()
                    .map(|item| item.source_path.clone())
                    .collect::<std::collections::HashSet<_>>()
            })
            .map(|(_, paths)| paths);
        //--agent TASK-224
        self.storage
            .with_connection(|connection| {
                let mut statement = connection.prepare(
                    "SELECT id,mode,source_paths_json FROM dictionary_configs WHERE database_id=?1",
                )?;
                let rows = statement
                    .query_map([database_id.to_string()], |row| {
                        let selectors_json: String = row.get(2)?;
                        let selectors: Vec<DictionarySelectorConfig> =
                            serde_json::from_str(&selectors_json)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                        Ok(DictionaryConfigView {
                            id: parse_uuid(row.get(0)?)?,
                            mode: row.get(1)?,
                            selectors: selectors
                                .into_iter()
                                .map(|selector| DictionarySelectorView {
                                    in_manifest: manifest_paths
                                        .as_ref()
                                        .map(|paths| paths.contains(&selector.source_path)),
                                    source_path: selector.source_path,
                                    category: selector.category,
                                    filter_ast: selector.filter_ast,
                                })
                                .collect(),
                        })
                    })?
                    .collect();
                rows
            })
            .map_err(|_| HumanDataError::Unavailable)
    }

    //++agent TASK-224 [24.09.2026]
    fn metadata_nodes(
        &self,
        database_id: Uuid,
        path: &str,
        query: Option<&str>,
    ) -> Result<MetadataNodesPage, HumanDataError> {
        let exists: bool = self
            .storage
            .with_connection(|connection| {
                connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM databases WHERE id=?1)",
                    [database_id.to_string()],
                    |row| row.get(0),
                )
            })
            .map_err(|_| HumanDataError::Unavailable)?;
        if !exists {
            return Err(HumanDataError::NotFound);
        }
        let Some((completed_at, (nodes, truncated))) =
            self.masking
                .metadata_manifest_view(database_id, |items| match query {
                    Some(needle) => search_metadata_nodes(items, needle),
                    None => build_metadata_nodes(items, path),
                })
        else {
            return Ok(MetadataNodesPage {
                manifest_ready: false,
                completed_at: None,
                nodes: Vec::new(),
                truncated: false,
            });
        };
        Ok(MetadataNodesPage {
            manifest_ready: true,
            completed_at: Some(completed_at),
            nodes,
            truncated,
        })
    }
    //--agent TASK-224

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
        //++agent TASK-222 [05.10.2026]
        // Config и intent коммитятся атомарно: следующий pull видит
        // согласованную пару. Refresh всегда 'full' — manifest устаревает
        // вместе с остальным содержимым snapshot.
        self.storage.with_connection(|connection| {
            let transaction=connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now=Utc::now().to_rfc3339();
            transaction.execute(
                "INSERT INTO dictionary_configs(id,database_id,mode,source_paths_json,filter_ast_json,updated_at) VALUES (?1,?2,?3,?4,NULL,?5)
                 ON CONFLICT(database_id) DO UPDATE SET id=excluded.id,mode=excluded.mode,source_paths_json=excluded.source_paths_json,filter_ast_json=NULL,updated_at=excluded.updated_at",
                params![config.id.to_string(),database_id.to_string(),config.mode,selectors,now],
            )?;
            upsert_intent_tx(
                &transaction,
                database_id,
                "dictionary_config",
                Some(actor.user_id),
                &now,
            )?;
            audit(&transaction,actor,"dictionary.update",database_id,correlation_id,&now)?;
            transaction.commit()
        }).map_err(sql_error)
        //++agent TASK-222
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
                //++agent TASK-222 [05.10.2026]
                // Смена policy меняет Mask allowlist All-expansion и правила
                // snapshot — intent 'full' в той же tx, pull пересоберёт.
                upsert_intent_tx(
                    &tx,
                    database_id,
                    "policy_activate",
                    Some(actor_id),
                    &now,
                )?;
                //++agent TASK-222
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

//++agent TASK-224 [24.09.2026]
/// Верхний лимит узлов на один ответ: Admin-UI лениво раскрывает уровни,
/// больше не требуется; дальше — поиск `q`.
const MAX_METADATA_NODES: usize = 1000;
const MAX_METADATA_SEARCH_NODES: usize = 200;

/// Дочерние узлы уровня `path` ("" — корень). Каждый `source_path` —
/// «Класс.Объект[.ТЧ].Реквизит»; группой считается сегмент, под которым
/// есть более глубокие записи, листом — собственный item manifest.
fn build_metadata_nodes(
    items: &[crate::domain::FeedMetadataItem],
    path: &str,
) -> (Vec<MetadataNode>, bool) {
    struct Child {
        deeper: bool,
        fields: usize,
        password: usize,
        item: Option<crate::domain::FeedMetadataItem>,
    }
    let prefix = if path.is_empty() {
        String::new()
    } else {
        format!("{path}.")
    };
    let mut children: std::collections::BTreeMap<String, Child> = Default::default();
    for item in items {
        let Some(rest) = item.source_path.strip_prefix(&prefix) else {
            continue;
        };
        let (segment, deeper) = match rest.split_once('.') {
            Some((segment, _)) => (segment, true),
            None => (rest, false),
        };
        if segment.is_empty() {
            continue;
        }
        let child = children.entry(segment.to_owned()).or_insert(Child {
            deeper: false,
            fields: 0,
            password: 0,
            item: None,
        });
        child.deeper |= deeper;
        child.fields += 1;
        child.password += usize::from(item.password_mode);
        if !deeper {
            child.item = Some(item.clone());
        }
    }
    let truncated = children.len() > MAX_METADATA_NODES;
    let nodes = children
        .into_iter()
        .take(MAX_METADATA_NODES)
        .map(|(segment, child)| {
            let leaf = !child.deeper;
            MetadataNode {
                kind: if leaf { "field" } else { "group" },
                name: child
                    .item
                    .as_ref()
                    .map(|item| item.field_name.clone())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| segment.clone()),
                path: format!("{prefix}{segment}"),
                field_count: child.fields,
                password_count: child.password,
                field_type: child.item.as_ref().map(|item| item.field_type.clone()),
                password_mode: child.item.as_ref().map(|item| item.password_mode),
            }
        })
        .collect();
    (nodes, truncated)
}

/// Плоский поиск по `source_path`/`field_name` без разбора уровней —
/// результатом всегда листовые поля.
fn search_metadata_nodes(
    items: &[crate::domain::FeedMetadataItem],
    query: &str,
) -> (Vec<MetadataNode>, bool) {
    let needle = query.to_lowercase();
    let mut matches: Vec<&crate::domain::FeedMetadataItem> = items
        .iter()
        .filter(|item| {
            item.source_path.to_lowercase().contains(&needle)
                || item.field_name.to_lowercase().contains(&needle)
        })
        .collect();
    matches.sort_by(|a, b| a.source_path.cmp(&b.source_path));
    let truncated = matches.len() > MAX_METADATA_SEARCH_NODES;
    let nodes = matches
        .into_iter()
        .take(MAX_METADATA_SEARCH_NODES)
        .map(|item| MetadataNode {
            name: item.field_name.clone(),
            path: item.source_path.clone(),
            kind: "field",
            field_count: 1,
            password_count: usize::from(item.password_mode),
            field_type: Some(item.field_type.clone()),
            password_mode: Some(item.password_mode),
        })
        .collect();
    (nodes, truncated)
}
//--agent TASK-224

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

//++agent TASK-222 [05.10.2026]
/// Tx-scoped durable refresh intent: phase всегда 'full' — pull refresh
/// пересобирает snapshot целиком. Upsert перезаписывает `created_at`, поэтому
/// конкурентная мутация во время in-flight pull не теряется: условное
/// удаление intent после успешного pull промахивается, и свежая мутация
/// получает свой refresh следующим тиком.
fn upsert_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    database_id: Uuid,
    reason: &str,
    actor_id: Option<Uuid>,
    now: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO v2_refresh_intents(database_id,phase,reason,actor_id,created_at)
         VALUES (?1,'full',?2,?3,?4) ON CONFLICT(database_id) DO UPDATE SET
         phase='full',reason=excluded.reason,actor_id=excluded.actor_id,created_at=excluded.created_at",
        params![
            database_id.to_string(),
            reason,
            actor_id.map(|id| id.to_string()),
            now
        ],
    )?;
    Ok(())
}
//++agent TASK-222
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
