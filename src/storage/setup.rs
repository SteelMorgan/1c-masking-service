//++agent TASK-225 [26.09.2026]
//! Устойчивое хранение версий настройки (spec §2): перенос данных
//! `migrate_setup_data` (§2.3, вызывается из миграции 0010 внутри её
//! транзакции), загрузка/запись контента версий, content_hash, журнал
//! setup_journal и реестр setup_imports. Таблицы созданы миграцией.

use chrono::Utc;
use rusqlite::{params, OptionalExtension, Transaction};
use serde_json::Value;
use uuid::Uuid;

use crate::domain::setup::{
    content_hash, rule_key, DictionarySourceSpec, GeneratedBy, RuleSpec, RuleTestsSpec, ToolSpec,
    VersionContent, VersionDictionary, MIGRATION_REASON,
};

/// Строка policies версии + её контент (rules загружаются отдельным
/// запросом — см. `version_content`).
#[derive(Debug, Clone)]
pub(crate) struct StoredVersion {
    pub id: Uuid,
    pub version: i64,
    pub status: String,
    pub dictionary_json: Option<String>,
    pub tools_json: Option<String>,
    pub origin: String,
    pub origin_ref: Option<String>,
    pub created_by: Option<String>,
    #[allow(dead_code)]
    pub created_at: String,
    pub updated_at: Option<String>,
    pub content_hash: Option<String>,
    #[allow(dead_code)]
    pub activated_at: Option<String>,
    #[allow(dead_code)]
    pub activated_by: Option<String>,
    #[allow(dead_code)]
    pub comment: Option<String>,
    #[allow(dead_code)]
    pub discarded_at: Option<String>,
    pub rules: Vec<StoredVersionRule>,
}

#[derive(Debug, Clone)]
pub(crate) struct StoredVersionRule {
    pub id: Uuid,
    pub selector: String,
    pub value: String,
    pub action: String,
    pub category: String,
    pub priority: i64,
    pub enabled: bool,
    pub reason: Option<String>,
    pub tests: Option<Value>,
}

/// Ссылка на версию в API: `active` | `draft` | номер.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum VersionRef {
    Active,
    Draft,
    Number(i64),
}

impl VersionRef {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text {
            "active" => Some(Self::Active),
            "draft" => Some(Self::Draft),
            _ => text
                .parse::<i64>()
                .ok()
                .filter(|n| *n >= 1)
                .map(Self::Number),
        }
    }
}

/// §2.3: перенос данных после создания колонок миграции 0010 — единая
/// функция, вызываемая внутри её транзакции (откат всего initialize на
/// любой ошибке). Ничего не удаляет (legacy `dictionary_configs` остаётся
/// fallback-источником для баз без активной версии).
pub(crate) fn migrate_setup_data(transaction: &Transaction) -> rusqlite::Result<()> {
    let now = Utc::now().to_rfc3339();
    let databases: Vec<String> = {
        let mut statement = transaction.prepare("SELECT id FROM databases")?;
        let rows = statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for database_id in databases {
        migrate_database(transaction, &database_id, &now)?;
    }
    Ok(())
}

fn migrate_database(
    transaction: &Transaction,
    database_id: &str,
    now: &str,
) -> rusqlite::Result<()> {
    // §2.3.1: словарь из dictionary_configs; sources[] дополняются reason
    // (в старом формате её не было) — фильтры и категории копируются как есть.
    let legacy: Option<(String, String)> = transaction
        .query_row(
            "SELECT mode, source_paths_json FROM dictionary_configs WHERE database_id=?1",
            [database_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();
    let mut sources_written = 0usize;
    let dictionary_json = match legacy {
        Some((mode, paths_json)) => {
            let mut sources = Vec::new();
            if let Value::Array(items) =
                serde_json::from_str::<Value>(&paths_json).unwrap_or(Value::Null)
            {
                for item in items {
                    let source_path = item["source_path"].as_str().unwrap_or_default();
                    if source_path.is_empty() {
                        continue;
                    }
                    let mut map = serde_json::Map::new();
                    map.insert(
                        "source_path".to_string(),
                        Value::String(source_path.to_string()),
                    );
                    map.insert(
                        "category".to_string(),
                        item.get("category")
                            .cloned()
                            .unwrap_or(Value::String(String::new())),
                    );
                    map.insert(
                        "reason".to_string(),
                        Value::String(MIGRATION_REASON.to_string()),
                    );
                    //++agent TASK-225 [26.09.2026] D7: null не
                    // прописываем — stored-форма без ключа.
                    if let Some(filter) = non_null_filter(item.get("filter_ast")) {
                        map.insert("filter_ast".to_string(), filter);
                    }
                    sources.push(Value::Object(map));
                }
            }
            sources_written = sources.len();
            serde_json::to_string(&serde_json::json!({
                "mode": mode,
                "sources": sources,
            }))
            .unwrap_or_else(|_| "{\"mode\":\"part\",\"sources\":[]}".to_string())
        }
        None => "{\"mode\":\"part\",\"sources\":[]}".to_string(),
    };

    //++agent TASK-225 [26.09.2026] MINOR-4: несколько active у одной
    // базы до миграции невозможны по контракту, но возможны по данным —
    // частичный уникальный индекс (POST-DATA) иначе роняет старт.
    // Каноническая — версия, на которую ссылается
    // databases.active_policy_id; без ссылки — максимальная version.
    // Остальные active → retired до заполнения словаря.
    transaction.execute(
        "UPDATE policies SET status='retired', discarded_at=?2
         WHERE database_id=?1 AND status='active' AND id <> COALESCE(
           (SELECT p.id FROM policies p
            JOIN databases d ON d.active_policy_id = p.id
            WHERE p.database_id=?1 AND p.status='active'),
           (SELECT id FROM policies WHERE database_id=?1 AND status='active'
            ORDER BY version DESC LIMIT 1))",
        params![database_id, now],
    )?;
    //++agent TASK-225

    // §2.3.2: активная версия получает словарь, если он ещё NULL.
    transaction.execute(
        "UPDATE policies SET dictionary_json=?2, updated_at=COALESCE(updated_at,?3)
         WHERE database_id=?1 AND status='active' AND dictionary_json IS NULL",
        params![database_id, dictionary_json, now],
    )?;

    // §2.3.3: активной нет, а источники были → создаём новую активную
    // версию, чтобы настройка не потерялась.
    let has_active: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM policies WHERE database_id=?1 AND status='active')",
        [database_id],
        |row| row.get(0),
    )?;
    if !has_active && sources_written > 0 {
        let next: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(version),0)+1 FROM policies WHERE database_id=?1",
            [database_id],
            |row| row.get(0),
        )?;
        let policy_id = Uuid::new_v4();
        transaction.execute(
            "INSERT INTO policies(id,database_id,version,status,created_at,updated_at,
               origin,dictionary_json,activated_at,activated_by)
             VALUES (?1,?2,?3,'active',?4,?4,'migration',?5,?4,'migration')",
            params![
                policy_id.to_string(),
                database_id,
                next,
                now,
                dictionary_json
            ],
        )?;
        transaction.execute(
            "UPDATE databases SET active_policy_id=?2, updated_at=?3 WHERE id=?1",
            params![database_id, policy_id.to_string(), now],
        )?;
    }

    // §2.3.4: draft'ы — словарь тем же (NULL), лишние draft → retired
    // (индекс один-черновик вступит в силу после переноса).
    transaction.execute(
        "UPDATE policies SET dictionary_json=?2
         WHERE database_id=?1 AND status='draft' AND dictionary_json IS NULL",
        params![database_id, dictionary_json],
    )?;
    let draft_ids: Vec<String> = {
        let mut statement = transaction.prepare(
            //++agent TASK-225 [26.09.2026] MINOR-4: выживает новейший
            // draft по version (спека §2.3.4), не по created_at.
            //++agent TASK-225
            "SELECT id FROM policies WHERE database_id=?1 AND status='draft' ORDER BY version DESC, id",
        )?;
        let rows = statement
            .query_map([database_id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for extra in draft_ids.iter().skip(1) {
        transaction.execute(
            "UPDATE policies SET status='retired', discarded_at=?2 WHERE id=?1",
            params![extra, now],
        )?;
    }

    // §2.3.5: retired без словаря — словарь версии приблизительный
    // (снимок на момент миграции, не на момент выхода версии) — флаг
    // фиксируем в журнальной записи базы.
    let retired_filled = transaction.execute(
        "UPDATE policies SET dictionary_json=?2
         WHERE database_id=?1 AND status='retired' AND dictionary_json IS NULL",
        params![database_id, dictionary_json],
    )?;

    // §2.3.6: content_hash для всех версий базы.
    fill_content_hashes(transaction, database_id)?;

    // §2.3.7: журнальная запись миграции.
    let details = serde_json::json!({
        "sources": sources_written,
        "approximate": retired_filled > 0,
    });
    transaction.execute(
        "INSERT INTO setup_journal(database_id,at,actor_kind,action,details_json)
         VALUES (?1,?2,'system','migration',?3)",
        params![database_id, now, details.to_string()],
    )?;
    Ok(())
}

/// §2.4/§2.3.6: пересчёт content_hash для всех версий базы без хэша.
pub(crate) fn fill_content_hashes(
    transaction: &Transaction,
    database_id: &str,
) -> rusqlite::Result<()> {
    let ids: Vec<String> = {
        let mut statement = transaction
            .prepare("SELECT id FROM policies WHERE database_id=?1 AND content_hash IS NULL")?;
        let rows = statement
            .query_map([database_id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for id in ids {
        let content = version_content(transaction, &id)?;
        transaction.execute(
            "UPDATE policies SET content_hash=?2 WHERE id=?1",
            params![id, content_hash(&content)],
        )?;
    }
    Ok(())
}

/// Контент версии: dictionary_json + правила + tools_json.
pub(crate) fn version_content(
    transaction: &Transaction,
    policy_id: &str,
) -> rusqlite::Result<VersionContent> {
    let row: Option<(Option<String>, Option<String>)> = transaction
        .query_row(
            "SELECT dictionary_json, tools_json FROM policies WHERE id=?1",
            [policy_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();
    let (dictionary_json, tools_json) = row.unwrap_or((None, None));
    let dictionary = parse_dictionary_json(dictionary_json.as_deref());
    let tools = tools_json
        .as_deref()
        .and_then(|text| serde_json::from_str::<Vec<ToolSpec>>(text).ok());
    let rules = version_rules(transaction, policy_id)?;
    Ok(VersionContent {
        dictionary,
        rules,
        tools,
    })
}

/// Контент версии через готовое соединение (для read-путей вне tx).
#[allow(dead_code)]
pub(crate) fn version_content_conn(
    connection: &rusqlite::Connection,
    policy_id: &str,
) -> rusqlite::Result<VersionContent> {
    let row: Option<(Option<String>, Option<String>)> = connection
        .query_row(
            "SELECT dictionary_json, tools_json FROM policies WHERE id=?1",
            [policy_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();
    let (dictionary_json, tools_json) = row.unwrap_or((None, None));
    let rules = {
        let mut statement = connection.prepare(
            "SELECT id,selector_kind,selector_value,action,category,priority,enabled,reason,tests_json
             FROM policy_rules WHERE policy_id=?1",
        )?;
        let rows = statement.query_map([policy_id], |row| {
            let tests_json: Option<String> = row.get(8)?;
            Ok(StoredVersionRule {
                id: parse_uuid(row.get::<_, String>(0)?)?,
                selector: row.get(1)?,
                value: row.get(2)?,
                action: row.get(3)?,
                category: row.get(4)?,
                priority: row.get(5)?,
                enabled: row.get::<_, i64>(6)? != 0,
                reason: row.get(7)?,
                tests: tests_json.and_then(|text| serde_json::from_str(&text).ok()),
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(VersionContent {
        dictionary: parse_dictionary_json(dictionary_json.as_deref()),
        rules: rules.iter().map(stored_rule_to_spec).collect(),
        tools: tools_json
            .as_deref()
            .and_then(|text| serde_json::from_str::<Vec<ToolSpec>>(text).ok()),
    })
}

fn version_rules(transaction: &Transaction, policy_id: &str) -> rusqlite::Result<Vec<RuleSpec>> {
    let mut statement = transaction.prepare(
        "SELECT id,selector_kind,selector_value,action,category,priority,enabled,reason,tests_json
         FROM policy_rules WHERE policy_id=?1",
    )?;
    let rows = statement.query_map([policy_id], |row| {
        let tests_json: Option<String> = row.get(8)?;
        Ok(StoredVersionRule {
            id: parse_uuid(row.get::<_, String>(0)?)?,
            selector: row.get(1)?,
            value: row.get(2)?,
            action: row.get(3)?,
            category: row.get(4)?,
            priority: row.get(5)?,
            enabled: row.get::<_, i64>(6)? != 0,
            reason: row.get(7)?,
            tests: tests_json.and_then(|text| serde_json::from_str(&text).ok()),
        })
    })?;
    let rules = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rules.iter().map(stored_rule_to_spec).collect())
}

fn stored_rule_to_spec(rule: &StoredVersionRule) -> RuleSpec {
    RuleSpec {
        rule_id: Some(rule.id.to_string()),
        selector: rule.selector.clone(),
        value: rule.value.clone(),
        action: rule.action.clone(),
        category: rule.category.clone(),
        priority: rule.priority,
        enabled: rule.enabled,
        reason: rule.reason.clone().unwrap_or_default(),
        tests: rule
            .tests
            .clone()
            .and_then(|value| serde_json::from_value::<RuleTestsSpec>(value).ok()),
    }
}

fn parse_dictionary_json(text: Option<&str>) -> VersionDictionary {
    let Some(text) = text else {
        return VersionDictionary {
            mode: "part".to_string(),
            sources: Vec::new(),
        };
    };
    let value: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    let mode = value["mode"].as_str().unwrap_or("part").to_string();
    let sources = value["sources"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(DictionarySourceSpec {
                        source_path: item["source_path"].as_str()?.to_string(),
                        category: item["category"].as_str().unwrap_or_default().to_string(),
                        filter_ast: non_null_filter(item.get("filter_ast")),
                        reason: item["reason"].as_str().unwrap_or_default().to_string(),
                        estimated_values: item["estimated_values"].as_i64(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    VersionDictionary { mode, sources }
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)
}

/// Загрузка версии по ссылке (`active|draft|<n>`) — с правилами.
pub(crate) fn load_version(
    connection: &rusqlite::Connection,
    database_id: Uuid,
    reference: &VersionRef,
) -> rusqlite::Result<Option<StoredVersion>> {
    const COLUMNS: &str =
        "id,version,status,dictionary_json,tools_json,origin,origin_ref,created_by,
                created_at,updated_at,content_hash,activated_at,activated_by,comment,discarded_at";
    let (sql, binds): (String, Vec<String>) = match reference {
        VersionRef::Active => (
            format!("SELECT {COLUMNS} FROM policies WHERE database_id=?1 AND status='active'"),
            vec![database_id.to_string()],
        ),
        VersionRef::Draft => (
            format!("SELECT {COLUMNS} FROM policies WHERE database_id=?1 AND status='draft'"),
            vec![database_id.to_string()],
        ),
        VersionRef::Number(number) => (
            format!("SELECT {COLUMNS} FROM policies WHERE database_id=?1 AND version=?2"),
            vec![database_id.to_string(), number.to_string()],
        ),
    };
    let mut statement = connection.prepare(&sql)?;
    let version = statement
        .query_row(rusqlite::params_from_iter(binds.iter()), |row| {
            Ok(StoredVersion {
                id: parse_uuid(row.get::<_, String>(0)?)?,
                version: row.get(1)?,
                status: row.get(2)?,
                dictionary_json: row.get(3)?,
                tools_json: row.get(4)?,
                origin: row.get(5)?,
                origin_ref: row.get(6)?,
                created_by: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
                content_hash: row.get(10)?,
                activated_at: row.get(11)?,
                activated_by: row.get(12)?,
                comment: row.get(13)?,
                discarded_at: row.get(14)?,
                rules: Vec::new(),
            })
        })
        .optional()?;
    let Some(mut version) = version else {
        return Ok(None);
    };
    let mut statement = connection.prepare(
        "SELECT id,selector_kind,selector_value,action,category,priority,enabled,reason,tests_json
         FROM policy_rules WHERE policy_id=?1",
    )?;
    let rules = statement
        .query_map([version.id.to_string()], |row| {
            let tests_json: Option<String> = row.get(8)?;
            Ok(StoredVersionRule {
                id: parse_uuid(row.get::<_, String>(0)?)?,
                selector: row.get(1)?,
                value: row.get(2)?,
                action: row.get(3)?,
                category: row.get(4)?,
                priority: row.get(5)?,
                enabled: row.get::<_, i64>(6)? != 0,
                reason: row.get(7)?,
                tests: tests_json.and_then(|text| serde_json::from_str(&text).ok()),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    version.rules = rules;
    Ok(Some(version))
}

/// Строка списка версий (D2): метаданные без контента + логин автора.
pub(crate) struct VersionListRow {
    pub version: i64,
    pub status: String,
    pub origin: String,
    pub created_at: String,
    pub updated_at: Option<String>,
    pub activated_at: Option<String>,
    pub created_by_login: Option<String>,
    pub content_hash: Option<String>,
}

/// D2: метаданные всех версий базы (author/date для UI), контент не грузится.
pub(crate) fn list_versions(
    connection: &rusqlite::Connection,
    database_id: Uuid,
) -> rusqlite::Result<Vec<VersionListRow>> {
    let mut statement = connection.prepare(
        "SELECT p.version,p.status,p.origin,p.created_at,p.updated_at,p.activated_at,p.content_hash,
                (SELECT u.display_login FROM users u WHERE u.id=p.created_by)
         FROM policies p WHERE p.database_id=?1 ORDER BY p.version DESC",
    )?;
    let rows = statement.query_map([database_id.to_string()], |row| {
        Ok(VersionListRow {
            version: row.get(0)?,
            status: row.get(1)?,
            origin: row.get(2)?,
            created_at: row.get(3)?,
            updated_at: row.get(4)?,
            activated_at: row.get(5)?,
            content_hash: row.get(6)?,
            created_by_login: row.get(7)?,
        })
    })?;
    rows.collect()
}

/// Контент StoredVersion → доменная модель (для diff/экспорта).
pub(crate) fn stored_version_content(version: &StoredVersion) -> VersionContent {
    VersionContent {
        dictionary: parse_dictionary_json(version.dictionary_json.as_deref()),
        rules: version.rules.iter().map(stored_rule_to_spec).collect(),
        tools: version
            .tools_json
            .as_deref()
            .and_then(|text| serde_json::from_str::<Vec<ToolSpec>>(text).ok()),
    }
}

//++agent TASK-225 [26.09.2026] review MAJOR-5
/// Контент ЦЕЛЕВОЙ (to) версии для diff/активации: `dictionary_json
/// IS NULL` у legacy-черновика (`create_policy` не пишет словарь)
/// означает «не задано», а не «явный пустой список» — наследуем
/// словарь `from`, иначе каждый источник активной версии давал бы
/// фантомный SOURCE_REMOVED и legacy-барьер блокировался без канала
/// подтверждения. Явно записанный `"sources":[]` остаётся реальным
/// удалением.
pub(crate) fn stored_version_content_for_to(
    version: &StoredVersion,
    from: &VersionContent,
) -> VersionContent {
    let mut content = stored_version_content(version);
    if version.dictionary_json.is_none() {
        content.dictionary = from.dictionary.clone();
    }
    content
}
//--agent TASK-225

/// §2.5: словарь активной версии (dictionary_json policies) — источник
/// истины селекторов pull; `None` → читать legacy `dictionary_configs`.
pub(crate) fn active_dictionary_json(
    connection: &rusqlite::Connection,
    database_id: Uuid,
) -> rusqlite::Result<Option<String>> {
    Ok(connection
        .query_row(
            "SELECT dictionary_json FROM policies WHERE database_id=?1 AND status='active'",
            [database_id.to_string()],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten())
}

/// Пустой контент (нет версии — для diff `from`).
pub(crate) fn empty_content() -> VersionContent {
    VersionContent {
        dictionary: VersionDictionary {
            mode: "part".to_string(),
            sources: Vec::new(),
        },
        rules: Vec::new(),
        tools: None,
    }
}

/// dictionary_json версии → stored-форма строки для policies.
pub(crate) fn dictionary_to_json(dictionary: &VersionDictionary) -> String {
    let sources: Vec<Value> = dictionary
        .sources
        .iter()
        .map(|source| {
            let mut map = serde_json::Map::new();
            map.insert(
                "source_path".to_string(),
                Value::String(source.source_path.clone()),
            );
            map.insert(
                "category".to_string(),
                Value::String(source.category.clone()),
            );
            map.insert("reason".to_string(), Value::String(source.reason.clone()));
            if let Some(filter) = &source.filter_ast {
                map.insert("filter_ast".to_string(), filter.clone());
            }
            if let Some(estimated) = source.estimated_values {
                map.insert("estimated_values".to_string(), Value::from(estimated));
            }
            Value::Object(map)
        })
        .collect();
    serde_json::json!({"mode": dictionary.mode, "sources": sources}).to_string()
}

pub(crate) fn tools_to_json(tools: &[ToolSpec]) -> String {
    serde_json::to_string(
        &tools
            .iter()
            .map(|tool| {
                serde_json::json!({"tool": tool.tool, "mode": tool.mode, "reason": tool.reason})
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string())
}

/// Запись контента версии в уже открытой транзакции: полная замена
/// policy_rules + dictionary_json/tools_json + content_hash/updated_at.
pub(crate) fn write_version_content(
    transaction: &Transaction,
    policy_id: Uuid,
    content: &VersionContent,
    now: &str,
) -> rusqlite::Result<()> {
    transaction.execute(
        "DELETE FROM policy_rules WHERE policy_id=?1",
        [policy_id.to_string()],
    )?;
    for rule in &content.rules {
        transaction.execute(
            "INSERT INTO policy_rules(id,policy_id,selector_kind,selector_value,action,category,priority,enabled,reason,tests_json,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                //++agent TASK-225 [26.09.2026] D4: id — глобальный PK,
                // всегда новый. rule_id версии-источника наследовать нельзя:
                // копия (черновик из активной/откат/импорт) попадала бы на
                // UNIQUE-конфликт с живой строкой другой версии. created_at
                // обязателен (NOT NULL без DEFAULT) — без него был 503.
                Uuid::new_v4().to_string(),
                //++agent TASK-225
                policy_id.to_string(),
                rule.selector,
                rule.value,
                rule.action,
                rule.category,
                rule.priority,
                if rule.enabled { 1 } else { 0 },
                rule.reason,
                rule.tests
                    .as_ref()
                    .and_then(|tests| serde_json::to_string(tests).ok()),
                now,
            ],
        )?;
    }
    transaction.execute(
        "UPDATE policies SET dictionary_json=?2, tools_json=?3, content_hash=?4, updated_at=?5
         WHERE id=?1",
        params![
            policy_id.to_string(),
            dictionary_to_json(&content.dictionary),
            content.tools.as_ref().map(|tools| tools_to_json(tools)),
            content_hash(content),
            now,
        ],
    )?;
    Ok(())
}

/// Журнальная запись §2.2 setup_journal в открытой транзакции.
#[allow(clippy::too_many_arguments)]
pub(crate) fn journal_insert(
    transaction: &Transaction,
    database_id: Uuid,
    actor_kind: &str,
    actor_id: Option<Uuid>,
    action: &str,
    version: Option<i64>,
    file_name: Option<&str>,
    sha256: Option<&str>,
    details: Option<Value>,
    now: &str,
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO setup_journal(database_id,at,actor_kind,actor_id,action,version,file_name,sha256,details_json)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            database_id.to_string(),
            now,
            actor_kind,
            actor_id.map(|id| id.to_string()),
            action,
            version,
            file_name,
            sha256,
            details.map(|value| value.to_string()),
        ],
    )?;
    Ok(())
}

/// Реестр импортов §2.2 setup_imports.
#[allow(clippy::too_many_arguments)]
pub(crate) fn import_insert(
    transaction: &Transaction,
    database_id: Uuid,
    actor_id: Uuid,
    file_name: Option<&str>,
    sha256: &str,
    size_bytes: usize,
    generated_by: Option<&GeneratedBy>,
    database_hint: Option<&Value>,
    result: &str,
    error_codes: &[String],
    draft_policy_id: Option<Uuid>,
    now: &str,
) -> rusqlite::Result<Uuid> {
    let import_id = Uuid::new_v4();
    transaction.execute(
        "INSERT INTO setup_imports(id,database_id,actor_id,file_name,sha256,size_bytes,schema,
           generated_by_json,database_hint_json,result,error_codes_json,draft_policy_id,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,'masking-setup/v1',?7,?8,?9,?10,?11,?12)",
        params![
            import_id.to_string(),
            database_id.to_string(),
            actor_id.to_string(),
            file_name,
            sha256,
            size_bytes.min(i64::MAX as usize) as i64,
            generated_by.and_then(|value| serde_json::to_string(value).ok()),
            database_hint.map(|value| value.to_string()),
            result,
            serde_json::to_string(error_codes).unwrap_or_else(|_| "[]".to_string()),
            draft_policy_id.map(|id| id.to_string()),
            now,
        ],
    )?;
    Ok(import_id)
}

/// Текущий draft (если есть) для базы в транзакции.
pub(crate) fn draft_row(
    transaction: &Transaction,
    database_id: Uuid,
) -> rusqlite::Result<Option<(Uuid, i64, Option<String>)>> {
    transaction
        .query_row(
            "SELECT id, version, content_hash FROM policies WHERE database_id=?1 AND status='draft'",
            [database_id.to_string()],
            |row| Ok((parse_uuid(row.get::<_, String>(0)?)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
}

/// Следующий номер версии базы.
pub(crate) fn next_version(transaction: &Transaction, database_id: Uuid) -> rusqlite::Result<i64> {
    transaction.query_row(
        "SELECT COALESCE(MAX(version),0)+1 FROM policies WHERE database_id=?1",
        [database_id.to_string()],
        |row| row.get(0),
    )
}

/// Создание черновика в открытой транзакции.
#[allow(clippy::too_many_arguments)]
pub(crate) fn insert_draft(
    transaction: &Transaction,
    database_id: Uuid,
    origin: &str,
    origin_ref: Option<&str>,
    created_by: Option<Uuid>,
    content: &VersionContent,
    now: &str,
) -> rusqlite::Result<(Uuid, i64)> {
    let policy_id = Uuid::new_v4();
    let version = next_version(transaction, database_id)?;
    transaction.execute(
        "INSERT INTO policies(id,database_id,version,status,created_at,updated_at,origin,origin_ref,created_by)
         VALUES (?1,?2,?3,'draft',?4,?4,?5,?6,?7)",
        params![
            policy_id.to_string(),
            database_id.to_string(),
            version,
            now,
            origin,
            origin_ref,
            created_by.map(|id| id.to_string()),
        ],
    )?;
    write_version_content(transaction, policy_id, content, now)?;
    Ok((policy_id, version))
}

/// Текущие классы инструментов → форма `tools` файла/версии
/// (`tool_classifications` — живое состояние, не снимок версии).
pub(crate) fn current_tools(
    connection: &rusqlite::Connection,
    database_id: Uuid,
) -> rusqlite::Result<Vec<ToolSpec>> {
    let mut statement = connection.prepare(
        "SELECT tool_name,class FROM tool_classifications WHERE database_id=?1 ORDER BY tool_name",
    )?;
    let rows = statement.query_map([database_id.to_string()], |row| {
        Ok(ToolSpec {
            tool: row.get(0)?,
            mode: row.get(1)?,
            reason: "экспортирована текущая классификация".to_string(),
        })
    })?;
    rows.collect()
}

/// §5a.3: статистика источников последнего успешного pull
/// (`cache_generations.source_stats_json`) → {source_path lowercase →
/// values}; нет данных — None.
pub(crate) fn last_source_stats(
    connection: &rusqlite::Connection,
    database_id: Uuid,
) -> rusqlite::Result<Option<std::collections::HashMap<String, crate::domain::setup::SourceStat>>> {
    let text: Option<String> = connection
        .query_row(
            "SELECT source_stats_json FROM cache_generations
             WHERE database_id=?1 AND status='active'",
            [database_id.to_string()],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    let Some(text) = text else {
        return Ok(None);
    };
    let Ok(items) = serde_json::from_str::<Vec<Value>>(&text) else {
        return Ok(None);
    };
    Ok(Some(
        items
            .iter()
            .filter_map(|item| {
                Some((
                    item["source_path"].as_str()?.to_lowercase(),
                    crate::domain::setup::SourceStat {
                        values: item["values"].as_i64().unwrap_or(0),
                        bytes: item["bytes"].as_i64().unwrap_or(0),
                    },
                ))
            })
            .collect(),
    ))
}

//++agent TASK-225

/// §3.6/B7 шаг 6: удаление элементов `to`-контента, на которые указывают
/// исключённые предупреждения. `id` не из списка предупреждений или
/// неисключаемое → Err(unknown). Возвращает применённые id.
pub(crate) fn apply_warning_exclusions(
    content: &mut VersionContent,
    warnings: &[crate::domain::setup::SetupWarning],
    excluded_ids: &[String],
) -> Result<Vec<String>, Vec<String>> {
    let index: std::collections::HashMap<&str, &crate::domain::setup::SetupWarning> = warnings
        .iter()
        .map(|warning| (warning.id.as_str(), warning))
        .collect();
    let mut applied = Vec::new();
    let mut unknown = Vec::new();
    for id in excluded_ids {
        match index.get(id.as_str()) {
            Some(warning) if warning.excludable => {
                apply_subject_removal(content, &warning.subject);
                applied.push(id.clone());
            }
            // известное, но неисключаемое — отдельный код на уровне API
            Some(_) => unknown.push(id.clone()),
            None => unknown.push(id.clone()),
        }
    }
    if unknown.is_empty() {
        Ok(applied)
    } else {
        Err(unknown)
    }
}

/// Удаление элемента контента по subject предупреждения §3.6.
fn apply_subject_removal(content: &mut VersionContent, subject: &Value) {
    match subject["area"].as_str() {
        Some("rule") => {
            let selector = subject["selector"].as_str().unwrap_or_default();
            let key = subject["key"].as_str().unwrap_or_default();
            content.rules.retain(|rule| {
                !(rule.selector == selector && rule_key(&rule.selector, &rule.value) == key)
            });
        }
        Some("dictionary") => {
            let path = subject["source_path"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase();
            content
                .dictionary
                .sources
                .retain(|source| source.source_path.to_lowercase() != path);
        }
        Some("tool") => {
            let tool = subject["tool"].as_str().unwrap_or_default();
            if let Some(tools) = &mut content.tools {
                tools.retain(|item| item.tool != tool);
            }
        }
        _ => {}
    }
}

/// B7 шаг 5 / B8 revert: откат изменений к состоянию `from` — элемент
/// восстанавливается из `before` (удаляется, если его не было). Возвращает
/// применённые id; неизвестный id → Err.
pub(crate) fn apply_change_reverts(
    content: &mut VersionContent,
    changes: &[crate::domain::setup::SetupChange],
    change_ids: &[String],
) -> Result<Vec<String>, Vec<String>> {
    let index: std::collections::HashMap<&str, &crate::domain::setup::SetupChange> = changes
        .iter()
        .map(|change| (change.id.as_str(), change))
        .collect();
    let mut applied = Vec::new();
    let mut unknown = Vec::new();
    for id in change_ids {
        match index.get(id.as_str()) {
            Some(change) if revert_element(content, change) => applied.push(id.clone()),
            // Известный id без применимого элемента — как неизвестный:
            // API отвечает UNKNOWN_CHANGE, а не имитирует откат.
            Some(_) | None => unknown.push(id.clone()),
        }
    }
    if unknown.is_empty() {
        Ok(applied)
    } else {
        Err(unknown)
    }
}

/// Восстановление элемента по карточке изменения: `before`=null →
/// элемент удаляется из черновика (его не было), иначе — вставляется
/// `before` взамен `after` (точная замена по идентичности). `false` —
/// изменение не относится к элементу (DICTIONARY_MODE_*/CATEGORY_WEAKER
/// и прочие беспредметные) либо нечего применять: caller отвечает
/// UNKNOWN_CHANGE вместо молчаливого «applied» (review MAJOR-3/4).
fn revert_element(
    content: &mut VersionContent,
    change: &crate::domain::setup::SetupChange,
) -> bool {
    let subject = &change.subject.clone().unwrap_or(Value::Null);
    match change.area.as_str() {
        "rule" => {
            let selector = subject["selector"].as_str().unwrap_or_default().to_string();
            if selector.is_empty() {
                return false;
            }
            // key предпочтительнее из before/after value — subject.key
            // есть только у новых карточек; fallback — value.
            let after_value = change
                .after
                .as_ref()
                .and_then(|value| value["value"].as_str())
                .unwrap_or_default()
                .to_string();
            let before_value = change
                .before
                .as_ref()
                .and_then(|value| value["value"].as_str())
                .unwrap_or_default()
                .to_string();
            let key_after = rule_key(&selector, &after_value);
            let key_before = rule_key(&selector, &before_value);
            content.rules.retain(|rule| {
                !(rule.selector == selector
                    && (rule_key(&rule.selector, &rule.value) == key_after
                        || rule_key(&rule.selector, &rule.value) == key_before))
            });
            if let Some(before) = &change.before {
                if let Some(rule) = spec_from_rule_json(before) {
                    content.rules.push(rule);
                }
            }
            true
        }
        "dictionary" => {
            let path = subject["source_path"]
                .as_str()
                .or_else(|| {
                    change
                        .after
                        .as_ref()
                        .and_then(|v| v["source_path"].as_str())
                })
                .or_else(|| {
                    change
                        .before
                        .as_ref()
                        .and_then(|v| v["source_path"].as_str())
                })
                .unwrap_or_default()
                .to_lowercase();
            if path.is_empty() {
                return false;
            }
            content
                .dictionary
                .sources
                .retain(|source| source.source_path.to_lowercase() != path);
            if let Some(before) = &change.before {
                if let Some(source) = spec_from_source_json(before) {
                    content.dictionary.sources.push(source);
                }
            }
            true
        }
        "tool" => {
            let tool = subject["tool"].as_str().unwrap_or_default();
            let Some(tools) = &mut content.tools else {
                return false;
            };
            if tool.is_empty() {
                return false;
            }
            tools.retain(|item| item.tool != tool);
            if let Some(before) = &change.before {
                //++agent TASK-225 [26.09.2026] review MAJOR-3: before несёт
                // только {"mode":…}; имя инструмента — из subject. Запись
                // tool:"" попадала бы в tool_classifications при активации.
                if let Some(mode) = before["mode"].as_str() {
                    tools.push(ToolSpec {
                        tool: tool.to_string(),
                        mode: mode.to_string(),
                        reason: before["reason"].as_str().unwrap_or_default().to_string(),
                    });
                }
            }
            true
        }
        _ => false,
    }
}

/// rule_json (§3.7 before/after форма) → RuleSpec.
fn spec_from_rule_json(value: &Value) -> Option<RuleSpec> {
    Some(RuleSpec {
        rule_id: None,
        selector: value["selector"].as_str()?.to_string(),
        value: value["value"].as_str()?.to_string(),
        action: value["action"].as_str()?.to_string(),
        category: value["category"].as_str()?.to_string(),
        priority: value["priority"].as_i64().unwrap_or(0),
        enabled: value["enabled"].as_bool().unwrap_or(true),
        reason: value["reason"].as_str().unwrap_or_default().to_string(),
        tests: value
            .get("tests")
            .and_then(|v| serde_json::from_value::<RuleTestsSpec>(v.clone()).ok()),
    })
}

//++agent TASK-225 [26.09.2026] D7: хранимый `"filter_ast":null` —
/// это отсутствие фильтра, а не AST: `Some(Null)` иначе доезжал до
/// экспорта как `"filter":null` и импорт того же файла отклонял
/// `SETUP_FILTER_INVALID`. Читаем Null как отсутствие.
fn non_null_filter(value: Option<&Value>) -> Option<Value> {
    value.filter(|v| !v.is_null()).cloned()
}
//++agent TASK-225

/// source_json → DictionarySourceSpec.
fn spec_from_source_json(value: &Value) -> Option<DictionarySourceSpec> {
    Some(DictionarySourceSpec {
        source_path: value["source_path"].as_str()?.to_string(),
        category: value["category"].as_str()?.to_string(),
        filter_ast: non_null_filter(value.get("filter_ast")),
        reason: value["reason"].as_str().unwrap_or_default().to_string(),
        estimated_values: value["estimated_values"].as_i64(),
    })
}

/// F8: включённое secret-правило в контенте.
pub(crate) fn has_enabled_secret(content: &VersionContent) -> bool {
    content
        .rules
        .iter()
        .any(|rule| rule.enabled && rule.action == "secret")
}

/// B7 шаг 10: переключение черновика в активную версию в открытой
/// транзакции — статусы, указатель базы, зеркало dictionary_configs
/// (§2.5 переходный мост для старых путей чтения), refresh intent.
pub(crate) fn activate_draft_tx(
    transaction: &Transaction,
    database_id: Uuid,
    draft_id: Uuid,
    actor_id: Option<Uuid>,
    comment: Option<&str>,
    now: &str,
) -> rusqlite::Result<i64> {
    transaction.execute(
        "UPDATE policies SET status='retired' WHERE database_id=?1 AND status='active'",
        [database_id.to_string()],
    )?;
    let version: i64 = transaction.query_row(
        "SELECT version FROM policies WHERE id=?1 AND database_id=?2 AND status='draft'",
        params![draft_id.to_string(), database_id.to_string()],
        |row| row.get(0),
    )?;
    transaction.execute(
        "UPDATE policies SET status='active',activated_at=?3,activated_by=?4,comment=?5,
         updated_at=?3 WHERE id=?1 AND database_id=?2",
        params![
            draft_id.to_string(),
            database_id.to_string(),
            now,
            actor_id.map(|id| id.to_string()),
            comment,
        ],
    )?;
    transaction.execute(
        "UPDATE databases SET active_policy_id=?2,updated_at=?3 WHERE id=?1",
        params![database_id.to_string(), draft_id.to_string(), now],
    )?;
    // §2.5: зеркало dictionary_configs — переходная совместимость для
    // потребителей, ещё читающих legacy-таблицу (источник истины —
    // policies.dictionary_json активной версии).
    let dictionary_json: Option<String> = transaction.query_row(
        "SELECT dictionary_json FROM policies WHERE id=?1",
        [draft_id.to_string()],
        |row| row.get(0),
    )?;
    if let Some(text) = dictionary_json {
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            let mode = value["mode"].as_str().unwrap_or("part");
            let selectors: Vec<Value> = value["sources"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|item| {
                            let mut selector = serde_json::Map::new();
                            selector.insert("source_path".into(), item["source_path"].clone());
                            selector.insert("category".into(), item["category"].clone());
                            //++agent TASK-225 [26.09.2026] D7: null не
                            // прописываем в селекторы.
                            if let Some(filter) = non_null_filter(item.get("filter_ast")) {
                                selector.insert("filter_ast".into(), filter);
                            }
                            Value::Object(selector)
                        })
                        .collect()
                })
                .unwrap_or_default();
            transaction.execute(
                "INSERT INTO dictionary_configs(id,database_id,mode,source_paths_json,filter_ast_json,updated_at)
                 VALUES (?1,?2,?3,?4,NULL,?5)
                 ON CONFLICT(database_id) DO UPDATE SET mode=excluded.mode,source_paths_json=excluded.source_paths_json,updated_at=excluded.updated_at",
                params![
                    Uuid::new_v4().to_string(),
                    database_id.to_string(),
                    mode,
                    serde_json::to_string(&selectors)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    now,
                ],
            )?;
        }
    }
    //++agent TASK-225 [26.09.2026] M-1: tools_json версии применяется к
    // tool_classifications в той же транзакции (§2.5) — иначе
    // подтверждённая секция tools молча не действовала. Журнал —
    // по записи на каждый инструмент с изменением класса.
    //++agent TASK-225
    let tools_json: Option<String> = transaction.query_row(
        "SELECT tools_json FROM policies WHERE id=?1",
        [draft_id.to_string()],
        |row| row.get(0),
    )?;
    if let Some(text) = tools_json {
        if let Ok(tools) = serde_json::from_str::<Vec<ToolSpec>>(&text) {
            for tool in tools {
                let before: Option<String> = transaction
                    .query_row(
                        "SELECT class FROM tool_classifications WHERE database_id=?1 AND tool_name=?2",
                        params![database_id.to_string(), tool.tool],
                        |row| row.get(0),
                    )
                    .ok();
                transaction.execute(
                    "INSERT INTO tool_classifications(database_id,tool_name,class,reviewer,updated_at,auto_added)
                     VALUES (?1,?2,?3,?4,?5,0)
                     ON CONFLICT(database_id,tool_name) DO UPDATE SET class=excluded.class,
                     reviewer=excluded.reviewer,updated_at=excluded.updated_at,auto_added=0",
                    params![
                        database_id.to_string(),
                        tool.tool,
                        tool.mode,
                        actor_id.map(|id| id.to_string()),
                        now,
                    ],
                )?;
                if before.as_deref() != Some(tool.mode.as_str()) {
                    journal_insert(
                        transaction,
                        database_id,
                        "human",
                        actor_id,
                        "tool_mode",
                        Some(version),
                        None,
                        None,
                        Some(serde_json::json!({
                            "tool": tool.tool,
                            "before": before.unwrap_or_else(|| "deny-pending-review".to_string()),
                            "after": tool.mode,
                        })),
                        now,
                    )?;
                }
            }
        }
    }
    // §2.5/T2-06: pull-intent после активации — RAM пересобирается
    // тиком воркера (attempts сбрасываются — явное действие Admin, §8.1).
    transaction.execute(
        "INSERT INTO v2_refresh_intents(database_id,phase,reason,actor_id,created_at)
         VALUES (?1,'full','setup_activate',?2,?3)
         ON CONFLICT(database_id) DO UPDATE SET phase='full',reason=excluded.reason,
         actor_id=excluded.actor_id,created_at=excluded.created_at,
         attempts=0,state='pending',next_attempt_at=NULL",
        params![
            database_id.to_string(),
            actor_id.map(|id| id.to_string()),
            now
        ],
    )?;
    Ok(version)
}
//++agent TASK-225
