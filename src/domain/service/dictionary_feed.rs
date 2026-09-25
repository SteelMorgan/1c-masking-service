//++agent TASK-222 [05.10.2026]
//! Pull-модель загрузки metadata/dictionary: сервис сам вызывает internal
//! tools через manager UDS (`POST /internal/v1/tools/call`), собирает
//! страницы по opaque cursor до `final_chunk` и атомарно заменяет
//! `PolicySnapshot` только после полного успешного прогона.
//!
//! Заменяет удалённый v1 feed receiver (jobs/chunks/activate) и v2
//! lease-протокол: durable `v2_refresh_intents` — очередь refresh,
//! `cache_generations` — журнал прогонов.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::MaskingService;
use crate::domain::manifest::MAX_MANIFEST_ITEMS;
use crate::domain::{
    DatabaseMode, ErrorCode, FeedDictionaryValue, FeedMetadataItem, PolicyRule, PolicySnapshot,
    RefreshIntent, RuleAction, RuleSelector, ServiceError,
};
use crate::manager_client::{ManagerClient, ManagerClientError};
use crate::storage::valid_filter_ast;

const METADATA_TOOL: &str = "mcp_internal_masking_metadata_feed";
const DICTIONARY_TOOL: &str = "mcp_internal_masking_dictionary_feed";
const MAX_PAGES_PER_STREAM: u32 = 10_000;
const MAX_DICTIONARY_VALUES: usize = 1_000_000;
const MAX_DICTIONARY_VALUE_BYTES: usize = 1024 * 1024 * 1024;
const MAX_DICTIONARY_SOURCE_PATHS: usize = 100;
const MAX_SELECTOR_COUNT: usize = 100;
const MAX_CURSOR_BYTES: usize = 1024 * 1024;

/// Страница internal feed инструмента (совпадает с BSL `РезультатFeed`/
/// `ОшибкаFeed` и бывшим `FeedPage` менеджера).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FeedPage {
    success: bool,
    metadata: Vec<FeedMetadataItem>,
    dictionary_values: Vec<FeedDictionaryValue>,
    next_cursor: Option<String>,
    final_chunk: bool,
    #[serde(default, alias = "error")]
    error_code: Option<String>,
    /// Опциональный producer digest (BSL не отдаёт — решение Р1(а)):
    /// принимается и записывается как declared evidence, не проверяется.
    #[serde(default)]
    manifest_digest: Option<String>,
}

/// Классификация сбоя pull: определяет судьбу durable intent и audit code.
/// `Transient` — повтор на следующем тике (менеджер/сессия недоступны или
/// инструмент вернул отказ; причина может уйти сама);
/// `Invalid` — детерминированная ошибка (форма страниц, лимиты, конфигурация,
/// политика), intent снимается, чтобы не крутить бесполезный retry;
/// `Skipped` — база не требует refresh (disabled/удалена).
#[derive(Debug)]
enum PullError {
    Transient(&'static str),
    Invalid(&'static str),
    Skipped,
}

impl PullError {
    fn code(&self) -> &'static str {
        match self {
            Self::Transient(code) | Self::Invalid(code) => code,
            Self::Skipped => "PULL_SKIPPED",
        }
    }
}

impl From<ManagerClientError> for PullError {
    fn from(error: ManagerClientError) -> Self {
        match error {
            ManagerClientError::Rejected { .. } => Self::Transient("INTERNAL_TOOL_FAILED"),
            ManagerClientError::Transport
            | ManagerClientError::Timeout
            | ManagerClientError::InvalidResponse => Self::Transient("MANAGER_UNAVAILABLE"),
        }
    }
}

/// Вытаскивает JSON-объект результата инструмента из `result` ответа
/// `/internal/v1/tools/call`: принимается `structured_content`, либо первый
/// `content[]` блок `{"type":"json","json":...}` или `{"type":"text","text":<json>}`;
/// голый объект страницы (для совместимости/тестов) — тоже допустим.
fn tool_result_value(result: &Value) -> Result<Value, PullError> {
    if let Some(structured) = result.get("structured_content") {
        if structured.is_object() {
            return Ok(structured.clone());
        }
    }
    if let Some(content) = result.get("content").and_then(Value::as_array) {
        if let Some(item) = content.first() {
            if item.get("type").and_then(Value::as_str) == Some("json") {
                if let Some(value) = item.get("json") {
                    return Ok(value.clone());
                }
            }
            if item.get("type").and_then(Value::as_str) == Some("text") {
                if let Some(text) = item.get("text").and_then(Value::as_str) {
                    return serde_json::from_str(text)
                        .map_err(|_| PullError::Invalid("RESULT_INVALID"));
                }
            }
        }
    }
    if result.get("success").is_some() {
        return Ok(result.clone());
    }
    Err(PullError::Invalid("RESULT_INVALID"))
}

struct PulledPages {
    metadata: Vec<FeedMetadataItem>,
    dictionary_values: Vec<FeedDictionaryValue>,
    manifest_digest: Option<String>,
}

fn metadata_selector() -> Value {
    json!({"mode": "all", "page_size": 1000})
}

/// Service-local digest собранного прогона: sha256 над канонизированным
/// (отсортированные ключи) `{metadata, dictionary_values}` — журнальный
/// идентификатор generation, не producer proof.
fn pull_digest(metadata: &[FeedMetadataItem], dictionary: &[FeedDictionaryValue]) -> String {
    let payload = json!({"metadata": metadata, "dictionary_values": dictionary});
    format!(
        "sha256:{:x}",
        Sha256::digest(canonical_value_bytes(&payload))
    )
}

/// Канонизация JSON: ключи объектов сортируются рекурсивно — digest не
/// зависит от порядка ключей на проводе.
fn canonical_value_bytes(value: &Value) -> Vec<u8> {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let sorted: BTreeMap<_, _> = object
                    .iter()
                    .map(|(key, value)| (key.clone(), sort(value)))
                    .collect();
                serde_json::to_value(sorted).unwrap_or(Value::Null)
            }
            Value::Array(array) => Value::Array(array.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sort(value)).unwrap_or_default()
}

/// Exact Mask SourcePath allowlist для All-expansion.
/// Wildcard-паттерны правил исключены — `*` никогда не expand-ится.
fn all_allowed_source_paths(rules: &[PolicyRule]) -> HashSet<&str> {
    rules
        .iter()
        .filter(|rule| {
            rule.selector == RuleSelector::SourcePath
                && rule.action == RuleAction::Mask
                && !rule.pattern.contains('*')
        })
        .map(|rule| rule.pattern.as_str())
        .collect()
}

/// Общий предикат eligible metadata source для All-expansion:
/// класс `Catalog.*`/`Справочник.*` (trusted manifest от BSL `ПолноеИмя()`
/// локализует имя класса) + тип String/Строка + `!password_mode` +
/// `!metadata_is_secret` + вхождение в Mask allowlist.
fn all_expandable_metadata(item: &FeedMetadataItem, allowed: &HashSet<&str>) -> bool {
    let field_type = item.field_type.to_lowercase();
    (item.source_path.starts_with("Catalog.") || item.source_path.starts_with("Справочник."))
        && (field_type.contains("string") || field_type.contains("строка"))
        && !item.password_mode
        && !metadata_is_secret(item)
        && allowed.contains(item.source_path.as_str())
}

fn metadata_is_secret(item: &FeedMetadataItem) -> bool {
    let name = format!("{} {}", item.field_name, item.source_path).to_lowercase();
    let compact: String = name
        .chars()
        .filter(|character| character.is_alphanumeric())
        .collect();
    [
        "password",
        "passwd",
        "secret",
        "access_token",
        "refresh_token",
        "api_key",
        "private_key",
        "authorization",
        "пароль",
        "токен",
        "секрет",
        "приватныйключ",
    ]
    .iter()
    .any(|marker| name.contains(marker) || compact.contains(&marker.replace('_', "")))
}

impl MaskingService {
    /// Один тик pull worker: выбирает ожидающие intents и последовательно
    /// выполняет pull по каждой базе. Возвращает число успешно
    /// обработанных refresh. Ошибка одного pull не останавливает тик.
    pub async fn refresh_due_intents(
        &self,
        client: &ManagerClient,
        limit: usize,
    ) -> Result<usize, ServiceError> {
        let intents = self
            .storage
            .pending_refresh_intents(limit)
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, Uuid::nil()))?;
        let mut completed = 0usize;
        for intent in intents {
            match self.pull_database(client, &intent).await {
                Ok(()) => {
                    completed += 1;
                }
                Err(PullError::Skipped) => {
                    let _ = self.storage.delete_refresh_intent(intent.database_id);
                }
                Err(error @ PullError::Invalid(_)) => {
                    let _ = self
                        .storage
                        .audit_feed_pull_failed(intent.database_id, error.code());
                    let _ = self.storage.delete_refresh_intent(intent.database_id);
                }
                Err(error @ PullError::Transient(_)) => {
                    // Intent остаётся — следующий тик повторит pull, старый
                    // snapshot при этом не тронут.
                    let _ = self
                        .storage
                        .audit_feed_pull_failed(intent.database_id, error.code());
                    //++agent TASK-225 [25.09.2026]
                    // Transient-отказы повторяются каждый тик без внешних
                    // симптомов — нужен журнальный след, иначе висячий pull
                    // невиден до ручного запроса к audit_events. Пишем
                    // один раз на instance intent-а (created_at) + код,
                    // иначе застрявший pull спамит лог каждым тиком.
                    {
                        let key = (intent.created_at.clone(), error.code());
                        let should_log = self
                            .feed_pull_log_dedup
                            .lock()
                            .map(|mut dedup| {
                                let changed = dedup.get(&intent.database_id) != Some(&key);
                                if changed {
                                    dedup.insert(intent.database_id, key);
                                }
                                changed
                            })
                            .unwrap_or(false);
                        if should_log {
                            tracing::warn!(
                                event = "feed_pull_failed",
                                database_id = %intent.database_id,
                                code = error.code(),
                            );
                        }
                    }
                    //++agent TASK-225
                }
            }
        }
        Ok(completed)
    }

    /// Полный pull для одной базы: metadata-страницы → расширение
    /// dictionary-селекторов (All по свежему манифесту) → dictionary-
    /// страницы → durable commit → атомарный RAM swap → снятие intent.
    async fn pull_database(
        &self,
        client: &ManagerClient,
        intent: &RefreshIntent,
    ) -> Result<(), PullError> {
        let database_id = intent.database_id;
        let settings = self
            .storage
            .database_settings(database_id)
            .map_err(|_| PullError::Transient("STORAGE_UNAVAILABLE"))?
            .ok_or(PullError::Skipped)?;
        if settings.mode != DatabaseMode::Enabled {
            return Err(PullError::Skipped);
        }
        let (version, rules) = if let Some(policy_id) = settings.active_policy_id.as_deref() {
            self.storage
                .active_policy(database_id, policy_id)
                .map_err(|_| PullError::Transient("STORAGE_UNAVAILABLE"))?
                .ok_or(PullError::Invalid("POLICY_INVALID"))?
        } else {
            (1, Vec::new())
        };
        // Старые активные Secret-политики не должны становиться ready —
        // детерминированная ошибка конфигурации.
        if rules.iter().any(|rule| rule.action == RuleAction::Secret) {
            return Err(PullError::Invalid("POLICY_INVALID"));
        }

        let metadata_pages = self
            .pull_pages(client, database_id, METADATA_TOOL, &metadata_selector())
            .await?;
        if !metadata_pages.dictionary_values.is_empty() {
            return Err(PullError::Invalid("RESULT_INVALID"));
        }
        let metadata = metadata_pages.metadata;
        if metadata.is_empty() {
            return Err(PullError::Invalid("METADATA_EMPTY"));
        }
        let declared_digest = metadata_pages.manifest_digest.unwrap_or_default();
        let password_paths: HashSet<&str> = metadata
            .iter()
            .filter(|item| item.password_mode)
            .map(|item| item.source_path.as_str())
            .collect();

        let selectors = self
            .dictionary_selectors(database_id, &metadata, &rules)
            .map_err(PullError::Invalid)?;
        let mut dictionary_values: Vec<FeedDictionaryValue> = Vec::new();
        let mut dictionary_bytes = 0usize;
        let mut dictionary_sources: HashSet<String> = HashSet::new();
        for selector in &selectors {
            let expected_source = selector["source_path"].as_str().unwrap_or_default();
            let expected_category = selector["category"].as_str().unwrap_or_default();
            let pages = self
                .pull_pages(client, database_id, DICTIONARY_TOOL, selector)
                .await?;
            if !pages.metadata.is_empty() {
                return Err(PullError::Invalid("RESULT_INVALID"));
            }
            for item in pages.dictionary_values {
                if item.value.len() > 2 * 1024 * 1024
                    || item.category.len() > 32
                    || item.source_path.len() > 512
                {
                    return Err(PullError::Invalid("FEED_DICTIONARY_VALUE_LIMIT"));
                }
                if item.source_path != expected_source || item.category != expected_category {
                    return Err(PullError::Invalid("FEED_DICTIONARY_SOURCE_MISMATCH"));
                }
                dictionary_sources.insert(item.source_path.clone());
                if dictionary_sources.len() > MAX_DICTIONARY_SOURCE_PATHS {
                    return Err(PullError::Invalid("FEED_LIMIT_EXCEEDED"));
                }
                dictionary_bytes = dictionary_bytes.saturating_add(item.value.len());
                if dictionary_bytes > MAX_DICTIONARY_VALUE_BYTES {
                    return Err(PullError::Invalid("FEED_LIMIT_EXCEEDED"));
                }
                dictionary_values.push(item);
                if dictionary_values.len() > MAX_DICTIONARY_VALUES {
                    return Err(PullError::Invalid("FEED_LIMIT_EXCEEDED"));
                }
            }
        }
        if dictionary_values
            .iter()
            .any(|item| password_paths.contains(item.source_path.as_str()))
        {
            return Err(PullError::Invalid("FEED_SECRET_SOURCE_FORBIDDEN"));
        }

        let mut snapshot = PolicySnapshot {
            version,
            rules: rules.clone(),
            dictionary: dictionary_values
                .iter()
                .map(|item| (item.value.clone(), item.category.clone()))
                .collect(),
            metadata_sources: metadata.clone(),
            ready: true,
        };
        snapshot
            .rules
            .extend(password_paths.into_iter().map(|path| PolicyRule {
                selector: RuleSelector::SourcePath,
                pattern: path.to_owned(),
                action: RuleAction::Secret,
                category: "SECRET".to_owned(),
                priority: i64::MAX,
            }));

        let digest = pull_digest(&metadata, &dictionary_values);
        let target_version = self
            .storage
            .next_cache_version(database_id)
            .map_err(|_| PullError::Transient("STORAGE_UNAVAILABLE"))?;
        let selectors_json = serde_json::to_string(&json!({
            "selectors": selectors,
            "metadata_count": metadata.len(),
            "dictionary_count": dictionary_values.len(),
        }))
        .unwrap_or_else(|_| "{}".to_owned());

        // Durable commit и RAM swap атомарно относительно обработки вызовов:
        // per-DB admission удерживается только на короткую секцию commit —
        // сетевые страницы admission не занимают.
        let _admission = self
            .admission_for(database_id, Uuid::nil())
            .map_err(|_| PullError::Transient("STORAGE_UNAVAILABLE"))?
            .lock_owned()
            .await;
        self.storage
            .commit_pull_generation(
                database_id,
                target_version,
                &digest,
                metadata.len(),
                dictionary_values.len(),
                &selectors_json,
            )
            .map_err(|_| PullError::Transient("STORAGE_UNAVAILABLE"))?;
        self.policy_cache
            .write()
            .await
            .insert(database_id, snapshot);
        if let Ok(mut manifests) = self.metadata_manifests.lock() {
            if manifests
                .insert(
                    database_id,
                    Uuid::new_v4(),
                    metadata.clone(),
                    declared_digest,
                )
                .is_err()
            {
                tracing::warn!(
                    database = %database_id,
                    "pull manifest store insert rejected; snapshot already committed"
                );
            }
        }
        drop(_admission);
        // Условное удаление: concurrent Admin-upsert за время pull получит
        // свой refresh следующим тиком.
        let _ = self
            .storage
            .delete_refresh_intent_if_unchanged(database_id, &intent.created_at);
        Ok(())
    }

    /// Пагинация по opaque cursor до `final_chunk`; каждая страница
    /// проверяется на форму и счётчики. `manifest_digest` необязателен
    /// (BSL его не отдаёт) и ни на что не влияет — см. решение Р1(а).
    async fn pull_pages(
        &self,
        client: &ManagerClient,
        database_id: Uuid,
        tool: &str,
        selector: &Value,
    ) -> Result<PulledPages, PullError> {
        let mut pages = PulledPages {
            metadata: Vec::new(),
            dictionary_values: Vec::new(),
            manifest_digest: None,
        };
        let mut cursor: Option<String> = None;
        for _page in 0..MAX_PAGES_PER_STREAM {
            let arguments = json!({
                "selector": selector,
                "cursor": cursor.clone().map_or(Value::Null, Value::String),
            });
            let result = client
                .call_tool(database_id, tool, &arguments)
                .await
                .map_err(PullError::from)?;
            let page: FeedPage = serde_json::from_value(tool_result_value(&result)?)
                .map_err(|_| PullError::Invalid("RESULT_INVALID"))?;
            if !page.success {
                // Producer error code — только diagnostics, доверия ему нет:
                // отказ инструмента всегда transient (может уйти сам).
                tracing::warn!(
                    database = %database_id,
                    tool,
                    error = page.error_code.as_deref().unwrap_or("UNKNOWN"),
                    "internal feed tool rejected the call"
                );
                return Err(PullError::Transient("INTERNAL_TOOL_FAILED"));
            }
            if page.final_chunk != page.next_cursor.is_none() {
                return Err(PullError::Invalid("RESULT_INVALID"));
            }
            if let Some(next) = &page.next_cursor {
                if next.is_empty() || next.len() > MAX_CURSOR_BYTES {
                    return Err(PullError::Invalid("RESULT_INVALID"));
                }
            }
            // Р1 решение (а): BSL manifest_digest не отдаёт — поле
            // опционально, требования и межстраничной сверки нет. Если
            // producer всё же прислал digest, сохраняем первое значение
            // как declared evidence; журнальный digest прогона сервис
            // считает сам (pull_digest).
            if pages.manifest_digest.is_none() {
                pages.manifest_digest = page.manifest_digest;
            }
            for item in page.metadata {
                // field_type bound повторяет прежний per-chunk предел
                // feed receiver: составные типы 1С длинные, но не мегабайтные.
                if item.source_path.len() > 512
                    || item.field_name.len() > 256
                    || item.field_type.len() > 1024 * 1024
                {
                    return Err(PullError::Invalid("FEED_METADATA_ITEM_LIMIT"));
                }
                pages.metadata.push(item);
                if pages.metadata.len() > MAX_MANIFEST_ITEMS {
                    return Err(PullError::Invalid("FEED_LIMIT_EXCEEDED"));
                }
            }
            for item in page.dictionary_values {
                pages.dictionary_values.push(item);
                if pages.dictionary_values.len() > MAX_DICTIONARY_VALUES {
                    return Err(PullError::Invalid("FEED_LIMIT_EXCEEDED"));
                }
            }
            if page.final_chunk {
                return Ok(pages);
            }
            cursor = page.next_cursor;
        }
        Err(PullError::Invalid("FEED_LIMIT_EXCEEDED"))
    }

    /// Dictionary-селекторы pull-прогона по durable `dictionary_configs`:
    /// `part` — нормализованные explicit selectors, `all` — wildcard
    /// `{"source_path":"*"}` расширяется по свежему manifest через
    /// service-owned Mask SourcePath allowlist.
    fn dictionary_selectors(
        &self,
        database_id: Uuid,
        metadata: &[FeedMetadataItem],
        rules: &[PolicyRule],
    ) -> Result<Vec<Value>, &'static str> {
        let Some((mode, source_paths_json, filter_ast_json)) = self
            .storage
            .dictionary_config_row(database_id)
            .map_err(|_| "STORAGE_UNAVAILABLE")?
        else {
            return Ok(Vec::new());
        };
        if filter_ast_json.is_some() {
            // filter_ast живёт только внутри per-selector записей.
            return Err("DICTIONARY_CONFIG_INVALID");
        }
        let configured: Vec<Value> =
            serde_json::from_str(&source_paths_json).map_err(|_| "DICTIONARY_CONFIG_INVALID")?;
        if configured.len() > MAX_SELECTOR_COUNT {
            return Err("DICTIONARY_CONFIG_INVALID");
        }
        let normalize = |value: &Value| -> Result<Value, &'static str> {
            let object = value.as_object().ok_or("DICTIONARY_CONFIG_INVALID")?;
            if !object
                .keys()
                .all(|key| matches!(key.as_str(), "source_path" | "category" | "filter_ast"))
            {
                return Err("DICTIONARY_CONFIG_INVALID");
            }
            let source = object
                .get("source_path")
                .and_then(Value::as_str)
                .ok_or("DICTIONARY_CONFIG_INVALID")?;
            let category = object
                .get("category")
                .and_then(Value::as_str)
                .ok_or("DICTIONARY_CONFIG_INVALID")?;
            if source.is_empty() || source.len() > 512 || category.is_empty() || category.len() > 32
            {
                return Err("DICTIONARY_CONFIG_INVALID");
            }
            let filter_ast = object.get("filter_ast").cloned().unwrap_or(Value::Null);
            if !filter_ast.is_null() && !valid_filter_ast(&filter_ast) {
                return Err("DICTIONARY_CONFIG_INVALID");
            }
            Ok(json!({
                "source_path": source,
                "category": category,
                "filter_ast": filter_ast,
                "page_size": 1000,
            }))
        };
        match mode.as_str() {
            "part" => configured.iter().map(normalize).collect(),
            "all" => {
                if configured.len() != 1
                    || configured[0].get("source_path").and_then(Value::as_str) != Some("*")
                {
                    return Err("DICTIONARY_CONFIG_INVALID");
                }
                let wildcard = normalize(&configured[0])?;
                let allowed = all_allowed_source_paths(rules);
                let mut paths = BTreeSet::new();
                for item in metadata {
                    if all_expandable_metadata(item, &allowed) {
                        paths.insert(item.source_path.clone());
                    }
                }
                if paths.len() > MAX_DICTIONARY_SOURCE_PATHS {
                    return Err("FEED_LIMIT_EXCEEDED");
                }
                Ok(paths
                    .into_iter()
                    .map(|path| {
                        let mut selector = wildcard.clone();
                        selector["source_path"] = Value::String(path);
                        selector
                    })
                    .collect())
            }
            _ => Err("DICTIONARY_CONFIG_INVALID"),
        }
    }
}
//++agent TASK-222
