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

use chrono::Utc;
use rand::Rng;
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

//++agent TASK-225 [25.09.2026]
/// §8.1: параметры backoff серии transient-неудач pull. Читаются из env
/// при старте сервиса; jitter (±0.2) подаётся caller'ом отдельно, чтобы
/// тесты оставались детерминированными.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PullRetryPolicy {
    pub base_seconds: u64,
    pub cap_seconds: u64,
    pub max_attempts: u64,
    /// Размах случайного джиттера (±span, доля от задержки). Тесты
    /// выставляют `MASKING_PULL_RETRY_JITTER_SPAN=0` — задержка
    /// становится точной, ассёрты детерминированы (без sleep).
    pub jitter_span: f64,
}

impl PullRetryPolicy {
    pub(crate) fn from_env() -> Self {
        Self {
            base_seconds: super::bounded_env_usize("MASKING_PULL_RETRY_BASE_SECONDS", 10, 1, 3_600)
                as u64,
            cap_seconds: super::bounded_env_usize("MASKING_PULL_RETRY_CAP_SECONDS", 900, 1, 86_400)
                as u64,
            max_attempts: super::bounded_env_usize("MASKING_PULL_MAX_ATTEMPTS", 8, 1, 1_000) as u64,
            jitter_span: std::env::var("MASKING_PULL_RETRY_JITTER_SPAN")
                .ok()
                .and_then(|value| value.parse::<f64>().ok())
                .map(|value| value.clamp(0.0, 0.5))
                .unwrap_or(0.2),
        }
    }

    /// delay = min(base·2^(attempts-1), cap)·(1+jitter), jitter∈[-0.2,0.2].
    /// `attempts` — номер зафиксированной неудачи (первая неудача → base).
    pub(crate) fn retry_delay_seconds(&self, attempts: u64, jitter: f64) -> u64 {
        let shift = attempts.saturating_sub(1).min(20);
        let base = self
            .base_seconds
            .saturating_mul(1u64 << shift)
            .min(self.cap_seconds);
        let span = self.jitter_span;
        let jittered = (base as f64) * (1.0 + jitter.clamp(-span, span));
        jittered.round().max(1.0) as u64
    }
}
//++agent TASK-225

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
            //++agent TASK-225 [26.09.2026]
            // K/N: менеджер жив и отвечает, но не может передать запрос
            // базе — это не «менеджер недоступен». `no_target` — сессия
            // этой ИБ сейчас неактивна: повторяем, сессия может
            // подключиться сама.
            ManagerClientError::Rejected { code } => match code.as_str() {
                "no_target" => Self::Transient("DATABASE_NOT_CONNECTED"),
                _ => Self::Transient("INTERNAL_TOOL_FAILED"),
            },
            //++agent TASK-225
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

//++agent TASK-225 [26.09.2026] §3.4: базовый предикат F9 без allowlist —
/// нужен и diff (эффективный набор `mode=all` считается по правилам
/// версии), и pull (allowlist из живого снимка). Источники иначе
/// разошлись бы между diff и фактической раскладкой feed.
pub(crate) fn metadata_expandable_basics(item: &FeedMetadataItem) -> bool {
    let field_type = item.field_type.to_lowercase();
    (item.source_path.starts_with("Catalog.") || item.source_path.starts_with("Справочник."))
        && (field_type.contains("string") || field_type.contains("строка"))
        && !item.password_mode
        && !metadata_is_secret(item)
}
//++agent TASK-225

/// Общий предикат eligible metadata source для All-expansion:
/// класс `Catalog.*`/`Справочник.*` (trusted manifest от BSL `ПолноеИмя()`
/// локализует имя класса) + тип String/Строка + `!password_mode` +
/// `!metadata_is_secret` + вхождение в Mask allowlist.
fn all_expandable_metadata(item: &FeedMetadataItem, allowed: &HashSet<&str>) -> bool {
    metadata_expandable_basics(item) && allowed.contains(item.source_path.as_str())
}

fn metadata_is_secret(item: &FeedMetadataItem) -> bool {
    let name = format!("{} {}", item.field_name, item.source_path).to_lowercase();
    let compact: String = name
        .chars()
        .filter(|character| character.is_alphanumeric())
        .collect();
    //++agent TASK-225 [27.09.2026] Y4 консолидация
    // Единый список с domain/masking.rs::SECRET_NAME_COMPACT_MARKERS и
    // ЭтоИмяСекрета границы 1С — держать синхронно. Подстрочная проверка
    // по compact-форме (как в 1С и masking.rs) покрывает и snake_case
    // варианты (access_token -> accesstoken через token).
    crate::domain::masking::SECRET_NAME_COMPACT_MARKERS
        .iter()
        .any(|marker| compact.contains(marker))
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
                    //++agent TASK-225 [25.09.2026]
                    // §8.1: детерминированный сбой — intent снимается, код и
                    // время сохраняются в databases (B2 → refresh.state
                    // "failed" до следующего успешного pull).
                    let _ = self
                        .storage
                        .record_refresh_terminal_failure(intent.database_id, error.code());
                    //++agent TASK-225
                }
                Err(error @ PullError::Transient(_)) => {
                    //++agent TASK-225 [25.09.2026]
                    // §8.1: backoff — повтор откладывается на
                    // next_attempt_at; по достижении max_attempts intent
                    // уходит в needs_attention (ждёт Admin). §8.2: аудируются
                    // только первая неудача серии и переход в
                    // needs_attention — промежуточные повторы в debug,
                    // иначе зависший pull спамил audit каждым тиком
                    // (живая проблема: 6105 строк).
                    let span = self.pull_retry.jitter_span;
                    let jitter: f64 = if span > 0.0 {
                        rand::thread_rng().gen_range(-span..=span)
                    } else {
                        0.0
                    };
                    let attempts_after = (intent.attempts.max(0) as u64).saturating_add(1);
                    let delay = self.pull_retry.retry_delay_seconds(attempts_after, jitter);
                    let next_attempt_at =
                        (Utc::now() + chrono::Duration::seconds(delay.max(1) as i64)).to_rfc3339();
                    if let Ok((attempts, needs_attention)) = self.storage.record_refresh_failure(
                        intent.database_id,
                        error.code(),
                        &next_attempt_at,
                        self.pull_retry.max_attempts,
                    ) {
                        if attempts == 1 || needs_attention {
                            let _ = self
                                .storage
                                .audit_feed_pull_failed(intent.database_id, error.code());
                        } else {
                            tracing::debug!(
                                event = "feed_pull_retry",
                                database_id = %intent.database_id,
                                attempts,
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
        //++agent TASK-225 [27.09.2026 00:00:00] S: ненастроенной базе
        // нужен manifest метаданных для админки — pull только метаданных;
        // словарь и автомат появятся с первой активацией. Disabled
        // пропускается, как раньше.
        if settings.mode == DatabaseMode::Disabled {
            return Err(PullError::Skipped);
        }
        let metadata_only = settings.mode == DatabaseMode::Unconfigured;
        //++agent TASK-225
        //++agent TASK-225 [26.09.2026] O2: маршрут feed-вызова — точный
        // ключ instance_id записи; менеджер сопоставляет сессию только
        // по нему.
        let identity = settings.call_identity();
        //++agent TASK-225
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
            .pull_pages(
                client,
                &identity,
                database_id,
                METADATA_TOOL,
                &metadata_selector(),
            )
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

        //++agent TASK-225 [27.09.2026 00:00:00] S: metadata-only pull —
        // словарные селекторы не расширяются и страницы словаря не
        // запрашиваются.
        let selectors = if metadata_only {
            Vec::new()
        } else {
            self.dictionary_selectors(database_id, &metadata, &rules)
                .map_err(PullError::Invalid)?
        };
        //++agent TASK-225
        let mut dictionary_values: Vec<FeedDictionaryValue> = Vec::new();
        let mut dictionary_bytes = 0usize;
        let mut dictionary_sources: HashSet<String> = HashSet::new();
        //++agent TASK-225 [25.09.2026]
        // §5a.3: статистика источников pull (source_path → категория,
        // число значений, суммарный размер) — пишется в
        // cache_generations.source_stats_json для B2/diff (SOURCE_LARGE).
        let mut source_stats: BTreeMap<String, (String, u64, u64)> = BTreeMap::new();
        //++agent TASK-225
        for selector in &selectors {
            let expected_source = selector["source_path"].as_str().unwrap_or_default();
            let expected_category = selector["category"].as_str().unwrap_or_default();
            let pages = self
                .pull_pages(client, &identity, database_id, DICTIONARY_TOOL, selector)
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
                //++agent TASK-225 [25.09.2026]
                {
                    let stat = source_stats
                        .entry(item.source_path.clone())
                        .or_insert_with(|| (item.category.clone(), 0, 0));
                    stat.1 += 1;
                    stat.2 = stat.2.saturating_add(item.value.len() as u64);
                }
                //++agent TASK-225
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

        //++agent TASK-225 [25.09.2026]
        // §5a.2: автомат словаря собирается до admission в spawn_blocking —
        // сборка ~1М значений занимает секунды CPU и не должна занимать
        // per-DB слот или блокировать executor-потоки.
        //++agent TASK-225 [26.09.2026] фаза-2 C
        // Пропуск пересборки по отпечатку: словарь не изменился → индекс
        // переиспользуется через дешёвый `with_actions` (автомат значений
        // внутри него сохраняется; сборка ~10с/1М значений не нужна).
        // Отпечаток считается в spawn_blocking (O(n) вне executor-
        // потоков), отпечаток и Arc индекса текущего снимка читаются
        // под read-локом до него.
        let map: std::collections::HashMap<String, String> = dictionary_values
            .iter()
            .map(|item| (item.value.clone(), item.category.clone()))
            .collect();
        // Автомат строится по правилам файла без встроенных
        // секретных путей — как было до фазы-2.
        let index_rules = rules.clone();
        let (existing_fingerprint, existing_index) = self
            .policy_cache
            .read()
            .await
            .get(&database_id)
            .map(|s| (s.dictionary_fingerprint, s.dictionary_index.clone()))
            .unwrap_or_default();
        let (snapshot_dictionary, new_fingerprint, dictionary_index) =
            tokio::task::spawn_blocking(move || {
                let fingerprint = crate::domain::dictionary_fingerprint(&map);
                let index = match existing_index
                    .filter(|_| fingerprint != 0 && fingerprint == existing_fingerprint)
                {
                    Some(index) => Some(index.with_actions(&index_rules)),
                    None => crate::domain::DictionaryIndex::build(&map, &index_rules),
                };
                (map, fingerprint, index)
            })
            .await
            .map_err(|_| PullError::Transient("STORAGE_UNAVAILABLE"))?;
        //++agent TASK-225
        //++agent TASK-225 [26.09.2026] D8: категория → путь источника
        // для причин `dictionary` (§6.3); первый источник категории по
        // порядку feed — значения всех источников категории делят путь.
        let dictionary_sources: std::collections::HashMap<String, String> = {
            let mut map = std::collections::HashMap::new();
            for item in &dictionary_values {
                map.entry(item.category.clone())
                    .or_insert_with(|| item.source_path.clone());
            }
            map
        };
        //++agent TASK-225
        let mut snapshot_rules = rules;
        snapshot_rules.extend(password_paths.iter().map(|path| PolicyRule {
            selector: RuleSelector::SourcePath,
            pattern: (*path).to_owned(),
            action: RuleAction::Secret,
            category: "SECRET".to_owned(),
            priority: i64::MAX,
            rule_id: None,
        }));
        let snapshot = PolicySnapshot {
            version,
            rules: snapshot_rules,
            dictionary: snapshot_dictionary,
            dictionary_sources,
            dictionary_index,
            metadata_sources: metadata.clone(),
            //++agent TASK-225 [26.09.2026] §6.1: связь истории с версией.
            policy_id: settings
                .active_policy_id
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok()),
            //++agent TASK-225 [26.09.2026] фаза-2 C: отпечаток посчитан
            // при pull — следующий pull с тем же словарём пропустит
            // пересборку автомата (см. выше), а set_policy_snapshot
            // получит корректный MINOR-9-ключ сравнения.
            dictionary_fingerprint: new_fingerprint,
            //++agent TASK-225
            //++agent TASK-225 [27.09.2026 00:00:00] S: metadata-only
            // снапшот не объявляет готовность — политики и словаря нет;
            // ready публикуется только полным pull активной базы.
            ready: !metadata_only,
            //++agent TASK-225
        };
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
        //++agent TASK-225 [25.09.2026]
        let source_stats_json = serde_json::to_string(
            &source_stats
                .iter()
                .map(|(source_path, (category, values, bytes))| {
                    json!({
                        "source_path": source_path,
                        "category": category,
                        "values": values,
                        "bytes": bytes,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".to_owned());
        //++agent TASK-225

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
                &source_stats_json,
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
        //++agent TASK-225 [25.09.2026]
        // §8.2: успех после серии transient-неудач — одна строка аудита
        // `feed.pull.recovered` с числом попыток.
        if intent.attempts > 0 {
            let _ = self
                .storage
                .audit_feed_pull_recovered(database_id, intent.attempts.max(0) as u64);
        }
        //++agent TASK-225
        Ok(())
    }

    /// Пагинация по opaque cursor до `final_chunk`; каждая страница
    /// проверяется на форму и счётчики. `manifest_digest` необязателен
    /// (BSL его не отдаёт) и ни на что не влияет — см. решение Р1(а).
    async fn pull_pages(
        &self,
        client: &ManagerClient,
        identity: &crate::domain::DatabaseIdentity,
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
                .call_tool(identity, tool, &arguments)
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
        //++agent TASK-225 [26.09.2026]
        // §2.5: селекторы словаря берутся из dictionary_json АКТИВНОЙ
        // версии; legacy dictionary_configs — только fallback для баз без
        // активной версии (переходный контур миграции).
        let versioned = self
            .storage
            .with_connection(|connection| {
                crate::storage::setup::active_dictionary_json(connection, database_id)
            })
            .map_err(|_| "STORAGE_UNAVAILABLE")?;
        let (mode, configured) = if let Some(dictionary_json) = versioned {
            let value: Value =
                serde_json::from_str(&dictionary_json).map_err(|_| "DICTIONARY_CONFIG_INVALID")?;
            let mode = value["mode"].as_str().unwrap_or_default().to_string();
            let sources = value["sources"].clone();
            (mode, sources)
        } else {
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
            (
                mode,
                serde_json::from_str(&source_paths_json)
                    .map_err(|_| "DICTIONARY_CONFIG_INVALID")?,
            )
        };
        let configured: Vec<Value> =
            serde_json::from_value(configured).map_err(|_| "DICTIONARY_CONFIG_INVALID")?;
        //++agent TASK-225
        if configured.len() > MAX_SELECTOR_COUNT {
            return Err("DICTIONARY_CONFIG_INVALID");
        }
        let normalize = |value: &Value| -> Result<Value, &'static str> {
            let object = value.as_object().ok_or("DICTIONARY_CONFIG_INVALID")?;
            //++agent TASK-225 [26.09.2026]
            // Снимок версии несёт reason/estimated_values — служебные для
            // селекторов ключи, пропускаем их (не часть провода).
            //++agent TASK-225
            if !object.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "source_path" | "category" | "filter_ast" | "reason" | "estimated_values"
                )
            }) {
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
