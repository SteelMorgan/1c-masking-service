use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

//++agent TASK-222 [05.10.2026]
mod dictionary_feed;
//++agent TASK-222
//++agent TASK-225 [26.09.2026] §3.4: предикат F9 для DiffContext.
pub(crate) use dictionary_feed::metadata_expandable_basics;
//++agent TASK-225

use crate::storage::{HistoryWrite, SqliteStorage, TerminalWrite};

use super::{
    DatabaseIdentity, DatabaseMode, ErrorCode, FeedMetadataItem, FinalizeOutcome, FinalizeRequest,
    FinalizeResponse, MappingLimits, MappingStore, MaskEngine, PolicySnapshot, PreflightRequest,
    PreflightResponse, ServiceError, TerminalEventRequest, TerminalEventResponse,
    TerminalScopeKind, ToolClass, SCHEMA_VERSION,
};

type CallKey = (Uuid, String, Uuid);

const VERIFIED_TERMINAL_CODES: &[&str] = &[
    "ACTION_REQUIRED",
    "TOOL_PENDING_REVIEW",
    "MASK_TOKEN_INVALID",
    "SERVICE_NOT_READY",
    //++agent TASK-225 [26.09.2026] фаза-2 L: менеджер пишет терминал на
    // каждый отказ preflight — включая SERVICE_WARMING_UP (фаза-2 C).
    // Без кода в этом списке outbox менеджера ретраил запись бесконечно.
    "SERVICE_WARMING_UP",
    //++agent TASK-225
    "POLICY_INVALID",
    "RESULT_LIMIT_EXCEEDED",
    "MASKING_TIMEOUT",
    "MASKING_FAILED",
    "HISTORY_UNAVAILABLE",
];

const UNVERIFIED_TERMINAL_CODES: &[&str] = &[
    "CHAT_IDENTITY_REQUIRED",
    "DATABASE_IDENTITY_UNVERIFIED",
    "SERVICE_NOT_READY",
];

//++agent TASK-225 [27.09.2026 00:00:00] S: белый список инструментов
// ненастроенной базы — только чтение метаданных (данных в ответе нет);
// вызов идёт обычным путём как no-mask, без политики и ready-состояния.
const UNCONFIGURED_WHITELIST: &[&str] = &["get_metadata"];
//++agent TASK-225

pub struct MaskingService {
    storage: Arc<SqliteStorage>,
    mappings: RwLock<MappingStore>,
    policy_cache: RwLock<HashMap<Uuid, PolicySnapshot>>,
    //++agent TASK-222 [05.10.2026]
    // Per-DB admission сериализует config-мутации и swap pull-снапшота с
    // обработкой вызовов. Манифесты живут в RAM и переживают только
    // process lifetime — pull-модель обновляет их при каждом refresh.
    admission_by_database: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
    pub(super) metadata_manifests: Mutex<super::manifest::MetadataManifestStore>,
    //++agent TASK-222
    // Raw disabled/bypass projections are never persisted. This bounded cache
    // preserves exact retry behavior only for the current process lifetime.
    completed_responses: Mutex<HashMap<CallKey, CachedResponse>>,
    admission: Arc<Semaphore>,
    workers: Arc<Semaphore>,
    database_workers: Mutex<HashMap<Uuid, Arc<Semaphore>>>,
    per_database_workers: usize,
    //++agent TASK-225 [26.09.2026]
    // §5.7: один сухой прогон на базу одновременно (409 DRY_RUN_BUSY).
    //++agent TASK-225
    dry_run_lock: Mutex<HashSet<Uuid>>,
    engine: MaskEngine,
    //++agent TASK-225 [25.09.2026]
    // §8.1: параметры backoff pull refresh (env при старте); аудит
    // неудач ведётся по durable-счётчику attempts в v2_refresh_intents,
    // отдельная in-memory дедупликация лога больше не нужна.
    pull_retry: dictionary_feed::PullRetryPolicy,
    //++agent TASK-225
}

struct CachedResponse {
    value: Value,
    expires_at: chrono::DateTime<Utc>,
}

//++agent TASK-225 [26.09.2026] M-6: RAII-метка занятости dry-run —
// флаг снимается при любом выходе из `dry_run`, включая отмену future
// при отключении клиента (axum дропает запросный future) и panic.
struct DryRunBusyGuard<'a> {
    lock: &'a Mutex<HashSet<Uuid>>,
    database_id: Uuid,
}

impl Drop for DryRunBusyGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut busy) = self.lock.lock() {
            busy.remove(&self.database_id);
        }
    }
}
//++agent TASK-225

impl MaskingService {
    pub fn new(storage: Arc<SqliteStorage>) -> Self {
        //++agent TASK-222 [05.10.2026]
        // RAM snapshots/manifests теряются при restart — для каждой
        // enabled-базы ставится durable 'full' intent, который pull worker
        // выполнит через manager UDS. INSERT … WHERE NOT EXISTS —
        // идемпотентно; ошибки fail-soft (следующий Admin trigger или тик
        // всё равно инициирует refresh через durable intent).
        let _ = storage.enqueue_startup_pull_intents();
        //++agent TASK-222
        //++agent TASK-224 [08.10.2026] итерация 4
        // Mapping store — только RAM: после рестарта ни одну запись истории
        // нельзя раскрыть. Нераскрываемая история — чистый риск хранения,
        // поэтому старт сервиса удаляет history и контексты вызовов целиком.
        let _ = storage.purge_ephemeral_history();
        //++agent TASK-224
        Self {
            storage,
            mappings: RwLock::new(MappingStore::new(MappingLimits::default())),
            policy_cache: RwLock::new(HashMap::new()),
            //++agent TASK-222 [05.10.2026]
            admission_by_database: Mutex::new(HashMap::new()),
            metadata_manifests: Mutex::new(super::manifest::MetadataManifestStore::default()),
            //++agent TASK-222
            completed_responses: Mutex::new(HashMap::new()),
            admission: Arc::new(Semaphore::new(bounded_env_usize(
                "MASKING_MAX_IN_FLIGHT",
                80,
                1,
                10_000,
            ))),
            workers: Arc::new(Semaphore::new(bounded_env_usize(
                "MASKING_WORKERS",
                16,
                1,
                1_000,
            ))),
            database_workers: Mutex::new(HashMap::new()),
            per_database_workers: bounded_env_usize("MASKING_PER_DATABASE_WORKERS", 4, 1, 100),
            //++agent TASK-225 [26.09.2026]
            dry_run_lock: Mutex::new(HashSet::new()),
            //++agent TASK-225
            engine: MaskEngine::new(),
            pull_retry: dictionary_feed::PullRetryPolicy::from_env(),
        }
    }

    pub fn storage(&self) -> &Arc<SqliteStorage> {
        &self.storage
    }

    /// Агрегат для health checks, без доступа к tokens, scopes или originals.
    pub async fn mapping_count(&self) -> usize {
        self.mappings.read().await.len()
    }

    //++agent TASK-222 [05.10.2026]
    /// Read-only проверка для human config ветки: completed
    /// metadata manifest существует для БД. Generation проверяется явно —
    /// nil означает «нет usable manifest»; содержимое manifest не
    /// раскрывается (trusted service state, не Admin data).
    /// Poisoned lock → false: отсутствие manifest — fail-closed ответ.
    pub fn has_metadata_manifest(&self, database_id: Uuid) -> bool {
        self.metadata_manifests
            .lock()
            .map(|manifests| {
                manifests
                    .generation(database_id)
                    .is_some_and(|generation| !generation.is_nil())
            })
            .unwrap_or(false)
    }
    //++agent TASK-224 [24.09.2026]
    /// Read-only проекция manifest для Admin-дерева метаданных: `view`
    /// вызывается над `items` под короткой блокировкой store, чтобы не
    /// клонировать до 100k записей наружу. `None` — manifest не получен
    /// (рестарт/refresh не завершён); poisoned lock → тот же None
    /// (fail-closed, как `has_metadata_manifest`).
    pub fn metadata_manifest_view<R>(
        &self,
        database_id: Uuid,
        view: impl FnOnce(&[FeedMetadataItem]) -> R,
    ) -> Option<(DateTime<Utc>, R)> {
        let manifests = self.metadata_manifests.lock().ok()?;
        let entry = manifests.get(database_id)?;
        Some((entry.completed_at, view(&entry.items)))
    }
    /// Тестовая загрузка manifest в RAM-store напрямую, минуя pull:
    /// integration-тесты human API не поднимают manager feed. Durable
    /// commit не выполняется — только для тестов.
    #[doc(hidden)]
    pub fn seed_metadata_manifest(&self, database_id: Uuid, items: Vec<FeedMetadataItem>) -> bool {
        self.metadata_manifests
            .lock()
            .map(|mut manifests| {
                manifests
                    .insert(database_id, Uuid::new_v4(), items, String::new())
                    .is_ok()
            })
            .unwrap_or(false)
    }
    //++agent TASK-224
    //++agent TASK-222

    pub(crate) fn admission_for(
        &self,
        database_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<Arc<tokio::sync::Mutex<()>>, ServiceError> {
        if database_id.is_nil() {
            return Err(ServiceError::new(
                ErrorCode::DatabaseIdentityUnverified,
                correlation_id,
            ));
        }
        let mut locks = self
            .admission_by_database
            .lock()
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, correlation_id))?;
        if let Some(lock) = locks.get(&database_id) {
            return Ok(Arc::clone(lock));
        }
        if locks.len() >= 256 {
            // Owned guard / waiter держит Arc: вытесняются только действительно idle locks.
            locks.retain(|_, lock| Arc::strong_count(lock) > 1);
            if locks.len() >= 256 {
                return Err(ServiceError::new(
                    ErrorCode::ServiceNotReady,
                    correlation_id,
                ));
            }
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(database_id, Arc::clone(&lock));
        Ok(lock)
    }

    //++agent TASK-225 [26.09.2026]
    /// RAM-снимок активной версии (для B6 — словарь прогона берётся из
    /// него, §5.6: новые источники файла не загружены).
    pub async fn policy_snapshot_view(&self, database_id: Uuid) -> Option<PolicySnapshot> {
        self.policy_cache.read().await.get(&database_id).cloned()
    }
    //++agent TASK-225

    pub async fn set_policy_snapshot(&self, database_id: Uuid, mut snapshot: PolicySnapshot) {
        //++agent TASK-225 [26.09.2026] MINOR-6/§5a.2: тяжёлая сборка
        // Aho-Corasick индекса — в spawn_blocking ВНЕ write-lock
        // policy_cache (~10с при 1 млн значений иначе блокирует чтение
        // всех снимков). Фаза 1: read-lock — нужна ли сборка и для
        // какого словаря. Фаза 2: spawn_blocking. Фаза 3: write-lock —
        // merge, built-индекс применяется только если словарь за это
        // время не подменили (pull мог прийти параллельно).
        //++agent TASK-225 [26.09.2026] review MINOR-9: отпечаток входного
        // словаря считаем ДО блокировок — сам по себе O(n), но вне
        // policy_cache.write (раньше под write-локом был O(n) HashMap::eq).
        if snapshot.dictionary_fingerprint == 0 && !snapshot.dictionary.is_empty() {
            snapshot.dictionary_fingerprint =
                crate::domain::dictionary_fingerprint(&snapshot.dictionary);
        }
        // [26.09.2026 review N-3] пересчёт `with_actions` и сборка
        // индекса — вне write-блокировки кэша: пересборка автомата на
        // 1M значений ~секунды, под write-локом она блокировала бы все
        // снимки. Под read-локом берём Arc-ссылки, тяжёлое — в
        // spawn_blocking; публикуем, только если состояние за это время
        // не сменилось (отпечаток / Arc-идентичность).
        let (existing_index, build_for) = {
            let cache = self.policy_cache.read().await;
            match cache.get(&database_id) {
                Some(existing) if snapshot.dictionary.is_empty() => (
                    existing.dictionary_index.clone(),
                    (existing.dictionary_index.is_none() && !existing.dictionary.is_empty())
                        .then(|| existing.dictionary.clone()),
                ),
                _ => (None, None),
            }
        };
        let (built_fingerprint, built_index, updated_index) = if let Some(dictionary) = build_for {
            let rules = snapshot.rules.clone();
            let for_build = dictionary.clone();
            let index = tokio::task::spawn_blocking(move || {
                let fingerprint = crate::domain::dictionary_fingerprint(&for_build);
                (
                    crate::domain::DictionaryIndex::build(&for_build, &rules),
                    fingerprint,
                )
            })
            .await
            .ok();
            index
                .map(|(index, fingerprint)| (Some(fingerprint), index, None))
                .unwrap_or_default()
        } else if let Some(index) = existing_index.clone() {
            let rules = snapshot.rules.clone();
            let updated = tokio::task::spawn_blocking(move || index.with_actions(&rules))
                .await
                .ok();
            (None, None, updated)
        } else {
            (None, None, None)
        };
        //++agent TASK-225
        let mut cache = self.policy_cache.write().await;
        if let Some(existing) = cache.get(&database_id) {
            if snapshot.dictionary.is_empty() {
                snapshot.dictionary = existing.dictionary.clone();
                snapshot.dictionary_fingerprint = existing.dictionary_fingerprint;
                //++agent TASK-225 [26.09.2026] D8: пути источников —
                // атрибуты того же словаря, наследуются вместе с ним.
                snapshot.dictionary_sources = existing.dictionary_sources.clone();
                //++agent TASK-225
                //++agent TASK-225 [25.09.2026]
                // §5a.2: смена правил без pull — пересчитываем действия
                // категорий, автомат значений переиспользуется (Arc);
                // индекса ещё нет (снимок до TASK-225) — строим по месту.
                // [26.09.2026 MINOR-6] сборка вынесена в spawn_blocking;
                // built-индекс применяем, только если словарь не сменился
                // за время сборки (pull мог прийти параллельно).
                // [26.09.2026 review MINOR-9] сравнение — по отпечатку
                // (O(1) вместо O(n) HashMap::eq под write-локом).
                // [26.09.2026 review N-3] `with_actions` тоже вынесен из
                // write-лока; пересчитанный индекс публикуем, только если
                // pull не сменил индекс за время пересчёта (Arc::ptr_eq),
                // иначе — редкий in-lock пересчёт по актуальному.
                snapshot.dictionary_index = match existing.dictionary_index.as_ref() {
                    Some(index) => match (&existing_index, &updated_index) {
                        (Some(used), Some(updated)) if std::sync::Arc::ptr_eq(used, index) => {
                            Some(updated.clone())
                        }
                        _ => Some(index.with_actions(&snapshot.rules)),
                    },
                    None => built_index
                        .filter(|_| built_fingerprint == Some(existing.dictionary_fingerprint)),
                };
                //++agent TASK-225
            }
            if snapshot.metadata_sources.is_empty() {
                snapshot.metadata_sources = existing.metadata_sources.clone();
            }
            snapshot.ready &= existing.ready;
        } else {
            // A policy-only snapshot cannot substitute for metadata/dictionary
            // feed data. Only an existing ready cache may stay ready here.
            snapshot.ready = false;
        }
        cache.insert(database_id, snapshot);
    }

    pub async fn reveal_history(
        &self,
        history_id: Uuid,
        database_id: Uuid,
        chat_id: &str,
    ) -> Result<Value, ServiceError> {
        let history = self
            .storage
            .history_for_reveal(history_id, database_id, chat_id)
            .map_err(|_| ServiceError::new(ErrorCode::HistoryUnavailable, Uuid::nil()))?
            .ok_or_else(|| ServiceError::new(ErrorCode::HistoryUnavailable, Uuid::nil()))?;
        let Some(batch_id) = history.mapping_batch_id else {
            return Ok(history.report);
        };
        let mut mappings = self.mappings.write().await;
        self.engine
            .resolve_tokens_for_batch(
                &history.report,
                database_id,
                chat_id,
                batch_id,
                &mut mappings,
            )
            .map_err(|_| ServiceError::new(ErrorCode::MappingUnavailable, Uuid::nil()))
    }

    pub async fn preflight(
        &self,
        request: PreflightRequest,
    ) -> Result<PreflightResponse, ServiceError> {
        validate_common(
            request.schema_version,
            &request.chat_id,
            &request.tool_name,
            request.correlation_id,
        )?;
        //++agent TASK-225 [26.09.2026] N: база резолвится по координатам
        // (Srvr, Ref) + RAS/GUID-паре; id записи возвращает ensure.
        let (database_id, settings, created) = self
            .storage
            .ensure_database(&request.identity)
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?;
        //++agent TASK-225
        let _admission = self
            .admission_for(database_id, request.correlation_id)?
            .lock_owned()
            .await;
        //++agent TASK-224 [08.10.2026] итерация 4; ревью R1 [25.09.2026]
        // Заголовок — durable-производная `request.arguments`: записывается
        // только после зачистки engine-ом (ключи-секреты и литералы
        // `Пароль = "…"`/`api_key=…` в тексте → [SECRET_REMOVED]) — сырые
        // литералы в arguments возможны, «только mask-токены» не гарантия.
        // Ошибка зачистки — fail-closed: контекст без title, отчёт в UI
        // покажет имя инструмента. Fail-soft: без контекста отчёт просто
        // без заголовка; finalize прочитает заголовок по call_id.
        let call_title = self
            .engine
            .cut_call_arguments(&request.arguments)
            .ok()
            .and_then(|arguments| describe_call(&request.tool_name, &arguments));
        let _ = self.storage.write_call_context(
            request.call_id,
            database_id,
            &request.chat_id,
            &request.tool_name,
            call_title.as_deref(),
            effective_history_ttl(&settings),
        );
        //++agent TASK-224
        //++agent TASK-225 [27.09.2026 00:00:00] S: ненастроенной базе
        // доступен только белый список — остальные отказываются
        // ACTION_REQUIRED, как раньше.
        let unconfigured_allow = (created || settings.mode == DatabaseMode::Unconfigured)
            && UNCONFIGURED_WHITELIST.contains(&request.tool_name.as_str());
        if (created || settings.mode == DatabaseMode::Unconfigured) && !unconfigured_allow {
            return self.persist_preflight_denial(
                &request,
                database_id,
                &settings,
                ErrorCode::ActionRequired,
            );
        }
        let class = match self.storage.tool_class(database_id, &request.tool_name) {
            Ok(class) => class,
            Err(_) => {
                return self.persist_preflight_denial(
                    &request,
                    database_id,
                    &settings,
                    ErrorCode::ServiceNotReady,
                )
            }
        };
        // У ненастроенной базы классификаций ещё нет — без навязанного
        // no-mask белый список упал бы в deny-pending-review.
        let class = if unconfigured_allow {
            ToolClass::NoMask
        } else {
            class
        };
        //++agent TASK-225
        //++agent TASK-225 [25.09.2026]
        // Отказ по классу deny-pending-review пишется отдельным путём:
        // та же durable-запись, но с учётом tool_classifications
        // (auto_added/first_seen_at/denied_count) в одной транзакции.
        //++agent TASK-225
        if class == ToolClass::DenyPendingReview {
            return self.persist_pending_review_denial(&request, database_id, &settings);
        }
        if class == ToolClass::DataMask && settings.mode == DatabaseMode::Enabled {
            let policy = match self
                .policy_for(database_id, &settings, request.correlation_id)
                .await
            {
                Ok(policy) => policy,
                Err(error) => {
                    return self.persist_preflight_denial(
                        &request,
                        database_id,
                        &settings,
                        error.code,
                    )
                }
            };
            if !policy.ready {
                //++agent TASK-225 [26.09.2026] фаза-2 C
                // Холодный старт/первый прогрев: !ready при ожидающем
                // pull — это прогрев, а не «сервис сломан». persist-запись
                // здесь не нужна: терминальный отказ агента фиксирует
                // менеджерский гейт через calls/terminal, повтор идёт с
                // новым call_id, как у всех отказов preflight.
                if let Some(error) = self.warming_error(database_id, request.correlation_id) {
                    return Err(error);
                }
                //++agent TASK-225
                return self.persist_preflight_denial(
                    &request,
                    database_id,
                    &settings,
                    ErrorCode::ServiceNotReady,
                );
            }
        }
        //++agent TASK-225 [25.09.2026]
        // Обратная расшифровка токенов в аргументах — только для
        // data-mask при Enabled: подстановка реальных значений в вызов,
        // чей ответ будет замаскирован. Для no-mask и data-mask
        // вне Enabled само наличие [MASK:v1:...] — попытка оракула
        // (резолв вернул бы сырьё в незамаскированный ответ или просто
        // протечку идентификатора) — отказ MASK_TOKEN_INVALID до 1С.
        //++agent TASK-225
        let can_resolve = class == ToolClass::DataMask && settings.mode == DatabaseMode::Enabled;
        let arguments = if can_resolve {
            let mut mappings = self.mappings.write().await;
            match self.engine.resolve_tokens(
                &request.arguments,
                database_id,
                &request.chat_id,
                &mut mappings,
            ) {
                Ok(arguments) => {
                    //++agent TASK-225 [26.09.2026] ревью-2 N-1
                    // Факт резолва хотя бы одного токена — durable-флаг
                    // на контексте вызова: finalize по нему гасит
                    // свободный текст ошибок (эхо запроса после резолва
                    // содержит исходные значения). Запись fail-closed:
                    // без флага вызов с расшифрованными аргументами к 1С
                    // не уходит — иначе finalize не узнает о подстановке.
                    if arguments != request.arguments
                        && !matches!(
                            self.storage.mark_call_context_mask_tokens(request.call_id),
                            Ok(true)
                        )
                    {
                        drop(mappings);
                        return self.persist_preflight_denial(
                            &request,
                            database_id,
                            &settings,
                            ErrorCode::ServiceNotReady,
                        );
                    }
                    //++agent TASK-225
                    arguments
                }
                Err(_) => {
                    drop(mappings);
                    return self.persist_preflight_denial(
                        &request,
                        database_id,
                        &settings,
                        ErrorCode::MaskTokenInvalid,
                    );
                }
            }
        } else {
            match self.engine.contains_tokens(&request.arguments) {
                Ok(false) => request.arguments.clone(),
                _ => {
                    return self.persist_preflight_denial(
                        &request,
                        database_id,
                        &settings,
                        ErrorCode::MaskTokenInvalid,
                    );
                }
            }
        };
        Ok(PreflightResponse {
            schema_version: SCHEMA_VERSION,
            decision: "allow",
            arguments,
        })
    }

    pub fn record_terminal_event(
        &self,
        request: TerminalEventRequest,
    ) -> Result<TerminalEventResponse, ServiceError> {
        if request.schema_version != SCHEMA_VERSION || !valid_terminal_tool_name(&request.tool_name)
        {
            return Err(ServiceError::new(
                ErrorCode::DatabaseIdentityUnverified,
                request.correlation_id,
            ));
        }
        let write = match request.scope.kind {
            TerminalScopeKind::Verified => {
                //++agent TASK-225 [26.09.2026] O2: verified-scope несёт
                // точный ключ instance_id (+Srvr/Ref для отображения).
                let (Some(instance_id), Some(chat_id)) = (
                    request.scope.instance_id.as_deref(),
                    request.scope.chat_id.as_deref(),
                ) else {
                    return Err(ServiceError::new(
                        ErrorCode::PolicyInvalid,
                        request.correlation_id,
                    ));
                };
                let identity = DatabaseIdentity {
                    instance_id: instance_id.to_owned(),
                    cluster_server: request.scope.cluster_server.clone().unwrap_or_default(),
                    infobase_name: request.scope.infobase_name.clone().unwrap_or_default(),
                };
                //++agent TASK-225
                if chat_id.is_empty()
                    || chat_id.len() > 512
                    || !VERIFIED_TERMINAL_CODES.contains(&request.error_code.as_str())
                {
                    return Err(ServiceError::new(
                        ErrorCode::PolicyInvalid,
                        request.correlation_id,
                    ));
                }
                let (database_id, settings, _) =
                    self.storage.ensure_database(&identity).map_err(|_| {
                        ServiceError::new(ErrorCode::HistoryUnavailable, request.correlation_id)
                    })?;
                let public_result =
                    safe_terminal_error(&request.error_code, request.correlation_id);
                //++agent TASK-224 [08.10.2026] итерация 4: заголовок берём из
                // контекста вызова, если preflight его записал; TTL —
                // effective min.
                let call_title = self
                    .storage
                    .call_context_text(request.call_id)
                    .ok()
                    .flatten();
                let report = neutral_report(
                    &public_result,
                    &ReportMeta {
                        title: call_title.as_deref(),
                        schema: None,
                    },
                );
                self.storage.write_scoped_terminal(
                    database_id,
                    chat_id,
                    request.call_id,
                    &request.tool_name,
                    &request.error_code,
                    &public_result,
                    &report,
                    effective_history_ttl(&settings),
                    request.correlation_id,
                )
                //++agent TASK-224
            }
            TerminalScopeKind::Unverified => {
                if request.scope.instance_id.is_some()
                    || request.scope.cluster_server.is_some()
                    || request.scope.infobase_name.is_some()
                    || request.scope.chat_id.is_some()
                    || !UNVERIFIED_TERMINAL_CODES.contains(&request.error_code.as_str())
                {
                    return Err(ServiceError::new(
                        ErrorCode::PolicyInvalid,
                        request.correlation_id,
                    ));
                }
                self.storage.write_unscoped_terminal(
                    request.call_id,
                    request.correlation_id,
                    &request.tool_name,
                    &request.error_code,
                    86_400,
                )
            }
        }
        .map_err(|_| ServiceError::new(ErrorCode::HistoryUnavailable, request.correlation_id))?;
        if write == TerminalWrite::Conflict {
            return Err(ServiceError::new(
                ErrorCode::TerminalAlreadyRecorded,
                request.correlation_id,
            ));
        }
        Ok(TerminalEventResponse {
            schema_version: SCHEMA_VERSION,
            status: "recorded",
        })
    }

    pub async fn finalize(
        &self,
        request: FinalizeRequest,
    ) -> Result<FinalizeResponse, ServiceError> {
        validate_common(
            request.schema_version,
            &request.chat_id,
            &request.tool_name,
            request.correlation_id,
        )?;
        //++agent TASK-225 [26.09.2026] N: см. preflight.
        let (database_id, settings, created) = self
            .storage
            .ensure_database(&request.identity)
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?;
        //++agent TASK-225
        let _admission = self
            .admission_for(database_id, request.correlation_id)?
            .lock_owned()
            .await;
        let key = (database_id, request.chat_id.clone(), request.call_id);
        let cached = self.completed_responses.lock().ok().and_then(|mut cache| {
            if cache
                .get(&key)
                .is_some_and(|entry| entry.expires_at <= Utc::now())
            {
                cache.remove(&key);
            }
            cache.get(&key).map(|entry| entry.value.clone())
        });
        if let Some(value) = cached {
            return Ok(FinalizeResponse {
                schema_version: SCHEMA_VERSION,
                public_result: value,
            });
        }
        if let Some(history) = self
            .storage
            .load_history(database_id, &request.chat_id, request.call_id)
            .map_err(|_| ServiceError::new(ErrorCode::HistoryUnavailable, request.correlation_id))?
        {
            return Ok(FinalizeResponse {
                schema_version: SCHEMA_VERSION,
                public_result: history.public_result,
            });
        }
        let _admission =
            self.admission.clone().try_acquire_owned().map_err(|_| {
                ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id)
            })?;
        let _worker =
            self.workers.clone().acquire_owned().await.map_err(|_| {
                ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id)
            })?;
        let database_worker = {
            let mut workers = self.database_workers.lock().map_err(|_| {
                ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id)
            })?;
            workers
                .entry(database_id)
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_database_workers)))
                .clone()
        };
        let _database_worker = database_worker
            .acquire_owned()
            .await
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?;
        //++agent TASK-225 [27.09.2026 00:00:00] S: тот же белый список,
        // что в preflight — иначе finalize отказал бы вызову, который
        // preflight уже допустил.
        let unconfigured_allow = (created || settings.mode == DatabaseMode::Unconfigured)
            && UNCONFIGURED_WHITELIST.contains(&request.tool_name.as_str());
        if (created || settings.mode == DatabaseMode::Unconfigured) && !unconfigured_allow {
            return Err(ServiceError::new(
                ErrorCode::ActionRequired,
                request.correlation_id,
            ));
        }
        let class = self
            .storage
            .tool_class(database_id, &request.tool_name)
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?;
        let class = if unconfigured_allow {
            ToolClass::NoMask
        } else {
            class
        };
        //++agent TASK-225
        if class == ToolClass::DenyPendingReview {
            return Err(ServiceError::new(
                ErrorCode::ToolPendingReview,
                request.correlation_id,
            ));
        }

        let (logical_result, outcome_name, sanitized_reason) = match &request.outcome {
            FinalizeOutcome::ToolResult { result } => {
                if validate_tool_result(result).is_err() {
                    (
                        safe_processing_error(request.correlation_id),
                        "sanitized_error",
                        Some("service:result_invalid"),
                    )
                } else {
                    (result.clone(), "tool_result", None)
                }
            }
            FinalizeOutcome::TransportError { .. } => (
                safe_transport_error(request.correlation_id),
                "transport_error",
                None,
            ),
        };
        //++agent TASK-225 [26.09.2026] ревью-2 N-1
        // Решение §12: preflight расшифровал mask-токены ⇒ эхо текста
        // запроса в ошибке разбора содержит исходные значения — свободный
        // текст не отдаём, только код и позицию. Флаг читается из
        // durable-контекста вызова (TTL-фильтра нет: истёкшая запись
        // всё ещё несёт правду). `Ok(None)` — строки нет: либо вызов
        // миновал preflight (резолв невозможен — mark fail-closed),
        // либо контекст вытерт рестартом — не отличить ⇒ консервативно
        // считаем, что токены были. Ошибка чтения — тоже неизвестно.
        let had_mask_tokens = !matches!(
            self.storage.call_context_mask_tokens(request.call_id),
            Ok(Some(false))
        );
        let logical_result = if had_mask_tokens {
            strip_parse_error_text(logical_result)
        } else {
            logical_result
        };
        //++agent TASK-225
        let policy = self
            .policy_for(database_id, &settings, request.correlation_id)
            .await?;
        if settings.mode == DatabaseMode::Enabled && class == ToolClass::DataMask && !policy.ready {
            //++agent TASK-225 [26.09.2026] фаза-2 C: !ready при
            // ожидающем pull — прогрев: агент получает SERVICE_WARMING_UP
            // с retry_after_s вместо безликого отказа.
            return Err(self
                .warming_error(database_id, request.correlation_id)
                .unwrap_or_else(|| {
                    ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id)
                }));
            //++agent TASK-225
        }
        //++agent TASK-224 [08.10.2026] итерация 4: заголовок отчёта —
        // текст запроса из контекста, записанного preflight-фазой
        // (fail-soft: без записи отчёт остаётся без заголовка).
        let call_title = self
            .storage
            .call_context_text(request.call_id)
            .ok()
            .flatten();
        //++agent TASK-224
        if let Some(reason) = sanitized_reason {
            return self.persist_sanitized_failure(
                &request,
                database_id,
                &settings,
                policy.version,
                outcome_name,
                reason,
                call_title.as_deref(),
            );
        }
        //++agent TASK-222 [05.10.2026]
        // Конверт P1: из `field_sources` берутся только сведения о
        // происхождении полей для маскирования по source_path; флага
        // `secret_cut_applied` в конверте нет и не проверяется.
        let field_sources = serde_json::to_value(&request.field_sources)
            .map_err(|_| ServiceError::new(ErrorCode::MaskingFailed, request.correlation_id))?;
        //++agent TASK-222
        if request.tool_name == "execute_query"
            && matches!(&request.outcome, FinalizeOutcome::ToolResult { .. })
            && logical_result.get("success") != Some(&Value::Bool(false))
            && !valid_query_lineage(
                &logical_result,
                &request.field_sources,
                settings.strict_mode,
            )
        {
            return self.persist_sanitized_failure(
                &request,
                database_id,
                &settings,
                policy.version,
                "sanitized_error",
                "service:query_lineage_incomplete",
                call_title.as_deref(),
            );
        }
        let cut_result = match self
            .engine
            .cut_secrets(&logical_result, &field_sources, &policy)
        {
            Ok(value) => value,
            Err(_) => {
                return self.persist_sanitized_failure(
                    &request,
                    database_id,
                    &settings,
                    policy.version,
                    "sanitized_error",
                    "service:result_limit_exceeded",
                    call_title.as_deref(),
                );
            }
        };
        let batch_id = Uuid::new_v4();
        let mut mappings = self.mappings.write().await;
        let masked = match self.engine.mask(
            &cut_result,
            database_id,
            &request.chat_id,
            batch_id,
            settings.mapping_ttl_seconds,
            &policy,
            &mappings,
            &field_sources,
        ) {
            Ok(masked) => masked,
            Err(_) => {
                drop(mappings);
                return self.persist_sanitized_failure(
                    &request,
                    database_id,
                    &settings,
                    policy.version,
                    "sanitized_error",
                    "service:result_limit_exceeded",
                    call_title.as_deref(),
                );
            }
        };
        if mappings.can_publish(&masked.candidates).is_err() {
            drop(mappings);
            return self.persist_sanitized_failure(
                &request,
                database_id,
                &settings,
                policy.version,
                "sanitized_error",
                "service:mapping_capacity_exceeded",
                call_title.as_deref(),
            );
        }

        //++agent TASK-225 [26.09.2026] §6: причины/привязки ячеек нужны
        // для mask_detail_json ниже — забираем до move `masked.value`.
        let reason_entries = masked.reason_entries;
        let cell_reasons = masked.cell_reasons;
        //++agent TASK-225
        let fully_masked = masked.value;
        let mut mask_reasons: Vec<_> = masked.reasons.iter().cloned().collect();
        mask_reasons.sort();
        let public_result =
            if settings.mode == DatabaseMode::Enabled && class == ToolClass::DataMask {
                fully_masked.clone()
            } else {
                cut_result
            };
        //++agent TASK-222 [05.10.2026]
        // Контракт Р2: бизнес-result непрозрачен; в публичную форму
        // (content[0].text) его оборачивает сервис. transport_error уже
        // приходит в публичной форме и не оборачивается повторно.
        // В историю кладётся маскированная replay-форма той же обёртки:
        // повторная выдача по call_id остаётся валидным ToolCallResult.
        let wrap = |value: &Value| {
            if outcome_name == "tool_result" {
                wrap_tool_result(value)
            } else {
                value.clone()
            }
        };
        let public_result = wrap(&public_result);
        let stored_public = wrap(&fully_masked);
        //++agent TASK-224 [08.10.2026] итерация 4: отчёт хранит исходный
        // порядок колонок запроса (field_sources.schema) и заголовок.
        let report = neutral_report(
            &fully_masked,
            &ReportMeta {
                title: call_title.as_deref(),
                schema: Some(&request.field_sources.schema),
            },
        );
        //++agent TASK-224
        //++agent TASK-225 [26.09.2026]
        // §6.1/§6.2: детальная запись — причины по ячейкам отчёта
        // (координаты из той же раскладки блоков, что neutral_report),
        // lineage без значений и id версии политики.
        let detail_text = mask_detail_json(
            &reason_entries,
            &cell_reasons,
            &fully_masked,
            Some(&request.field_sources.schema),
            policy.version,
        );
        let field_sources_text = serde_json::to_string(&request.field_sources).ok();
        let detail = crate::storage::HistoryDetail {
            mask_detail_json: detail_text.as_deref(),
            field_sources_json: field_sources_text.as_deref(),
            policy_id: policy.policy_id,
        };
        //++agent TASK-225
        let write = self
            .storage
            .write_history(
                database_id,
                &request.chat_id,
                request.call_id,
                &request.tool_name,
                outcome_name,
                &stored_public,
                &report,
                policy.version,
                &mask_reasons,
                effective_history_ttl(&settings),
                (!masked.candidates.is_empty()).then_some(batch_id),
                request.correlation_id,
                Some(&detail),
            )
            .map_err(|_| {
                ServiceError::new(ErrorCode::HistoryUnavailable, request.correlation_id)
            })?;
        match write {
            HistoryWrite::Existing(history) => {
                return Ok(FinalizeResponse {
                    schema_version: SCHEMA_VERSION,
                    public_result: history.public_result,
                });
            }
            HistoryWrite::Inserted(_) => mappings
                .publish(masked.candidates)
                .map_err(|_| ServiceError::new(ErrorCode::MaskingFailed, request.correlation_id))?,
            HistoryWrite::Conflict => {
                return Err(ServiceError::new(
                    ErrorCode::TerminalAlreadyRecorded,
                    request.correlation_id,
                ))
            }
        }
        self.cache_response(key, public_result.clone(), effective_history_ttl(&settings));
        Ok(FinalizeResponse {
            schema_version: SCHEMA_VERSION,
            public_result,
        })
    }

    pub async fn maintenance_tick(&self) -> Result<(usize, usize, usize, usize), ServiceError> {
        //++agent TASK-222 [05.10.2026]
        // Manifest store живёт в RAM — TTL-evict чистит записи БД, чей pull
        // давно не обновлял манифест (snapshot несёт собственную копию
        // metadata_sources, поэтому evict безопасен для маскирования).
        if let Ok(mut manifests) = self.metadata_manifests.lock() {
            let now = Utc::now();
            manifests.retain(|_, entry| now - entry.completed_at <= Duration::hours(2));
        }
        //++agent TASK-222
        let mappings = self.mappings.write().await.cleanup(2_000);
        if let Ok(mut cache) = self.completed_responses.lock() {
            let now = Utc::now();
            cache.retain(|_, entry| entry.expires_at > now);
        }
        let history = self
            .storage
            .cleanup_history(500)
            .map_err(|_| ServiceError::new(ErrorCode::HistoryUnavailable, Uuid::nil()))?;
        let terminal = self
            .storage
            .cleanup_unscoped_terminal(500)
            .map_err(|_| ServiceError::new(ErrorCode::HistoryUnavailable, Uuid::nil()))?;
        let audit = self
            .storage
            .cleanup_audit(500)
            .map_err(|_| ServiceError::new(ErrorCode::HistoryUnavailable, Uuid::nil()))?;
        Ok((mappings, terminal, history, audit))
    }

    //++agent TASK-225 [26.09.2026]
    /// §5: сухой прогон — статусная разница ячеек последних записей
    /// истории между активной и проверяемой версиями. Значения не
    /// покидают память прогона; в ответе только координаты и причины.
    /// Один прогон на базу одновременно (DRY_RUN_BUSY).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn dry_run(
        &self,
        database_id: Uuid,
        to: &PolicySnapshot,
        source_stats: &std::collections::HashMap<String, crate::domain::setup::SourceStat>,
        draft_sources: &std::collections::HashSet<String>,
        new_source_estimates: &std::collections::HashMap<String, i64>,
        limit: u32,
    ) -> Result<DryRunOutcome, ServiceError> {
        {
            let mut busy = self
                .dry_run_lock
                .lock()
                .map_err(|_| ServiceError::new(ErrorCode::MaskingFailed, Uuid::nil()))?;
            if !busy.insert(database_id) {
                return Err(ServiceError::new(ErrorCode::DryRunBusy, Uuid::nil()));
            }
        }
        //++agent TASK-225 [26.09.2026] M-6: флаг живёт, пока жив гард —
        // отмена запросного future при отключении клиента обязана его
        // снять; снятие после .await оставляло базу в вечном DRY_RUN_BUSY.
        let _busy_guard = DryRunBusyGuard {
            lock: &self.dry_run_lock,
            database_id,
        };
        //++agent TASK-225
        self.dry_run_inner(
            database_id,
            to,
            source_stats,
            draft_sources,
            new_source_estimates,
            limit,
        )
        .await
    }

    async fn dry_run_inner(
        &self,
        database_id: Uuid,
        to: &PolicySnapshot,
        source_stats: &std::collections::HashMap<String, crate::domain::setup::SourceStat>,
        draft_sources: &std::collections::HashSet<String>,
        new_source_estimates: &std::collections::HashMap<String, i64>,
        limit: u32,
    ) -> Result<DryRunOutcome, ServiceError> {
        let deadline = std::time::Instant::now()
            + Duration::milliseconds(bounded_env_usize(
                "MASKING_DRY_RUN_TIMEOUT_MS",
                10_000,
                500,
                60_000,
            ) as i64)
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(10));
        let budget_ms = bounded_env_usize("MASKING_CHECK_BUDGET_MS", 200, 10, 60_000) as f64;
        let records = self
            .storage
            .dry_run_records(database_id, limit)
            .map_err(|_| ServiceError::new(ErrorCode::HistoryUnavailable, Uuid::nil()))?;
        if records.is_empty() {
            // §5.1: записей нет вовсе → no_records; есть, но все без
            // lineage (история до §6.1) → no_lineage.
            let any = self
                .storage
                .has_tool_result_records(database_id)
                .unwrap_or(false);
            return Ok(DryRunOutcome::Empty(if any {
                "no_lineage"
            } else {
                "no_records"
            }));
        }
        let settings = self
            .storage
            .database_settings(database_id)
            .map_err(|_| ServiceError::new(ErrorCode::MaskingFailed, Uuid::nil()))?
            .ok_or_else(|| ServiceError::new(ErrorCode::MaskingFailed, Uuid::nil()))?;
        let active = self
            .policy_for(database_id, &settings, Uuid::nil())
            .await
            .unwrap_or_default();

        let mut records_out = Vec::new();
        let mut skipped = Vec::new();
        let mut became_masked = 0u64;
        let mut became_open = 0u64;
        let mut unevaluable = 0u64;
        let mut active_times: Vec<(f64, Uuid)> = Vec::new();
        let mut draft_times: Vec<(f64, Uuid)> = Vec::new();

        for record in records {
            if std::time::Instant::now() > deadline {
                break;
            }
            let masked_value = unwrap_stored_result(&record.public_result);
            let schema = record
                .field_sources
                .as_deref()
                .and_then(|text| serde_json::from_str::<Value>(text).ok())
                .map(|fs| fs.get("schema").cloned().unwrap_or(Value::Null));
            let map = report_pointer_map(&masked_value, schema.as_ref());
            // Статус ячеек «до»: токен → masked, [SECRET_REMOVED] → secret.
            let mut before: Vec<(String, &'static str)> = Vec::new();
            collect_cell_status(&masked_value, "", &mut before);
            // Восстановление исходных значений по mapping батча записи.
            let resolved = match record.mapping_batch_id {
                Some(batch_id) => {
                    let mut mappings = self.mappings.write().await;
                    self.engine
                        .resolve_tokens_for_batch(
                            &masked_value,
                            database_id,
                            &record.chat_id,
                            batch_id,
                            &mut mappings,
                        )
                        .ok()
                }
                None => Some(masked_value.clone()),
            };
            let Some(resolved) = resolved else {
                skipped.push(json!({"history_id": record.id, "reason": "mapping_expired"}));
                continue;
            };
            let field_sources: Value = record
                .field_sources
                .as_deref()
                .and_then(|text| serde_json::from_str(text).ok())
                .unwrap_or(Value::Null);
            // Два прогона с замером чистого времени engine.mask.
            // Изолированный «dry» MappingStore: токены прогона не
            // публикуются и выбрасываются с окончанием итерации (§5.3).
            let dry_store = MappingStore::new(MappingLimits::default());
            let start = std::time::Instant::now();
            let _after_active = self.engine.mask(
                &resolved,
                database_id,
                &record.chat_id,
                Uuid::nil(),
                settings.mapping_ttl_seconds,
                &active,
                &dry_store,
                &field_sources,
            );
            let active_ms = start.elapsed().as_secs_f64() * 1000.0;
            let start = std::time::Instant::now();
            let after_draft = self.engine.mask(
                &resolved,
                database_id,
                &record.chat_id,
                Uuid::nil(),
                settings.mapping_ttl_seconds,
                to,
                &dry_store,
                &field_sources,
            );
            let draft_ms = start.elapsed().as_secs_f64() * 1000.0;
            active_times.push((active_ms, record.id));
            draft_times.push((draft_ms, record.id));
            drop(dry_store);

            let mut cells = Vec::new();
            //++agent TASK-225 [26.09.2026] D3: маскированная сетка для UI —
            // ВСЕ оценённые ячейки со статусами до/после и причиной.
            // Значений и токенов в сетке нет (§5.4: в ответе только
            // координаты и причины).
            let mut grid_cells = Vec::new();
            let mut grid_truncated = false;
            let mut masked_count = 0u64;
            let mut open_count = 0u64;
            if let Ok(after) = after_draft.as_ref() {
                let mut after_cells = Vec::new();
                collect_cell_status(&after.value, "", &mut after_cells);
                let mut reason_idx: HashMap<String, u32> = HashMap::new();
                for (pointer, idx) in &after.cell_reasons {
                    reason_idx.entry(pointer.clone()).or_insert(*idx);
                }
                let after_map: HashMap<&str, &str> =
                    after_cells.iter().map(|(p, s)| (p.as_str(), *s)).collect();
                for (pointer, status_before) in before {
                    let status_after = if status_before == "secret" {
                        "unknown" // SECRET_REMOVED необратим
                    } else {
                        after_map.get(pointer.as_str()).copied().unwrap_or("open")
                    };
                    if status_before == "secret" {
                        unevaluable += 1;
                    }
                    let (block, row, col) = cell_coord(&map, &pointer);
                    let column = col
                        .and_then(|index| {
                            map.columns
                                .get(block as usize)
                                .and_then(|cols| cols.get(index as usize))
                        })
                        .cloned();
                    let reason = reason_idx
                        .get(&pointer)
                        .and_then(|idx| after.reason_entries.get(*idx as usize))
                        //++agent TASK-225 [26.09.2026] MINOR-1: у
                        // source_path-причин отдаём сам путь (pattern
                        // правила); у прочих — поле опускается, селектор
                        // вида «dictionary» путём источника не является.
                        .map(|entry| {
                            json!({
                                "kind": entry.kind,
                                "category": entry.category,
                                "source_path": entry.source_path,
                            })
                        });
                    //++agent TASK-225
                    if grid_cells.len() < 20_000 {
                        grid_cells.push(json!({
                            "block": block,
                            "row": row,
                            "column": column,
                            "before": status_before,
                            "after": status_after,
                            "reason": reason,
                        }));
                    } else {
                        grid_truncated = true;
                    }
                    if status_after == status_before || status_before == "secret" {
                        continue;
                    }
                    match (status_before, status_after) {
                        ("open", "masked") => masked_count += 1,
                        ("masked", "open") | ("masked", "unknown") => open_count += 1,
                        _ => {}
                    }
                    if cells.len() < 2_000 {
                        cells.push(json!({
                            "block": block,
                            "row": row,
                            "column": column,
                            "before": status_before,
                            "after": status_after,
                            "reason": reason,
                        }));
                    }
                }
            }
            became_masked += masked_count;
            became_open += open_count;
            let title = self
                .storage
                .call_context_text(record.call_id)
                .ok()
                .flatten()
                .map(|text: String| text.chars().take(200).collect::<String>());
            records_out.push(json!({
                "history_id": record.id,
                "created_at": record.created_at,
                "tool": record.tool_name,
                "chat_id": record.chat_id,
                "title": title,
                "became_masked": masked_count,
                "became_open": open_count,
                "cells": cells,
                "cells_truncated": masked_count + open_count > 2_000,
                //++agent TASK-225 [26.09.2026] D3: сетка всех ячеек
                // (статусы, не значения) + имена колонок по блокам.
                "grid": {
                    "columns": map.columns,
                    "cells": grid_cells,
                    "truncated": grid_truncated,
                },
                //++agent TASK-225
            }));
        }
        let timing = |times: &mut Vec<(f64, Uuid)>| {
            times.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
            let median = times.get(times.len() / 2).map(|(v, _)| *v).unwrap_or(0.0);
            let (max, worst) = times.last().cloned().unwrap_or((0.0, Uuid::nil()));
            (
                median,
                max,
                worst,
                times.iter().filter(|(v, _)| *v > budget_ms).count(),
            )
        };
        let (a_med, a_max, a_worst, a_over) = timing(&mut active_times);
        let (d_med, d_max, d_worst, d_over) = timing(&mut draft_times);
        // §5: память словаря — §5a.3 эмпирика bytes×2 + values×48 по
        // измеренным источникам последнего pull; для источников черновика
        // без статистики — estimated_values × средний размер значения.
        let memory_of = |stat: &crate::domain::setup::SourceStat| -> u64 {
            (stat.bytes.max(0) as u64).saturating_mul(2) + (stat.values.max(0) as u64) * 48
        };
        let active_bytes: u64 = source_stats.values().map(memory_of).sum();
        let total_values: u64 = source_stats
            .values()
            .map(|stat| stat.values.max(0) as u64)
            .sum();
        let total_bytes: u64 = source_stats
            .values()
            .map(|stat| stat.bytes.max(0) as u64)
            .sum();
        let avg_value = total_bytes.checked_div(total_values).unwrap_or(24).max(1);
        // Черновик: измеренные источники, оставшиеся в `to`, + оценки новых.
        let draft_measured: u64 = source_stats
            .iter()
            .filter(|(path, _)| draft_sources.contains(path.as_str()))
            .map(|(_, stat)| memory_of(stat))
            .sum();
        let draft_estimated: u64 = new_source_estimates
            .values()
            .map(|values| (*values as u64).saturating_mul(avg_value))
            .sum();
        // top-3 источника по байтам активного словаря (§5).
        let mut top: Vec<(&String, &crate::domain::setup::SourceStat)> =
            source_stats.iter().collect();
        top.sort_by_key(|(_, stat)| std::cmp::Reverse(stat.bytes));
        let top_sources: Vec<Value> = top
            .iter()
            .take(3)
            .map(|(path, stat)| {
                json!({
                    "source_path": path,
                    "values": stat.values,
                    "bytes": stat.bytes,
                    "share": if total_bytes > 0 {
                        stat.bytes.max(0) as f64 / total_bytes as f64
                    } else { 0.0 },
                })
            })
            .collect();
        let automaton_bytes = to
            .dictionary_index
            .as_ref()
            .map(|index| index.heap_bytes())
            .unwrap_or(0);
        let changed = records_out
            .iter()
            .filter(|record| {
                record["became_masked"].as_u64().unwrap_or(0)
                    + record["became_open"].as_u64().unwrap_or(0)
                    > 0
            })
            .count();
        Ok(DryRunOutcome::Done(json!({
            "checked": records_out.len() + skipped.len(),
            "changed": changed,
            "skipped": skipped,
            "totals": {
                "became_masked": became_masked,
                "became_open": became_open,
                "unevaluable_cells": unevaluable,
            },
            "records": records_out,
            "timing": {
                "active": {
                    "median_ms": a_med,
                    "p_max_ms": a_max,
                    "worst_history_id": a_worst,
                    "over_budget": a_over,
                },
                "draft": {
                    "median_ms": d_med,
                    "p_max_ms": d_max,
                    "worst_history_id": d_worst,
                    "over_budget": d_over,
                },
                "budget_ms": budget_ms,
                "dictionary_memory": {
                    "active_bytes": active_bytes,
                    "draft_estimated_bytes": draft_measured + draft_estimated,
                    "automaton_bytes": automaton_bytes,
                    // §5: новые источники оценены по estimated_values файла.
                    "estimated": !new_source_estimates.is_empty(),
                },
                "top_sources": top_sources,
            },
        })))
    }
    //++agent TASK-225

    pub async fn database_ready(&self, database_id: Uuid) -> bool {
        let Ok(Some(settings)) = self.storage.database_settings(database_id) else {
            return false;
        };
        if settings.mode != DatabaseMode::Enabled {
            return settings.mode == DatabaseMode::Disabled;
        }
        self.policy_for(database_id, &settings, Uuid::nil())
            .await
            .is_ok_and(|policy| policy.ready)
    }

    async fn policy_for(
        &self,
        database_id: Uuid,
        settings: &super::DatabaseSettings,
        correlation_id: Uuid,
    ) -> Result<PolicySnapshot, ServiceError> {
        if let Some(snapshot) = self.policy_cache.read().await.get(&database_id).cloned() {
            return Ok(snapshot);
        }
        let (version, rules) = if let Some(policy_id) = settings.active_policy_id.as_deref() {
            self.storage
                .active_policy(database_id, policy_id)
                .map_err(|_| ServiceError::new(ErrorCode::PolicyInvalid, correlation_id))?
                .ok_or_else(|| ServiceError::new(ErrorCode::PolicyInvalid, correlation_id))?
        } else {
            (1, Vec::new())
        };
        Ok(PolicySnapshot {
            version,
            rules,
            //++agent TASK-225 [26.09.2026] §6.1: связь истории с версией.
            policy_id: settings
                .active_policy_id
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok()),
            //++agent TASK-225
            // A persisted version without its process-local snapshot is also
            // unready; only feed activation can publish a usable generation.
            ready: false,
            ..PolicySnapshot::default()
        })
    }

    //++agent TASK-225 [26.09.2026] фаза-2 C
    /// `!ready` при ожидающем pull — прогрев, а не отказ:
    /// SERVICE_WARMING_UP с `retry_after_s` по объёму прошлого pull
    /// (~100 тыс. значений/с сборки автомата, минимум 5с). Intent
    /// отсутствует (`needs_attention`, снят терминальной ошибкой или ещё
    /// не поставлен) — прогрева нет: None, caller отдаёт SERVICE_NOT_READY.
    /// Ошибка чтения — тоже None: не обещаем повтор, которого нет.
    fn warming_error(&self, database_id: Uuid, correlation_id: Uuid) -> Option<ServiceError> {
        if !matches!(self.storage.refresh_intent_pending(database_id), Ok(true)) {
            return None;
        }
        let values = self
            .storage
            .with_connection(|connection| {
                crate::storage::setup::last_source_stats(connection, database_id)
            })
            .ok()
            .flatten()
            .map(|stats| {
                stats
                    .values()
                    .map(|stat| stat.values.max(0) as u64)
                    .sum::<u64>()
            })
            .unwrap_or(0);
        Some(ServiceError::warming_up(correlation_id, values / 100_000))
    }
    //++agent TASK-225

    fn cache_response(&self, key: CallKey, response: Value, ttl_seconds: u64) {
        if let Ok(mut cache) = self.completed_responses.lock() {
            if cache.len() >= 10_000 {
                if let Some(oldest) = cache.keys().next().cloned() {
                    cache.remove(&oldest);
                }
            }
            cache.insert(
                key,
                CachedResponse {
                    value: response,
                    expires_at: Utc::now()
                        + Duration::seconds(ttl_seconds.min(i64::MAX as u64) as i64),
                },
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_sanitized_failure(
        &self,
        request: &FinalizeRequest,
        database_id: Uuid,
        settings: &super::DatabaseSettings,
        policy_version: i64,
        outcome: &str,
        reason: &str,
        //++agent TASK-224 [08.10.2026] итерация 4: заголовок из контекста
        // вызова — sanitized-запись тоже должна показывать текст запроса.
        //++agent TASK-224
        title: Option<&str>,
    ) -> Result<FinalizeResponse, ServiceError> {
        let public_result = safe_processing_error(request.correlation_id);
        let report = neutral_report(
            &public_result,
            &ReportMeta {
                title,
                schema: Some(&request.field_sources.schema),
            },
        );
        let reasons = [reason.to_owned()];
        let write = self
            .storage
            .write_history(
                database_id,
                &request.chat_id,
                request.call_id,
                &request.tool_name,
                outcome,
                &public_result,
                &report,
                policy_version,
                &reasons,
                effective_history_ttl(settings),
                None,
                request.correlation_id,
                //++agent TASK-225 [26.09.2026] §6.1: отказы — legacy-запись.
                None,
                //++agent TASK-225
            )
            .map_err(|_| {
                ServiceError::new(ErrorCode::HistoryUnavailable, request.correlation_id)
            })?;
        let public_result = match write {
            HistoryWrite::Existing(history) => history.public_result,
            HistoryWrite::Inserted(_) => public_result,
            HistoryWrite::Conflict => {
                return Err(ServiceError::new(
                    ErrorCode::TerminalAlreadyRecorded,
                    request.correlation_id,
                ))
            }
        };
        self.cache_response(
            (database_id, request.chat_id.clone(), request.call_id),
            public_result.clone(),
            effective_history_ttl(settings),
        );
        Ok(FinalizeResponse {
            schema_version: SCHEMA_VERSION,
            public_result,
        })
    }

    fn persist_preflight_denial(
        &self,
        request: &PreflightRequest,
        database_id: Uuid,
        settings: &super::DatabaseSettings,
        code: ErrorCode,
    ) -> Result<PreflightResponse, ServiceError> {
        let public_result = safe_terminal_error(code.as_str(), request.correlation_id);
        //++agent TASK-224 [08.10.2026] итерация 4: заголовок — из контекста
        // первого preflight (first-write-wins), а не из текущих аргументов:
        // повторный вызов с тем же call_id и другим текстом запроса
        // остаётся идемпотентным (report совпадает → Existing → тот же
        // код отказа, а не TERMINAL_ALREADY_RECORDED).
        let call_title = self
            .storage
            .call_context_text(request.call_id)
            .ok()
            .flatten();
        let report = neutral_report(
            &public_result,
            &ReportMeta {
                title: call_title.as_deref(),
                schema: None,
            },
        );
        let write = self
            .storage
            .write_scoped_terminal(
                database_id,
                &request.chat_id,
                request.call_id,
                &request.tool_name,
                code.as_str(),
                &public_result,
                &report,
                effective_history_ttl(settings),
                request.correlation_id,
            )
            .map_err(|_| {
                ServiceError::new(ErrorCode::HistoryUnavailable, request.correlation_id)
            })?;
        //++agent TASK-224
        if write == TerminalWrite::Conflict {
            return Err(ServiceError::new(
                ErrorCode::TerminalAlreadyRecorded,
                request.correlation_id,
            ));
        }
        Err(ServiceError::new(code, request.correlation_id))
    }

    //++agent TASK-225 [25.09.2026]
    /// Отказ TOOL_PENDING_REVIEW: durable-запись истории и авто-учёт
    /// инструмента в tool_classifications выполняются одной
    /// storage-операцией (`write_tool_pending_review`, спека §7).
    fn persist_pending_review_denial(
        &self,
        request: &PreflightRequest,
        database_id: Uuid,
        settings: &super::DatabaseSettings,
    ) -> Result<PreflightResponse, ServiceError> {
        let public_result = safe_terminal_error(
            ErrorCode::ToolPendingReview.as_str(),
            request.correlation_id,
        );
        // Заголовок — из контекста первого preflight (first-write-wins),
        // как в persist_preflight_denial: ретрай остаётся идемпотентным.
        let call_title = self
            .storage
            .call_context_text(request.call_id)
            .ok()
            .flatten();
        let report = neutral_report(
            &public_result,
            &ReportMeta {
                title: call_title.as_deref(),
                schema: None,
            },
        );
        let write = self
            .storage
            .write_tool_pending_review(
                database_id,
                &request.chat_id,
                request.call_id,
                &request.tool_name,
                &public_result,
                &report,
                effective_history_ttl(settings),
                request.correlation_id,
            )
            .map_err(|_| {
                ServiceError::new(ErrorCode::HistoryUnavailable, request.correlation_id)
            })?;
        if write == TerminalWrite::Conflict {
            return Err(ServiceError::new(
                ErrorCode::TerminalAlreadyRecorded,
                request.correlation_id,
            ));
        }
        Err(ServiceError::new(
            ErrorCode::ToolPendingReview,
            request.correlation_id,
        ))
    }
    //++agent TASK-225
}

fn bounded_env_usize(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .unwrap_or(default)
}

fn validate_common(
    schema_version: u32,
    chat_id: &str,
    tool_name: &str,
    correlation_id: Uuid,
) -> Result<(), ServiceError> {
    if schema_version != SCHEMA_VERSION
        || chat_id.is_empty()
        || chat_id.len() > 512
        || tool_name.is_empty()
        || tool_name.len() > 128
    {
        return Err(ServiceError::new(
            ErrorCode::DatabaseIdentityUnverified,
            correlation_id,
        ));
    }
    Ok(())
}

//++agent TASK-225 [25.09.2026]
// Политика имени зеркалирует manager-side valid_terminal (gate.rs):
// непустое, ≤128 байт — без ограничения алфавита. Сужение до
// [A-Za-z0-9_-] отвергало валидные для менеджера имена (кириллица,
// ':'), а outbox менеджера ретраит строго с головы — один
// недоставленный terminal-ивент навсегда блокировал очередь.
//++agent TASK-225
fn valid_terminal_tool_name(tool_name: &str) -> bool {
    !tool_name.is_empty() && tool_name.len() <= 128
}

//++agent TASK-222 [05.10.2026]
// Контракт Р2: `result` — непрозрачный бизнес-JSON; сервис не навязывает
// форму ToolCallResult, проверяет только объект и отсутствие опасных форм
// отчётов. Публичную обёртку строит `wrap_tool_result` на выходе.
//++agent TASK-225 [25.09.2026]
// `result` конверта — непрозрачный JSON: скаляры (в т.ч. JSON-строка
// бизнес-результата validate_query) валидны и идут в text дословно.
// Небезопасные формы проверяются только внутри контейнеров.
fn validate_tool_result(result: &Value) -> Result<(), ()> {
    reject_unsafe_report_shapes(result, 0)
}
//++agent TASK-225

//++agent TASK-221 [23.09.2026 18:30:00]
// Query rows require an unambiguous canonical source for every public column.
// Other tools can return arbitrary text and use their remaining detectors.
//++agent TASK-225 [25.09.2026]
// `strict_mode` — настройка базы (databases.strict_mode): при включении
// колонки с `unverified:true` допустимы и их значения маскируются
// целиком в движке; при выключении маркер остаётся отказом.
// Белые списки ключей evidence строгого режима (контракт с границей
// t226): неизвестное поле колонки или lineage — отказ.
const COLUMN_EVIDENCE_KEYS: &[&str] = &[
    "name",
    "type",
    "types",
    "sources",
    "sourceless",
    "unverified",
    "output_types",
];
const LINEAGE_EVIDENCE_KEYS: &[&str] = &[
    "column",
    "result_name",
    "name",
    "source_path",
    "source_type",
    "source_types",
    "secret_cut",
];

fn valid_query_lineage(
    result: &Value,
    field_sources: &super::FieldSources,
    strict_mode: bool,
) -> bool {
    // Контракт Р2: `result` — сам бизнес-результат запроса; data/rows лежат
    // на верхнем уровне, обёртки ToolCallResult внутри нет.
    let payloads: Vec<&Value> = vec![result];
    if payloads
        .iter()
        .any(|value| value.get("data").is_some_and(|data| !data.is_array()))
    {
        return false;
    }
    let has_query_envelope = payloads.iter().any(|value| {
        value.get("data").and_then(Value::as_array).is_some()
            || value.get("rows").and_then(Value::as_array).is_some()
    });
    if !has_query_envelope {
        return false;
    }
    let row_sets: Vec<&Vec<Value>> = payloads
        .into_iter()
        .filter_map(|value| {
            value.get("data").and_then(Value::as_array).or_else(|| {
                value
                    .get("rows")
                    .and_then(Value::as_array)
                    .filter(|rows| rows.iter().all(Value::is_object))
            })
        })
        .filter(|rows| !rows.is_empty())
        .collect();
    if row_sets.is_empty() {
        return true;
    }
    let Some(columns) = field_sources
        .schema
        .get("columns")
        .and_then(Value::as_array)
    else {
        return false;
    };
    if columns.is_empty() {
        return false;
    }
    let mut sources_by_name = HashMap::new();
    //++agent TASK-225 [25.09.2026]
    // Безисточниковые колонки от границы (контракт ДопускиКолонок):
    // `sources` пуст + `sourceless` ∈ {count,literal,parameter,value,
    // composite} → колонка допустима, а её значения проверяются по
    // строкам ниже (примитивы; для count — только числа). Маркер
    // `unverified` — только `true` и только при strict_mode базы:
    // колонка допустима, а все её значения маскируются целиком
    // типизированным токеном в движке; без strict_mode маркер —
    // отказ, как и любое неизвестное поле evidence.
    //++agent TASK-225
    let mut sourceless_by_name = HashMap::new();
    let mut unverified_by_name = HashSet::new();
    for column in columns {
        //++agent TASK-225 [25.09.2026]
        // Неизвестные ключи evidence — отказ. Белый список колонки:
        // name, type/types (типы источника), sources, sourceless,
        // unverified, output_types (платформенные типы колонки,
        // эмитируются границей на всех колонках при включённом флаге).
        if column.as_object().is_none_or(|keys| {
            keys.keys()
                .any(|key| !COLUMN_EVIDENCE_KEYS.contains(&key.as_str()))
        }) {
            return false;
        }
        //++agent TASK-225
        let Some(name) = column.get("name").and_then(Value::as_str) else {
            return false;
        };
        // Маркер принимает единственную форму `unverified:true`; любое
        // другое значение — неизвестное evidence и отказ. Без strict_mode
        // и сам маркер — отказ как раньше.
        let unverified = match column.get("unverified") {
            None => false,
            Some(Value::Bool(true)) if strict_mode => true,
            Some(_) => return false,
        };
        let Some(sources) = column.get("sources").and_then(Value::as_array) else {
            return false;
        };
        if name.is_empty()
            || sources_by_name.contains_key(name)
            || sourceless_by_name.contains_key(name)
            || unverified_by_name.contains(name)
        {
            return false;
        }
        if unverified {
            // Противоречия отсекаются: sourceless доказывал бы допуск,
            // а output_types обязан лежать на unverified-колонке
            // (массив платформенных имён типов, пустой допустим).
            // Пути в sources не проверяются: они заведомо недоказуемы
            // (пустой массив либо неразрешимые/нестроковые пути).
            if column.get("sourceless").is_some() {
                return false;
            }
            let types_valid = column
                .get("output_types")
                .and_then(Value::as_array)
                .is_some_and(|types| types.iter().all(Value::is_string));
            if !types_valid {
                return false;
            }
            unverified_by_name.insert(name);
            continue;
        }
        if sources.is_empty() {
            let Some(kind) = column.get("sourceless").and_then(Value::as_str) else {
                return false;
            };
            if !matches!(
                kind,
                "count" | "literal" | "parameter" | "value" | "composite"
            ) {
                return false;
            }
            sourceless_by_name.insert(name, kind);
            continue;
        }
        // `sourceless` при непустом sources — противоречивое evidence.
        if column.get("sourceless").is_some() {
            return false;
        }
        let mut paths = HashSet::new();
        for source in sources {
            let Some(path) = source.as_str().filter(|path| !path.is_empty()) else {
                return false;
            };
            paths.insert(path);
        }
        sources_by_name.insert(name, paths);
    }
    let mut evidenced = HashMap::<&str, HashSet<&str>>::new();
    for item in &field_sources.lineage {
        //++agent TASK-225 [25.09.2026]
        // Неизвестные ключи lineage — отказ (маркер unverified здесь
        // не входит в контракт и тоже отсекается списком).
        if item.as_object().is_none_or(|keys| {
            keys.keys()
                .any(|key| !LINEAGE_EVIDENCE_KEYS.contains(&key.as_str()))
        }) {
            return false;
        }
        //++agent TASK-225
        if item.get("unverified").is_some() {
            return false;
        }
        let Some(name) = item
            .get("column")
            .or_else(|| item.get("result_name"))
            .or_else(|| item.get("name"))
            .and_then(Value::as_str)
        else {
            return false;
        };
        let Some(path) = item.get("source_path").and_then(Value::as_str) else {
            return false;
        };
        //++agent TASK-225 [25.09.2026]
        // Граница эмитирует lineage и по недоказуемым источникам
        // (unverified-кейс с непустым sources): элемент допустим,
        // значение колонки всё равно маскируется целиком.
        if unverified_by_name.contains(name) {
            continue;
        }
        //++agent TASK-225
        if !sources_by_name
            .get(name)
            .is_some_and(|paths| paths.contains(path))
        {
            return false;
        }
        evidenced.entry(name).or_default().insert(path);
    }
    if sources_by_name
        .iter()
        .any(|(name, paths)| evidenced.get(name).is_none_or(|known| known != paths))
    {
        return false;
    }
    row_sets.into_iter().all(|rows| {
        rows.iter().all(|row| {
            row.as_object().is_some_and(|fields| {
                fields.iter().all(|(name, value)| {
                    if unverified_by_name.contains(name.as_str()) {
                        // Любое JSON-значение: ячейка маскируется
                        // целиком одним токеном в движке.
                        true
                    } else if let Some(&kind) = sourceless_by_name.get(name.as_str()) {
                        sourceless_cell_valid(value, kind)
                    } else {
                        sources_by_name.contains_key(name.as_str())
                    }
                })
            })
        })
    })
}
//++agent TASK-221

//++agent TASK-225 [25.09.2026]
/// Значение ячейки безисточниковой колонки: только JSON-примитив
/// (число/строка/булево/null); для `count` — строго число. Согласованность
/// с фактическим типом платформы обеспечивает граница (ДопускиКолонок),
/// сервис проверяет лишь примитивность формы — объект/массив мог бы
/// нести в себе разыменованные данные.
/// Исключение: `value`/`composite` могут нести непустое `ЗНАЧЕНИЕ(...)` —
/// граница сериализует ссылку плоским объектом `_objectRef` (само
/// описание: UUID, имя типа, представление — без разыменованных полей);
/// строковые поля такого объекта проходят обычное маскирование в движке.
/// Форма строго ограничена: `_objectRef: true` и только примитивные поля.
fn sourceless_cell_valid(value: &Value, kind: &str) -> bool {
    match kind {
        "count" => value.is_number(),
        "value" | "composite" => match value {
            Value::Array(_) => false,
            Value::Object(object) => {
                object.get("_objectRef") == Some(&Value::Bool(true))
                    && object
                        .values()
                        .all(|field| !matches!(field, Value::Object(_) | Value::Array(_)))
            }
            _ => true,
        },
        _ => !matches!(value, Value::Object(_) | Value::Array(_)),
    }
}
//++agent TASK-225

fn reject_unsafe_report_shapes(value: &Value, depth: usize) -> Result<(), ()> {
    if depth > 64 {
        return Err(());
    }
    match value {
        Value::Object(object) => {
            if object.keys().any(|key| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "binary" | "html" | "script" | "formatter"
                )
            }) {
                return Err(());
            }
            for child in object.values() {
                reject_unsafe_report_shapes(child, depth + 1)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                reject_unsafe_report_shapes(child, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn safe_transport_error(correlation_id: Uuid) -> Value {
    json!({
        "content": [{"type": "text", "text": format!("Операция временно недоступна; correlation_id={correlation_id}")}],
        "is_error": true
    })
}

fn safe_processing_error(correlation_id: Uuid) -> Value {
    json!({
        "content": [{"type": "text", "text": format!("Результат недоступен; correlation_id={correlation_id}")}],
        "is_error": true
    })
}

fn safe_terminal_error(code: &str, correlation_id: Uuid) -> Value {
    let message = match code {
        "ACTION_REQUIRED" => "База требует настройки пользователем",
        "TOOL_PENDING_REVIEW" => "Инструмент ожидает проверки",
        "MASK_TOKEN_INVALID" => "Значение недоступно",
        "CHAT_IDENTITY_REQUIRED" => "Требуется подтверждённый контекст диалога",
        "DATABASE_IDENTITY_UNVERIFIED" => "Идентичность базы не подтверждена",
        //++agent TASK-225 [26.09.2026] фаза-2 C: терминальная запись
        // прогрева — без N (оценка живёт в ответе вызова, не в истории).
        "SERVICE_WARMING_UP" => "Сервис маскирования прогревает словарь",
        //++agent TASK-225
        _ => "Операция временно недоступна",
    };
    json!({
        "content": [{"type": "text", "text": format!("{message}; correlation_id={correlation_id}")}],
        "is_error": true,
        "structured_content": {"error":{"code":code,"correlation_id":correlation_id}}
    })
}

//++agent TASK-225 [26.09.2026] ревью-2 N-1
/// Решение §12: вызов с расшифрованными mask-токенами не может получить
/// свободный текст ошибки разбора — эхо текста запроса уже содержит
/// подставленные исходные значения. Из конверта QUERY_PARSE_ERROR
/// остаются только код, признак неуспеха и позиция в запросе
/// (строка/колонка — единственный фрагмент без данных). Позицию
/// восстанавливаем и из message границы без поля position — фрагмент
/// `{(строка, колонка)}` берём по форме, не по содержимому.
fn strip_parse_error_text(result: Value) -> Value {
    let Some(object) = result.as_object() else {
        return result;
    };
    if object.get("error").and_then(Value::as_str) != Some("QUERY_PARSE_ERROR") {
        return result;
    }
    let mut stripped = serde_json::Map::new();
    for key in ["success", "error", "position"] {
        if let Some(value) = object.get(key) {
            stripped.insert(key.to_owned(), value.clone());
        }
    }
    if !stripped.contains_key("position") {
        if let Some(position) = object
            .get("message")
            .and_then(Value::as_str)
            .and_then(|message| {
                regex::Regex::new(r"\{(\(\d+,\s*\d+\))\}")
                    .ok()
                    .and_then(|pattern| {
                        pattern
                            .captures(message)
                            .and_then(|captures| captures.get(1))
                            .map(|found| found.as_str().to_owned())
                    })
            })
        {
            stripped.insert("position".to_owned(), Value::String(position));
        }
    }
    Value::Object(stripped)
}
//++agent TASK-225

//++agent TASK-222 [05.10.2026]
// Публичная форма результата инструмента (контракт Р2): замаскированное
// бизнес-значение уходит агенту в content[0].text; is_error выводится из
// `success:false` в теле результата.
//++agent TASK-225 [25.09.2026]
// Для opaque-результатов (без конверта границы данных) менеджер передаёт
// весь ToolCallResult — его `is_error:true` лежит прямо в JSON и тоже
// сохраняется наружу.
//++agent TASK-225
//++agent TASK-225 [25.09.2026]
// Бизнес-result бывает JSON-строкой (validate_query и другие
// no-mask инструменты возвращают сериализованный JSON из BSL).
// Её нельзя сериализовать повторно — to_string дал бы экранированный
// литерал `"{\"valid\":...}"`; в text уходит само строковое значение.
// Opaque-результат (ToolCallResult без конверта границы) уже находится в
// публичной форме — повторная обёртка вложила бы весь объект в text;
// он возвращается как есть (is_error/isError сохраняются внутри).
//++agent TASK-225
fn wrap_tool_result(masked: &Value) -> Value {
    if masked
        .get("content")
        .and_then(Value::as_array)
        .is_some_and(|blocks| {
            !blocks.is_empty()
                && blocks
                    .iter()
                    .all(|block| block.get("type").and_then(Value::as_str).is_some())
        })
    {
        return masked.clone();
    }
    let is_error = masked.get("success") == Some(&Value::Bool(false))
        || masked.get("is_error") == Some(&Value::Bool(true));
    let text = match masked {
        Value::String(text) => text.clone(),
        _ => serde_json::to_string(masked).unwrap_or_else(|_| "null".to_owned()),
    };
    json!({
        "content": [{"type": "text", "text": text}],
        "is_error": is_error
    })
}
//++agent TASK-222

//++agent TASK-224 [08.10.2026] итерация 4
/// Метаданные отчёта истории: `title` — текст запроса/описание вызова,
/// `schema` — `field_sources.schema` (по `columns[].name` восстанавливается
/// исходный порядок колонок: serde_json Map сортирует ключи, поэтому без
/// схемы порядок запроса был бы потерян).
struct ReportMeta<'a> {
    title: Option<&'a str>,
    schema: Option<&'a Value>,
}

/// Заголовок записи истории из preflight-arguments. На вход принимается
/// только зачищенная форма (`MaskEngine::cut_call_arguments`) — функция
/// сама по себе секреты не вырезает. Для инструментов с текстовым
/// параметром `query` — сам текст запроса; иначе компактный JSON
/// аргументов. Длина ограничена — это durable-поле.
const MAX_CALL_TITLE_CHARS: usize = 4096;

fn describe_call(_tool_name: &str, arguments: &Value) -> Option<String> {
    let title = arguments
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .or_else(|| match arguments {
            Value::Null => None,
            Value::Object(object) if object.is_empty() => None,
            _ => Some(canonical_json(arguments)),
        })?;
    Some(truncate_chars(&title, MAX_CALL_TITLE_CHARS))
}

fn truncate_chars(text: &str, max: usize) -> String {
    let mut chars = text.chars();
    let truncated: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

/// Effective срок жизни записи истории: не дольше, чем живёт RAM-mapping —
/// запись без возможности раскрытия бесполезна и только рискует хранением.
fn effective_history_ttl(settings: &super::DatabaseSettings) -> u64 {
    settings
        .history_ttl_seconds
        .min(settings.mapping_ttl_seconds)
}
//++agent TASK-224

//++agent TASK-225 [26.09.2026]
/// §6.1: отображение JSON-pointer маскированного результата в координату
/// отчёта `(block, row, col_idx)` — та же раскладка блоков и колонок, что
/// у `neutral_report`. `row`/`col_idx` = None для указателей вне таблиц
/// ({block, kind:"text"}).
/// Раскладка отчёта: указатель → координата + имена колонок блоков
/// (нужны B9 и B6 — ответы несут `column`, а не индекс).
#[derive(Default)]
struct ReportMap {
    cells: HashMap<String, (u32, Option<u32>, Option<u32>)>,
    columns: Vec<Vec<String>>,
}

fn report_pointer_map(result: &Value, schema: Option<&Value>) -> ReportMap {
    let mut map = HashMap::new();
    let mut columns: Vec<Vec<String>> = Vec::new();
    let mut block = 0u32;
    if let Some(content) = result.get("content").and_then(Value::as_array) {
        for (index, item) in content.iter().enumerate() {
            let prefix = format!("/content/{index}");
            match item.get("type").and_then(Value::as_str) {
                Some("text") if item.get("text").and_then(Value::as_str).is_some() => {
                    map.insert(prefix, (block, None, None));
                    columns.push(Vec::new());
                    block += 1;
                }
                Some("json") => {
                    columns.push(block_pointer_map(
                        item.get("json").unwrap_or(&Value::Null),
                        &format!("{prefix}/json"),
                        block,
                        schema,
                        &mut map,
                    ));
                    block += 1;
                }
                _ => {}
            }
        }
    }
    if let Some(structured) = result.get("structured_content") {
        columns.push(block_pointer_map(
            structured,
            "/structured_content",
            block,
            schema,
            &mut map,
        ));
        block += 1;
    }
    if block == 0 {
        columns.push(block_pointer_map(result, "", block, schema, &mut map));
    }
    ReportMap {
        cells: map,
        columns,
    }
}

/// Раскладка одного блока: таблица → ячейки `prefix/row/key`; иначе —
/// весь подграф значения ведёт в (block, None, None).
fn block_pointer_map(
    value: &Value,
    prefix: &str,
    block: u32,
    schema: Option<&Value>,
    map: &mut HashMap<String, (u32, Option<u32>, Option<u32>)>,
) -> Vec<String> {
    map.insert(prefix.to_owned(), (block, None, None));
    let rows_path = if value.is_array() {
        Some(prefix.to_owned())
    } else {
        value
            .get("rows")
            .and_then(Value::as_array)
            .map(|_| format!("{prefix}/rows"))
            .or_else(|| {
                value
                    .get("data")
                    .and_then(Value::as_array)
                    .map(|_| format!("{prefix}/data"))
            })
    };
    let Some(rows_path) = rows_path else {
        return Vec::new();
    };
    let Some(rows) = pointer_value(value, &rows_path[prefix.len()..])
        .and_then(Value::as_array)
        .filter(|rows| !rows.is_empty())
    else {
        return Vec::new();
    };
    let Some(objects) = rows
        .iter()
        .map(Value::as_object)
        .collect::<Option<Vec<_>>>()
    else {
        return Vec::new();
    };
    // Порядок колонок ≡ neutral_block: сначала schema.columns, затем
    // остальные ключи строк по алфавиту (BTreeSet).
    let mut columns: Vec<String> = Vec::new();
    if let Some(schema_columns) = schema
        .and_then(|s| s.get("columns"))
        .and_then(Value::as_array)
    {
        for name in schema_columns
            .iter()
            .filter_map(|column| column.get("name").and_then(Value::as_str))
        {
            let key = objects
                .iter()
                .flat_map(|row| row.keys())
                .find(|key| key.eq_ignore_ascii_case(name))
                .cloned()
                .unwrap_or_else(|| name.to_owned());
            if !columns.iter().any(|c| c.eq_ignore_ascii_case(&key)) {
                columns.push(key);
            }
        }
    }
    let extra: std::collections::BTreeSet<String> = objects
        .iter()
        .flat_map(|row| row.keys())
        .filter(|key| !columns.iter().any(|c| c.eq_ignore_ascii_case(key)))
        .cloned()
        .collect();
    columns.extend(extra);
    for (row_index, object) in objects.iter().enumerate() {
        for key in object.keys() {
            let Some(col) = columns
                .iter()
                .position(|column| column.eq_ignore_ascii_case(key))
            else {
                continue;
            };
            map.insert(
                format!(
                    "{}/{row_index}/{}",
                    rows_path,
                    key.replace('~', "~0").replace('/', "~1")
                ),
                (block, Some(row_index as u32), Some(col as u32)),
            );
        }
    }
    columns
}

fn pointer_value<'a>(value: &'a Value, suffix: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in suffix.trim_start_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }
        current = current.get(segment.replace("~1", "/").replace("~0", "~"))?;
    }
    Some(current)
}

/// Координата указателя — точное совпадение или ближайший предок
/// (вложенные значения ячейки ведут в свою ячейку).
fn cell_coord(map: &ReportMap, pointer: &str) -> (u32, Option<u32>, Option<u32>) {
    let mut current = pointer;
    loop {
        if let Some(coord) = map.cells.get(current) {
            return *coord;
        }
        match current.rfind('/') {
            Some(0) => current = "",
            Some(index) => current = &current[..index],
            None => return (0, None, None),
        }
    }
}

/// §6.2: сборка `mask_detail_json` — компактные кортежи
/// `[block,row,col,reason_idx]` (row/col = -1 вне таблиц), лимиты
/// 256 причин (в движке), 20 000 ячеек и 512 КБ JSON.
fn mask_detail_json(
    reason_entries: &[super::masking::ReasonEntry],
    cell_reasons: &[(String, u32)],
    result: &Value,
    schema: Option<&Value>,
    policy_version: i64,
) -> Option<String> {
    if reason_entries.is_empty() {
        return None;
    }
    let map = report_pointer_map(result, schema);
    let mut cells: Vec<[i64; 4]> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (pointer, reason_idx) in cell_reasons {
        let (block, row, col) = cell_coord(&map, pointer);
        let tuple = [
            block as i64,
            row.map_or(-1, |v| v as i64),
            col.map_or(-1, |v| v as i64),
            *reason_idx as i64,
        ];
        if seen.insert(tuple) {
            cells.push(tuple);
        }
    }
    // §6.2: счётчики reasons[].cells считаются по ПОЛНОМУ списку ячеек —
    // обрезание cells не должно занижать агрегаты.
    let mut counts = vec![0u64; reason_entries.len()];
    for tuple in &cells {
        if let Some(count) = counts.get_mut(tuple[3].max(0) as usize) {
            *count += 1;
        }
    }
    let mut truncated = false;
    if cells.len() > 20_000 {
        cells.truncate(20_000);
        truncated = true;
    }
    let reasons_json: Vec<Value> = reason_entries
        .iter()
        .enumerate()
        .map(|(idx, entry)| {
            let mut value = serde_json::to_value(entry).unwrap_or(Value::Null);
            value["cells"] = counts.get(idx).copied().unwrap_or(0).into();
            value
        })
        .collect();
    let render = |cells: &[[i64; 4]], truncated: bool| {
        json!({
            "v": 1,
            "policy_version": policy_version,
            "reasons": reasons_json,
            "cells": cells,
            "truncated": truncated,
        })
        .to_string()
    };
    let mut text = render(&cells, truncated);
    if text.len() > 512 * 1024 {
        let mut keep = cells.len();
        while keep > 0 && text.len() > 512 * 1024 {
            keep /= 2;
            text = render(&cells[..keep], true);
        }
        cells.truncate(keep);
        text = render(&cells, true);
    }
    Some(text)
}
//++agent TASK-225

fn neutral_report(result: &Value, meta: &ReportMeta) -> Value {
    let mut blocks = Vec::new();
    if let Some(content) = result.get("content").and_then(Value::as_array) {
        for item in content {
            match item.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(text) = item.get("text").and_then(Value::as_str) {
                        blocks.push(json!({"kind":"text", "text":text}));
                    }
                }
                Some("json") => blocks.push(neutral_block(
                    item.get("json").unwrap_or(&Value::Null),
                    meta.schema,
                )),
                _ => {}
            }
        }
    }
    if let Some(structured) = result.get("structured_content") {
        blocks.push(neutral_block(structured, meta.schema));
    }
    //++agent TASK-222 [05.10.2026]
    // Контракт Р2: result — сам бизнес-JSON; без ToolCallResult-ключей
    // отчёт строится по всему значению.
    if blocks.is_empty() {
        blocks.push(neutral_block(result, meta.schema));
    }
    //++agent TASK-224 [08.10.2026] итерация 4: title — текст запроса
    // (при его отсутствии null — форма отчёта стабильна).
    json!({"version":1, "title":meta.title, "blocks":blocks})
    //++agent TASK-224
}

fn neutral_block(value: &Value, schema: Option<&Value>) -> Value {
    let rows = value
        .as_array()
        .or_else(|| value.get("rows").and_then(Value::as_array))
        //++agent TASK-222: бизнес-результат execute_query хранит строки в `data`.
        .or_else(|| value.get("data").and_then(Value::as_array));
    let Some(rows) = rows.filter(|rows| !rows.is_empty()) else {
        return json!({"kind":"text", "text":canonical_json(value)});
    };
    let Some(objects) = rows
        .iter()
        .map(Value::as_object)
        .collect::<Option<Vec<_>>>()
    else {
        return json!({"kind":"text", "text":canonical_json(value)});
    };
    //++agent TASK-224 [08.10.2026] итерация 4
    // Порядок колонок — порядок запроса из schema.columns[].name (ключи
    // строк сортируются serde_json — без схемы порядок был бы алфавитным).
    // Ключи строк вне схемы дописываются в конец; колонка схемы без
    // значений в строках всё равно показывается (null).
    let mut columns: Vec<String> = Vec::new();
    if let Some(schema_columns) = schema
        .and_then(|s| s.get("columns"))
        .and_then(Value::as_array)
    {
        for name in schema_columns
            .iter()
            .filter_map(|column| column.get("name").and_then(Value::as_str))
        {
            let key = objects
                .iter()
                .flat_map(|row| row.keys())
                .find(|key| key.eq_ignore_ascii_case(name))
                .cloned()
                .unwrap_or_else(|| name.to_owned());
            if !columns.iter().any(|c| c.eq_ignore_ascii_case(&key)) {
                columns.push(key);
            }
        }
    }
    let extra: std::collections::BTreeSet<String> = objects
        .iter()
        .flat_map(|row| row.keys())
        .filter(|key| !columns.iter().any(|c| c.eq_ignore_ascii_case(key)))
        .cloned()
        .collect();
    columns.extend(extra);
    if columns.is_empty() {
        return json!({"kind":"text", "text":canonical_json(value)});
    }
    // Нескалярные ячейки (например, ссылочные объекты 1С) больше не роняют
    // всю таблицу в text-блок — приводятся к читаемому скаляру.
    let scalar_rows: Vec<Vec<Value>> = objects
        .iter()
        .map(|row| {
            columns
                .iter()
                .map(|column| {
                    let cell = objects_cell(row, column);
                    report_cell(cell)
                })
                .collect()
        })
        .collect();
    let column_descriptors: Vec<_> = columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let mut types: HashSet<_> = scalar_rows
                .iter()
                .map(|row| report_scalar_type(&row[index]))
                .collect();
            types.remove("null");
            let value_type = if types.len() == 1 {
                types.into_iter().next().unwrap_or("null")
            } else if types.is_empty() {
                "null"
            } else {
                "mixed"
            };
            // Замок в UI: колонка реально содержит маскированные значения.
            let masked = scalar_rows
                .iter()
                .any(|row| row[index].as_str().is_some_and(masked_cell));
            json!({"id":column,"label":column,"type":value_type,"masked":masked})
        })
        .collect();
    json!({"kind":"table","columns":column_descriptors,"rows":scalar_rows})
    //++agent TASK-224
}

//++agent TASK-224 [08.10.2026] итерация 4
/// Ячейка строки по имени колонки — регистронезависимо (схема запроса и
/// ключи ответа 1С могут различаться регистром).
fn objects_cell<'a>(row: &'a serde_json::Map<String, Value>, column: &str) -> &'a Value {
    row.get(column)
        .or_else(|| {
            row.iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(column))
                .map(|(_, value)| value)
        })
        .unwrap_or(&Value::Null)
}

/// Приведение ячейки к скаляру отчёта: ссылочные объекты 1С отдают
/// человекочитаемое представление, прочие — компактный JSON.
fn report_cell(value: &Value) -> Value {
    if is_report_scalar(value) {
        return value.clone();
    }
    if let Some(object) = value.as_object() {
        for key in [
            "Представление",
            "presentation",
            "ПредставлениеСсылки",
            "name",
            "text",
            "value",
        ] {
            if let Some(text) = object.get(key).and_then(Value::as_str) {
                return Value::String(text.to_owned());
            }
        }
    }
    Value::String(canonical_json(value))
}

fn masked_cell(text: &str) -> bool {
    text.contains("[MASK:v1:") || text.contains("[SECRET_REMOVED]")
}
//++agent TASK-224

fn is_report_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

fn report_scalar_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        _ => "invalid",
    }
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())
}

//++agent TASK-225 [26.09.2026]
/// §5: результат сухого прогона — Empty для `history_empty:true` ответа.
pub enum DryRunOutcome {
    Empty(&'static str),
    Done(Value),
}

/// Снятие обёртки сохранённого публичного ответа: ToolCallResult
/// `{content:[{type:"text",text}]}` → бизнес-JSON текста; остальное —
/// само значение (opaque-форма Р2).
fn unwrap_stored_result(stored: &Value) -> Value {
    if let Some(text) = stored
        .get("content")
        .and_then(Value::as_array)
        .and_then(|items| items.iter().find(|item| item["type"] == "text"))
        .and_then(|item| item["text"].as_str())
    {
        return serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()));
    }
    stored.clone()
}

/// Обход листьев → (pointer, статус): `masked` — токен `[MASK:v1:`,
/// `secret` — врезка `[SECRET_REMOVED]` (содержится в строке целиком),
/// иначе `open`.
fn collect_cell_status(value: &Value, pointer: &str, out: &mut Vec<(String, &'static str)>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                collect_cell_status(value, &format!("{pointer}/{escaped}"), out);
            }
        }
        Value::Array(array) => {
            for (index, value) in array.iter().enumerate() {
                collect_cell_status(value, &format!("{pointer}/{index}"), out);
            }
        }
        Value::String(text) => {
            let status = if text.contains("[SECRET_REMOVED]") {
                "secret"
            } else if text.contains("[MASK:v1:") {
                "masked"
            } else {
                "open"
            };
            out.push((pointer.to_owned(), status));
        }
        _ => out.push((pointer.to_owned(), "open")),
    }
}
//++agent TASK-225

//++agent TASK-225 [26.09.2026] M-6
#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    /// M-6: отмена future сухого прогона (отключение клиента) обязана
    /// снять busy-флаг — иначе база навсегда в DRY_RUN_BUSY до рестарта.
    /// Прогон удерживается в Pending на `mappings.write()` — тест держит
    /// write-гард, future дропается незавершённым, Drop гарда чистит флаг.
    #[tokio::test]
    async fn dry_run_busy_flag_released_when_future_cancelled() {
        let storage = Arc::new(SqliteStorage::in_memory().unwrap());
        // Конструктор чистит history (purge_ephemeral_history) — записи
        // снимка прогона вставляются уже после new.
        let service = MaskingService::new(storage);
        let database_id = Uuid::new_v4();
        service
            .storage
            .with_connection(|connection| {
                connection.execute(
                    "INSERT INTO databases(id,instance_id,mode,created_at,updated_at)
                     VALUES (?1,?2,'enabled','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
                    rusqlite::params![database_id.to_string(), Uuid::new_v4().to_string()],
                )?;
                connection.execute(
                    "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,
                            policy_version,mask_reasons_json,public_result_json,report_json,
                            created_at,expires_at,mapping_batch_id,field_sources_json)
                     VALUES (?1,?2,'chat',?3,'execute_query','tool_result',1,'[]',
                            '{\"content\":[]}','{}','2026-01-02T00:00:00Z',
                            '2999-01-01T00:00:00Z',?4,'{}')",
                    rusqlite::params![
                        Uuid::new_v4().to_string(),
                        database_id.to_string(),
                        Uuid::new_v4().to_string(),
                        Uuid::new_v4().to_string()
                    ],
                )
            })
            .unwrap();
        assert_eq!(
            service
                .storage
                .dry_run_records(database_id, 10)
                .unwrap()
                .len(),
            1,
            "запись history не попала в выборку dry_run"
        );
        let to = PolicySnapshot::default();
        let source_stats = HashMap::new();
        let draft_sources = HashSet::new();
        let new_source_estimates = HashMap::new();
        // Прогон упрётся в этот же write-лок на этапе разрешения mapping.
        let hold_mappings = service.mappings.write().await;
        {
            let future = service.dry_run(
                database_id,
                &to,
                &source_stats,
                &draft_sources,
                &new_source_estimates,
                10,
            );
            tokio::pin!(future);
            std::future::poll_fn(|context| match future.as_mut().poll(context) {
                std::task::Poll::Pending => std::task::Poll::Ready(()),
                std::task::Poll::Ready(result) => panic!(
                    "dry_run завершился до mappings.write(): {:?}",
                    result.map(|_| ()).map_err(|error| error.code)
                ),
            })
            .await;
            assert!(
                service.dry_run_lock.lock().unwrap().contains(&database_id),
                "busy-флаг не выставлен во время прогона"
            );
            // drop(future): имитация отключения клиента — axum отменяет
            // future, снятие возможно только через Drop гарда.
        }
        assert!(
            service.dry_run_lock.lock().unwrap().is_empty(),
            "busy-флаг завис после отмены dry_run"
        );
        drop(hold_mappings);
        let second = service
            .dry_run(
                database_id,
                &to,
                &source_stats,
                &draft_sources,
                &new_source_estimates,
                10,
            )
            .await;
        assert!(
            !matches!(second, Err(ref error) if error.code == ErrorCode::DryRunBusy),
            "повторный dry-run после отмены вернул DRY_RUN_BUSY"
        );
    }

    /// N-3: обновление политики с пустым словарём пересчитывает действия
    /// на существующем индексе (`with_actions` в spawn_blocking вне
    /// write-лока кэша) и публикует результат — снимок маскирует по
    /// НОВЫМ правилам, а не по действиям прежнего индекса.
    #[tokio::test]
    async fn policy_update_recomputes_index_actions() {
        use crate::domain::{DictionaryIndex, PolicyRule, RuleAction, RuleSelector};

        fn dictionary_rule(action: RuleAction) -> PolicyRule {
            PolicyRule {
                selector: RuleSelector::Dictionary,
                pattern: "ORG".to_string(),
                action,
                category: "ORG".to_string(),
                priority: 0,
                rule_id: None,
            }
        }

        let storage = Arc::new(SqliteStorage::in_memory().unwrap());
        let service = MaskingService::new(storage);
        let database_id = Uuid::new_v4();
        let dictionary: HashMap<String, String> =
            [("СекретноеЗначение".to_string(), "ORG".to_string())]
                .into_iter()
                .collect();

        // v1: keep — значение остаётся как есть.
        let keep_rules = vec![dictionary_rule(RuleAction::Keep)];
        let index = DictionaryIndex::build(&dictionary, &keep_rules).expect("index");
        let snapshot = PolicySnapshot {
            version: 1,
            rules: keep_rules,
            dictionary,
            dictionary_index: Some(index),
            ready: true,
            ..PolicySnapshot::default()
        };
        service.set_policy_snapshot(database_id, snapshot).await;

        // v2: mask при пустом словаре — пересчёт действий на индексе v1.
        let update = PolicySnapshot {
            version: 2,
            rules: vec![dictionary_rule(RuleAction::Mask)],
            ready: true,
            ..PolicySnapshot::default()
        };
        service.set_policy_snapshot(database_id, update).await;

        let merged = service
            .policy_snapshot_view(database_id)
            .await
            .expect("snapshot");
        assert!(!merged.dictionary.is_empty(), "словарь смержен из кэша");
        assert!(merged.dictionary_index.is_some(), "индекс сохранён");

        // Семантика: новое действие применено — значение маскируется.
        let engine = MaskEngine::default();
        let mappings = MappingStore::new(MappingLimits::default());
        let output = engine
            .mask(
                &json!({"columns": ["префикс СекретноеЗначение суффикс"]}),
                database_id,
                "chat",
                Uuid::new_v4(),
                3600,
                &merged,
                &mappings,
                &json!({}),
            )
            .expect("mask");
        let rendered = serde_json::to_string(&output.value).unwrap();
        assert!(
            !rendered.contains("СекретноеЗначение"),
            "действие keep устарело, значение должно маскироваться: {rendered}"
        );
        assert!(
            output.reasons.iter().any(|code| code == "dictionary:ORG"),
            "причина dictionary:ORG: {:?}",
            output.reasons
        );
    }
}
//++agent TASK-225
