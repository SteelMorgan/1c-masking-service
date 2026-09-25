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

use crate::storage::{HistoryWrite, SqliteStorage, TerminalWrite};

use super::{
    DatabaseMode, ErrorCode, FeedMetadataItem, FinalizeOutcome, FinalizeRequest, FinalizeResponse,
    MappingLimits, MappingStore, MaskEngine, PolicySnapshot, PreflightRequest, PreflightResponse,
    ServiceError, TerminalEventRequest, TerminalEventResponse, TerminalScopeKind, ToolClass,
    SCHEMA_VERSION,
};

type CallKey = (Uuid, String, Uuid);

const VERIFIED_TERMINAL_CODES: &[&str] = &[
    "ACTION_REQUIRED",
    "TOOL_PENDING_REVIEW",
    "MASK_TOKEN_INVALID",
    "SERVICE_NOT_READY",
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
    engine: MaskEngine,
    //++agent TASK-225 [25.09.2026]
    // Дедуп лога feed-pull отказов: transient-ошибка повторяется каждый
    // тик, журналировать надо факт отказа intent-а (created_at + код), а
    // не каждый повтор попытки.
    feed_pull_log_dedup: Mutex<HashMap<Uuid, (String, &'static str)>>,
    //++agent TASK-225
}

struct CachedResponse {
    value: Value,
    expires_at: chrono::DateTime<Utc>,
}

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
        //--agent TASK-224
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
            engine: MaskEngine::new(),
            feed_pull_log_dedup: Mutex::new(HashMap::new()),
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
    //--agent TASK-224
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

    pub async fn set_policy_snapshot(&self, database_id: Uuid, mut snapshot: PolicySnapshot) {
        let mut cache = self.policy_cache.write().await;
        if let Some(existing) = cache.get(&database_id) {
            if snapshot.dictionary.is_empty() {
                snapshot.dictionary = existing.dictionary.clone();
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
        let _admission = self
            .admission_for(request.database_id, request.correlation_id)?
            .lock_owned()
            .await;
        validate_common(
            request.schema_version,
            &request.chat_id,
            &request.tool_name,
            request.correlation_id,
        )?;
        let (settings, created) = self
            .storage
            .ensure_database(request.database_id)
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?;
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
            request.database_id,
            &request.chat_id,
            &request.tool_name,
            call_title.as_deref(),
            effective_history_ttl(&settings),
        );
        //--agent TASK-224
        if created || settings.mode == DatabaseMode::Unconfigured {
            return self.persist_preflight_denial(&request, &settings, ErrorCode::ActionRequired);
        }
        let class = match self
            .storage
            .tool_class(request.database_id, &request.tool_name)
        {
            Ok(class) => class,
            Err(_) => {
                return self.persist_preflight_denial(
                    &request,
                    &settings,
                    ErrorCode::ServiceNotReady,
                )
            }
        };
        //++agent TASK-225 [25.09.2026]
        // Отказ по классу deny-pending-review пишется отдельным путём:
        // та же durable-запись, но с учётом tool_classifications
        // (auto_added/first_seen_at/denied_count) в одной транзакции.
        //++agent TASK-225
        if class == ToolClass::DenyPendingReview {
            return self.persist_pending_review_denial(&request, &settings);
        }
        if class == ToolClass::DataMask && settings.mode == DatabaseMode::Enabled {
            let policy = match self
                .policy_for(request.database_id, &settings, request.correlation_id)
                .await
            {
                Ok(policy) => policy,
                Err(error) => {
                    return self.persist_preflight_denial(&request, &settings, error.code)
                }
            };
            if !policy.ready {
                return self.persist_preflight_denial(
                    &request,
                    &settings,
                    ErrorCode::ServiceNotReady,
                );
            }
        }
        //++agent TASK-225 [25.09.2026]
        // Обратная расшифровка токенов в аргументах — только для
        // data-mask при Enabled: подстановка реальных значений в вызов,
        // чей ответ будет замаскирован. Для metadata-bypass и data-mask
        // вне Enabled само наличие [MASK:v1:...] — попытка оракула
        // (резолв вернул бы сырьё в незамаскированный ответ или просто
        // протечку идентификатора) — отказ MASK_TOKEN_INVALID до 1С.
        //++agent TASK-225
        let can_resolve = class == ToolClass::DataMask && settings.mode == DatabaseMode::Enabled;
        let arguments = if can_resolve {
            let mut mappings = self.mappings.write().await;
            match self.engine.resolve_tokens(
                &request.arguments,
                request.database_id,
                &request.chat_id,
                &mut mappings,
            ) {
                Ok(arguments) => arguments,
                Err(_) => {
                    drop(mappings);
                    return self.persist_preflight_denial(
                        &request,
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
                let (Some(database_id), Some(chat_id)) =
                    (request.scope.database_id, request.scope.chat_id.as_deref())
                else {
                    return Err(ServiceError::new(
                        ErrorCode::PolicyInvalid,
                        request.correlation_id,
                    ));
                };
                if chat_id.is_empty()
                    || chat_id.len() > 512
                    || !VERIFIED_TERMINAL_CODES.contains(&request.error_code.as_str())
                {
                    return Err(ServiceError::new(
                        ErrorCode::PolicyInvalid,
                        request.correlation_id,
                    ));
                }
                let (settings, _) = self.storage.ensure_database(database_id).map_err(|_| {
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
            }
            TerminalScopeKind::Unverified => {
                if request.scope.database_id.is_some()
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
        let _admission = self
            .admission_for(request.database_id, request.correlation_id)?
            .lock_owned()
            .await;
        validate_common(
            request.schema_version,
            &request.chat_id,
            &request.tool_name,
            request.correlation_id,
        )?;
        let key = (
            request.database_id,
            request.chat_id.clone(),
            request.call_id,
        );
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
            .load_history(request.database_id, &request.chat_id, request.call_id)
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
                .entry(request.database_id)
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_database_workers)))
                .clone()
        };
        let _database_worker = database_worker
            .acquire_owned()
            .await
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?;
        let (settings, created) = self
            .storage
            .ensure_database(request.database_id)
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?;
        if created || settings.mode == DatabaseMode::Unconfigured {
            return Err(ServiceError::new(
                ErrorCode::ActionRequired,
                request.correlation_id,
            ));
        }
        let class = self
            .storage
            .tool_class(request.database_id, &request.tool_name)
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?;
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
        let policy = self
            .policy_for(request.database_id, &settings, request.correlation_id)
            .await?;
        if settings.mode == DatabaseMode::Enabled && class == ToolClass::DataMask && !policy.ready {
            return Err(ServiceError::new(
                ErrorCode::ServiceNotReady,
                request.correlation_id,
            ));
        }
        //++agent TASK-224 [08.10.2026] итерация 4: заголовок отчёта —
        // текст запроса из контекста, записанного preflight-фазой
        // (fail-soft: без записи отчёт остаётся без заголовка).
        let call_title = self
            .storage
            .call_context_text(request.call_id)
            .ok()
            .flatten();
        //--agent TASK-224
        if let Some(reason) = sanitized_reason {
            return self.persist_sanitized_failure(
                &request,
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
            request.database_id,
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
                &settings,
                policy.version,
                "sanitized_error",
                "service:mapping_capacity_exceeded",
                call_title.as_deref(),
            );
        }

        let fully_masked = masked.value;
        let mut mask_reasons: Vec<_> = masked.reasons.into_iter().collect();
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
        //--agent TASK-224
        let write = self
            .storage
            .write_history(
                request.database_id,
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
            // A persisted version without its process-local snapshot is also
            // unready; only feed activation can publish a usable generation.
            ready: false,
            ..PolicySnapshot::default()
        })
    }

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

    fn persist_sanitized_failure(
        &self,
        request: &FinalizeRequest,
        settings: &super::DatabaseSettings,
        policy_version: i64,
        outcome: &str,
        reason: &str,
        //++agent TASK-224 [08.10.2026] итерация 4: заголовок из контекста
        // вызова — sanitized-запись тоже должна показывать текст запроса.
        //--agent TASK-224
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
                request.database_id,
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
            (
                request.database_id,
                request.chat_id.clone(),
                request.call_id,
            ),
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
                request.database_id,
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
                request.database_id,
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
        _ => "Операция временно недоступна",
    };
    json!({
        "content": [{"type": "text", "text": format!("{message}; correlation_id={correlation_id}")}],
        "is_error": true,
        "structured_content": {"error":{"code":code,"correlation_id":correlation_id}}
    })
}

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
// metadata-bypass инструменты возвращают сериализованный JSON из BSL).
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
//--agent TASK-224

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
    //--agent TASK-224
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
    //--agent TASK-224
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
//--agent TASK-224

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
