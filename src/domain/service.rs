use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use chrono::{Duration, Utc};
use serde_json::{json, Value};
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

//++agent TASK-222 [05.10.2026]
mod dictionary_feed;
//++agent TASK-222

use crate::storage::{HistoryWrite, SqliteStorage, TerminalWrite};

use super::{
    DatabaseMode, ErrorCode, FinalizeOutcome, FinalizeRequest, FinalizeResponse, MappingLimits,
    MappingStore, MaskEngine, PolicySnapshot, PreflightRequest, PreflightResponse, ServiceError,
    TerminalEventRequest, TerminalEventResponse, TerminalScopeKind, ToolClass, SCHEMA_VERSION,
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
        if class == ToolClass::DenyPendingReview {
            return self.persist_preflight_denial(
                &request,
                &settings,
                ErrorCode::ToolPendingReview,
            );
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
        let mut mappings = self.mappings.write().await;
        let arguments = match self.engine.resolve_tokens(
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
                let report = neutral_report(&public_result);
                self.storage.write_scoped_terminal(
                    database_id,
                    chat_id,
                    request.call_id,
                    &request.tool_name,
                    &request.error_code,
                    &public_result,
                    &report,
                    settings.history_ttl_seconds,
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
        if let Some(reason) = sanitized_reason {
            return self.persist_sanitized_failure(
                &request,
                &settings,
                policy.version,
                outcome_name,
                reason,
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
            && !valid_query_lineage(&logical_result, &request.field_sources)
        {
            return self.persist_sanitized_failure(
                &request,
                &settings,
                policy.version,
                "sanitized_error",
                "service:query_lineage_incomplete",
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
        let report = neutral_report(&fully_masked);
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
                settings.history_ttl_seconds,
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
        self.cache_response(key, public_result.clone(), settings.history_ttl_seconds);
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
    ) -> Result<FinalizeResponse, ServiceError> {
        let public_result = safe_processing_error(request.correlation_id);
        let report = neutral_report(&public_result);
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
                settings.history_ttl_seconds,
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
            settings.history_ttl_seconds,
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
        let report = neutral_report(&public_result);
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
                settings.history_ttl_seconds,
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

fn valid_terminal_tool_name(tool_name: &str) -> bool {
    !tool_name.is_empty()
        && tool_name.len() <= 128
        && tool_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

//++agent TASK-222 [05.10.2026]
// Контракт Р2: `result` — непрозрачный бизнес-JSON; сервис не навязывает
// форму ToolCallResult, проверяет только объект и отсутствие опасных форм
// отчётов. Публичную обёртку строит `wrap_tool_result` на выходе.
fn validate_tool_result(result: &Value) -> Result<(), ()> {
    result.as_object().ok_or(())?;
    reject_unsafe_report_shapes(result, 0)
}

//++agent TASK-221 [23.09.2026 18:30:00]
// Query rows require an unambiguous canonical source for every public column.
// Other tools can return arbitrary text and use their remaining detectors.
fn valid_query_lineage(result: &Value, field_sources: &super::FieldSources) -> bool {
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
    for column in columns {
        let Some(name) = column.get("name").and_then(Value::as_str) else {
            return false;
        };
        let Some(sources) = column.get("sources").and_then(Value::as_array) else {
            return false;
        };
        if name.is_empty() || sources.is_empty() || sources_by_name.contains_key(name) {
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
                fields
                    .keys()
                    .all(|name| sources_by_name.contains_key(name.as_str()))
            })
        })
    })
}
//++agent TASK-221

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
fn wrap_tool_result(masked: &Value) -> Value {
    let is_error = masked.get("success") == Some(&Value::Bool(false));
    let text = serde_json::to_string(masked).unwrap_or_else(|_| "null".to_owned());
    json!({
        "content": [{"type": "text", "text": text}],
        "is_error": is_error
    })
}
//++agent TASK-222

fn neutral_report(result: &Value) -> Value {
    let mut blocks = Vec::new();
    if let Some(content) = result.get("content").and_then(Value::as_array) {
        for item in content {
            match item.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(text) = item.get("text").and_then(Value::as_str) {
                        blocks.push(json!({"kind":"text", "text":text}));
                    }
                }
                Some("json") => {
                    blocks.push(neutral_block(item.get("json").unwrap_or(&Value::Null)))
                }
                _ => {}
            }
        }
    }
    if let Some(structured) = result.get("structured_content") {
        blocks.push(neutral_block(structured));
    }
    //++agent TASK-222 [05.10.2026]
    // Контракт Р2: result — сам бизнес-JSON; без ToolCallResult-ключей
    // отчёт строится по всему значению.
    if blocks.is_empty() {
        blocks.push(neutral_block(result));
    }
    json!({"version":1, "blocks":blocks})
}

fn neutral_block(value: &Value) -> Value {
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
    let columns: std::collections::BTreeSet<_> =
        objects.iter().flat_map(|row| row.keys().cloned()).collect();
    if columns.is_empty()
        || objects.iter().any(|row| {
            columns
                .iter()
                .any(|column| !is_report_scalar(row.get(column).unwrap_or(&Value::Null)))
        })
    {
        return json!({"kind":"text", "text":canonical_json(value)});
    }
    let column_descriptors: Vec<_> = columns
        .iter()
        .map(|column| {
            let mut types: HashSet<_> = objects
                .iter()
                .map(|row| report_scalar_type(row.get(column).unwrap_or(&Value::Null)))
                .collect();
            types.remove("null");
            let value_type = if types.len() == 1 {
                types.into_iter().next().unwrap_or("null")
            } else if types.is_empty() {
                "null"
            } else {
                "mixed"
            };
            json!({"id":column,"label":column,"type":value_type})
        })
        .collect();
    let scalar_rows: Vec<_> = objects
        .iter()
        .map(|row| {
            Value::Array(
                columns
                    .iter()
                    .map(|column| row.get(column).cloned().unwrap_or(Value::Null))
                    .collect(),
            )
        })
        .collect();
    json!({"kind":"table","columns":column_descriptors,"rows":scalar_rows})
}

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
