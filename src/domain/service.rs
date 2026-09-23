use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

use crate::storage::{HistoryWrite, SqliteStorage, TerminalWrite};

use super::{
    DatabaseMode, ErrorCode, FeedActivateRequest, FeedChunkRequest, FeedJob, FinalizeOutcome,
    FinalizeRequest, FinalizeResponse, MappingLimits, MappingStore, MaskEngine, PolicyRule,
    PolicySnapshot, PreflightRequest, PreflightResponse, RuleAction, RuleSelector, ServiceError,
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
    // Raw disabled/bypass projections are never persisted. This bounded cache
    // preserves exact retry behavior only for the current process lifetime.
    completed_responses: Mutex<HashMap<CallKey, CachedResponse>>,
    feed_staging: Mutex<HashMap<Uuid, FeedStaging>>,
    issued_feed_jobs: Mutex<HashMap<Uuid, FeedJob>>,
    metadata_bootstrap_jobs: Mutex<HashSet<Uuid>>,
    admission: Arc<Semaphore>,
    workers: Arc<Semaphore>,
    database_workers: Mutex<HashMap<Uuid, Arc<Semaphore>>>,
    per_database_workers: usize,
    engine: MaskEngine,
}

struct FeedStaging {
    chunks: BTreeMap<u32, StagedChunk>,
}

struct StagedChunk {
    digest: [u8; 32],
    payload: super::FeedPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeedChunkRejectReason {
    MetadataCountLimit,
    DictionaryCountLimit,
    MetadataSourcePathLimit,
    MetadataFieldNameLimit,
    DictionarySelectionMissing,
    DictionarySelectorNotFound,
    DictionarySelectorSourceInvalid,
    DictionarySelectorCategoryInvalid,
    DictionaryValueLimit,
    DictionarySourceMismatch,
    DictionaryCategoryMismatch,
}

impl FeedChunkRejectReason {
    fn code(self) -> &'static str {
        match self {
            Self::MetadataCountLimit => "FEED_METADATA_COUNT_LIMIT",
            Self::DictionaryCountLimit => "FEED_DICTIONARY_COUNT_LIMIT",
            Self::MetadataSourcePathLimit => "FEED_METADATA_SOURCE_PATH_LIMIT",
            Self::MetadataFieldNameLimit => "FEED_METADATA_FIELD_NAME_LIMIT",
            Self::DictionarySelectionMissing => "FEED_DICTIONARY_SELECTION_MISSING",
            Self::DictionarySelectorNotFound => "FEED_DICTIONARY_SELECTOR_NOT_FOUND",
            Self::DictionarySelectorSourceInvalid => "FEED_DICTIONARY_SELECTOR_SOURCE_INVALID",
            Self::DictionarySelectorCategoryInvalid => "FEED_DICTIONARY_SELECTOR_CATEGORY_INVALID",
            Self::DictionaryValueLimit => "FEED_DICTIONARY_VALUE_LIMIT",
            Self::DictionarySourceMismatch => "FEED_DICTIONARY_SOURCE_MISMATCH",
            Self::DictionaryCategoryMismatch => "FEED_DICTIONARY_CATEGORY_MISMATCH",
        }
    }
}

struct CachedResponse {
    value: Value,
    expires_at: chrono::DateTime<Utc>,
}

impl MaskingService {
    pub fn new(storage: Arc<SqliteStorage>) -> Self {
        // RAM feed data is intentionally lost on restart. Queue a new bounded
        // generation immediately so manager polling can restore readiness.
        let _ = storage.enqueue_startup_refresh_jobs();
        Self {
            storage,
            mappings: RwLock::new(MappingStore::new(MappingLimits::default())),
            policy_cache: RwLock::new(HashMap::new()),
            completed_responses: Mutex::new(HashMap::new()),
            feed_staging: Mutex::new(HashMap::new()),
            issued_feed_jobs: Mutex::new(HashMap::new()),
            metadata_bootstrap_jobs: Mutex::new(HashSet::new()),
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

    pub async fn pending_feed_jobs(
        &self,
        limit: usize,
        correlation_id: Uuid,
    ) -> Result<Vec<FeedJob>, ServiceError> {
        let jobs = self
            .storage
            .pending_feed_jobs(limit)
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, correlation_id))?;
        let cache = self.policy_cache.read().await;
        let mut issued = self
            .issued_feed_jobs
            .lock()
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, correlation_id))?;
        let mut result = Vec::with_capacity(jobs.len());
        for mut job in jobs {
            if job.dictionary_selectors.iter().any(is_wildcard_selector) {
                let Some(snapshot) = cache
                    .get(&job.database_id)
                    .filter(|snapshot| !snapshot.metadata_sources.is_empty())
                else {
                    // All selectors require a service-owned allowlist derived
                    // from metadata. Issue a metadata-only generation first;
                    // the follow-up generation carries explicit selectors.
                    job.dictionary_selectors.clear();
                    self.metadata_bootstrap_jobs
                        .lock()
                        .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, correlation_id))?
                        .insert(job.job_id);
                    issued.insert(job.job_id, job.clone());
                    result.push(job);
                    continue;
                };
                if let Ok(mut bootstrap) = self.metadata_bootstrap_jobs.lock() {
                    bootstrap.remove(&job.job_id);
                }
                let wildcard = job
                    .dictionary_selectors
                    .iter()
                    .find(|selector| is_wildcard_selector(selector))
                    .cloned()
                    .ok_or_else(|| ServiceError::new(ErrorCode::PolicyInvalid, correlation_id))?;
                let expanded = match expand_all_selectors(&job, snapshot, &wildcard) {
                    Ok(expanded) => expanded,
                    Err(()) => {
                        let _ = self.storage.fail_feed_job(
                            job.job_id,
                            "LIMIT_EXCEEDED",
                            correlation_id,
                        );
                        return Err(ServiceError::new(
                            ErrorCode::ResultLimitExceeded,
                            correlation_id,
                        ));
                    }
                };
                if expanded.is_empty() {
                    continue;
                }
                job.dictionary_selectors = expanded;
            }
            issued.insert(job.job_id, job.clone());
            result.push(job);
        }
        Ok(result)
    }

    pub fn upload_feed_chunk(
        &self,
        job_id: Uuid,
        index: u32,
        request: FeedChunkRequest,
    ) -> Result<u32, ServiceError> {
        if request.schema_version != SCHEMA_VERSION || request.payload.page_index != index {
            return Err(feed_chunk_error(
                "FEED_REQUEST_PAGE_OR_VERSION_MISMATCH",
                index,
                &request.payload,
                ErrorCode::PolicyInvalid,
                request.correlation_id,
            ));
        }
        let job = self
            .issued_feed_jobs
            .lock()
            .map_err(|_| {
                feed_chunk_error(
                    "FEED_ISSUED_JOBS_LOCK_UNAVAILABLE",
                    index,
                    &request.payload,
                    ErrorCode::ServiceNotReady,
                    request.correlation_id,
                )
            })?
            .get(&job_id)
            .cloned()
            .ok_or_else(|| {
                feed_chunk_error(
                    "FEED_JOB_NOT_ISSUED",
                    index,
                    &request.payload,
                    ErrorCode::PolicyInvalid,
                    request.correlation_id,
                )
            })?;
        validate_feed_payload(&job, &request.payload).map_err(|reason| {
            feed_chunk_error(
                reason.code(),
                index,
                &request.payload,
                ErrorCode::PolicyInvalid,
                request.correlation_id,
            )
        })?;
        let canonical =
            canonical_value_bytes(&serde_json::to_value(&request.payload).map_err(|_| {
                feed_chunk_error(
                    "FEED_PAYLOAD_SERIALIZATION_FAILED",
                    index,
                    &request.payload,
                    ErrorCode::PolicyInvalid,
                    request.correlation_id,
                )
            })?);
        if canonical.len() > job.max_chunk_bytes {
            return Err(feed_chunk_error(
                "FEED_CHUNK_BYTES_LIMIT",
                index,
                &request.payload,
                ErrorCode::ResultLimitExceeded,
                request.correlation_id,
            ));
        }
        let digest: [u8; 32] = Sha256::digest(&canonical).into();
        if request.chunk_digest != hex_encode(&digest) {
            return Err(feed_chunk_error(
                "FEED_DIGEST_MISMATCH",
                index,
                &request.payload,
                ErrorCode::PolicyInvalid,
                request.correlation_id,
            ));
        }
        let mut staging = self.feed_staging.lock().map_err(|_| {
            feed_chunk_error(
                "FEED_STAGING_LOCK_UNAVAILABLE",
                index,
                &request.payload,
                ErrorCode::ServiceNotReady,
                request.correlation_id,
            )
        })?;
        if !staging.contains_key(&job_id) && staging.len() >= 100 {
            return Err(feed_chunk_error(
                "FEED_STAGING_JOB_LIMIT",
                index,
                &request.payload,
                ErrorCode::ResultLimitExceeded,
                request.correlation_id,
            ));
        }
        let feed = staging.entry(job_id).or_insert_with(|| FeedStaging {
            chunks: BTreeMap::new(),
        });
        if let Some(existing) = feed.chunks.get(&index) {
            if existing.digest == digest {
                return Ok(index);
            }
            return Err(feed_chunk_error(
                "FEED_CHUNK_INDEX_CONFLICT",
                index,
                &request.payload,
                ErrorCode::PolicyInvalid,
                request.correlation_id,
            ));
        }
        if feed.chunks.len() >= 4096 {
            return Err(feed_chunk_error(
                "FEED_CHUNK_COUNT_LIMIT",
                index,
                &request.payload,
                ErrorCode::ResultLimitExceeded,
                request.correlation_id,
            ));
        }
        let staged_values: usize = feed
            .chunks
            .values()
            .map(|chunk| chunk.payload.dictionary_values.len())
            .sum();
        if staged_values.saturating_add(request.payload.dictionary_values.len()) > 1_000_000 {
            return Err(feed_chunk_error(
                "FEED_STAGED_DICTIONARY_COUNT_LIMIT",
                index,
                &request.payload,
                ErrorCode::ResultLimitExceeded,
                request.correlation_id,
            ));
        }
        feed.chunks.insert(
            index,
            StagedChunk {
                digest,
                payload: request.payload,
            },
        );
        drop(staging);
        if !self.storage.mark_feed_receiving(job_id).map_err(|_| {
            tracing::warn!(
                reason = "FEED_STORAGE_UNAVAILABLE",
                index,
                "feed chunk rejected"
            );
            ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id)
        })? {
            tracing::warn!(
                reason = "FEED_JOB_STATE_CONFLICT",
                index,
                "feed chunk rejected"
            );
            return Err(ServiceError::new(
                ErrorCode::PolicyInvalid,
                request.correlation_id,
            ));
        }
        Ok(index)
    }

    pub async fn activate_feed(
        &self,
        job_id: Uuid,
        request: FeedActivateRequest,
    ) -> Result<u64, ServiceError> {
        if request.schema_version != SCHEMA_VERSION {
            return Err(ServiceError::new(
                ErrorCode::PolicyInvalid,
                request.correlation_id,
            ));
        }
        let job = self
            .issued_feed_jobs
            .lock()
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?
            .get(&job_id)
            .cloned()
            .ok_or_else(|| ServiceError::new(ErrorCode::PolicyInvalid, request.correlation_id))?;
        let metadata_bootstrap = self
            .metadata_bootstrap_jobs
            .lock()
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?
            .contains(&job_id);
        let (metadata, dictionary, aggregate) = {
            let staging = self.feed_staging.lock().map_err(|_| {
                ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id)
            })?;
            let feed = staging.get(&job_id).ok_or_else(|| {
                ServiceError::new(ErrorCode::PolicyInvalid, request.correlation_id)
            })?;
            if feed.chunks.len() != request.expected_chunks as usize
                || !feed.chunks.keys().copied().eq(0..request.expected_chunks)
                || !feed
                    .chunks
                    .last_key_value()
                    .is_some_and(|(_, chunk)| chunk.payload.final_chunk)
            {
                return Err(ServiceError::new(
                    ErrorCode::PolicyInvalid,
                    request.correlation_id,
                ));
            }
            let metadata: Vec<_> = feed
                .chunks
                .values()
                .flat_map(|chunk| chunk.payload.metadata.clone())
                .collect();
            let dictionary: Vec<_> = feed
                .chunks
                .values()
                .flat_map(|chunk| chunk.payload.dictionary_values.clone())
                .collect();
            let mut hasher = Sha256::new();
            for chunk in feed.chunks.values() {
                hasher.update(chunk.digest);
            }
            (metadata, dictionary, hex_encode(&hasher.finalize()))
        };
        if metadata.len() as u64 != request.expected_metadata_count
            || dictionary.len() as u64 != request.expected_dictionary_count
            || aggregate != request.aggregate_digest
            || dictionary.len() > 1_000_000
            || dictionary
                .iter()
                .map(|item| item.value.len())
                .sum::<usize>()
                > 1024 * 1024 * 1024
        {
            return Err(ServiceError::new(
                ErrorCode::PolicyInvalid,
                request.correlation_id,
            ));
        }
        let password_paths: HashSet<&str> = metadata
            .iter()
            .filter(|item| item.password_mode)
            .map(|item| item.source_path.as_str())
            .collect();
        if dictionary
            .iter()
            .any(|item| password_paths.contains(item.source_path.as_str()))
        {
            return Err(ServiceError::new(
                ErrorCode::PolicyInvalid,
                request.correlation_id,
            ));
        }
        let mut snapshot = PolicySnapshot {
            dictionary: dictionary
                .into_iter()
                .map(|item| (item.value, item.category))
                .collect(),
            metadata_sources: metadata.clone(),
            ..PolicySnapshot::default()
        };
        snapshot.ready = !metadata_bootstrap;
        if let Some(settings) = self
            .storage
            .database_settings(job.database_id)
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?
        {
            if let Some(policy_id) = settings.active_policy_id.as_deref() {
                let (version, rules) = self
                    .storage
                    .active_policy(job.database_id, policy_id)
                    .map_err(|_| {
                        ServiceError::new(ErrorCode::PolicyInvalid, request.correlation_id)
                    })?
                    .ok_or_else(|| {
                        ServiceError::new(ErrorCode::PolicyInvalid, request.correlation_id)
                    })?;
                snapshot.version = version;
                snapshot.rules = rules;
            }
        }
        snapshot
            .rules
            .extend(password_paths.into_iter().map(|path| PolicyRule {
                selector: RuleSelector::SourcePath,
                pattern: path.to_owned(),
                action: RuleAction::Secret,
                category: "SECRET".to_owned(),
                priority: i64::MAX,
            }));
        self.storage
            .activate_feed_job(&job, &aggregate, metadata.len(), snapshot.dictionary.len())
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?;
        self.policy_cache
            .write()
            .await
            .insert(job.database_id, snapshot);
        if metadata_bootstrap {
            self.storage
                .enqueue_feed_job(job.database_id, job.target_version.saturating_add(1))
                .map_err(|_| {
                    ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id)
                })?;
        }
        if let Ok(mut staging) = self.feed_staging.lock() {
            staging.remove(&job_id);
        }
        if let Ok(mut issued) = self.issued_feed_jobs.lock() {
            issued.remove(&job_id);
        }
        if let Ok(mut bootstrap) = self.metadata_bootstrap_jobs.lock() {
            bootstrap.remove(&job_id);
        }
        Ok(job.target_version)
    }

    pub fn fail_feed(
        &self,
        job_id: Uuid,
        request: super::FeedFailRequest,
    ) -> Result<(), ServiceError> {
        const ALLOWED: &[&str] = &[
            "SOURCE_UNAVAILABLE",
            "SOURCE_INVALID",
            "LIMIT_EXCEEDED",
            "DIGEST_MISMATCH",
            "CANCELLED",
            "SERVICE_NOT_READY",
            "INTERNAL_TOOL_UNAVAILABLE",
            "INTERNAL_TOOL_FAILED",
            "RESULT_INVALID",
            "RESULT_LIMIT_EXCEEDED",
            "DICTIONARY_FEED_BINDING_REQUIRED",
            "FEED_CHUNK_REJECTED",
            "FEED_ACTIVATION_FAILED",
            "FILTER_AST_UNSUPPORTED",
            "DICTIONARY_WILDCARD_ALLOWLIST_REQUIRED",
        ];
        if request.schema_version != SCHEMA_VERSION
            || !ALLOWED.contains(&request.reason_code.as_str())
        {
            return Err(ServiceError::new(
                ErrorCode::PolicyInvalid,
                request.correlation_id,
            ));
        }
        if !self
            .storage
            .fail_feed_job(job_id, &request.reason_code, request.correlation_id)
            .map_err(|_| ServiceError::new(ErrorCode::ServiceNotReady, request.correlation_id))?
        {
            return Err(ServiceError::new(
                ErrorCode::PolicyInvalid,
                request.correlation_id,
            ));
        }
        if let Ok(mut staging) = self.feed_staging.lock() {
            staging.remove(&job_id);
        }
        if let Ok(mut issued) = self.issued_feed_jobs.lock() {
            issued.remove(&job_id);
        }
        if let Ok(mut bootstrap) = self.metadata_bootstrap_jobs.lock() {
            bootstrap.remove(&job_id);
        }
        Ok(())
    }

    pub fn storage(&self) -> &Arc<SqliteStorage> {
        &self.storage
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
        let evidence = serde_json::to_value(&request.evidence)
            .map_err(|_| ServiceError::new(ErrorCode::MaskingFailed, request.correlation_id))?;
        if request.tool_name == "execute_query"
            && matches!(&request.outcome, FinalizeOutcome::ToolResult { .. })
            && logical_result.get("is_error") == Some(&Value::Bool(false))
            && !valid_query_lineage(&logical_result, &request.evidence)
        {
            return self.persist_sanitized_failure(
                &request,
                &settings,
                policy.version,
                "sanitized_error",
                "service:query_lineage_incomplete",
            );
        }
        let cut_result = match self.engine.cut_secrets(&logical_result, &evidence, &policy) {
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
            &evidence,
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
        let report = neutral_report(&fully_masked);
        let write = self
            .storage
            .write_history(
                request.database_id,
                &request.chat_id,
                request.call_id,
                &request.tool_name,
                outcome_name,
                &fully_masked,
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

fn validate_feed_payload(
    job: &FeedJob,
    payload: &super::FeedPayload,
) -> Result<(), FeedChunkRejectReason> {
    if payload.metadata.len() > 10_000 {
        return Err(FeedChunkRejectReason::MetadataCountLimit);
    }
    if payload.dictionary_values.len() > 100_000 {
        return Err(FeedChunkRejectReason::DictionaryCountLimit);
    }
    for item in &payload.metadata {
        if item.source_path.len() > 512 {
            return Err(FeedChunkRejectReason::MetadataSourcePathLimit);
        }
        if item.field_name.len() > 256 {
            return Err(FeedChunkRejectReason::MetadataFieldNameLimit);
        }
    }
    if payload.dictionary_values.is_empty() {
        return Ok(());
    }
    let selection_id = payload
        .selection_id
        .ok_or(FeedChunkRejectReason::DictionarySelectionMissing)?
        .to_string();
    let selector = job
        .dictionary_selectors
        .iter()
        .find(|selector| {
            selector.get("selection_id").and_then(Value::as_str) == Some(selection_id.as_str())
        })
        .ok_or(FeedChunkRejectReason::DictionarySelectorNotFound)?;
    let source = selector
        .get("source_path")
        .and_then(Value::as_str)
        .ok_or(FeedChunkRejectReason::DictionarySelectorSourceInvalid)?;
    let category = selector
        .get("category")
        .and_then(Value::as_str)
        .ok_or(FeedChunkRejectReason::DictionarySelectorCategoryInvalid)?;
    for item in &payload.dictionary_values {
        if item.value.len() > 2 * 1024 * 1024
            || item.category.len() > 32
            || item.source_path.len() > 512
        {
            return Err(FeedChunkRejectReason::DictionaryValueLimit);
        }
        if source != "*" && item.source_path != source {
            return Err(FeedChunkRejectReason::DictionarySourceMismatch);
        }
        if source != "*" && item.category != category {
            return Err(FeedChunkRejectReason::DictionaryCategoryMismatch);
        }
    }
    Ok(())
}

fn log_feed_chunk_rejection(reason: &str, index: u32, payload: &super::FeedPayload) {
    let metadata_source_path_max = payload
        .metadata
        .iter()
        .map(|item| item.source_path.len())
        .max()
        .unwrap_or(0);
    let metadata_field_name_max = payload
        .metadata
        .iter()
        .map(|item| item.field_name.len())
        .max()
        .unwrap_or(0);
    let metadata_field_type_max = payload
        .metadata
        .iter()
        .map(|item| item.field_type.len())
        .max()
        .unwrap_or(0);
    let dictionary_source_path_max = payload
        .dictionary_values
        .iter()
        .map(|item| item.source_path.len())
        .max()
        .unwrap_or(0);
    let dictionary_category_max = payload
        .dictionary_values
        .iter()
        .map(|item| item.category.len())
        .max()
        .unwrap_or(0);
    let dictionary_value_max = payload
        .dictionary_values
        .iter()
        .map(|item| item.value.len())
        .max()
        .unwrap_or(0);
    tracing::warn!(
        reason,
        index,
        metadata_count = payload.metadata.len(),
        dictionary_count = payload.dictionary_values.len(),
        metadata_source_path_max,
        metadata_field_name_max,
        metadata_field_type_max,
        dictionary_source_path_max,
        dictionary_category_max,
        dictionary_value_max,
        "feed chunk rejected"
    );
}

fn feed_chunk_error(
    reason: &str,
    index: u32,
    payload: &super::FeedPayload,
    code: ErrorCode,
    correlation_id: Uuid,
) -> ServiceError {
    log_feed_chunk_rejection(reason, index, payload);
    ServiceError::new(code, correlation_id)
}

fn bounded_env_usize(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .unwrap_or(default)
}

fn is_wildcard_selector(selector: &Value) -> bool {
    selector.get("source_path").and_then(Value::as_str) == Some("*")
}

fn expand_all_selectors(
    job: &FeedJob,
    snapshot: &PolicySnapshot,
    wildcard: &Value,
) -> Result<Vec<Value>, ()> {
    let category = wildcard.get("category").and_then(Value::as_str).ok_or(())?;
    let filter_ast = wildcard.get("filter_ast").cloned().unwrap_or(Value::Null);
    let allowed_paths: HashSet<&str> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.selector == RuleSelector::SourcePath
                && rule.action == RuleAction::Mask
                && !rule.pattern.contains('*')
        })
        .map(|rule| rule.pattern.as_str())
        .collect();
    if allowed_paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut paths = std::collections::BTreeSet::new();
    for item in &snapshot.metadata_sources {
        let field_type = item.field_type.to_lowercase();
        if item.source_path.starts_with("Catalog.")
            && (field_type.contains("string") || field_type.contains("строка"))
            && !item.password_mode
            && !metadata_is_secret(item)
            && allowed_paths.contains(item.source_path.as_str())
        {
            paths.insert(item.source_path.clone());
        }
    }
    if paths.len() > 100 {
        return Err(());
    }
    Ok(paths
        .into_iter()
        .enumerate()
        .map(|(index, source_path)| {
            let mut hasher = Sha256::new();
            hasher.update(job.job_id.as_bytes());
            hasher.update(source_path.as_bytes());
            hasher.update((index as u64).to_be_bytes());
            let digest = hasher.finalize();
            let mut id = [0_u8; 16];
            id.copy_from_slice(&digest[..16]);
            json!({
                "selection_id":Uuid::from_bytes(id), "source_path":source_path,
                "category":category, "filter_ast":filter_ast.clone(), "page_size":1000
            })
        })
        .collect())
}

fn metadata_is_secret(item: &super::FeedMetadataItem) -> bool {
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
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

fn validate_tool_result(result: &Value) -> Result<(), ()> {
    let object = result.as_object().ok_or(())?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "content" | "is_error" | "structured_content"))
    {
        return Err(());
    }
    if !object.get("is_error").is_some_and(Value::is_boolean) {
        return Err(());
    }
    let content = object.get("content").and_then(Value::as_array).ok_or(())?;
    for item in content {
        let item = item.as_object().ok_or(())?;
        match item.get("type").and_then(Value::as_str) {
            Some("text") if item.len() == 2 && item.get("text").is_some_and(Value::is_string) => {}
            Some("json") if item.len() == 2 && item.contains_key("json") => {}
            _ => return Err(()),
        }
    }
    reject_unsafe_report_shapes(result, 0)
}

//++agent TASK-221 [23.09.2026 18:30:00]
// Query rows require an unambiguous canonical source for every public column.
// Other tools can return arbitrary text and use their remaining detectors.
fn valid_query_lineage(result: &Value, evidence: &super::MaskingEvidence) -> bool {
    let payloads: Vec<&Value> = result
        .get("structured_content")
        .into_iter()
        .chain(
            result
                .get("content")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|item| item.get("json")),
        )
        .collect();
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
    if !evidence.degraded_reasons.is_empty() {
        return false;
    }
    let Some(columns) = evidence.schema.get("columns").and_then(Value::as_array) else {
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
        let mut paths = std::collections::HashSet::new();
        for source in sources {
            let Some(path) = source.as_str().filter(|path| !path.is_empty()) else {
                return false;
            };
            paths.insert(path);
        }
        sources_by_name.insert(name, paths);
    }
    let mut evidenced = HashMap::<&str, std::collections::HashSet<&str>>::new();
    for item in &evidence.lineage {
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
    json!({"version":1, "blocks":blocks})
}

fn neutral_block(value: &Value) -> Value {
    let rows = value
        .as_array()
        .or_else(|| value.get("rows").and_then(Value::as_array));
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
