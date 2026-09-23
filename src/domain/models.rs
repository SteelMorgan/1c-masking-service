use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseMode {
    Unconfigured,
    Enabled,
    Disabled,
}

impl DatabaseMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unconfigured => "unconfigured",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

impl TryFrom<&str> for DatabaseMode {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "unconfigured" => Ok(Self::Unconfigured),
            "enabled" => Ok(Self::Enabled),
            "disabled" => Ok(Self::Disabled),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolClass {
    DataMask,
    MetadataBypass,
    DenyPendingReview,
}

impl ToolClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataMask => "data-mask",
            Self::MetadataBypass => "metadata-bypass",
            Self::DenyPendingReview => "deny-pending-review",
        }
    }
}

impl TryFrom<&str> for ToolClass {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "data-mask" => Ok(Self::DataMask),
            "metadata-bypass" => Ok(Self::MetadataBypass),
            "deny-pending-review" => Ok(Self::DenyPendingReview),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightRequest {
    pub schema_version: u32,
    pub call_id: Uuid,
    pub correlation_id: Uuid,
    pub database_id: Uuid,
    pub chat_id: String,
    pub tool_name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightResponse {
    pub schema_version: u32,
    pub decision: &'static str,
    pub arguments: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalEventRequest {
    pub schema_version: u32,
    pub call_id: Uuid,
    pub correlation_id: Uuid,
    pub tool_name: String,
    pub error_code: String,
    pub scope: TerminalScope,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalScope {
    pub kind: TerminalScopeKind,
    #[serde(default)]
    pub database_id: Option<Uuid>,
    #[serde(default)]
    pub chat_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TerminalScopeKind {
    Verified,
    Unverified,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TerminalEventResponse {
    pub schema_version: u32,
    pub status: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FinalizeOutcome {
    ToolResult { result: Value },
    TransportError { error: Value },
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MaskingEvidence {
    #[serde(default)]
    pub schema: Value,
    #[serde(default)]
    pub lineage: Vec<Value>,
    #[serde(default)]
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeRequest {
    pub schema_version: u32,
    pub call_id: Uuid,
    pub correlation_id: Uuid,
    pub database_id: Uuid,
    pub chat_id: String,
    pub tool_name: String,
    pub outcome: FinalizeOutcome,
    #[serde(default)]
    pub evidence: MaskingEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FinalizeResponse {
    pub schema_version: u32,
    pub public_result: Value,
}

#[derive(Debug, Clone)]
pub struct DatabaseSettings {
    pub mode: DatabaseMode,
    pub mapping_ttl_seconds: u64,
    pub history_ttl_seconds: u64,
    pub active_policy_id: Option<String>,
    pub active_cache_version: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct StoredHistory {
    pub id: Uuid,
    pub public_result: Value,
}

#[derive(Debug, Clone)]
pub struct HistoryForReveal {
    pub report: Value,
    pub mapping_batch_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FeedJob {
    pub job_id: Uuid,
    pub database_id: Uuid,
    pub target_version: u64,
    pub max_chunk_bytes: usize,
    pub metadata_selector: Value,
    pub dictionary_selectors: Vec<Value>,
    pub hard_limits: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedMetadataItem {
    pub source_path: String,
    pub field_name: String,
    pub field_type: String,
    pub password_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedDictionaryValue {
    pub source_path: String,
    pub category: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedPayload {
    #[serde(default)]
    pub selection_id: Option<Uuid>,
    pub page_index: u32,
    #[serde(default)]
    pub metadata: Vec<FeedMetadataItem>,
    #[serde(default)]
    pub dictionary_values: Vec<FeedDictionaryValue>,
    pub final_chunk: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedChunkRequest {
    pub schema_version: u32,
    pub correlation_id: Uuid,
    pub chunk_digest: String,
    pub payload: FeedPayload,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedActivateRequest {
    pub schema_version: u32,
    pub correlation_id: Uuid,
    pub expected_chunks: u32,
    pub expected_metadata_count: u64,
    pub expected_dictionary_count: u64,
    pub aggregate_digest: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedFailRequest {
    pub schema_version: u32,
    pub correlation_id: Uuid,
    pub reason_code: String,
}
