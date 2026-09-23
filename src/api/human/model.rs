use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::{Principal, Role, UserStatus};

#[derive(Debug, Clone, Serialize)]
pub struct DatabaseSummary {
    pub id: Uuid,
    pub label: String,
    pub mode: String,
    pub mapping_ttl_seconds: u64,
    pub history_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatSummary {
    pub chat_id: String,
    pub message_count: u64,
    pub last_message_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryItem {
    pub id: Uuid,
    pub database_id: Uuid,
    pub chat_id: String,
    pub tool_name: String,
    pub outcome: String,
    pub created_at: DateTime<Utc>,
    pub report: NeutralReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralReport {
    pub version: u32,
    pub blocks: Vec<NeutralBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NeutralBlock {
    Text {
        text: String,
    },
    Table {
        columns: Vec<NeutralColumn>,
        rows: Vec<Vec<Value>>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeutralColumn {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub value_type: String,
}

impl NeutralReport {
    pub fn is_safe(&self) -> bool {
        self.version == 1
            && self.blocks.iter().all(|block| match block {
                NeutralBlock::Text { .. } => true,
                NeutralBlock::Table { columns, rows } => rows
                    .iter()
                    .all(|row| row.len() == columns.len() && row.iter().all(is_scalar)),
            })
    }
}

fn is_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminDatabasePatch {
    pub mode: Option<String>,
    pub mapping_ttl_seconds: Option<u64>,
    pub history_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAccessPatch {
    pub role: Role,
    pub status: UserStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolClassification {
    pub tool_name: String,
    pub class: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolClassificationPatch {
    pub class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DictionaryConfig {
    pub id: Uuid,
    pub mode: String,
    pub selectors: Vec<DictionarySelectorConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DictionarySelectorConfig {
    pub source_path: String,
    pub category: String,
    pub filter_ast: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleInput {
    pub selector_kind: String,
    pub selector_value: String,
    pub action: String,
    pub category: String,
    #[serde(default)]
    pub priority: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePolicyRequest {
    pub rules: Vec<PolicyRuleInput>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicySummary {
    pub id: Uuid,
    pub version: u64,
    pub status: String,
    pub rules: Vec<PolicyRuleInput>,
}

#[derive(Debug, Error)]
pub enum HumanDataError {
    #[error("record was not found")]
    NotFound,
    #[error("mapping is unavailable")]
    MappingUnavailable,
    #[error("request conflicts with current state")]
    Conflict,
    #[error("human data storage is unavailable")]
    Unavailable,
}

/// Human-only boundary. Implementations must audit reveal and admin mutations
/// without raw values and must never persist the report returned by reveal.
pub trait HumanDataStore: Send + Sync {
    fn list_databases(&self) -> Result<Vec<DatabaseSummary>, HumanDataError>;
    fn list_chats(&self, database_id: Uuid) -> Result<Vec<ChatSummary>, HumanDataError>;
    fn list_history(
        &self,
        database_id: Uuid,
        chat_id: &str,
        limit: u8,
    ) -> Result<Vec<HistoryItem>, HumanDataError>;
    fn reveal_history<'a>(
        &'a self,
        actor: &Principal,
        history_id: Uuid,
        correlation_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<NeutralReport, HumanDataError>> + Send + 'a>>;
    fn update_database(
        &self,
        actor: &Principal,
        database_id: Uuid,
        patch: AdminDatabasePatch,
        correlation_id: Uuid,
    ) -> Result<(), HumanDataError>;
    fn refresh_database(
        &self,
        actor: &Principal,
        database_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(), HumanDataError>;
    fn list_tool_classifications(
        &self,
        database_id: Uuid,
    ) -> Result<Vec<ToolClassification>, HumanDataError>;
    fn update_tool_classification(
        &self,
        actor: &Principal,
        database_id: Uuid,
        tool_name: &str,
        patch: ToolClassificationPatch,
        correlation_id: Uuid,
    ) -> Result<(), HumanDataError>;
    fn list_dictionary_configs(
        &self,
        database_id: Uuid,
    ) -> Result<Vec<DictionaryConfig>, HumanDataError>;
    fn put_dictionary_config(
        &self,
        actor: &Principal,
        database_id: Uuid,
        config: DictionaryConfig,
        correlation_id: Uuid,
    ) -> Result<(), HumanDataError>;
    fn list_policies(&self, database_id: Uuid) -> Result<Vec<PolicySummary>, HumanDataError>;
    fn create_policy(
        &self,
        actor: &Principal,
        database_id: Uuid,
        request: CreatePolicyRequest,
        correlation_id: Uuid,
    ) -> Result<PolicySummary, HumanDataError>;
    fn activate_policy<'a>(
        &'a self,
        actor: &Principal,
        database_id: Uuid,
        policy_id: Uuid,
        correlation_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), HumanDataError>> + Send + 'a>>;
}
