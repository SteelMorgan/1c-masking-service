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
    //++agent TASK-224 [24.09.2026]
    // Сырое display_label отдельно от вычисленного label — UI различает
    // «заданное имя» и fallback на GUID.
    //--agent TASK-224
    pub display_label: Option<String>,
    pub mode: String,
    pub mapping_ttl_seconds: u64,
    pub history_ttl_seconds: u64,
    /// Stage durable refresh intent (`full`), если refresh в работе;
    /// `null`, когда очередь пуста. Stage label без feed данных — только
    /// состояние очереди.
    pub refresh_stage: Option<String>,
    //++agent TASK-225 [25.09.2026]
    /// B2: число авто-добавленных инструментов, ждущих классификации
    /// (COUNT(*) WHERE auto_added=1).
    //++agent TASK-225
    pub new_tools_count: i64,
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
    //++agent TASK-224 [08.10.2026] итерация 4: заголовок записи — текст
    // запроса/описание вызова (secret-cut форма preflight-arguments —
    // ревью R1). Отсутствует в старых записях и у terminal-денайев.
    //--agent TASK-224
    #[serde(default)]
    pub title: Option<String>,
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
    //++agent TASK-224 [08.10.2026] итерация 4: колонка содержит маскированные
    // значения (токены [MASK:…]/[SECRET_REMOVED]) — UI рисует замок и
    // подсветку. В старых записях поля нет — default false.
    //--agent TASK-224
    #[serde(default)]
    pub masked: bool,
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
    //++agent TASK-224 [24.09.2026]
    // Tri-state: поле отсутствует — не трогаем; null/пустая строка — сброс
    // названия (колонка nullable); строка — установить. serde не различает
    // «нет поля» и null для Option<Option<_>>, поэтому свой deserializer.
    //--agent TASK-224
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    pub display_label: Option<Option<String>>,
}

//++agent TASK-224 [24.09.2026]
fn deserialize_nullable_string<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}
//--agent TASK-224

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAccessPatch {
    pub role: Role,
    pub status: UserStatus,
}

//++agent TASK-225 [25.09.2026]
// GET-форма по спеке B10: поля учёта авто-регистрации (auto_added,
// first_seen_at, denied_count, last_denied_at) видны администратору —
// без них список не отличал бы авто-добавленные отзывы от решений.
//++agent TASK-225
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolClassification {
    pub tool_name: String,
    pub class: String,
    pub reviewer: Option<String>,
    pub updated_at: String,
    pub auto_added: bool,
    pub first_seen_at: Option<String>,
    pub denied_count: i64,
    pub last_denied_at: Option<String>,
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

//++agent TASK-224 [24.09.2026]
// GET-ответ dictionary config: `in_manifest` — вычисляемая проверка пути по
// RAM manifest (None — manifest не загружен, проверить нельзя). Отдельный
// view-тип, чтобы вычисляемое поле не попало в PUT-вход и durable JSON.
#[derive(Debug, Clone, Serialize)]
pub struct DictionarySelectorView {
    pub source_path: String,
    pub category: String,
    pub filter_ast: Option<Value>,
    pub in_manifest: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DictionaryConfigView {
    pub id: Uuid,
    pub mode: String,
    pub selectors: Vec<DictionarySelectorView>,
}

/// Узел дерева метаданных для Admin UI (`GET .../databases/{id}/metadata`).
/// `kind="group"` — узел с вложенными узлами; `kind="field"` — листовое поле
/// manifest (его `path` — полный `source_path` FeedMetadataItem).
#[derive(Debug, Clone, Serialize)]
pub struct MetadataNode {
    /// Отображаемое имя: сегмент пути для групп, `field_name` для полей.
    pub name: String,
    /// Полный путь узла для ленивой подгрузки следующего уровня.
    pub path: String,
    pub kind: &'static str,
    /// Число листовых полей в поддереве (1 для самого поля).
    pub field_count: usize,
    /// Из них с `password_mode` — режутся границей всегда.
    pub password_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_mode: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetadataNodesPage {
    /// false — manifest ещё не получен (рестарт/refresh не завершён): дерево
    /// недоступно, UI предлагает «Обновить сейчас».
    pub manifest_ready: bool,
    pub completed_at: Option<DateTime<Utc>>,
    pub nodes: Vec<MetadataNode>,
    /// true — выдача обрезана лимитом; дальше — только поиск `q`.
    pub truncated: bool,
}
//--agent TASK-224

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
    //++agent TASK-221 2026-09-23
    #[error(
        "configurable secret policy is unsupported until pre-manager enforcement is available"
    )]
    SecretPolicyUnsupported,
    //--agent TASK-221
    #[error("human data storage is unavailable")]
    Unavailable,
}

/// Human-only boundary. Implementations must audit admin mutations without
/// raw values and must never persist the report returned by reveal.
//++agent TASK-224 [24.09.2026] итерация 3: reveal не аудируется — раскрытие
// автоматическое при открытии записи, audit-событие выродилось бы в шум.
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
    ) -> Result<Vec<DictionaryConfigView>, HumanDataError>;
    //++agent TASK-224 [24.09.2026]
    /// Ленивая выдача дерева метаданных для dictionary selectors:
    /// `path` — префикс source_path ("" — корневые группы), `query` —
    /// подстрочный поиск по пути/имени поля (перекрывает path).
    //--agent TASK-224
    fn metadata_nodes(
        &self,
        database_id: Uuid,
        path: &str,
        query: Option<&str>,
    ) -> Result<MetadataNodesPage, HumanDataError>;
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
