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
    NoMask,
    DenyPendingReview,
}

impl ToolClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataMask => "data-mask",
            Self::NoMask => "no-mask",
            Self::DenyPendingReview => "deny-pending-review",
        }
    }
}

impl TryFrom<&str> for ToolClass {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "data-mask" => Ok(Self::DataMask),
            "no-mask" => Ok(Self::NoMask),
            "deny-pending-review" => Ok(Self::DenyPendingReview),
            _ => Err(()),
        }
    }
}

//++agent TASK-225 [26.09.2026] N: identity инлайнится в JSON
// (`#[serde(flatten)]`); deny_unknown_fields с flatten несовместим —
// форму гарантирует bounded_json + schema_version.
#[derive(Debug, Clone, Deserialize)]
pub struct PreflightRequest {
    pub schema_version: u32,
    pub call_id: Uuid,
    pub correlation_id: Uuid,
    #[serde(flatten)]
    pub identity: DatabaseIdentity,
    pub chat_id: String,
    pub tool_name: String,
    pub arguments: Value,
}
//++agent TASK-225

/// Детерминированная идентичность базы (раздел O2): непрозрачный
/// строковый ключ `instance_id`, который менеджер вычисляет при
/// `session.register` — `ras:<cluster_guid>:<infobase_guid>` после
/// RAS-резолюции либо `gen:<srvr>/<ref>` verbatim при недоступном RAS.
/// Сопоставление — только точное равенство ключа: никакой нормализации
/// координат и фолбэков, поэтому склейка баз невозможна по построению.
/// `cluster_server`/`infobase_name` — отображаемые координаты (Srvr/Ref)
/// для новой записи и админки, в идентичности не участвуют.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseIdentity {
    pub instance_id: String,
    pub cluster_server: String,
    pub infobase_name: String,
}

impl DatabaseIdentity {
    /// Источник ключа — выводится из префикса, отдельным состоянием
    /// не хранится: `ras:` — реальная RAS-пара, `gen:` — сгенерированный
    /// ключ; иное (legacy-ключ до раздела O2) — источника нет.
    pub fn guid_source(instance_id: &str) -> Option<&'static str> {
        if instance_id.starts_with("ras:") {
            Some("ras")
        } else if instance_id.starts_with("gen:") {
            Some("generated")
        } else {
            None
        }
    }
}
//++agent TASK-225

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
    //++agent TASK-225 [26.09.2026] O2: verified-scope несёт ключ базы
    // (instance_id обязателен, Srvr/Ref — отображаемые координаты —
    // см. DatabaseIdentity).
    #[serde(default)]
    pub instance_id: Option<String>,
    #[serde(default)]
    pub cluster_server: Option<String>,
    #[serde(default)]
    pub infobase_name: Option<String>,
    //++agent TASK-225
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

//++agent TASK-222 [05.10.2026]
// Конверт P1 (contract.md): 1С отдаёт ровно {schema_version, result,
// field_sources}; `secret_cut_applied` и прочего `evidence` нет и не
// проверяется. `field_sources` — только сведения о происхождении полей,
// нужные сервису для маскирования по source_path.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FieldSources {
    #[serde(default)]
    pub schema: Value,
    #[serde(default)]
    pub lineage: Vec<Value>,
}
//++agent TASK-222

//++agent TASK-225 [26.09.2026] N: flatten — см. PreflightRequest.
#[derive(Debug, Clone, Deserialize)]
pub struct FinalizeRequest {
    pub schema_version: u32,
    pub call_id: Uuid,
    pub correlation_id: Uuid,
    //++agent TASK-225 [26.09.2026] N: см. PreflightRequest.
    #[serde(flatten)]
    pub identity: DatabaseIdentity,
    //++agent TASK-225
    pub chat_id: String,
    pub tool_name: String,
    pub outcome: FinalizeOutcome,
    #[serde(default)]
    pub field_sources: FieldSources,
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
    //++agent TASK-225 [25.09.2026]
    /// Строгий режим lineage: `unverified`-колонки execute_query
    /// возвращаются с полностью маскированными значениями вместо отказа.
    /// Хранится в `databases.strict_mode`, по умолчанию включён.
    //++agent TASK-225
    pub strict_mode: bool,
    //++agent TASK-225 [26.09.2026] O2: ключ базы и отображаемые координаты.
    /// `instance_id` — непрозрачный ключ, вычисленный менеджером:
    /// `ras:<cluster_guid>:<infobase_guid>` либо `gen:<srvr>/<ref>`;
    /// `cluster_server`/`infobase_name` — исходные (Srvr, Ref) для
    /// отображения. `None` у записей без координат (legacy строки до
    /// первой регистрации сессии).
    pub instance_id: String,
    pub cluster_server: Option<String>,
    pub infobase_name: Option<String>,
    //++agent TASK-225
}

//++agent TASK-225 [26.09.2026] O2
impl DatabaseSettings {
    /// Источник ключа выводится из префикса `instance_id`
    /// (`ras:`/`gen:`), колонкой не хранится.
    pub fn guid_source(&self) -> Option<&'static str> {
        DatabaseIdentity::guid_source(&self.instance_id)
    }

    /// Идентичность для внутреннего вызова менеджера — точный ключ.
    /// Координаты только информативны (логи/отладка): маршрут идёт
    /// строго по `instance_id`.
    pub fn call_identity(&self) -> DatabaseIdentity {
        DatabaseIdentity {
            instance_id: self.instance_id.clone(),
            cluster_server: self.cluster_server.clone().unwrap_or_default(),
            infobase_name: self.infobase_name.clone().unwrap_or_default(),
        }
    }
}
//++agent TASK-225

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

//++agent TASK-222 [05.10.2026]
/// Строка durable-очереди pull refresh (`v2_refresh_intents`, фаза всегда
/// 'full' — читаемые legacy-значения фазы игнорируются).
#[derive(Debug, Clone)]
pub struct RefreshIntent {
    pub database_id: Uuid,
    pub reason: Option<String>,
    pub actor_id: Option<Uuid>,
    pub created_at: String,
    //++agent TASK-225 [25.09.2026]
    /// §8.1: число transient-неудач текущей серии и состояние очереди
    /// (`pending` — worker берёт, `needs_attention` — ждёт Admin).
    //++agent TASK-225
    pub attempts: i64,
    pub state: String,
}
//++agent TASK-222
