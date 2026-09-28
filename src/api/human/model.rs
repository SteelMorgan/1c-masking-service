use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::{DatabaseScope, Principal, Role, UserStatus};

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
    /// Строгий режим lineage (databases.strict_mode): unverified-
    /// колонки execute_query маскируются целиком вместо отказа.
    //++agent TASK-225
    pub strict_mode: bool,
    //++agent TASK-225 [25.09.2026]
    /// §8.4: состояние refresh pull-модели — очередь intent, backoff,
    /// последняя ошибка и её текст по таблице §8.3.
    //++agent TASK-225
    pub refresh: RefreshStatus,
    /// B2: состояние настройки `unconfigured|draft|active`, номера
    /// активной версии и черновика (NULL при отсутствии).
    //++agent TASK-225
    pub setup_state: String,
    pub active_version: Option<i64>,
    pub draft_version: Option<i64>,
    //++agent TASK-225 [26.09.2026] N
    /// Координаты базы из session.register (`Srvr`/`Ref`) и источник
    /// идентификаторов: `ras` — реальные GUID-ы кластера/ИБ, `generated` —
    /// сгенерированная пара при недоступном RAS, `null` — запись до
    /// первой регистрации по координатам.
    pub cluster_server: Option<String>,
    pub infobase_name: Option<String>,
    pub guid_source: Option<String>,
    //++agent TASK-225
}

//++agent TASK-225 [25.09.2026]
/// §8.4: поле `refresh` ответа B2. `state`:
/// `idle` — очередь пуста, ошибок нет; `running` — intent ждёт ближайшего
/// тика; `retrying` — серия неудач, повтор по backoff;
/// `needs_attention` — автоматика остановлена; `failed` — последний pull
/// завершился детерминированной ошибкой (intent снят).
#[derive(Debug, Clone, Serialize)]
pub struct RefreshStatus {
    pub state: String,
    pub attempts: i64,
    pub next_attempt_at: Option<String>,
    pub last_error_code: Option<String>,
    pub last_error_text: Option<String>,
    pub first_failed_at: Option<String>,
    pub last_success_at: Option<String>,
}

/// §8.3: текст причины последней неудачи для UI. `needs_attention`
/// добавляет префикс с числом попыток и моментом первой неудачи серии.
pub(crate) fn refresh_error_text(
    code: &str,
    needs_attention: bool,
    attempts: i64,
    first_failed_at: Option<&str>,
) -> String {
    let base = match code {
        //++agent TASK-225 [26.09.2026] N: различаем «менеджер не отвечает»
        // (транспорт/таймаут) и «менеджер работает, но активной сессии этой
        // ИБ сейчас нет» (`no_target` → DATABASE_NOT_CONNECTED).
        "MANAGER_UNAVAILABLE" => "Менеджер MCP недоступен: сервис не может получить метаданные и словарь базы. Проверьте, что менеджер запущен.".to_owned(),
        "DATABASE_NOT_CONNECTED" => "Менеджер MCP работает, но активной сессии этой информационной базы сейчас нет: подключите базу и нажмите «Обновить метаданные».".to_owned(),
        //++agent TASK-225
        "INTERNAL_TOOL_FAILED" => "База отклонила запрос метаданных/словаря (инструмент выгрузки вернул ошибку). Проверьте журнал регистрации базы.".to_owned(),
        "STORAGE_UNAVAILABLE" => "Внутреннее хранилище сервиса занято или недоступно. Повтор будет автоматически.".to_owned(),
        "POLICY_INVALID" => "Действующая настройка содержит правила, которые сервис пока не может применить (например, «Секрет»). Исправьте настройку.".to_owned(),
        "METADATA_EMPTY" => "База вернула пустой список метаданных.".to_owned(),
        "FEED_LIMIT_EXCEEDED" | "FEED_DICTIONARY_VALUE_LIMIT" => "Превышен лимит словаря (не более 100 источников / 1 000 000 значений). Сузьте словарь.".to_owned(),
        "FEED_SECRET_SOURCE_FORBIDDEN" => "В словарь выбран реквизит-пароль или секрет — такие источники запрещены.".to_owned(),
        other => format!("Не удалось обновить словарь: {other}. Обратитесь к разработчику сервиса."),
    };
    if needs_attention {
        format!(
            "Автоматические попытки остановлены после {attempts} неудач (с {}). Нажмите «Обновить метаданные», когда причина устранена. {base}",
            first_failed_at.unwrap_or("—")
        )
    } else {
        base
    }
}
//++agent TASK-225

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
    //++agent TASK-225 [25.09.2026]
    // Tri-state через Option: поле отсутствует — настройку strict_mode
    // не трогаем; true/false пишутся напрямую.
    //++agent TASK-225
    pub strict_mode: Option<bool>,
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
    //++agent TASK-225 [26.09.2026]
    /// B10: `no-mask` — исключение инструмента из маскирования,
    /// сервер требует явного подтверждения диалога С4.
    //++agent TASK-225
    #[serde(default)]
    pub confirm_bypass: bool,
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
    //++agent TASK-225 [26.09.2026]
    /// §6.1: id строки policy_rules — заполняется только сервером при
    /// чтении; из запроса не принимается (skip = не десериализуется).
    //++agent TASK-225
    #[serde(skip)]
    pub rule_id: Option<Uuid>,
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
    //++agent TASK-225 [26.09.2026]
    // §4 legacy POST /policies: черновик уже существует — версии хранят
    // максимум один draft на базу (§2.2 частичный индекс).
    #[error("draft already exists")]
    DraftExists,
    /// B10: no-mask без confirm_bypass:true — серверный барьер
    /// к подтверждающему диалогу С4 в UI.
    #[error("no-mask requires confirm_bypass")]
    BypassNotConfirmed,
    /// §4 legacy-activate: diff(active, черновик) содержит ослабления —
    /// без подтверждений B7 они неактивируемы (барьер не обходится
    /// старым маршрутом).
    #[error("weakening not confirmed")]
    WeakeningNotConfirmed(Vec<String>),
    //++agent TASK-225
    #[error("human data storage is unavailable")]
    Unavailable,
}

/// Human-only boundary. Implementations must audit admin mutations without
/// raw values and must never persist the report returned by reveal.
//++agent TASK-224 [24.09.2026] итерация 3: reveal не аудируется — раскрытие
// автоматическое при открытии записи, audit-событие выродилось бы в шум.
pub trait HumanDataStore: Send + Sync {
    /// Список баз, отфильтрованный по scope вызывающего: `All` — все
    /// записи, `Only` — только явно выданные (пустой набор → пустая
    /// выдача, запрос к таблице не выполняется).
    fn list_databases(
        &self,
        scope: &DatabaseScope,
    ) -> Result<Vec<DatabaseSummary>, HumanDataError>;
    fn list_chats(&self, database_id: Uuid) -> Result<Vec<ChatSummary>, HumanDataError>;
    fn list_history(
        &self,
        database_id: Uuid,
        chat_id: &str,
        limit: u8,
    ) -> Result<Vec<HistoryItem>, HumanDataError>;
    /// `actor` живёт столько же, сколько future: scope-проверка внутри
    /// реализации (до расшифровки) — обход через чужой history id
    /// невозможен извне.
    fn reveal_history<'a>(
        &'a self,
        actor: &'a Principal,
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
    //++agent TASK-225 [27.09.2026 00:00:00] T: удаление записи базы —
    // каскад по всем таблицам с database_id в одной tx + сброс
    // RAM-состояния сервиса. `NotFound`, если записи нет; повторный
    // вызов регистрирует базу заново (штатная авто-регистрация).
    //++agent TASK-225
    fn delete_database<'a>(
        &'a self,
        actor: &'a Principal,
        database_id: Uuid,
        correlation_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), HumanDataError>> + Send + 'a>>;
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
    //++agent TASK-225 [26.09.2026]
    /// Удаление записи классификации (снятый из 1С инструмент не должен
    /// вечно висеть в админке). `NotFound`, если записи нет.
    //++agent TASK-225
    fn delete_tool_classification(
        &self,
        actor: &Principal,
        database_id: Uuid,
        tool_name: &str,
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
    /// §4 legacy-маршрут: правка переписывается на секцию dictionary
    /// черновика (создаётся из активной при отсутствии). Возвращает
    /// номер версии черновика для `draft_version` в ответе.
    fn put_dictionary_config(
        &self,
        actor: &Principal,
        database_id: Uuid,
        config: DictionaryConfig,
        correlation_id: Uuid,
    ) -> Result<i64, HumanDataError>;
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
