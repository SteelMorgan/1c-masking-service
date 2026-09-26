//++agent TASK-225 [26.09.2026]
//! Версионированная настройка маскирования — Human API (spec §4):
//! экспорт B3/B3v, импорт B4, diff B5, черновик B8, активация B7,
//! откат B7r, журнал B11, причины ячеек B9, сухой прогон B6, поля
//! объекта B13. Вся мутирующая логика — одна IMMEDIATE-транзакция на
//! операцию; журнал setup_journal и audit_events пишутся в ней же.

use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use rusqlite::{params, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::handlers::{authorize, same_origin, ApiError};
use super::sqlite::audit;
use super::HumanState;
use crate::domain::setup::{
    self, compute_diff, parse_setup_body, DiffContext, VersionContent, SETUP_MAX_BYTES,
    SETUP_SCHEMA,
};
use crate::storage::setup::{self as store, VersionRef};
use crate::storage::SqliteStorage;

/// Сервисный фасад: конкретные `SqliteStorage`/`MaskingService`, не
/// dyn-трейт — нужны транзакции и RAM-снимки (manifest, mapping).
pub struct SetupService {
    pub storage: Arc<SqliteStorage>,
    pub masking: Arc<crate::domain::MaskingService>,
}

impl SetupService {
    pub fn new(storage: Arc<SqliteStorage>, masking: Arc<crate::domain::MaskingService>) -> Self {
        Self { storage, masking }
    }

    /// Контекст предупреждений §3.6: manifest путей, известные
    /// инструменты, статистика источников последнего pull.
    fn diff_context(
        &self,
        connection: &rusqlite::Connection,
        database_id: Uuid,
        database_mismatch: bool,
    ) -> rusqlite::Result<DiffContext> {
        //++agent TASK-225 [26.09.2026] M-2/M-3: expandable-пути F9 и
        // текущие режимы инструментов — контекст §3.4/§3.5.
        //++agent TASK-225
        let manifest = self.masking.metadata_manifest_view(database_id, |items| {
            (
                items
                    .iter()
                    .map(|item| item.source_path.to_lowercase())
                    .collect::<HashSet<_>>(),
                items
                    .iter()
                    .filter(|item| crate::domain::metadata_expandable_basics(item))
                    .map(|item| item.source_path.clone())
                    .collect::<HashSet<_>>(),
            )
        });
        let (manifest_paths, manifest_expandable) = match manifest {
            Some((_, (paths, expandable))) => (Some(paths), Some(expandable)),
            None => (None, None),
        };
        let mut known_tools: Option<HashSet<String>> = None;
        let mut tool_modes: Option<std::collections::HashMap<String, String>> = None;
        if let Ok(mut statement) = connection
            .prepare("SELECT tool_name,class FROM tool_classifications WHERE database_id=?1")
        {
            if let Ok(rows) = statement.query_map([database_id.to_string()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }) {
                let pairs: Vec<(String, String)> = rows.flatten().collect();
                known_tools = Some(pairs.iter().map(|(name, _)| name.clone()).collect());
                tool_modes = Some(pairs.into_iter().collect());
            }
        }
        let source_stats = store::last_source_stats(connection, database_id)?;
        Ok(DiffContext {
            manifest_paths,
            manifest_expandable,
            known_tools,
            tool_modes,
            source_stats,
            database_mismatch,
        })
    }
}

/// Сборка §1-файла из контента версии. Общая функция для B3/B3v и
/// UDS-экспорта B12 (сторона t226 зовёт `export_file_json`).
/// В файл не попадают внутренние id (§1.1 MUST NOT). `filter`
/// отсутствующий в источнике в файл не пишется (отсутствие ≡ null).
pub(crate) fn export_file_json(
    content: &VersionContent,
    database_id: Uuid,
    label: Option<&str>,
    source_version: i64,
    include_tools: Option<Vec<setup::ToolSpec>>,
    now: &str,
) -> Value {
    let missing_reason = "не указано (создано до TASK-225)";
    let sources: Vec<Value> = content
        .dictionary
        .sources
        .iter()
        .map(|source| {
            let mut map = serde_json::Map::new();
            map.insert("source_path".into(), source.source_path.clone().into());
            map.insert("category".into(), source.category.clone().into());
            if let Some(filter) = &source.filter_ast {
                map.insert("filter".into(), filter.clone());
            }
            map.insert(
                "reason".into(),
                (if source.reason.is_empty() {
                    missing_reason.to_string()
                } else {
                    source.reason.clone()
                })
                .into(),
            );
            if let Some(estimated) = source.estimated_values {
                map.insert("estimated_values".into(), estimated.into());
            }
            Value::Object(map)
        })
        .collect();
    let rules: Vec<Value> = content
        .rules
        .iter()
        .map(|rule| {
            let mut map = serde_json::Map::new();
            map.insert("selector".into(), rule.selector.clone().into());
            map.insert("value".into(), rule.value.clone().into());
            map.insert("action".into(), rule.action.clone().into());
            map.insert("category".into(), rule.category.clone().into());
            map.insert("priority".into(), rule.priority.into());
            map.insert("enabled".into(), rule.enabled.into());
            map.insert(
                "reason".into(),
                (if rule.reason.is_empty() {
                    missing_reason.to_string()
                } else {
                    rule.reason.clone()
                })
                .into(),
            );
            if let Some(tests) = &rule.tests {
                map.insert(
                    "tests".into(),
                    serde_json::to_value(tests).unwrap_or(Value::Null),
                );
            }
            Value::Object(map)
        })
        .collect();
    let mut file = serde_json::Map::new();
    file.insert("schema".into(), SETUP_SCHEMA.into());
    file.insert("generated_at".into(), now.into());
    file.insert(
        "generated_by".into(),
        json!({"kind":"service","tool":concat!("1c-masking-service ", env!("CARGO_PKG_VERSION"))}),
    );
    let mut hint = json!({"id": database_id.to_string(), "source_version": source_version});
    if let Some(label) = label {
        hint["label"] = label.into();
    }
    file.insert("database_hint".into(), hint);
    file.insert(
        "dictionary".into(),
        json!({"mode": content.dictionary.mode, "sources": sources}),
    );
    file.insert("rules".into(), Value::Array(rules));
    if let Some(tools) = include_tools {
        file.insert(
            "tools".into(),
            serde_json::to_value(tools).unwrap_or(Value::Array(Vec::new())),
        );
    }
    Value::Object(file)
}

// ------------------------------------------------------------------
// Модели запросов
// ------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct ExportQuery {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub include_tools: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ImportQuery {
    #[serde(default)]
    pub replace_draft: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DiffQuery {
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DraftCreateRequest {
    /// `active` — копия активной версии; `empty` — пустой черновик.
    #[serde(default = "default_from_active")]
    pub from: String,
}

fn default_from_active() -> String {
    "active".to_string()
}

#[derive(Debug, Deserialize)]
pub(crate) struct DraftRevertRequest {
    #[serde(default)]
    pub change_ids: Vec<String>,
    #[serde(default)]
    pub warning_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ActivateRequest {
    pub version: i64,
    pub draft_hash: String,
    #[serde(default)]
    pub confirmed_weakenings: Vec<String>,
    #[serde(default)]
    pub accepted_strengthenings: Vec<String>,
    #[serde(default)]
    pub excluded_warnings: Vec<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RollbackRequest {
    pub version: i64,
    #[serde(default)]
    pub replace_draft: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct JournalQuery {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub before: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DryRunRequest {
    #[serde(default = "default_dry_run_version")]
    pub version: String,
    #[serde(default)]
    pub limit: Option<u32>,
}

fn default_dry_run_version() -> String {
    "draft".to_string()
}

// ------------------------------------------------------------------
// Handlers — маршруты подключаются в human/mod.rs.
// ------------------------------------------------------------------

fn database_exists(state: &SetupService, database_id: Uuid) -> rusqlite::Result<bool> {
    state
        .storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM databases WHERE id=?1)",
                [database_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
        })
        .map(|exists| exists != 0)
}

//++agent TASK-225 [26.09.2026] review MINOR-8: сбой хранилища не
// маскируется в 404 — Some(Response) либо продолжаем.
fn database_guard(
    state: &SetupService,
    database_id: Uuid,
    handler: &'static str,
) -> Option<Response> {
    match database_exists(state, database_id) {
        Ok(true) => None,
        Ok(false) => {
            Some(ApiError::not_found_code("DATABASE_NOT_FOUND", "база не найдена").into_response())
        }
        Err(error) => Some(setup_storage_error(handler, &error)),
    }
}

/// B3 (Admin) / B3v (Viewer): viewer-вариант фиксирует `version=active`
/// и запрещает параметр `version`.
pub(crate) async fn export_setup(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
    viewer_only: bool,
) -> Response {
    let role = if viewer_only {
        crate::auth::Role::Viewer
    } else {
        crate::auth::Role::Admin
    };
    let actor = match authorize(&state, &headers, Some(role), false) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if viewer_only && query.version.is_some() {
        return ApiError::bad_request("параметр version доступен только администратору")
            .into_response();
    }
    //++agent TASK-225 [26.09.2026] review MINOR-14: внутренности набора
    // (tools) viewer не раскрываем — как version.
    if viewer_only && query.include_tools == Some(1) {
        return ApiError::bad_request("параметр include_tools доступен только администратору")
            .into_response();
    }
    let version_ref = if viewer_only {
        "active".to_string()
    } else {
        query
            .version
            .clone()
            .unwrap_or_else(|| "active".to_string())
    };
    //++agent TASK-225 [26.09.2026] review MINOR-7: невалидный ref —
    // 400, а не 503 через rusqlite::Error::InvalidQuery.
    let Some(reference) = VersionRef::parse(&version_ref) else {
        return ApiError::bad_request("version: active|draft|номер").into_response();
    };
    if let Some(response) = database_guard(&state.setup, id, "export_setup") {
        return response;
    }
    let include_tools = query.include_tools == Some(1);
    let outcome = state.setup.storage.with_connection(|connection| {
        let version = store::load_version(connection, id, &reference)?;
        let Some(version) = version else {
            return Ok(Err(if version_ref == "active" {
                "NO_ACTIVE_VERSION"
            } else {
                "VERSION_NOT_FOUND"
            }));
        };
        let content = store::stored_version_content(&version);
        let tools = if include_tools {
            Some(store::current_tools(connection, id)?)
        } else {
            None
        };
        let label: String = connection
            .query_row(
                "SELECT COALESCE(display_label,id) FROM databases WHERE id=?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| id.to_string());
        let now = Utc::now().to_rfc3339();
        let file = export_file_json(&content, id, Some(&label), version.version, tools, &now);
        let body = serde_json::to_vec_pretty(&file).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let sha = setup::sha256_bytes_hex(&body);
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        store::journal_insert(
            &transaction,
            id,
            "human",
            Some(actor.user_id),
            "export",
            Some(version.version),
            None,
            Some(&sha),
            None,
            &now,
        )?;
        audit(
            &transaction,
            &actor,
            "setup.export",
            id,
            Uuid::new_v4(),
            &now,
        )?;
        transaction.commit()?;
        let safe_label: String = label
            .chars()
            .map(|ch| {
                if ch.is_alphanumeric() || ch == '-' || ch == '_' {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        let file_name = format!(
            "masking-setup-{}-v{}-{}.json",
            safe_label,
            version.version,
            &now[..10]
        );
        Ok(Ok((body, file_name)))
    });
    match outcome {
        Ok(Ok((body, file_name))) => {
            let mut response = Response::new(Body::from(body));
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            );
            headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{file_name}\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            );
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(Err(code)) => {
            ApiError::not_found_code(code, "запрошенная версия не найдена").into_response()
        }
        Err(error) => setup_storage_error("export_setup", &error),
    }
}

//++agent TASK-225 [26.09.2026] D2: список версий и просмотр конкретной —
// UI больше не зависит от legacy GET /policies; чтение не пишет журнал.
/// D2: `GET …/setup/versions` — метаданные версий (автор/дата/статус).
pub(crate) async fn version_list(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = authorize(&state, &headers, Some(crate::auth::Role::Admin), false) {
        return error.into_response();
    }
    if let Some(response) = database_guard(&state.setup, id, "version_list") {
        return response;
    }
    match state
        .setup
        .storage
        .with_connection(|connection| store::list_versions(connection, id))
    {
        Ok(rows) => Json(
            rows.iter()
                .map(|row| {
                    json!({
                        "version": row.version,
                        "status": row.status,
                        "origin": row.origin,
                        "created_at": row.created_at,
                        "updated_at": row.updated_at,
                        "activated_at": row.activated_at,
                        "created_by": {"kind": "human", "login": row.created_by_login},
                        "content_hash": row.content_hash,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => setup_storage_error("version_list", &error),
    }
}

/// D2: `GET …/setup/versions/{version}` — контент версии в формате §1,
/// без журнала/аудита (просмотр, не экспорт).
pub(crate) async fn version_get(
    State(state): State<Arc<HumanState>>,
    Path((id, number)): Path<(Uuid, i64)>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = authorize(&state, &headers, Some(crate::auth::Role::Admin), false) {
        return error.into_response();
    }
    if let Some(response) = database_guard(&state.setup, id, "version_get") {
        return response;
    }
    let outcome = state.setup.storage.with_connection(|connection| {
        let Some(version) = store::load_version(connection, id, &VersionRef::Number(number))?
        else {
            return Ok(None);
        };
        let content = store::stored_version_content(&version);
        let label: String = connection
            .query_row(
                "SELECT COALESCE(display_label,id) FROM databases WHERE id=?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| id.to_string());
        let now = Utc::now().to_rfc3339();
        let mut file = export_file_json(
            &content,
            id,
            Some(&label),
            version.version,
            content.tools.clone(),
            &now,
        );
        //++agent TASK-225 [26.09.2026] D8: API-просмотр версии —
        // rule_id нужен UI для связки с причинами B9; в ФАЙЛ экспорта
        // id не попадают (§1.1 MUST NOT) — добавляем только здесь.
        if let Some(rules) = file
            .get_mut("rules")
            .and_then(serde_json::Value::as_array_mut)
        {
            for (out, rule) in rules.iter_mut().zip(content.rules.iter()) {
                if let Some(rule_id) = &rule.rule_id {
                    out["rule_id"] = rule_id.clone().into();
                }
            }
        }
        //++agent TASK-225
        if let Some(map) = file.as_object_mut() {
            map.insert("status".into(), version.status.clone().into());
        }
        Ok(Some(file))
    });
    match outcome {
        Ok(Some(file)) => {
            let mut response = Json(file).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(None) => {
            ApiError::not_found_code("VERSION_NOT_FOUND", "версия не найдена").into_response()
        }
        Err(error) => setup_storage_error("version_get", &error),
    }
}
//++agent TASK-225

/// B11: журнал операций настройки.
pub(crate) async fn setup_journal(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<JournalQuery>,
) -> Response {
    if let Err(error) = authorize(&state, &headers, Some(crate::auth::Role::Admin), false) {
        return error.into_response();
    }
    let limit = query.limit.unwrap_or(100).min(200);
    let result = state.setup.storage.with_connection(|connection| {
        //++agent TASK-225 [26.09.2026] D1: колонка users называется
        // display_login, не login — иначе SELECT падал в 503.
        //++agent TASK-225
        let mut statement = connection.prepare(
            "SELECT j.id,j.at,j.actor_kind,j.actor_id,j.action,j.version,j.file_name,j.sha256,j.details_json,
                    (SELECT u.display_login FROM users u WHERE u.id=j.actor_id)
             FROM setup_journal j
             WHERE j.database_id=?1 AND (?2 IS NULL OR j.id<?2)
             ORDER BY j.id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![id.to_string(), query.before, limit as i64],
            |row| {
                let login: Option<String> = row.get(9)?;
                Ok(json!({
                    "id": row.get::<_, i64>(0)?,
                    "at": row.get::<_, String>(1)?,
                    "actor": {
                        "kind": row.get::<_, String>(2)?,
                        "login": login,
                    },
                    "action": row.get::<_, String>(4)?,
                    "version": row.get::<_, Option<i64>>(5)?,
                    "file_name": row.get::<_, Option<String>>(6)?,
                    "sha256": row.get::<_, Option<String>>(7)?,
                    "details": row.get::<_, Option<String>>(8)?
                        .and_then(|text| serde_json::from_str::<Value>(&text).ok()),
                }))
            },
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    });
    match result {
        Ok(entries) => Json(Value::Array(entries)).into_response(),
        Err(error) => setup_storage_error("setup_journal", &error),
    }
}

// ------------------------------------------------------------------
// B5: diff версий (§3)
// ------------------------------------------------------------------

/// Общий прогон diff: загружает версии из ссылки, считает §3-функцию.
/// `Ok(None)` — версия не найдена (ответ формирует вызывающий).
fn run_diff(
    state: &SetupService,
    database_id: Uuid,
    from_ref: &VersionRef,
    to_ref: &VersionRef,
    database_mismatch: bool,
) -> Result<Option<(store::StoredVersion, store::StoredVersion, setup::SetupDiff)>, rusqlite::Error>
{
    state.storage.with_connection(|connection| {
        let from = store::load_version(connection, database_id, from_ref)?;
        let to = store::load_version(connection, database_id, to_ref)?;
        let (Some(from), Some(to)) = (from, to) else {
            return Ok(None);
        };
        let context = state.diff_context(connection, database_id, database_mismatch)?;
        let from_content = store::stored_version_content(&from);
        let diff = compute_diff(
            &from_content,
            //++agent TASK-225: NULL-словарь цели наследуется (review MAJOR-5)
            &store::stored_version_content_for_to(&to, &from_content),
            &context,
        );
        Ok(Some((from, to, diff)))
    })
}

/// Сводка классов изменений для ответа B5/B7.
fn diff_counts(diff: &setup::SetupDiff) -> Value {
    let mut weakening = 0u32;
    let mut strengthening = 0u32;
    let mut neutral = 0u32;
    for change in &diff.changes {
        match change.change_class {
            setup::ChangeClass::Weakening => weakening += 1,
            setup::ChangeClass::Strengthening => strengthening += 1,
            setup::ChangeClass::Neutral => neutral += 1,
        }
    }
    json!({
        "weakening": weakening,
        "strengthening": strengthening,
        "neutral": neutral,
    })
}

fn diff_response(diff: &setup::SetupDiff) -> Value {
    json!({
        "changes": diff.changes,
        "counts": diff_counts(diff),
        "warnings": diff.warnings,
    })
}

pub(crate) async fn diff_setup(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<DiffQuery>,
) -> Response {
    if let Err(error) = authorize(&state, &headers, Some(crate::auth::Role::Admin), false) {
        return error.into_response();
    }
    if let Some(response) = database_guard(&state.setup, id, "diff_setup") {
        return response;
    }
    let from_text = query.from.as_deref().unwrap_or("active");
    let to_text = query.to.as_deref().unwrap_or("draft");
    //++agent TASK-225 [26.09.2026] review MINOR-7: parse-ошибка = 400.
    let (Some(from_ref), Some(to_ref)) = (VersionRef::parse(from_text), VersionRef::parse(to_text))
    else {
        return ApiError::bad_request("from/to: active|draft|номер").into_response();
    };
    match run_diff(&state.setup, id, &from_ref, &to_ref, false) {
        Ok(Some((from, to, diff))) => {
            let mut body = diff_response(&diff);
            body["from_version"] = from.version.into();
            body["to_version"] = to.version.into();
            body["to_hash"] = to.content_hash.unwrap_or_default().into();
            Json(body).into_response()
        }
        //++agent TASK-225: NO_DRAFT только когда отсутствует именно
        // черновик (review MINOR-7) — иначе маскируем отсутствие from.
        Ok(None) if to_ref == VersionRef::Draft => {
            ApiError::conflict_code("NO_DRAFT", "у базы нет черновика").into_response()
        }
        Ok(None) => {
            ApiError::not_found_code("VERSION_NOT_FOUND", "версия не найдена").into_response()
        }
        Err(error) => setup_storage_error("diff_setup", &error),
    }
}

// ------------------------------------------------------------------
// B4: импорт файла настройки → черновик
// ------------------------------------------------------------------

pub(crate) async fn import_setup(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<ImportQuery>,
    body: axum::body::Bytes,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let actor = match authorize(&state, &headers, Some(crate::auth::Role::Admin), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if let Some(response) = database_guard(&state.setup, id, "import_setup") {
        return response;
    }
    if body.len() > SETUP_MAX_BYTES {
        return ApiError::coded(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SETUP_TOO_LARGE",
            "файл настройки больше 1 МиБ",
            None,
        )
        .into_response();
    }
    let file_name = headers
        .get("x-file-name")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.chars().count() <= 255)
        .map(str::to_owned);
    let sha256 = setup::sha256_bytes_hex(&body);
    let now = Utc::now().to_rfc3339();
    let outcome = state.setup.storage.with_connection(|connection| {
        let parsed = parse_setup_body(&body);
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(parsed) = parsed.parsed else {
            // Отклонённый импорт тоже фиксируется (§4/B4).
            let codes: Vec<String> = parsed
                .errors
                .iter()
                .map(|issue| issue.code.clone())
                .collect();
            store::import_insert(
                &transaction,
                id,
                actor.user_id,
                file_name.as_deref(),
                &sha256,
                body.len(),
                None,
                None,
                "rejected",
                &codes,
                None,
                &now,
            )?;
            store::journal_insert(
                &transaction,
                id,
                "human",
                Some(actor.user_id),
                "import_rejected",
                None,
                file_name.as_deref(),
                Some(&sha256),
                Some(json!({"codes": codes})),
                &now,
            )?;
            transaction.commit()?;
            return Ok(Err(parsed.errors));
        };
        let existing_draft = store::draft_row(&transaction, id)?;
        if query.replace_draft != Some(1) {
            if let Some((_, draft_version, _)) = &existing_draft {
                transaction.commit()?;
                return Ok(Ok(Err(json!({
                    "code": "DRAFT_EXISTS",
                    "draft_version": draft_version,
                }))));
            }
        }
        // replace_draft=1: старый черновик уходит в retired/discarded.
        if let Some((draft_id, _, _)) = existing_draft {
            transaction.execute(
                "UPDATE policies SET status='retired',discarded_at=?2 WHERE id=?1",
                params![draft_id.to_string(), now],
            )?;
        }
        //++agent TASK-225 [26.09.2026] review MINOR-11: hint сравниваем
        // как UUID, а не как строку — регистр/скобки той же базы не
        // должны давать ложный DATABASE_MISMATCH.
        let database_mismatch = parsed
            .database_hint
            .as_ref()
            .and_then(|hint| hint.id.as_deref())
            .is_some_and(|hint| Uuid::parse_str(hint).map(|uuid| uuid != id).unwrap_or(true));
        let (draft_id, draft_version) = store::insert_draft(
            &transaction,
            id,
            "import",
            None,
            Some(actor.user_id),
            &parsed.content,
            &now,
        )?;
        transaction.execute(
            "UPDATE policies SET origin_ref=?2 WHERE id=?1",
            params![draft_id.to_string(), "pending"],
        )?;
        let import_id = store::import_insert(
            &transaction, id, actor.user_id, file_name.as_deref(), &sha256,
            body.len(), Some(&parsed.generated_by),
            parsed.database_hint.as_ref().map(|hint| {
                json!({"id":hint.id,"label":hint.label,"source_version":hint.source_version})
            }).as_ref(),
            "accepted", &[], Some(draft_id), &now,
        )?;
        transaction.execute(
            "UPDATE policies SET origin_ref=?2 WHERE id=?1",
            params![draft_id.to_string(), import_id.to_string()],
        )?;
        let draft_hash: String = transaction.query_row(
            "SELECT content_hash FROM policies WHERE id=?1",
            [draft_id.to_string()],
            |row| row.get(0),
        )?;
        // Предупреждения импорта — по diff(active, draft) с флагом
        // database_mismatch (§3.6 DATABASE_MISMATCH).
        let active = store::load_version(&transaction, id, &VersionRef::Active)?;
        let diff_context = state
            .setup
            .diff_context(&transaction, id, database_mismatch)?;
        let warnings = active
            .map(|active| {
                compute_diff(
                    &store::stored_version_content(&active),
                    &parsed.content,
                    &diff_context,
                )
                .warnings
            })
            .unwrap_or_else(|| {
                compute_diff(&store::empty_content(), &parsed.content, &diff_context).warnings
            });
        store::journal_insert(
            &transaction,
            id,
            "human",
            Some(actor.user_id),
            "import",
            Some(draft_version),
            file_name.as_deref(),
            Some(&sha256),
            Some(json!({"import_id": import_id})),
            &now,
        )?;
        audit(
            &transaction,
            &actor,
            "setup.import",
            id,
            Uuid::new_v4(),
            &now,
        )?;
        transaction.commit()?;
        Ok(Ok(Ok(json!({
            "import_id": import_id,
            "draft_version": draft_version,
            "draft_hash": draft_hash,
            "sha256": sha256,
            "size_bytes": body.len(),
            "schema": SETUP_SCHEMA,
            "generated_by": parsed.generated_by,
            "database_hint": parsed.database_hint,
            "database_mismatch": database_mismatch,
            "counts": {
                "sources": parsed.content.dictionary.sources.len(),
                "rules": parsed.content.rules.len(),
                "regex_tests_passed": parsed.regex_tests_passed,
                "tools": parsed.content.tools.as_ref().map_or(0, Vec::len),
            },
            "warnings": warnings,
        }))))
    });
    match outcome {
        Ok(Ok(Ok(body))) => (StatusCode::CREATED, Json(body)).into_response(),
        Ok(Ok(Err(conflict))) => ApiError::coded(
            StatusCode::CONFLICT,
            "DRAFT_EXISTS",
            "у базы уже есть черновик",
            Some(conflict),
        )
        .into_response(),
        Ok(Err(errors)) => ApiError::coded(
            StatusCode::BAD_REQUEST,
            "SETUP_INVALID",
            "файл настройки не прошёл валидацию",
            Some(json!({"errors": errors})),
        )
        .into_response(),
        Err(error) => setup_storage_error("import_setup", &error),
    }
}

// ------------------------------------------------------------------
// B8: черновик — создание/просмотр/правки/revert/удаление
// ------------------------------------------------------------------

/// Ответ 409 DRAFT_CHANGED с телом по §4 (current_hash + автор/время).
fn draft_changed(details: Value) -> Response {
    ApiError::coded(
        StatusCode::CONFLICT,
        "DRAFT_CHANGED",
        "черновик изменился после получения хеша",
        Some(details),
    )
    .into_response()
}

/// If-Match из заголовка — без него 428 (T4-11).
fn if_match_hash(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim_matches('"').to_owned())
        .ok_or_else(|| {
            ApiError::coded(
                StatusCode::PRECONDITION_REQUIRED,
                "PRECONDITION_REQUIRED",
                "требуется заголовок If-Match с хешем черновика",
                None,
            )
        })
}

/// Черновик в транзакции: проверка существования и сверка If-Match.
/// `Ok(None)` — черновика нет (404 NO_DRAFT).
fn checked_draft(
    transaction: &rusqlite::Transaction,
    database_id: Uuid,
    expected_hash: Option<&str>,
) -> Result<Option<(store::StoredVersion, Option<Value>)>, rusqlite::Error> {
    let Some((draft_id, _, _)) = store::draft_row(transaction, database_id)? else {
        return Ok(None);
    };
    let Some(draft) = store::load_version(
        transaction,
        database_id,
        &VersionRef::Number(transaction.query_row(
            "SELECT version FROM policies WHERE id=?1",
            [draft_id.to_string()],
            |row| row.get(0),
        )?),
    )?
    else {
        return Ok(None);
    };
    let current_hash = draft.content_hash.clone().unwrap_or_default();
    if let Some(expected) = expected_hash {
        if expected != current_hash {
            let details = json!({
                "current_hash": current_hash,
                //++agent TASK-225: поле называется как хранится — автора
                // последнего редактирования мы не храним (review MINOR-13).
                "created_by": draft.created_by,
                "updated_at": draft.updated_at,
            });
            return Ok(Some((draft, Some(details))));
        }
    }
    Ok(Some((draft, None)))
}

pub(crate) async fn draft_create(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<DraftCreateRequest>,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let actor = match authorize(&state, &headers, Some(crate::auth::Role::Admin), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if let Some(response) = database_guard(&state.setup, id, "draft_create") {
        return response;
    }
    if !matches!(request.from.as_str(), "active" | "empty") {
        return ApiError::bad_request("from ∈ {active, empty}").into_response();
    }
    let now = Utc::now().to_rfc3339();
    let outcome = state.setup.storage.with_connection(|connection| {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if store::draft_row(&transaction, id)?.is_some() {
            transaction.commit()?;
            return Ok(None);
        }
        let content = if request.from == "active" {
            store::load_version(&transaction, id, &VersionRef::Active)?
                .map(|version| store::stored_version_content(&version))
                .unwrap_or_else(store::empty_content)
        } else {
            store::empty_content()
        };
        let (draft_id, version) = store::insert_draft(
            &transaction,
            id,
            "manual",
            None,
            Some(actor.user_id),
            &content,
            &now,
        )?;
        let draft_hash: String = transaction.query_row(
            "SELECT content_hash FROM policies WHERE id=?1",
            [draft_id.to_string()],
            |row| row.get(0),
        )?;
        store::journal_insert(
            &transaction,
            id,
            "human",
            Some(actor.user_id),
            "draft_create",
            Some(version),
            None,
            None,
            Some(json!({"from": request.from})),
            &now,
        )?;
        audit(
            &transaction,
            &actor,
            "setup.draft_create",
            id,
            Uuid::new_v4(),
            &now,
        )?;
        transaction.commit()?;
        Ok(Some((version, draft_hash)))
    });
    match outcome {
        Ok(Some((version, hash))) => (
            StatusCode::CREATED,
            Json(json!({"draft_version": version, "draft_hash": hash})),
        )
            .into_response(),
        Ok(None) => {
            ApiError::conflict_code("DRAFT_EXISTS", "у базы уже есть черновик").into_response()
        }
        Err(error) => setup_storage_error("draft_create", &error),
    }
}

/// Контент версии в §1-форме области (для GET draft и внутренних сличений).
fn draft_view(
    state: &SetupService,
    version: &store::StoredVersion,
    connection: &rusqlite::Connection,
    database_id: Uuid,
) -> rusqlite::Result<Value> {
    let content = store::stored_version_content(version);
    let manifest_paths = state
        .diff_context(connection, database_id, false)?
        .manifest_paths;
    let sources: Vec<Value> = content
        .dictionary
        .sources
        .iter()
        .map(|source| {
            let in_manifest = manifest_paths
                .as_ref()
                .map(|paths| paths.contains(&source.source_path.to_lowercase()));
            let mut map = serde_json::Map::new();
            map.insert("source_path".into(), source.source_path.clone().into());
            map.insert("category".into(), source.category.clone().into());
            if let Some(filter) = &source.filter_ast {
                map.insert("filter".into(), filter.clone());
            }
            map.insert("reason".into(), source.reason.clone().into());
            if let Some(estimated) = source.estimated_values {
                map.insert("estimated_values".into(), estimated.into());
            }
            if let Some(flag) = in_manifest {
                map.insert("in_manifest".into(), flag.into());
            }
            Value::Object(map)
        })
        .collect();
    let rules: Vec<Value> = version
        .rules
        .iter()
        .map(|rule| {
            let mut map = serde_json::Map::new();
            map.insert("rule_id".into(), rule.id.to_string().into());
            map.insert("selector".into(), rule.selector.clone().into());
            map.insert("value".into(), rule.value.clone().into());
            map.insert("action".into(), rule.action.clone().into());
            map.insert("category".into(), rule.category.clone().into());
            map.insert("priority".into(), rule.priority.into());
            map.insert("enabled".into(), rule.enabled.into());
            map.insert(
                "reason".into(),
                rule.reason.clone().unwrap_or_default().into(),
            );
            if let Some(tests) = &rule.tests {
                map.insert("tests".into(), tests.clone());
            }
            Value::Object(map)
        })
        .collect();
    Ok(json!({
        "version": version.version,
        "draft_hash": version.content_hash,
        "origin": version.origin,
        "origin_ref": version.origin_ref,
        "created_by": version.created_by,
        "updated_at": version.updated_at,
        "dictionary": {"mode": content.dictionary.mode, "sources": sources},
        "rules": rules,
        "tools": content.tools,
    }))
}

pub(crate) async fn draft_get(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = authorize(&state, &headers, Some(crate::auth::Role::Admin), false) {
        return error.into_response();
    }
    if let Some(response) = database_guard(&state.setup, id, "draft_get") {
        return response;
    }
    let result = state.setup.storage.with_connection(|connection| {
        let draft = store::load_version(connection, id, &VersionRef::Draft)?;
        draft
            .map(|version| draft_view(&state.setup, &version, connection, id))
            .transpose()
    });
    match result {
        Ok(Some(view)) => {
            let mut response = Json(view.clone()).into_response();
            if let Some(hash) = view["draft_hash"].as_str() {
                if let Ok(value) = HeaderValue::from_str(&format!("\"{hash}\"")) {
                    response.headers_mut().insert(header::ETAG, value);
                }
            }
            response
        }
        Ok(None) => ApiError::not_found_code("NO_DRAFT", "у базы нет черновика").into_response(),
        Err(error) => setup_storage_error("draft_get", &error),
    }
}

/// Разбор тела правки области в контент §1 (валидация parse_setup_body
/// переиспользуется через синтетический файл — сохраняет все проверки).
fn parse_area(area: &str, body: &Value) -> Result<VersionContentPatch, Vec<setup::SetupIssue>> {
    let mut file = serde_json::Map::new();
    file.insert("schema".into(), SETUP_SCHEMA.into());
    file.insert("generated_at".into(), Utc::now().to_rfc3339().into());
    //++agent TASK-225 [26.09.2026] D5: полный обязательный каркас §1 —
    // generated_by и оба массива, иначе parse_setup_body всегда отвечал
    // 400 SETUP_INVALID на любую правку области.
    file.insert(
        "generated_by".into(),
        json!({"kind":"service","tool":"human-api","note":"draft area update"}),
    );
    file.insert("dictionary".into(), json!({"mode":"part","sources":[]}));
    file.insert("rules".into(), json!([]));
    match area {
        "dictionary" => {
            file.insert("dictionary".into(), body.clone());
        }
        "rules" => {
            file.insert("rules".into(), body["rules"].clone());
        }
        "tools" => {
            file.insert("tools".into(), body["tools"].clone());
        }
        _ => return Err(Vec::new()),
    }
    //++agent TASK-225
    let parsed = parse_setup_body(&serde_json::to_vec(&Value::Object(file)).unwrap_or_default());
    match parsed.parsed {
        Some(parsed) => Ok(VersionContentPatch {
            content: parsed.content,
        }),
        None => Err(parsed.errors),
    }
}

struct VersionContentPatch {
    content: VersionContent,
}

//++agent TASK-225 [26.09.2026]
// Ошибка хранилища в setup/* раньше сворачивалась в 503 без следа —
// логируем контекст и тип ошибки (значения данных в ответ/лог не идут).
fn setup_storage_error(handler: &str, error: &impl std::fmt::Debug) -> Response {
    tracing::error!(event = "setup_storage_error", handler, error = ?error);
    ApiError::unavailable().into_response()
}
//++agent TASK-225

/// PUT …/setup/draft/{dictionary|rules|tools}: полная замена области.
pub(crate) async fn draft_put_area(
    State(state): State<Arc<HumanState>>,
    Path((id, area)): Path<(Uuid, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let actor = match authorize(&state, &headers, Some(crate::auth::Role::Admin), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if !matches!(area.as_str(), "dictionary" | "rules" | "tools") {
        return ApiError::not_found().into_response();
    }
    let expected_hash = match if_match_hash(&headers) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let body: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return ApiError::bad_request("тело должно быть JSON-объектом").into_response(),
    };
    let patch = match parse_area(&area, &body) {
        Ok(patch) => patch,
        Err(errors) => {
            return ApiError::coded(
                StatusCode::BAD_REQUEST,
                "SETUP_INVALID",
                "область не прошла валидацию",
                Some(json!({"errors": errors})),
            )
            .into_response();
        }
    };
    let now = Utc::now().to_rfc3339();
    let outcome = state.setup.storage.with_connection(|connection| {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match checked_draft(&transaction, id, Some(&expected_hash))? {
            None => {
                transaction.commit()?;
                Ok(Ok(None))
            }
            Some((_, Some(details))) => {
                transaction.commit()?;
                Ok(Err(details))
            }
            Some((draft, None)) => {
                let mut content = store::stored_version_content(&draft);
                match area.as_str() {
                    "dictionary" => content.dictionary = patch.content.dictionary,
                    "rules" => content.rules = patch.content.rules,
                    // tools: null в файле = «не трогать классификацию» —
                    // PATCH-семантика области (§1.3 tools nullable).
                    "tools" => content.tools = patch.content.tools,
                    _ => {}
                }
                store::write_version_content(&transaction, draft.id, &content, &now)?;
                let draft_hash: String = transaction.query_row(
                    "SELECT content_hash FROM policies WHERE id=?1",
                    [draft.id.to_string()],
                    |row| row.get(0),
                )?;
                store::journal_insert(
                    &transaction,
                    id,
                    "human",
                    Some(actor.user_id),
                    "draft_edit",
                    Some(draft.version),
                    None,
                    None,
                    Some(json!({"area": area})),
                    &now,
                )?;
                audit(
                    &transaction,
                    &actor,
                    "setup.draft_edit",
                    id,
                    Uuid::new_v4(),
                    &now,
                )?;
                transaction.commit()?;
                Ok(Ok(Some(draft_hash)))
            }
        }
    });
    match outcome {
        Ok(Ok(Some(hash))) => Json(json!({"draft_hash": hash})).into_response(),
        Ok(Ok(None)) => {
            ApiError::not_found_code("NO_DRAFT", "у базы нет черновика").into_response()
        }
        Ok(Err(details)) => draft_changed(details),
        Err(error) => setup_storage_error("draft_put_area", &error),
    }
}

/// POST …/setup/draft/revert — откат изменений и исключение элементов
/// предупреждений (§4: необязательный путь, штатно списки идут в B7).
pub(crate) async fn draft_revert(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<DraftRevertRequest>,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let actor = match authorize(&state, &headers, Some(crate::auth::Role::Admin), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let expected_hash = match if_match_hash(&headers) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let now = Utc::now().to_rfc3339();
    let outcome = state.setup.storage.with_connection(|connection| {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (draft, mismatch) = match checked_draft(&transaction, id, Some(&expected_hash))? {
            None => {
                transaction.commit()?;
                return Ok(Ok(None));
            }
            Some((_, Some(details))) => {
                transaction.commit()?;
                return Ok(Err(details));
            }
            Some((draft, None)) => (draft, None::<Value>),
        };
        let active = store::load_version(&transaction, id, &VersionRef::Active)?;
        let from = active
            .as_ref()
            .map(store::stored_version_content)
            .unwrap_or_else(store::empty_content);
        let mut content = store::stored_version_content(&draft);
        let context = state.setup.diff_context(&transaction, id, false)?;
        let diff = compute_diff(&from, &content, &context);
        if let Err(unknown) =
            store::apply_change_reverts(&mut content, &diff.changes, &request.change_ids)
        {
            transaction.commit()?;
            return Ok(Ok(Some(Err(
                json!({"code":"UNKNOWN_CHANGE","ids":unknown}),
            ))));
        }
        if let Err(unknown) =
            store::apply_warning_exclusions(&mut content, &diff.warnings, &request.warning_ids)
        {
            transaction.commit()?;
            return Ok(Ok(Some(Err(json!({
                "code":"WARNING_NOT_EXCLUDABLE","ids":unknown
            })))));
        }
        store::write_version_content(&transaction, draft.id, &content, &now)?;
        let draft_hash: String = transaction.query_row(
            "SELECT content_hash FROM policies WHERE id=?1",
            [draft.id.to_string()],
            |row| row.get(0),
        )?;
        store::journal_insert(
            &transaction,
            id,
            "human",
            Some(actor.user_id),
            "draft_edit",
            Some(draft.version),
            None,
            None,
            Some(json!({
                "area": "revert",
                "change_ids": request.change_ids,
                "warning_ids": request.warning_ids,
            })),
            &now,
        )?;
        audit(
            &transaction,
            &actor,
            "setup.draft_edit",
            id,
            Uuid::new_v4(),
            &now,
        )?;
        transaction.commit()?;
        let _ = mismatch;
        Ok(Ok(Some(Ok(draft_hash))))
    });
    match outcome {
        Ok(Ok(Some(Ok(hash)))) => Json(json!({"draft_hash": hash})).into_response(),
        Ok(Ok(Some(Err(error)))) => {
            // §4: error.code — конкретный код отказа (UNKNOWN_CHANGE /
            // WARNING_NOT_EXCLUDABLE), payload несёт ids.
            let code = match error["code"].as_str() {
                Some("WARNING_NOT_EXCLUDABLE") => "WARNING_NOT_EXCLUDABLE",
                Some("UNKNOWN_CHANGE") => "UNKNOWN_CHANGE",
                _ => "INVALID_REQUEST",
            };
            ApiError::coded(
                StatusCode::BAD_REQUEST,
                code,
                "операция отклонена",
                Some(error),
            )
            .into_response()
        }
        Ok(Ok(None)) => {
            ApiError::not_found_code("NO_DRAFT", "у базы нет черновика").into_response()
        }
        Ok(Err(details)) => draft_changed(details),
        Err(error) => setup_storage_error("draft_revert", &error),
    }
}

/// DELETE …/setup/draft — снятие черновика (retired + discarded_at).
pub(crate) async fn draft_delete(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let actor = match authorize(&state, &headers, Some(crate::auth::Role::Admin), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let expected_hash = match if_match_hash(&headers) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let now = Utc::now().to_rfc3339();
    let outcome = state.setup.storage.with_connection(|connection| {
        let transaction =
            connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match checked_draft(&transaction, id, Some(&expected_hash))? {
            None => {
                transaction.commit()?;
                Ok(Ok(false))
            }
            Some((_, Some(details))) => {
                transaction.commit()?;
                Ok(Err(details))
            }
            Some((draft, None)) => {
                transaction.execute(
                    "UPDATE policies SET status='retired',discarded_at=?2,updated_at=?2 WHERE id=?1",
                    params![draft.id.to_string(), now],
                )?;
                store::journal_insert(
                    &transaction, id, "human", Some(actor.user_id), "draft_discard",
                    Some(draft.version), None, None, None, &now,
                )?;
                audit(&transaction, &actor, "setup.draft_discard", id, Uuid::new_v4(), &now)?;
                transaction.commit()?;
                Ok(Ok(true))
            }
        }
    });
    match outcome {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => {
            ApiError::not_found_code("NO_DRAFT", "у базы нет черновика").into_response()
        }
        Ok(Err(details)) => draft_changed(details),
        Err(error) => setup_storage_error("draft_delete", &error),
    }
}

// ------------------------------------------------------------------
// B7: активация черновика (серверная перепроверка §4)
// ------------------------------------------------------------------

pub(crate) async fn activate_setup(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ActivateRequest>,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let actor = match authorize(&state, &headers, Some(crate::auth::Role::Admin), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    //++agent TASK-225 [26.09.2026] review MINOR-12: comment пишется
    // дословно в policies/journal — ограничиваем как прочие тексты.
    if let Some(comment) = &request.comment {
        if comment.chars().count() > 500 || comment.chars().any(char::is_control) {
            return ApiError::bad_request("comment: до 500 символов, без управляющих символов")
                .into_response();
        }
    }
    let now = Utc::now().to_rfc3339();
    let outcome = state.setup.storage.with_connection(|connection| {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Шаг 1: версия — черновик именно этой базы.
        let draft = store::load_version(&transaction, id, &VersionRef::Number(request.version))?;
        let Some(draft) = draft.filter(|version| version.status == "draft") else {
            transaction.commit()?;
            return Ok(Err(json!({"code":"NOT_A_DRAFT"})));
        };
        // Шаг 2: хеш.
        let current_hash = draft.content_hash.clone().unwrap_or_default();
        if request.draft_hash != current_hash {
            transaction.commit()?;
            return Ok(Err(json!({
                "code":"DRAFT_CHANGED",
                "current_hash": current_hash,
                //++agent TASK-225: created_by, а не updated_by — отдельного
                // поля последнего редактора нет (review MINOR-13).
                "created_by": draft.created_by,
                "updated_at": draft.updated_at,
            })));
        }
        let active = store::load_version(&transaction, id, &VersionRef::Active)?;
        let from = active
            .as_ref()
            .map(store::stored_version_content)
            .unwrap_or_else(store::empty_content);
        // Шаг 3: пересчёт diff и предупреждений сервером.
        let context = state.setup.diff_context(&transaction, id, false)?;
        //++agent TASK-225 [26.09.2026] review MAJOR-5: legacy-черновик без
        // dictionary_json («не задано») наследует словарь активной — иначе
        // барьер видел бы фантомные SOURCE_REMOVED. Унаследованное
        // содержимое далее материализуется write_version_content — у
        // активированной версии появляется явный словарь.
        let mut content = store::stored_version_content_for_to(&draft, &from);
        let diff = compute_diff(&from, &content, &context);
        let weakening_ids: HashSet<String> = diff
            .changes
            .iter()
            .filter(|change| change.change_class == setup::ChangeClass::Weakening)
            .map(|change| change.id.clone())
            .collect();
        let strengthening_ids: HashSet<String> = diff
            .changes
            .iter()
            .filter(|change| change.change_class == setup::ChangeClass::Strengthening)
            .map(|change| change.id.clone())
            .collect();
        let warning_ids: HashSet<String> = diff
            .warnings
            .iter()
            .map(|warning| warning.id.clone())
            .collect();
        let confirmed: HashSet<&str> = request
            .confirmed_weakenings
            .iter()
            .map(String::as_str)
            .collect();
        let accepted: HashSet<&str> = request
            .accepted_strengthenings
            .iter()
            .map(String::as_str)
            .collect();
        let excluded: HashSet<&str> = request
            .excluded_warnings
            .iter()
            .map(String::as_str)
            .collect();
        // Шаг 4: confirmed ⊇ W; id вне текущего diff — STALE_CONFIRMATION.
        let stale: Vec<String> = confirmed
            .iter()
            .filter(|id| !weakening_ids.contains(**id))
            .chain(
                accepted
                    .iter()
                    .filter(|id| !strengthening_ids.contains(**id)),
            )
            .chain(excluded.iter().filter(|id| !warning_ids.contains(**id)))
            .map(|id| id.to_string())
            .collect();
        if !stale.is_empty() {
            transaction.commit()?;
            return Ok(Err(json!({"code":"STALE_CONFIRMATION","unknown":stale})));
        }
        let missing: Vec<String> = weakening_ids
            .iter()
            .filter(|id| !confirmed.contains(id.as_str()))
            .cloned()
            .collect();
        if !missing.is_empty() {
            transaction.commit()?;
            return Ok(Err(
                json!({"code":"WEAKENING_NOT_CONFIRMED","missing":missing}),
            ));
        }
        // Неисключаемые предупреждения → 400 WARNING_NOT_EXCLUDABLE.
        let not_excludable: Vec<String> = diff
            .warnings
            .iter()
            .filter(|warning| excluded.contains(warning.id.as_str()) && !warning.excludable)
            .map(|warning| warning.id.clone())
            .collect();
        if !not_excludable.is_empty() {
            transaction.commit()?;
            return Ok(Err(
                json!({"code":"WARNING_NOT_EXCLUDABLE","ids":not_excludable,"status":400}),
            ));
        }
        // Шаг 5: непринятые усиления откатываются к состоянию `from`.
        let reverted: Vec<String> = strengthening_ids
            .iter()
            .filter(|id| !accepted.contains(id.as_str()))
            .cloned()
            .collect();
        store::apply_change_reverts(&mut content, &diff.changes, &reverted)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        // Шаг 6: исключённые предупреждения удаляют свои элементы.
        let excluded_items = store::apply_warning_exclusions(
            &mut content,
            &diff.warnings,
            &request.excluded_warnings,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        // Шаг 7: повторный diff итога — ослабления ⊆ confirmed.
        let final_diff = compute_diff(&from, &content, &context);
        let missing: Vec<String> = final_diff
            .changes
            .iter()
            .filter(|change| change.change_class == setup::ChangeClass::Weakening)
            .map(|change| change.id.clone())
            .filter(|id| !confirmed.contains(id.as_str()))
            .collect();
        if !missing.is_empty() {
            transaction.commit()?;
            return Ok(Err(
                json!({"code":"WEAKENING_NOT_CONFIRMED","missing":missing}),
            ));
        }
        // Шаг 9: F8 — включённое secret-правило не активируется.
        if store::has_enabled_secret(&content) {
            transaction.commit()?;
            return Ok(Err(json!({"code":"SECRET_POLICY_UNSUPPORTED"})));
        }
        // Шаги 8+10: итог в черновик, переключение статусов/зеркала/intent.
        store::write_version_content(&transaction, draft.id, &content, &now)?;
        let version = store::activate_draft_tx(
            &transaction,
            id,
            draft.id,
            Some(actor.user_id),
            request.comment.as_deref(),
            &now,
        )?;
        store::journal_insert(
            &transaction,
            id,
            "human",
            Some(actor.user_id),
            "activate",
            Some(version),
            None,
            None,
            Some(json!({
                "confirmed_weakenings": request.confirmed_weakenings,
                "accepted_strengthenings": request.accepted_strengthenings,
                "reverted_strengthenings": reverted,
                "excluded_warnings": request.excluded_warnings,
                "comment": request.comment,
            })),
            &now,
        )?;
        audit(
            &transaction,
            &actor,
            "setup.activate",
            id,
            Uuid::new_v4(),
            &now,
        )?;
        let final_counts = diff_counts(&final_diff);
        transaction.commit()?;
        Ok(Ok((
            version,
            draft.id,
            final_counts,
            reverted,
            excluded_items,
        )))
    });
    match outcome {
        Ok(Ok((version, policy_id, counts, reverted, excluded))) => {
            //++agent TASK-225 [26.09.2026] MINOR-5/§2.5: снимок правил в
            // RAM применяем сразу после commit — активированная версия
            // действует до успешного pull (менеджер может быть в
            // backoff). Ошибка перечтения не отменяет активацию —
            // durable intent всё равно пересоберёт снимок.
            if let Ok(rules) = state
                .setup
                .storage
                .with_connection(|c| super::sqlite::load_rules(c, policy_id, id))
            {
                state
                    .setup
                    .masking
                    .set_policy_snapshot(
                        id,
                        crate::domain::PolicySnapshot {
                            version,
                            rules: rules.into_iter().map(super::sqlite::domain_rule).collect(),
                            policy_id: Some(policy_id),
                            ..crate::domain::PolicySnapshot::default()
                        },
                    )
                    .await;
            }
            //++agent TASK-225
            Json(json!({
                "active_version": version,
                "activated_at": now,
                "applied": counts,
                "reverted_strengthenings": reverted,
                "excluded_items": excluded,
                "refresh": {"state": "pending"},
            }))
            .into_response()
        }
        Ok(Err(error)) => {
            let code = error["code"].as_str().unwrap_or("CONFLICT");
            let status = match code {
                "WARNING_NOT_EXCLUDABLE" => StatusCode::BAD_REQUEST,
                _ => StatusCode::CONFLICT,
            };
            let static_code: &'static str = match code {
                "NOT_A_DRAFT" => "NOT_A_DRAFT",
                "DRAFT_CHANGED" => "DRAFT_CHANGED",
                "STALE_CONFIRMATION" => "STALE_CONFIRMATION",
                "WEAKENING_NOT_CONFIRMED" => "WEAKENING_NOT_CONFIRMED",
                "WARNING_NOT_EXCLUDABLE" => "WARNING_NOT_EXCLUDABLE",
                "SECRET_POLICY_UNSUPPORTED" => "SECRET_POLICY_UNSUPPORTED",
                _ => "CONFLICT",
            };
            ApiError::coded(status, static_code, "активация отклонена", Some(error)).into_response()
        }
        Err(error) => setup_storage_error("activate_setup", &error),
    }
}

// ------------------------------------------------------------------
// B7r: откат — черновик-копия архивной версии
// ------------------------------------------------------------------

pub(crate) async fn rollback_setup(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<RollbackRequest>,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let actor = match authorize(&state, &headers, Some(crate::auth::Role::Admin), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let now = Utc::now().to_rfc3339();
    let outcome = state.setup.storage.with_connection(|connection| {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let source = store::load_version(&transaction, id, &VersionRef::Number(request.version))?;
        let Some(source) = source else {
            transaction.commit()?;
            return Ok(Err("VERSION_NOT_FOUND"));
        };
        if source.status == "active" {
            transaction.commit()?;
            return Ok(Err("VERSION_IS_ACTIVE"));
        }
        let existing = store::draft_row(&transaction, id)?;
        if existing.is_some() && !request.replace_draft {
            transaction.commit()?;
            return Ok(Err("DRAFT_EXISTS"));
        }
        if let Some((draft_id, _, _)) = existing {
            transaction.execute(
                "UPDATE policies SET status='retired',discarded_at=?2 WHERE id=?1",
                params![draft_id.to_string(), now],
            )?;
        }
        let content = store::stored_version_content(&source);
        let (draft_id, draft_version) = store::insert_draft(
            &transaction,
            id,
            "rollback",
            Some(&request.version.to_string()),
            Some(actor.user_id),
            &content,
            &now,
        )?;
        let draft_hash: String = transaction.query_row(
            "SELECT content_hash FROM policies WHERE id=?1",
            [draft_id.to_string()],
            |row| row.get(0),
        )?;
        store::journal_insert(
            &transaction,
            id,
            "human",
            Some(actor.user_id),
            "rollback",
            Some(draft_version),
            None,
            None,
            Some(json!({"from_version": request.version})),
            &now,
        )?;
        audit(
            &transaction,
            &actor,
            "setup.rollback_draft",
            id,
            Uuid::new_v4(),
            &now,
        )?;
        transaction.commit()?;
        Ok(Ok((draft_version, draft_hash)))
    });
    match outcome {
        Ok(Ok((version, hash))) => (
            StatusCode::CREATED,
            Json(json!({"draft_version": version, "draft_hash": hash})),
        )
            .into_response(),
        Ok(Err("DRAFT_EXISTS")) => {
            ApiError::conflict_code("DRAFT_EXISTS", "у базы уже есть черновик").into_response()
        }
        Ok(Err("VERSION_IS_ACTIVE")) => {
            ApiError::conflict_code("VERSION_IS_ACTIVE", "откат активной версии не имеет смысла")
                .into_response()
        }
        Ok(Err(_)) => {
            ApiError::not_found_code("VERSION_NOT_FOUND", "версия не найдена").into_response()
        }
        Err(error) => setup_storage_error("rollback_setup", &error),
    }
}

// ------------------------------------------------------------------
// B9: детальные причины записи истории (§6.3)
// ------------------------------------------------------------------

/// Подпись причины для UI (§6.3): встроенные коды — фиксированные
/// русские метки, прочие — сам `code`.
fn reason_label(entry: &Value) -> String {
    let code = entry["code"].as_str().unwrap_or_default();
    match entry["kind"].as_str() {
        _ if code == "secret:name" => "Секрет по имени поля (встроенное)".to_string(),
        _ if code == "secret:value" => "Секрет по значению (встроенное)".to_string(),
        _ if code.starts_with("mandatory:fio") => {
            "Обязательная маскировка ФИО (встроенное)".to_string()
        }
        _ if code.starts_with("unverified:") => {
            "Строгий режим: недоказуемое происхождение колонки".to_string()
        }
        Some("dictionary") => format!(
            "Словарь «{}»",
            entry["category"].as_str().unwrap_or_default()
        ),
        Some("rule") => format!(
            "Правило {} «{}»",
            entry["selector"].as_str().unwrap_or_default(),
            entry["pattern"].as_str().unwrap_or_default()
        ),
        _ if !code.is_empty() => code.to_string(),
        _ => "Причина маскирования".to_string(),
    }
}

/// Ссылка на элемент настройки в админке (§6.3 `link.admin_path`).
fn reason_link(database_id: Uuid, version: i64, entry: &Value) -> Value {
    let path = match entry["kind"].as_str() {
        Some("rule") => entry["rule_id"]
            .as_str()
            .map(|rule| format!("/admin#db={database_id}&tab=setup&rule={rule}&version={version}")),
        Some("dictionary") => entry["source_path"]
            .as_str()
            .or_else(|| entry["category"].as_str())
            .map(|source| {
                format!("/admin#db={database_id}&tab=setup&source={source}&version={version}")
            }),
        _ => None,
    };
    match path {
        Some(path) => json!({"admin_path": path}),
        None => Value::Null,
    }
}

pub(crate) async fn history_reasons(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    // Viewer — как reveal: роль + сессия, без Origin/CSRF (GET).
    if let Err(error) = authorize(&state, &headers, Some(crate::auth::Role::Viewer), false) {
        return error.into_response();
    }
    //++agent TASK-225 [26.09.2026] review: чтение записи ВНЕ with_connection —
    // history_reasons_record сам берёт тот же мьютекс, вложенный вызов
    // дедлочил бы единственное соединение (любой Viewer мог повесить сервис).
    let row = match state.setup.storage.history_reasons_record(id) {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::not_found_code("HISTORY_NOT_FOUND", "запись истории не найдена")
                .into_response();
        }
        Err(error) => {
            return setup_storage_error("history_reasons", &error);
        }
    };
    let outcome = state.setup.storage.with_connection(|connection| {
        let expired = row.expires_at <= Utc::now().to_rfc3339();
        if expired {
            return Ok(Err("HISTORY_EXPIRED"));
        }
        let policy_state: Option<String> = row.policy_id.and_then(|policy_id| {
            connection
                .query_row(
                    "SELECT status FROM policies WHERE id=?1",
                    [policy_id.to_string()],
                    |row| row.get(0),
                )
                .ok()
        });
        let active_version: Option<i64> = connection
            .query_row(
                "SELECT version FROM policies WHERE database_id=?1 AND status='active'",
                [row.database_id.to_string()],
                |row| row.get(0),
            )
            .ok();
        let Some(detail_text) = row.mask_detail_json else {
            let legacy: Vec<String> = row
                .mask_reasons_json
                .as_deref()
                .and_then(|text| serde_json::from_str(text).ok())
                .unwrap_or_default();
            return Ok(Ok(json!({
                "detailed": false,
                "legacy_reasons": legacy,
            })));
        };
        let detail: Value =
            serde_json::from_str(&detail_text).map_err(|_| rusqlite::Error::InvalidQuery)?;
        // Колонки блоков из сохранённого отчёта — col_idx → имя.
        let blocks: Vec<Vec<String>> = row.report["blocks"]
            .as_array()
            .map(|blocks| {
                blocks
                    .iter()
                    .map(|block| {
                        block["columns"]
                            .as_array()
                            .map(|columns| {
                                columns
                                    .iter()
                                    .filter_map(|col| col["id"].as_str().map(str::to_owned))
                                    .collect()
                            })
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Счётчики ячеек по индексу причины и группировка cells-ответа.
        let mut cells_per_reason: std::collections::HashMap<i64, u64> =
            std::collections::HashMap::new();
        let mut cells_out: std::collections::BTreeMap<(i64, i64, i64), Vec<i64>> =
            std::collections::BTreeMap::new();
        if let Some(cells) = detail["cells"].as_array() {
            for cell in cells {
                let block = cell[0].as_i64().unwrap_or(-1);
                let row_idx = cell[1].as_i64().unwrap_or(-1);
                let col = cell[2].as_i64().unwrap_or(-1);
                let reason_idx = cell[3].as_i64().unwrap_or(-1);
                *cells_per_reason.entry(reason_idx).or_default() += 1;
                cells_out
                    .entry((block, row_idx, col))
                    .or_default()
                    .push(reason_idx);
            }
        }
        let reasons: Vec<Value> = detail["reasons"]
            .as_array()
            .map(|reasons| {
                reasons
                    .iter()
                    .enumerate()
                    .map(|(idx, entry)| {
                        let mut map = serde_json::Map::new();
                        map.insert("idx".into(), (idx as i64).into());
                        map.insert("kind".into(), entry["kind"].clone());
                        map.insert("code".into(), entry["code"].clone());
                        if let Some(category) = entry.get("category") {
                            map.insert("category".into(), category.clone());
                        }
                        if let Some(rule_id) = entry.get("rule_id") {
                            map.insert("rule_id".into(), rule_id.clone());
                        }
                        if let Some(selector) = entry.get("selector") {
                            map.insert("selector".into(), selector.clone());
                        }
                        if let Some(pattern) = entry.get("pattern") {
                            map.insert("pattern".into(), pattern.clone());
                        }
                        if let Some(source_path) = entry.get("source_path") {
                            map.insert("source_path".into(), source_path.clone());
                        }
                        if let Some(action) = entry.get("action") {
                            map.insert("action".into(), action.clone());
                        }
                        map.insert("label".into(), reason_label(entry).into());
                        // §6.2: сохранённый агрегат reasons[].cells полный
                        // даже при truncated — предпочитаем его.
                        let cells_count = entry["cells"].as_u64().unwrap_or_else(|| {
                            cells_per_reason.get(&(idx as i64)).copied().unwrap_or(0)
                        });
                        map.insert("cells".into(), cells_count.into());
                        map.insert(
                            "link".into(),
                            reason_link(row.database_id, row.policy_version, entry),
                        );
                        Value::Object(map)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let cells: Vec<Value> = cells_out
            .iter()
            .map(|((block, row_idx, col), reasons)| {
                let mut map = serde_json::Map::new();
                map.insert("block".into(), (*block).into());
                if *row_idx >= 0 {
                    map.insert("row".into(), (*row_idx).into());
                }
                if *col >= 0 {
                    let column = blocks
                        .get(*block as usize)
                        .and_then(|cols| cols.get(*col as usize))
                        .cloned();
                    if let Some(column) = column {
                        map.insert("column".into(), column.into());
                    }
                } else {
                    map.insert("kind".into(), "text".into());
                }
                let mut sorted = reasons.clone();
                sorted.sort_unstable();
                sorted.dedup();
                map.insert("reasons".into(), sorted.into());
                Value::Object(map)
            })
            .collect();
        Ok(Ok(json!({
            "detailed": true,
            "policy_version": row.policy_version,
            "policy_state": policy_state,
            "active_version": active_version,
            "reasons": reasons,
            "cells": cells,
            "truncated": detail["truncated"].as_bool().unwrap_or(false),
        })))
    });
    match outcome {
        Ok(Ok(body)) => {
            let mut response = Json(body).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(Err("HISTORY_EXPIRED")) => ApiError::coded(
            StatusCode::GONE,
            "HISTORY_EXPIRED",
            "запись истории удалена по TTL",
            None,
        )
        .into_response(),
        Ok(Err(_)) => ApiError::unavailable().into_response(),
        Err(error) => setup_storage_error("history_reasons", &error),
    }
}

// ------------------------------------------------------------------
// B6: сухой прогон (§5)
// ------------------------------------------------------------------

pub(crate) async fn dry_run_setup(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<DryRunRequest>,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let actor = match authorize(&state, &headers, Some(crate::auth::Role::Admin), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let limit = request.limit.unwrap_or(50).clamp(1, 50);
    // Целевая версия → PolicySnapshot (правила + словарь активной RAM —
    // новые источники не загружены, §5.6).
    let Some(reference) = VersionRef::parse(&request.version) else {
        //++agent TASK-225 [26.09.2026] review MINOR-6: невалидный
        // version — ошибка клиента, а не отсутствие версии.
        return ApiError::bad_request("version: active|draft|номер").into_response();
    };
    let prepared = state.setup.storage.with_connection(|connection| {
        let version = store::load_version(connection, id, &reference)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let content = store::stored_version_content(&version);
        // Источники `to`, которых нет в статистике последнего pull —
        // честная оговорка UI «новые источники не учитываются».
        let stats = store::last_source_stats(connection, id)?.unwrap_or_default();
        let draft_sources: std::collections::HashSet<String> = content
            .dictionary
            .sources
            .iter()
            .map(|source| source.source_path.to_lowercase())
            .collect();
        let dictionary_not_loaded: Vec<String> = content
            .dictionary
            .sources
            .iter()
            .map(|source| source.source_path.to_lowercase())
            .filter(|path| !stats.contains_key(path))
            .collect();
        let new_estimates: std::collections::HashMap<String, i64> = content
            .dictionary
            .sources
            .iter()
            .filter(|source| !stats.contains_key(&source.source_path.to_lowercase()))
            .filter_map(|source| {
                source
                    .estimated_values
                    .map(|est| (source.source_path.to_lowercase(), est))
            })
            .collect();
        let snapshot = crate::domain::PolicySnapshot {
            version: version.version,
            rules: content
                .rules
                .iter()
                .filter(|rule| rule.enabled)
                .map(|rule| crate::domain::PolicyRule {
                    selector: match rule.selector.as_str() {
                        "source_path" => crate::domain::RuleSelector::SourcePath,
                        "name" => crate::domain::RuleSelector::Name,
                        "type" => crate::domain::RuleSelector::Type,
                        "dictionary" => crate::domain::RuleSelector::Dictionary,
                        _ => crate::domain::RuleSelector::Regex,
                    },
                    pattern: rule.value.clone(),
                    action: match rule.action.as_str() {
                        "secret" => crate::domain::RuleAction::Secret,
                        "keep" => crate::domain::RuleAction::Keep,
                        _ => crate::domain::RuleAction::Mask,
                    },
                    category: rule.category.clone(),
                    priority: rule.priority,
                    rule_id: rule
                        .rule_id
                        .as_deref()
                        .and_then(|id| Uuid::parse_str(id).ok()),
                })
                .collect(),
            // Словарь прогона — активный RAM (§5.6: новые источники
            // не загружены); словарь версии в файле не тащим.
            ..crate::domain::PolicySnapshot::default()
        };
        Ok::<_, rusqlite::Error>((
            version.version,
            snapshot,
            stats,
            draft_sources,
            dictionary_not_loaded,
            new_estimates,
        ))
    });
    let (version, mut snapshot, stats, draft_sources, dictionary_not_loaded, new_estimates) =
        match prepared {
            Ok(value) => value,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                //++agent TASK-225: отсутствие версии ≠ сбой хранилища.
                return if request.version == "draft" {
                    ApiError::conflict_code("NO_DRAFT", "у базы нет черновика").into_response()
                } else {
                    ApiError::not_found_code("VERSION_NOT_FOUND", "версия не найдена")
                        .into_response()
                };
            }
            Err(error) => return setup_storage_error("dry_run_setup", &error),
        };
    // RAM-словарь активного снимка — как у настоящей обработки.
    if let Some(active) = state.setup.masking.policy_snapshot_view(id).await {
        snapshot.dictionary = active.dictionary;
        //++agent TASK-225 [26.09.2026] D8: пути источников словаря —
        // причины сухого прогона несут source_path, как боевые (§5/§6.3).
        snapshot.dictionary_sources = active.dictionary_sources;
        //++agent TASK-225
        snapshot.dictionary_index = active.dictionary_index;
        snapshot.metadata_sources = active.metadata_sources;
    }
    let outcome = state
        .setup
        .masking
        .dry_run(id, &snapshot, &stats, &draft_sources, &new_estimates, limit)
        .await;
    //++agent TASK-225 [26.09.2026] review MINOR-15: §4 аудирует ВЫЗОВ
    // сухого прогона — включая пустой исход; сбои (busy/storage)
    // аудируются как ошибки сервиса, не как вызов.
    if outcome.is_ok() {
        let now = Utc::now().to_rfc3339();
        let _ = state.setup.storage.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            audit(
                &transaction,
                &actor,
                "setup.dry_run",
                id,
                Uuid::new_v4(),
                &now,
            )?;
            transaction.commit()
        });
    }
    match outcome {
        Ok(crate::domain::DryRunOutcome::Empty(reason)) => {
            Json(json!({"history_empty": true, "reason": reason})).into_response()
        }
        Ok(crate::domain::DryRunOutcome::Done(mut body)) => {
            body["version"] = version.into();
            body["dictionary_not_loaded"] = json!(dictionary_not_loaded);
            Json(body).into_response()
        }
        Err(error) if error.code == crate::domain::ErrorCode::DryRunBusy => {
            ApiError::conflict_code("DRY_RUN_BUSY", "сухой прогон уже выполняется").into_response()
        }
        Err(error) => setup_storage_error("dry_run_setup", &error),
    }
}

// ------------------------------------------------------------------
// B13: поля объекта метаданных (fields_of)
// ------------------------------------------------------------------

pub(crate) fn fields_of_view(state: &SetupService, database_id: Uuid, object: &str) -> Value {
    let view = state.masking.metadata_manifest_view(database_id, |items| {
        let prefix = format!("{object}.");
        items
            .iter()
            .filter(|item| item.source_path.starts_with(&prefix))
            .take(1_000)
            .map(|item| {
                json!({
                    "name": item.field_name,
                    "source_path": item.source_path,
                    "field_type": item.field_type,
                    "password_mode": item.password_mode,
                })
            })
            .collect::<Vec<_>>()
    });
    json!({
        "manifest_ready": view.is_some(),
        "object": object,
        "fields": view.map(|(_, fields)| fields).unwrap_or_default(),
    })
}
//++agent TASK-225
