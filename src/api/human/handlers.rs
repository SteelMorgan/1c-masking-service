use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::auth::{
    ActivationError, AuthError, AuthProvider, ChangePasswordError, IssuedSession, LoginError,
    Principal, Role, UserStatus,
};

use super::{
    AdminDatabasePatch, CreatePolicyRequest, DictionaryConfig, HumanDataError, HumanState,
    ToolClassificationPatch, UserAccessPatch,
};

const SESSION_COOKIE: &str = "__Host-mask_session";
const GENERIC_LOGIN_MESSAGE: &str = "Неверные учетные данные или вход недоступен";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    login: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordRequest {
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    login: String,
    role: Role,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseQuery {
    database_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    database_id: Uuid,
    chat_id: String,
    limit: Option<u8>,
}

//++agent TASK-224 [24.09.2026]
/// `path` — уровень дерева ("" = корень); `q` — плоский поиск по имени/пути
/// (перекрывает path). Обе границы ограничены до разбора.
//--agent TASK-224
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataQuery {
    pub path: Option<String>,
    pub q: Option<String>,
    //++agent TASK-225 [26.09.2026] B13: плоский список полей объекта.
    pub fields_of: Option<String>,
    //++agent TASK-225
}

#[derive(Serialize)]
struct SessionResponse {
    user_id: Uuid,
    role: Role,
    //++agent TASK-224 [24.09.2026]
    // login — для подписи меню профиля; csrf_token выдаётся и существующей
    // сессии (Б11) — клиент больше не держит его в web storage.
    //--agent TASK-224
    login: String,
    csrf_token: String,
}

#[derive(Serialize)]
struct CreatedUserResponse {
    user_id: Uuid,
    login: String,
    role: Role,
    activation_token: String,
    //++agent TASK-224 [24.09.2026]
    // Б4: ссылку формирует сервер — он знает канонический origin
    // (MASKING_EXPECTED_ORIGIN), за прокси location.origin может отличаться.
    //--agent TASK-224
    activation_url: String,
    expires_in_seconds: u16,
}

#[derive(Serialize)]
struct UserResponse {
    user_id: Uuid,
    login: String,
    role: Role,
    status: UserStatus,
    activated: bool,
    //++agent TASK-224 [24.09.2026] Б7
    invitation_expires_at: Option<DateTime<Utc>>,
    last_login_at: Option<DateTime<Utc>>,
    //--agent TASK-224
}

//++agent TASK-224 [24.09.2026]
#[derive(Serialize)]
struct ActivationInfoResponse {
    login: String,
    expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct StatusResponse {
    bootstrap_required: bool,
    version: &'static str,
}
//--agent TASK-224

pub async fn login(
    State(state): State<Arc<HumanState>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    // The MVP listener is a Unix socket. The reverse proxy must additionally
    // enforce source-based limits; this key enforces the in-process login limit.
    let source = "human-endpoint".to_owned();
    let provider = state.auth.clone();
    let login = request.login;
    let password = request.password;
    let auth =
        tokio::task::spawn_blocking(move || provider.authenticate(&source, &login, &password))
            .await;
    let principal = match auth {
        Ok(Ok(principal)) => principal,
        Ok(Err(LoginError::RateLimited)) => return ApiError::rate_limited().into_response(),
        Ok(Err(LoginError::Rejected | LoginError::Unavailable)) | Err(_) => {
            return ApiError::unauthorized().into_response();
        }
    };
    let issued = match state.sessions.issue(principal, Utc::now()) {
        Ok(value) => value,
        Err(_) => return ApiError::unavailable().into_response(),
    };
    session_response(&state, issued)
}

fn session_response(state: &HumanState, issued: IssuedSession) -> Response {
    let cookie_token = issued.token;
    //++agent TASK-224 [24.09.2026]
    let login = state
        .auth
        .display_login(issued.principal.user_id)
        .ok()
        .flatten()
        .unwrap_or_default();
    //--agent TASK-224
    let mut response = Json(SessionResponse {
        user_id: issued.principal.user_id,
        role: issued.principal.role,
        login,
        csrf_token: issued.csrf_token,
    })
    .into_response();
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict",
        cookie_token
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn logout(State(state): State<Arc<HumanState>>, headers: HeaderMap) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let Some(token) = session_cookie(&headers) else {
        return ApiError::unauthorized().into_response();
    };
    if authorize(&state, &headers, None, true).is_err() {
        return ApiError::unauthorized().into_response();
    }
    if state.sessions.revoke(token, Utc::now()).is_err() {
        return ApiError::unavailable().into_response();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-mask_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict",
        ),
    );
    response
}

//++agent TASK-224 [24.09.2026]
/// Б2: предпроверка кода приглашения — показывает логин и срок до ввода пароля.
/// GET без побочных эффектов; generic 400 не различает «истёк/использован/нет».
pub async fn activation_info(
    State(state): State<Arc<HumanState>>,
    Path(token): Path<String>,
) -> Response {
    if token.is_empty() || token.len() > 128 {
        return ApiError::invalid_activation().into_response();
    }
    //++agent TASK-224 [25.09.2026] ревью R3: ответ отдаёт логин по ссылке —
    // no-store, чтобы кэш прокси/браузера не сохранял его вместе с токеном
    // в URL.
    let mut response = match state.auth.pending_activation(&token) {
        Ok(Some(pending)) => Json(ActivationInfoResponse {
            login: pending.display_login,
            expires_at: pending.expires_at,
        })
        .into_response(),
        Ok(None) => ApiError::invalid_activation().into_response(),
        Err(_) => ApiError::unavailable().into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
    //--agent TASK-224
}

/// Б9: публичный признак незавершённого bootstrap — раскрывает только факт,
/// допустимо по дизайну (экран «Сервис ещё не настроен»).
pub async fn service_status(State(state): State<Arc<HumanState>>) -> Response {
    match state.auth.bootstrap_pending() {
        Ok(pending) => Json(StatusResponse {
            bootstrap_required: pending,
            version: env!("CARGO_PKG_VERSION"),
        })
        .into_response(),
        Err(_) => ApiError::unavailable().into_response(),
    }
}
//--agent TASK-224

pub async fn activate(
    State(state): State<Arc<HumanState>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PasswordRequest>,
) -> Response {
    let csrf_matches = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|csrf| {
            csrf.len() == token.len() && bool::from(csrf.as_bytes().ct_eq(token.as_bytes()))
        });
    if !same_origin(&headers, &state.expected_origin) || !csrf_matches || token.len() > 128 {
        return ApiError::forbidden().into_response();
    }
    let provider = state.auth.clone();
    //++agent TASK-224 [24.09.2026]
    // Б10: rate limit внутри provider (ключ activation\0human-endpoint);
    // Б8: PASSWORD_POLICY отдельно от недействительного кода;
    // Б3: успех сразу выдаёт сессию (автовход).
    let result = tokio::task::spawn_blocking(move || {
        provider.activate("human-endpoint", &token, &request.password)
    })
    .await;
    let principal = match result {
        Ok(Ok(principal)) => principal,
        Ok(Err(ActivationError::RateLimited)) => return ApiError::rate_limited().into_response(),
        Ok(Err(ActivationError::PasswordPolicy)) => {
            return ApiError::password_policy().into_response()
        }
        Ok(Err(ActivationError::Invalid)) => return ApiError::invalid_activation().into_response(),
        Ok(Err(ActivationError::Unavailable)) | Err(_) => {
            return ApiError::unavailable().into_response()
        }
    };
    let issued = match state.sessions.issue(principal, Utc::now()) {
        Ok(value) => value,
        Err(_) => return ApiError::unavailable().into_response(),
    };
    session_response(&state, issued)
    //--agent TASK-224
}

pub async fn current_session(State(state): State<Arc<HumanState>>, headers: HeaderMap) -> Response {
    //++agent TASK-224 [24.09.2026]
    // Б11: существующая сессия получает свой CSRF — тот же, что при login,
    // благодаря детерминированному выводу из session token.
    let Some(token) = session_cookie(&headers) else {
        return ApiError::unauthorized().into_response();
    };
    match authorize(&state, &headers, None, false) {
        Ok(principal) => {
            let login = state
                .auth
                .display_login(principal.user_id)
                .ok()
                .flatten()
                .unwrap_or_default();
            let mut response = Json(SessionResponse {
                user_id: principal.user_id,
                role: principal.role,
                login,
                csrf_token: state.sessions.csrf_for_session_token(token),
            })
            .into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => error.into_response(),
    }
    //--agent TASK-224
}

pub async fn change_password(
    State(state): State<Arc<HumanState>>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let principal = match authorize(&state, &headers, None, true) {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let provider = state.auth.clone();
    let correlation_id = Uuid::new_v4();
    let changed = tokio::task::spawn_blocking(move || {
        provider.change_password(
            "human-endpoint",
            &principal,
            &request.current_password,
            &request.new_password,
            correlation_id,
        )
    })
    .await;
    let principal = match changed {
        Ok(Ok(principal)) => principal,
        Ok(Err(ChangePasswordError::RateLimited)) => {
            return ApiError::rate_limited().into_response()
        }
        Ok(Err(ChangePasswordError::Rejected)) => return ApiError::unauthorized().into_response(),
        Ok(Err(ChangePasswordError::InvalidNewPassword)) => {
            return ApiError::password_policy().into_response()
        }
        Ok(Err(ChangePasswordError::Unavailable)) | Err(_) => {
            return ApiError::unavailable().into_response()
        }
    };

    // Issuing only after atomic revocation guarantees that the response cannot
    // accidentally preserve the pre-change authentication epoch.
    let issued = match state.sessions.issue(principal, Utc::now()) {
        Ok(issued) => issued,
        Err(_) => return ApiError::unavailable().into_response(),
    };
    session_response(&state, issued)
}

pub async fn databases(State(state): State<Arc<HumanState>>, headers: HeaderMap) -> Response {
    if let Err(error) = authorize(&state, &headers, Some(Role::Viewer), false) {
        return error.into_response();
    }
    match state.data.list_databases() {
        Ok(value) => Json(value).into_response(),
        Err(error) => data_error(error).into_response(),
    }
}

pub async fn admin_databases(State(state): State<Arc<HumanState>>, headers: HeaderMap) -> Response {
    if let Err(error) = authorize(&state, &headers, Some(Role::Admin), false) {
        return error.into_response();
    }
    match state.data.list_databases() {
        Ok(value) => Json(value).into_response(),
        Err(error) => data_error(error).into_response(),
    }
}

pub async fn chats(
    State(state): State<Arc<HumanState>>,
    headers: HeaderMap,
    Query(query): Query<DatabaseQuery>,
) -> Response {
    if let Err(error) = authorize(&state, &headers, Some(Role::Viewer), false) {
        return error.into_response();
    }
    match state.data.list_chats(query.database_id) {
        Ok(value) => Json(value).into_response(),
        Err(error) => data_error(error).into_response(),
    }
}

pub async fn history(
    State(state): State<Arc<HumanState>>,
    headers: HeaderMap,
    Query(query): Query<HistoryQuery>,
) -> Response {
    if let Err(error) = authorize(&state, &headers, Some(Role::Viewer), false) {
        return error.into_response();
    }
    let limit = query.limit.unwrap_or(50);
    if !(30..=50).contains(&limit) {
        return ApiError::bad_request("limit должен находиться в диапазоне 30..50").into_response();
    }
    match state
        .data
        .list_history(query.database_id, &query.chat_id, limit)
    {
        Ok(value) if value.iter().all(|item| item.report.is_safe()) => Json(value).into_response(),
        Ok(_) => ApiError::unavailable().into_response(),
        Err(error) => data_error(error).into_response(),
    }
}

pub async fn reveal(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let principal = match authorize(&state, &headers, Some(Role::Viewer), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    //++agent TASK-224 [24.09.2026] итерация 3: reveal без audit-события
    // (автоматический при открытии записи) — correlation_id не нужен.
    match state.data.reveal_history(&principal, id).await {
        Ok(report) if report.is_safe() => {
            let mut response = Json(report).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(_) => ApiError::unavailable().into_response(),
        Err(error) => data_error(error).into_response(),
    }
}

pub async fn users(State(state): State<Arc<HumanState>>, headers: HeaderMap) -> Response {
    if let Err(error) = authorize(&state, &headers, Some(Role::Admin), false) {
        return error.into_response();
    }
    match state.auth.list_users() {
        //++agent TASK-224 [24.09.2026] Б7: агрегаты приглашения и входа.
        Ok(users) => Json(
            users
                .into_iter()
                .map(|entry| UserResponse {
                    user_id: entry.account.id,
                    login: entry.account.display_login,
                    role: entry.account.role,
                    status: entry.account.status,
                    activated: entry.account.password_hash.is_some(),
                    invitation_expires_at: entry.invitation_expires_at,
                    last_login_at: entry.last_login_at,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        //--agent TASK-224
        Err(_) => ApiError::unavailable().into_response(),
    }
}

pub async fn create_user(
    State(state): State<Arc<HumanState>>,
    headers: HeaderMap,
    Json(request): Json<CreateUserRequest>,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let actor = match authorize(&state, &headers, Some(Role::Admin), true) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    match state
        .auth
        .create_user(&actor, &request.login, request.role, Uuid::new_v4())
    {
        //++agent TASK-224 [24.09.2026] Б4: ссылка собирается на сервере.
        Ok((user, activation_token)) => (
            StatusCode::CREATED,
            Json(CreatedUserResponse {
                user_id: user.id,
                login: user.display_login,
                role: user.role,
                activation_url: activation_url(&state.expected_origin, &activation_token),
                activation_token,
                expires_in_seconds: 900,
            }),
        )
            .into_response(),
        //--agent TASK-224
        Err(_) => ApiError::conflict().into_response(),
    }
}

//++agent TASK-224 [24.09.2026]
/// Б1: перевыпуск приглашения для «ожидающего» пользователя — старые коды
/// гасятся в той же транзакции, ответ идентичен созданию пользователя.
pub async fn reissue_invitation(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let actor = match admin_mutation(&state, &headers) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    match state.auth.reissue_invitation(&actor, id, Uuid::new_v4()) {
        Ok((user, token)) => (
            StatusCode::CREATED,
            Json(CreatedUserResponse {
                user_id: user.id,
                login: user.display_login,
                role: user.role,
                activation_url: activation_url(&state.expected_origin, &token),
                activation_token: token,
                expires_in_seconds: 900,
            }),
        )
            .into_response(),
        //++agent TASK-224 [08.10.2026] итерация 4: disabled — явный 409
        // USER_DISABLED; карточка UI не должна выдавать приглашение от
        // несохранённого/отключённого состояния.
        Err(AuthError::UserDisabled) => ApiError::conflict_code(
            "USER_DISABLED",
            "Пользователь отключён — сначала включите его и сохраните",
        )
        .into_response(),
        //--agent TASK-224
        Err(_) => ApiError::conflict().into_response(),
    }
}

/// Б5: сброс пароля администратором — пароль обнуляется, сессии отзываются,
/// выдаётся свежее приглашение (ответ идентичен созданию пользователя).
pub async fn reset_user_password(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let actor = match admin_mutation(&state, &headers) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    match state.auth.reset_user_password(&actor, id, Uuid::new_v4()) {
        Ok((user, token)) => (
            StatusCode::CREATED,
            Json(CreatedUserResponse {
                user_id: user.id,
                login: user.display_login,
                role: user.role,
                activation_url: activation_url(&state.expected_origin, &token),
                activation_token: token,
                expires_in_seconds: 900,
            }),
        )
            .into_response(),
        Err(AuthError::UserDisabled) => ApiError::conflict_code(
            "USER_DISABLED",
            "Пользователь отключён — сначала включите его и сохраните",
        )
        .into_response(),
        Err(_) => ApiError::conflict().into_response(),
    }
}

/// Б6: удаление «никогда не входившего» пользователя освобождает логин.
pub async fn delete_user(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let actor = match admin_mutation(&state, &headers) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    match state.auth.delete_user(&actor, id, Uuid::new_v4()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => ApiError::conflict().into_response(),
    }
}

fn activation_url(origin: &str, token: &str) -> String {
    format!("{}/activate/{token}", origin.trim_end_matches('/'))
}
//--agent TASK-224

pub async fn update_user(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UserAccessPatch>,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let actor = match authorize(&state, &headers, Some(Role::Admin), true) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    match state
        .auth
        .update_user_access(&actor, id, request.role, request.status, Uuid::new_v4())
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => ApiError::conflict().into_response(),
    }
}

pub async fn update_database(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(patch): Json<AdminDatabasePatch>,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let principal = match authorize(&state, &headers, Some(Role::Admin), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if !valid_database_patch(&patch) {
        return ApiError::bad_request("Некорректные параметры базы").into_response();
    }
    match state
        .data
        .update_database(&principal, id, patch, Uuid::new_v4())
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => data_error(error).into_response(),
    }
}

pub async fn refresh_database(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers, &state.expected_origin) {
        return ApiError::forbidden().into_response();
    }
    let principal = match authorize(&state, &headers, Some(Role::Admin), true) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    match state.data.refresh_database(&principal, id, Uuid::new_v4()) {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => data_error(error).into_response(),
    }
}

//++agent TASK-224 [24.09.2026]
/// Ленивое дерево метаданных для вкладки «Справочники» (только чтение,
/// Admin; CSRF не нужен). Границы длины — до обращения к store.
//--agent TASK-224
pub async fn database_metadata(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<MetadataQuery>,
) -> Response {
    if let Err(e) = authorize(&state, &headers, Some(Role::Admin), false) {
        return e.into_response();
    }
    let path = query.path.unwrap_or_default();
    let q = query
        .q
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty());
    //++agent TASK-225 [26.09.2026] B13: fields_of=<Класс.Объект> —
    // плоский список полей для редактора фильтров (≤512 символов).
    if let Some(object) = query.fields_of {
        if object.len() > 512 {
            return ApiError::bad_request("fields_of длиннее 512 символов").into_response();
        }
        return Json(super::setup::fields_of_view(&state.setup, id, &object)).into_response();
    }
    //++agent TASK-225
    if path.len() > 512 || q.as_deref().is_some_and(|v| v.len() > 128) {
        return ApiError::bad_request("Слишком длинный path или q").into_response();
    }
    match state.data.metadata_nodes(id, &path, q.as_deref()) {
        Ok(page) => Json(page).into_response(),
        Err(e) => data_error(e).into_response(),
    }
}

pub async fn tool_classifications(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&state, &headers, Some(Role::Admin), false) {
        return e.into_response();
    }
    match state.data.list_tool_classifications(id) {
        Ok(v) => Json(v).into_response(),
        Err(e) => data_error(e).into_response(),
    }
}

pub async fn update_tool_classification(
    State(state): State<Arc<HumanState>>,
    Path((id, tool)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Json(patch): Json<ToolClassificationPatch>,
) -> Response {
    let actor = match admin_mutation(&state, &headers) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match state
        .data
        .update_tool_classification(&actor, id, &tool, patch, Uuid::new_v4())
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => data_error(e).into_response(),
    }
}

//++agent TASK-225 [26.09.2026]
// DELETE — снятие записи классификации (инструмент, снятый из 1С,
// не должен вечно висеть в админке). Только Admin + CSRF, аудит
// tool.delete в той же транзакции, что и DELETE.
//++agent TASK-225
pub async fn delete_tool_classification(
    State(state): State<Arc<HumanState>>,
    Path((id, tool)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Response {
    let actor = match admin_mutation(&state, &headers) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match state
        .data
        .delete_tool_classification(&actor, id, &tool, Uuid::new_v4())
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => data_error(e).into_response(),
    }
}

pub async fn dictionary_configs(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&state, &headers, Some(Role::Admin), false) {
        return e.into_response();
    }
    match state.data.list_dictionary_configs(id) {
        Ok(v) => Json(v).into_response(),
        Err(e) => data_error(e).into_response(),
    }
}

pub async fn put_dictionary_config(
    State(state): State<Arc<HumanState>>,
    Path((id, config_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(mut config): Json<DictionaryConfig>,
) -> Response {
    let actor = match admin_mutation(&state, &headers) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    config.id = config_id;
    //++agent TASK-225 [26.09.2026] M-4: правка идёт в черновик —
    // ответ прежний по коду, плюс номер версии черновика (spec §4).
    match state
        .data
        .put_dictionary_config(&actor, id, config, Uuid::new_v4())
    {
        Ok(draft_version) => Json(serde_json::json!({
            "draft_version": draft_version,
        }))
        .into_response(),
        Err(e) => data_error(e).into_response(),
    }
    //++agent TASK-225
}

pub async fn policies(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&state, &headers, Some(Role::Admin), false) {
        return e.into_response();
    }
    match state.data.list_policies(id) {
        Ok(v) => Json(v).into_response(),
        Err(e) => data_error(e).into_response(),
    }
}

pub async fn create_policy(
    State(state): State<Arc<HumanState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreatePolicyRequest>,
) -> Response {
    let actor = match admin_mutation(&state, &headers) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match state
        .data
        .create_policy(&actor, id, request, Uuid::new_v4())
    {
        Ok(v) => (StatusCode::CREATED, Json(v)).into_response(),
        Err(e) => data_error(e).into_response(),
    }
}

pub async fn activate_policy(
    State(state): State<Arc<HumanState>>,
    Path((id, policy_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Response {
    let actor = match admin_mutation(&state, &headers) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match state
        .data
        .activate_policy(&actor, id, policy_id, Uuid::new_v4())
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => data_error(e).into_response(),
    }
}

pub(crate) fn admin_mutation(
    state: &HumanState,
    headers: &HeaderMap,
) -> Result<Principal, ApiError> {
    if !same_origin(headers, &state.expected_origin) {
        return Err(ApiError::forbidden());
    }
    authorize(state, headers, Some(Role::Admin), true)
}

pub(crate) fn authorize(
    state: &HumanState,
    headers: &HeaderMap,
    required_role: Option<Role>,
    require_csrf: bool,
) -> Result<Principal, ApiError> {
    let token = session_cookie(headers).ok_or_else(ApiError::unauthorized)?;
    let csrf = if require_csrf {
        Some(
            headers
                .get("x-csrf-token")
                .and_then(|value| value.to_str().ok())
                .ok_or_else(ApiError::forbidden)?,
        )
    } else {
        None
    };
    let principal = state
        .sessions
        .validate(token, csrf, Utc::now())
        .map_err(|_| ApiError::unauthorized())?;
    if required_role.is_some_and(|role| principal.role != role) {
        return Err(ApiError::forbidden());
    }
    Ok(principal)
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (name == SESSION_COOKIE && !value.is_empty()).then_some(value)
        })
}

pub(crate) fn same_origin(headers: &HeaderMap, expected_origin: &str) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin == expected_origin)
}

fn valid_database_patch(patch: &AdminDatabasePatch) -> bool {
    patch
        .mode
        .as_deref()
        .is_none_or(|mode| matches!(mode, "enabled" | "disabled"))
        && patch.mapping_ttl_seconds.is_none_or(|ttl| ttl > 0)
        && patch.history_ttl_seconds.is_none_or(|ttl| ttl > 0)
        //++agent TASK-224 [24.09.2026] display_label: не длиннее 128 символов,
        // без управляющих символов (unicode-невидимые допустимы — имя базы
        // отображаемое, а не идентификатор).
        //--agent TASK-224
        && patch.display_label.as_ref().is_none_or(|label| {
            label.as_ref().is_none_or(|value| {
                let value = value.trim();
                value.chars().count() <= 128 && !value.chars().any(char::is_control)
            })
        })
}

pub(crate) fn data_error(error: HumanDataError) -> ApiError {
    match error {
        HumanDataError::NotFound => ApiError::not_found(),
        HumanDataError::MappingUnavailable => {
            ApiError::conflict_code("MAPPING_UNAVAILABLE", "Соответствие недоступно")
        }
        HumanDataError::Conflict => ApiError::conflict(),
        //++agent TASK-221 2026-09-23
        HumanDataError::SecretPolicyUnsupported => ApiError::conflict_code(
            "SECRET_POLICY_UNSUPPORTED",
            "Secret-правила недоступны до включения предменеджерной защиты",
        ),
        //--agent TASK-221
        //++agent TASK-225 [26.09.2026]
        HumanDataError::DraftExists => ApiError::conflict_code(
            "DRAFT_EXISTS",
            "Черновик настройки уже существует — правьте его или удалите",
        ),
        //++agent TASK-225 [26.09.2026] §4 legacy-activate: 409 + ids.
        HumanDataError::WeakeningNotConfirmed(missing) => ApiError::coded(
            StatusCode::CONFLICT,
            "WEAKENING_NOT_CONFIRMED",
            "ослабления требуют явного подтверждения",
            Some(serde_json::json!({"missing": missing})),
        ),
        //++agent TASK-225
        HumanDataError::BypassNotConfirmed => ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "BYPASS_NOT_CONFIRMED",
            message:
                "Режим «без маскирования» (no-mask) требует явного подтверждения (confirm_bypass)",
            details: None,
        },
        //++agent TASK-225
        HumanDataError::Unavailable => ApiError::unavailable(),
    }
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
    correlation_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    details: Option<serde_json::Value>,
}

impl ApiError {
    //++agent TASK-225 [26.09.2026]
    /// Произвольный код/статус и details — ошибки setup API (§4)
    /// несут структурные payloads (`missing`, `unknown`, `errors` …).
    pub(crate) fn coded(
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        details: Option<serde_json::Value>,
    ) -> Self {
        Self {
            status,
            code,
            message,
            details,
        }
    }

    pub(crate) fn not_found_code(code: &'static str, message: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code,
            message,
            details: None,
        }
    }
    //++agent TASK-225

    pub(crate) fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "AUTHENTICATION_FAILED",
            message: GENERIC_LOGIN_MESSAGE,
            details: None,
        }
    }
    pub(crate) fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "FORBIDDEN",
            message: "Операция запрещена",
            details: None,
        }
    }
    pub(crate) fn rate_limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "AUTHENTICATION_FAILED",
            message: GENERIC_LOGIN_MESSAGE,
            details: None,
        }
    }
    pub(crate) fn invalid_activation() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "ACTIVATION_FAILED",
            message: "Активация недоступна",
            details: None,
        }
    }
    pub(crate) fn password_policy() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "PASSWORD_POLICY",
            message: "Новый пароль должен содержать от 12 до 1024 символов",
            details: None,
        }
    }
    pub(crate) fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_REQUEST",
            message,
            details: None,
        }
    }
    pub(crate) fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "NOT_FOUND",
            message: "Запись не найдена",
            details: None,
        }
    }
    pub(crate) fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "CONFLICT",
            message: "Операция недоступна в текущем состоянии",
            details: None,
        }
    }
    pub(crate) fn conflict_code(code: &'static str, message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message,
            details: None,
        }
    }
    pub(crate) fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "SERVICE_NOT_READY",
            message: "Операция временно недоступна",
            details: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code: self.code,
                    message: self.message,
                    correlation_id: Uuid::new_v4(),
                    details: self.details,
                },
            }),
        )
            .into_response()
    }
}

//++agent TASK-224 [24.09.2026]
// Б12: рабочие страницы не отдаются без живой сессии — редирект на вход;
// при чужой роли — в свой раздел. Стартовая страница при живой сессии
// наоборот уводит в раздел (форма входа не показывается).
fn session_principal(state: &HumanState, headers: &HeaderMap) -> Option<Principal> {
    let token = session_cookie(headers)?;
    state.sessions.validate(token, None, Utc::now()).ok()
}

fn role_home(role: Role) -> &'static str {
    match role {
        Role::Viewer => "/viewer",
        Role::Admin => "/admin",
    }
}

pub async fn index_page(State(state): State<Arc<HumanState>>, headers: HeaderMap) -> Response {
    if let Some(principal) = session_principal(&state, &headers) {
        return Redirect::to(role_home(principal.role)).into_response();
    }
    static_response(
        "text/html; charset=utf-8",
        include_str!("../../../web/index.html"),
    )
}

pub async fn viewer_page(State(state): State<Arc<HumanState>>, headers: HeaderMap) -> Response {
    match session_principal(&state, &headers) {
        Some(principal) if principal.role == Role::Viewer => static_response(
            "text/html; charset=utf-8",
            include_str!("../../../web/viewer.html"),
        ),
        Some(principal) => Redirect::to(role_home(principal.role)).into_response(),
        None => Redirect::to("/").into_response(),
    }
}

pub async fn admin_page(State(state): State<Arc<HumanState>>, headers: HeaderMap) -> Response {
    match session_principal(&state, &headers) {
        Some(principal) if principal.role == Role::Admin => static_response(
            "text/html; charset=utf-8",
            include_str!("../../../web/admin.html"),
        ),
        Some(principal) => Redirect::to(role_home(principal.role)).into_response(),
        None => Redirect::to("/").into_response(),
    }
}
//--agent TASK-224

pub async fn activation_page() -> Response {
    static_response(
        "text/html; charset=utf-8",
        include_str!("../../../web/activate.html"),
    )
}

//++agent TASK-224 [24.09.2026] Б12: новые файлы UI; favicon — 204 без тела.
pub async fn javascript() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../../../web/app.js"),
    )
}

pub async fn grid_javascript() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../../../web/grid.js"),
    )
}

pub async fn stylesheet() -> Response {
    static_response(
        "text/css; charset=utf-8",
        include_str!("../../../web/app.css"),
    )
}

pub async fn favicon() -> Response {
    StatusCode::NO_CONTENT.into_response()
}
//--agent TASK-224

fn static_response(content_type: &'static str, body: &'static str) -> Response {
    let mut response = if content_type.starts_with("text/html") {
        Html(body).into_response()
    } else {
        body.into_response()
    };
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    //++agent TASK-224 [25.09.2026 09:00:00] статика вшита в бинарь: без
    // no-cache браузер держит прежние app.css/app.js после обновления сервиса.
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    //++agent TASK-224
    response
}
