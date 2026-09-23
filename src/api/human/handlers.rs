use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::auth::{
    AuthProvider, ChangePasswordError, IssuedSession, LoginError, Principal, Role, UserStatus,
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

#[derive(Serialize)]
struct SessionResponse {
    user_id: Uuid,
    role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    csrf_token: Option<String>,
}

#[derive(Serialize)]
struct CreatedUserResponse {
    user_id: Uuid,
    login: String,
    role: Role,
    activation_token: String,
    expires_in_seconds: u16,
}

#[derive(Serialize)]
struct UserResponse {
    user_id: Uuid,
    login: String,
    role: Role,
    status: UserStatus,
    activated: bool,
}

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
    session_response(issued)
}

fn session_response(issued: IssuedSession) -> Response {
    let cookie_token = issued.token;
    let mut response = Json(SessionResponse {
        user_id: issued.principal.user_id,
        role: issued.principal.role,
        csrf_token: Some(issued.csrf_token),
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
    let result =
        tokio::task::spawn_blocking(move || provider.activate(&token, &request.password)).await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(_)) => ApiError::invalid_activation().into_response(),
        Err(_) => ApiError::unavailable().into_response(),
    }
}

pub async fn current_session(State(state): State<Arc<HumanState>>, headers: HeaderMap) -> Response {
    match authorize(&state, &headers, None, false) {
        Ok(principal) => Json(SessionResponse {
            user_id: principal.user_id,
            role: principal.role,
            csrf_token: None,
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
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
    session_response(issued)
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
    let correlation_id = Uuid::new_v4();
    match state
        .data
        .reveal_history(&principal, id, correlation_id)
        .await
    {
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
        Ok(users) => Json(
            users
                .into_iter()
                .map(|user| UserResponse {
                    user_id: user.id,
                    login: user.display_login,
                    role: user.role,
                    status: user.status,
                    activated: user.password_hash.is_some(),
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
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
        Ok((user, activation_token)) => (
            StatusCode::CREATED,
            Json(CreatedUserResponse {
                user_id: user.id,
                login: user.display_login,
                role: user.role,
                activation_token,
                expires_in_seconds: 900,
            }),
        )
            .into_response(),
        Err(_) => ApiError::conflict().into_response(),
    }
}

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
    match state
        .data
        .put_dictionary_config(&actor, id, config, Uuid::new_v4())
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => data_error(e).into_response(),
    }
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

fn admin_mutation(state: &HumanState, headers: &HeaderMap) -> Result<Principal, ApiError> {
    if !same_origin(headers, &state.expected_origin) {
        return Err(ApiError::forbidden());
    }
    authorize(state, headers, Some(Role::Admin), true)
}

fn authorize(
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

fn same_origin(headers: &HeaderMap, expected_origin: &str) -> bool {
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
}

fn data_error(error: HumanDataError) -> ApiError {
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
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "AUTHENTICATION_FAILED",
            message: GENERIC_LOGIN_MESSAGE,
        }
    }
    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "FORBIDDEN",
            message: "Операция запрещена",
        }
    }
    fn rate_limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "AUTHENTICATION_FAILED",
            message: GENERIC_LOGIN_MESSAGE,
        }
    }
    fn invalid_activation() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "ACTIVATION_FAILED",
            message: "Активация недоступна",
        }
    }
    fn password_policy() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "PASSWORD_POLICY",
            message: "Новый пароль должен содержать от 12 до 1024 символов",
        }
    }
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_REQUEST",
            message,
        }
    }
    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "NOT_FOUND",
            message: "Запись не найдена",
        }
    }
    fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "CONFLICT",
            message: "Операция недоступна в текущем состоянии",
        }
    }
    fn conflict_code(code: &'static str, message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message,
        }
    }
    fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "SERVICE_NOT_READY",
            message: "Операция временно недоступна",
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
                },
            }),
        )
            .into_response()
    }
}

pub async fn index_page() -> Response {
    static_response(
        "text/html; charset=utf-8",
        include_str!("../../../web/index.html"),
    )
}

pub async fn viewer_page() -> Response {
    static_response(
        "text/html; charset=utf-8",
        include_str!("../../../web/viewer.html"),
    )
}

pub async fn admin_page() -> Response {
    static_response(
        "text/html; charset=utf-8",
        include_str!("../../../web/admin.html"),
    )
}

pub async fn activation_page() -> Response {
    static_response(
        "text/html; charset=utf-8",
        include_str!("../../../web/activate.html"),
    )
}

pub async fn javascript() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../../../web/human.js"),
    )
}

pub async fn stylesheet() -> Response {
    static_response(
        "text/css; charset=utf-8",
        include_str!("../../../web/human.css"),
    )
}

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
    response
}
