mod handlers;
mod model;
mod sqlite;

use std::sync::Arc;

use axum::{
    routing::{get, patch, post},
    Router,
};

pub use model::{
    AdminDatabasePatch, ChatSummary, CreatePolicyRequest, DatabaseSummary, DictionaryConfig,
    DictionarySelectorConfig, HistoryItem, HumanDataError, HumanDataStore, NeutralBlock,
    NeutralColumn, NeutralReport, PolicyRuleInput, PolicySummary, ToolClassification,
    ToolClassificationPatch, UserAccessPatch,
};
pub use sqlite::SqliteHumanDataStore;

use crate::auth::{LocalAuthProvider, SessionService};

pub struct HumanState {
    pub auth: Arc<LocalAuthProvider>,
    pub sessions: Arc<SessionService>,
    pub data: Arc<dyn HumanDataStore>,
    /// Exact public HTTPS origin, for example `https://masking.example.test`.
    pub expected_origin: String,
}

pub fn router(state: Arc<HumanState>) -> Router {
    Router::new()
        .route("/auth/login", post(handlers::login))
        .route("/auth/logout", post(handlers::logout))
        .route("/auth/activate/{token}", post(handlers::activate))
        .route("/activate/{token}", get(handlers::activation_page))
        .route("/api/v1/session", get(handlers::current_session))
        .route("/api/v1/session/password", post(handlers::change_password))
        .route("/api/v1/databases", get(handlers::databases))
        .route("/api/v1/chats", get(handlers::chats))
        .route("/api/v1/history", get(handlers::history))
        .route("/api/v1/history/{id}/reveal", post(handlers::reveal))
        .route(
            "/api/v1/admin/users",
            get(handlers::users).post(handlers::create_user),
        )
        .route("/api/v1/admin/users/{id}", patch(handlers::update_user))
        .route("/api/v1/admin/databases", get(handlers::admin_databases))
        .route(
            "/api/v1/admin/databases/{id}",
            patch(handlers::update_database),
        )
        .route(
            "/api/v1/admin/databases/{id}/refresh",
            post(handlers::refresh_database),
        )
        .route(
            "/api/v1/admin/databases/{id}/tools",
            get(handlers::tool_classifications),
        )
        .route(
            "/api/v1/admin/databases/{id}/tools/{tool}",
            axum::routing::put(handlers::update_tool_classification),
        )
        .route(
            "/api/v1/admin/databases/{id}/dictionaries",
            get(handlers::dictionary_configs),
        )
        .route(
            "/api/v1/admin/databases/{id}/dictionaries/{config_id}",
            axum::routing::put(handlers::put_dictionary_config),
        )
        .route(
            "/api/v1/admin/databases/{id}/policies",
            get(handlers::policies).post(handlers::create_policy),
        )
        .route(
            "/api/v1/admin/databases/{id}/policies/{policy_id}/activate",
            post(handlers::activate_policy),
        )
        .route("/", get(handlers::index_page))
        .route("/viewer", get(handlers::viewer_page))
        .route("/admin", get(handlers::admin_page))
        .route("/human.js", get(handlers::javascript))
        .route("/human.css", get(handlers::stylesheet))
        .with_state(state)
}
