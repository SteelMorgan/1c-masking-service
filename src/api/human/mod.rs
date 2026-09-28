mod handlers;
mod model;
//++agent TASK-225 [26.09.2026] §4: версионированная настройка (B3-B13).
pub mod setup;
//++agent TASK-225
mod sqlite;

use std::sync::Arc;

use axum::{
    routing::{get, patch, post},
    Router,
};

pub use model::{
    AdminDatabasePatch, CreatePolicyRequest, DatabaseSummary, DictionaryConfig,
    DictionaryConfigView, DictionarySelectorConfig, DictionarySelectorView, HistoryItem,
    HumanDataError, HumanDataStore, MetadataNode, MetadataNodesPage, NeutralBlock, NeutralColumn,
    NeutralReport, PolicyRuleInput, PolicySummary, ToolClassification, ToolClassificationPatch,
    UserAccessPatch,
};
pub use sqlite::SqliteHumanDataStore;

use crate::auth::{LocalAuthProvider, SessionService};

pub struct HumanState {
    pub auth: Arc<LocalAuthProvider>,
    pub sessions: Arc<SessionService>,
    pub data: Arc<dyn HumanDataStore>,
    /// Exact public HTTPS origin, for example `https://masking.example.test`.
    pub expected_origin: String,
    //++agent TASK-225 [26.09.2026]
    /// §4: версионированная настройка — конкретный фасад (транзакции +
    /// RAM-снимки), не входит в dyn HumanDataStore.
    //++agent TASK-225
    pub setup: setup::SetupService,
}

pub fn router(state: Arc<HumanState>) -> Router {
    Router::new()
        .route("/auth/login", post(handlers::login))
        .route("/auth/logout", post(handlers::logout))
        //++agent TASK-224 [24.09.2026]
        // Б2: GET /auth/activate/{token} — предпроверка кода (логин и срок).
        //--agent TASK-224
        .route(
            "/auth/activate/{token}",
            get(handlers::activation_info).post(handlers::activate),
        )
        .route("/activate/{token}", get(handlers::activation_page))
        //++agent TASK-224 [24.09.2026] Б9: публичный статус инициализации.
        .route("/api/v1/status", get(handlers::service_status))
        //--agent TASK-224
        .route("/api/v1/session", get(handlers::current_session))
        .route("/api/v1/session/password", post(handlers::change_password))
        .route("/api/v1/databases", get(handlers::databases))
        .route("/api/v1/history", get(handlers::history))
        .route("/api/v1/history/{id}/reveal", post(handlers::reveal))
        .route(
            "/api/v1/admin/users",
            get(handlers::users).post(handlers::create_user),
        )
        //++agent TASK-224 [24.09.2026]
        // Б1 перевыпуск, Б5 сброс пароля, Б6 удаление пользователя.
        //--agent TASK-224
        .route(
            "/api/v1/admin/users/{id}",
            patch(handlers::update_user).delete(handlers::delete_user),
        )
        .route(
            "/api/v1/admin/users/{id}/databases",
            get(handlers::list_user_databases).put(handlers::set_user_databases),
        )
        .route(
            "/api/v1/admin/users/{id}/invitation",
            post(handlers::reissue_invitation),
        )
        .route(
            "/api/v1/admin/users/{id}/password-reset",
            post(handlers::reset_user_password),
        )
        .route("/api/v1/admin/databases", get(handlers::admin_databases))
        .route(
            "/api/v1/admin/databases/{id}",
            //**agent TASK-225 [27.09.2026 00:00:00] T: DELETE — снятие записи базы.
            //    patch(handlers::update_database),
            patch(handlers::update_database).delete(handlers::delete_database),
            //**agent TASK-225
        )
        .route(
            "/api/v1/admin/databases/{id}/refresh",
            post(handlers::refresh_database),
        )
        //++agent TASK-224 [24.09.2026]
        // Ленивое дерево метаданных для вкладки «Справочники».
        //--agent TASK-224
        .route(
            "/api/v1/admin/databases/{id}/metadata",
            get(handlers::database_metadata),
        )
        .route(
            "/api/v1/admin/databases/{id}/tools",
            get(handlers::tool_classifications),
        )
        .route(
            "/api/v1/admin/databases/{id}/tools/{tool}",
            axum::routing::put(handlers::update_tool_classification)
                //++agent TASK-225 [26.09.2026] снятие записи классификации.
                .delete(handlers::delete_tool_classification),
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
        //++agent TASK-225 [26.09.2026]
        // §4: версионированная настройка (B3–B8, B11). B9/B13 — в
        // существующих маршрутах history/metadata.
        //++agent TASK-225
        .route(
            "/api/v1/admin/databases/{id}/setup/export",
            get(|state, path, headers, query| async move {
                setup::export_setup(state, path, headers, query, false).await
            }),
        )
        .route(
            "/api/v1/databases/{id}/setup/export",
            get(|state, path, headers, query| async move {
                setup::export_setup(state, path, headers, query, true).await
            }),
        )
        .route(
            "/api/v1/admin/databases/{id}/setup/imports",
            post(setup::import_setup),
        )
        .route(
            "/api/v1/admin/databases/{id}/setup/diff",
            get(setup::diff_setup),
        )
        .route(
            "/api/v1/admin/databases/{id}/setup/draft",
            post(setup::draft_create)
                .get(setup::draft_get)
                .delete(setup::draft_delete),
        )
        .route(
            "/api/v1/admin/databases/{id}/setup/draft/revert",
            post(setup::draft_revert),
        )
        .route(
            "/api/v1/admin/databases/{id}/setup/draft/{area}",
            axum::routing::put(setup::draft_put_area),
        )
        //++agent TASK-225 [26.09.2026] D2: список версий (автор/дата) и
        // чтение конкретной версии — просмотр без записи в журнал.
        .route(
            "/api/v1/admin/databases/{id}/setup/versions",
            get(setup::version_list),
        )
        .route(
            "/api/v1/admin/databases/{id}/setup/versions/{version}",
            get(setup::version_get),
        )
        //++agent TASK-225
        .route(
            "/api/v1/admin/databases/{id}/setup/activate",
            post(setup::activate_setup),
        )
        .route(
            "/api/v1/admin/databases/{id}/setup/rollback",
            post(setup::rollback_setup),
        )
        .route(
            "/api/v1/admin/databases/{id}/setup/dry-run",
            post(setup::dry_run_setup),
        )
        .route(
            "/api/v1/admin/databases/{id}/setup/journal",
            get(setup::setup_journal),
        )
        .route("/api/v1/history/{id}/reasons", get(setup::history_reasons))
        .route("/", get(handlers::index_page))
        .route("/viewer", get(handlers::viewer_page))
        .route("/admin", get(handlers::admin_page))
        //++agent TASK-224 [24.09.2026] Б12: статика нового UI.
        .route("/app.js", get(handlers::javascript))
        //++agent TASK-224 [24.09.2026] итерация 3: изолированный grid-модуль.
        .route("/grid.js", get(handlers::grid_javascript))
        .route("/app.css", get(handlers::stylesheet))
        .route("/favicon.ico", get(handlers::favicon))
        //--agent TASK-224
        .with_state(state)
}
