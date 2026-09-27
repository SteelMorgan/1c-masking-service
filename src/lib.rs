use std::sync::Arc;

use axum::Router;

pub mod api {
    pub mod human;
}
pub mod auth;
pub mod domain;
#[path = "api/internal.rs"]
pub mod internal_api;
pub mod manager_client;
pub mod storage;

pub use storage::SqliteStorage;

pub struct AppState {
    pub masking: Arc<domain::MaskingService>,
    pub storage: Arc<SqliteStorage>,
    pub expected_origin: String,
    pub expected_peer_uid: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppBuildError {
    #[error("authentication initialization failed")]
    Password(#[from] auth::PasswordError),
    #[error("authentication storage initialization failed")]
    Auth(#[from] auth::AuthError),
}

impl AppState {
    pub fn new(storage: Arc<SqliteStorage>, expected_origin: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            masking: Arc::new(domain::MaskingService::new(storage.clone())),
            storage,
            expected_origin: expected_origin.into(),
            expected_peer_uid: None,
        })
    }

    pub fn new_with_peer_uid(
        storage: Arc<SqliteStorage>,
        expected_origin: impl Into<String>,
        expected_peer_uid: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            masking: Arc::new(domain::MaskingService::new(storage.clone())),
            storage,
            expected_origin: expected_origin.into(),
            expected_peer_uid: Some(expected_peer_uid),
        })
    }
}

pub fn internal_app(state: Arc<AppState>) -> Router {
    internal_api::router(state)
}

pub fn human_app(state: Arc<AppState>) -> Result<Router, AppBuildError> {
    let auth_store: Arc<dyn auth::AuthStore> = state.storage.clone();
    let auth = Arc::new(auth::LocalAuthProvider::new(auth_store.clone())?);
    auth.initialize()?;
    let human_data = Arc::new(api::human::SqliteHumanDataStore::new(
        state.storage.clone(),
        state.masking.clone(),
    ));
    let human_state = Arc::new(api::human::HumanState {
        auth,
        sessions: Arc::new(auth::SessionService::new(auth_store)),
        data: human_data,
        expected_origin: state.expected_origin.clone(),
        //++agent TASK-225 [26.09.2026]
        setup: api::human::setup::SetupService::new(state.storage.clone(), state.masking.clone()),
        //++agent TASK-225
    });
    Ok(api::human::router(human_state))
}
