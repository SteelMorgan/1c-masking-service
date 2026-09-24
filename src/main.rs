use std::{
    env, fs,
    io::IsTerminal,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use onec_masking_service::{
    auth::{AuthStore, LocalAuthProvider},
    human_app, internal_app,
    manager_client::ManagerClient,
    AppState, SqliteStorage,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, UnixListener, UnixStream},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args()
        .skip(1)
        .eq(["admin", "bootstrap"].map(str::to_owned))
    {
        return bootstrap_client().await;
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .without_time()
        .compact()
        .init();
    std::panic::set_hook(Box::new(|info| {
        if let Some(location) = info.location() {
            eprintln!(
                "MASKING_SERVICE_PANIC at {}:{}",
                location.file(),
                location.line()
            );
        } else {
            eprintln!("MASKING_SERVICE_PANIC");
        }
    }));

    let database_path = PathBuf::from(
        env::var("MASKING_DATABASE_PATH")
            .unwrap_or_else(|_| "/var/lib/1c-masking/service.sqlite3".to_owned()),
    );
    let socket_path = PathBuf::from(
        env::var("MASKING_SOCKET_PATH")
            .unwrap_or_else(|_| "/run/1c-masking/service.sock".to_owned()),
    );
    let control_path = PathBuf::from(
        env::var("MASKING_CONTROL_SOCKET_PATH")
            .unwrap_or_else(|_| "/run/1c-masking/control.sock".to_owned()),
    );
    let human_bind = env::var("MASKING_HUMAN_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
    let expected_origin = env::var("MASKING_EXPECTED_ORIGIN")
        .map_err(|_| "MASKING_EXPECTED_ORIGIN is required for the human listener")?;
    if expected_origin.is_empty() {
        return Err("MASKING_EXPECTED_ORIGIN must not be empty".into());
    }
    prepare_parent(&database_path)?;
    prepare_parent(&socket_path)?;
    prepare_parent(&control_path)?;
    remove_stale_socket(&socket_path)?;
    remove_stale_socket(&control_path)?;
    let storage = Arc::new(SqliteStorage::open(&database_path)?);
    set_private_file_mode(&database_path)?;
    let manager_uid = env::var("MASKING_MANAGER_UID")
        .ok()
        .map(|value| value.parse::<u32>())
        .transpose()?
        // SAFETY: geteuid has no arguments, does not dereference memory, and has no failure mode.
        .unwrap_or_else(|| unsafe { libc::geteuid() });
    //++agent TASK-222 [05.10.2026]
    // Pull-модель: metadata/dictionary сервис загружает сам, вызывая internal
    // tools через UDS менеджера. Переменная обязательна — без неё durable
    // intents некому выполнять, enabled-базы остались бы not-ready навсегда.
    let manager_socket_path = PathBuf::from(
        env::var("MASKING_MANAGER_SOCKET_PATH")
            .map_err(|_| "MASKING_MANAGER_SOCKET_PATH is required for metadata pull")?,
    );
    //++agent TASK-222
    let state = AppState::new_with_peer_uid(storage.clone(), expected_origin, manager_uid);
    let auth_store: Arc<dyn AuthStore> = storage.clone();
    let control_auth = Arc::new(LocalAuthProvider::new(auth_store)?);
    control_auth.initialize()?;
    let listener = UnixListener::bind(&socket_path)?;
    let control_listener = UnixListener::bind(&control_path)?;
    let human_listener = TcpListener::bind(&human_bind).await?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))?;
    fs::set_permissions(&control_path, fs::Permissions::from_mode(0o600))?;
    tokio::spawn(serve_control(control_listener, control_auth));
    let maintenance = state.masking.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let _ = maintenance.maintenance_tick().await;
        }
    });
    //++agent TASK-222 [05.10.2026]
    // Pull worker: короткий тик дрейнит durable v2_refresh_intents — startup
    // intents ставятся конструктором сервиса, Admin-мутации дополняют очередь.
    // Сбой одного pull не останавливает цикл (transient intent переживает тик).
    let pull_service = state.masking.clone();
    let manager_client = ManagerClient::new(manager_socket_path, Some(manager_uid));
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(bounded_env(
            "MASKING_PULL_INTERVAL_SECONDS",
            10,
            1,
            300,
        )));
        loop {
            interval.tick().await;
            let _ = pull_service.refresh_due_intents(&manager_client, 10).await;
        }
    });
    //++agent TASK-222
    tracing::info!(event = "service_started");
    let internal = axum::serve(
        listener,
        internal_app(state.clone()).into_make_service_with_connect_info::<onec_masking_service::internal_api::UdsConnectInfo>(),
    );
    let human = axum::serve(human_listener, human_app(state)?);
    tokio::try_join!(internal, human)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct BootstrapRequest {
    password: String,
}

#[derive(Serialize, Deserialize)]
struct BootstrapResponse {
    success: bool,
}

async fn bootstrap_client() -> Result<(), Box<dyn std::error::Error>> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err("bootstrap requires an interactive TTY".into());
    }
    let first = rpassword::prompt_password("Новый пароль Admin: ")?;
    let second = rpassword::prompt_password("Повторите пароль: ")?;
    if first != second || first.len() < 12 || first.len() > 1024 {
        return Err("password confirmation or length is invalid".into());
    }
    let control_path = env::var("MASKING_CONTROL_SOCKET_PATH")
        .unwrap_or_else(|_| "/run/1c-masking/control.sock".to_owned());
    let mut stream = UnixStream::connect(control_path).await?;
    let mut request = serde_json::to_vec(&BootstrapRequest { password: first })?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    request.fill(0);
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).await?;
    let response: BootstrapResponse = serde_json::from_str(&response)?;
    if !response.success {
        return Err("bootstrap was rejected".into());
    }
    eprintln!("Пароль Admin установлен.");
    Ok(())
}

async fn serve_control(listener: UnixListener, auth: Arc<LocalAuthProvider>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let auth = auth.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut line = String::new();
            let success = match BufReader::new(reader).take(2049).read_line(&mut line).await {
                Ok(size) if size <= 2048 => serde_json::from_str::<BootstrapRequest>(&line)
                    .ok()
                    .filter(|request| (12..=1024).contains(&request.password.len()))
                    .is_some_and(|request| {
                        auth.bootstrap_admin_password(&request.password).is_ok()
                    }),
                _ => false,
            };
            line.clear();
            let response = serde_json::to_vec(&BootstrapResponse { success })
                .unwrap_or_else(|_| b"{\"success\":false}".to_vec());
            let _ = writer.write_all(&response).await;
            let _ = writer.write_all(b"\n").await;
        });
    }
}

//++agent TASK-222 [05.10.2026]
fn bounded_env(name: &str, default: u64, minimum: u64, maximum: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .unwrap_or(default)
}
//++agent TASK-222

fn prepare_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn set_private_file_mode(path: &Path) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn remove_stale_socket(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err("refusing to replace a non-socket path".into());
        }
        fs::remove_file(path)?;
    }
    Ok(())
}
