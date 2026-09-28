//++agent TASK-225 [26.09.2026]
//! O2: идентичность базы — непрозрачный ключ `instance_id`
//! (`ras:<c>:<i>` / `gen:<srvr>/<ref>`), вычисленный менеджером при
//! session.register. `ensure_database` — только точное совпадение ключа;
//! никакой нормализации координат, фолбэков и переходов generated→ras:
//! склейка баз невозможна по построению.

mod common;

use std::sync::Arc;

use onec_masking_service::auth::DatabaseScope;
use onec_masking_service::{
    domain::{DatabaseIdentity, DatabaseMode},
    AppState, SqliteStorage,
};
use uuid::Uuid;

fn ras_identity(cluster: Uuid, infobase: Uuid) -> DatabaseIdentity {
    DatabaseIdentity {
        instance_id: format!("ras:{cluster}:{infobase}"),
        cluster_server: "onec-infra".to_owned(),
        infobase_name: "gbig_pam_ai".to_owned(),
    }
}

fn generated_identity() -> DatabaseIdentity {
    DatabaseIdentity {
        instance_id: "gen:onec-infra/gbig_pam_ai".to_owned(),
        cluster_server: "onec-infra".to_owned(),
        infobase_name: "gbig_pam_ai".to_owned(),
    }
}

/// RAS-ключ: запись ключуется `ras:<c>:<i>` как есть, guid_source
/// выводится из префикса, повторная регистрация попадает в ту же запись.
#[test]
fn ras_identity_creates_record_keyed_by_ras_key() {
    let storage = SqliteStorage::in_memory().unwrap();
    let (cluster, infobase) = (Uuid::new_v4(), Uuid::new_v4());
    let identity = ras_identity(cluster, infobase);

    let (database_id, settings, created) = storage.ensure_database(&identity).unwrap();
    assert!(created);
    assert_eq!(settings.guid_source(), Some("ras"));
    assert_eq!(settings.instance_id, format!("ras:{cluster}:{infobase}"));
    assert_eq!(settings.mode, DatabaseMode::Unconfigured);

    let (again, settings, created) = storage.ensure_database(&identity).unwrap();
    assert_eq!(again, database_id);
    assert_eq!(settings.instance_id, format!("ras:{cluster}:{infobase}"));
    assert!(!created);
}

/// generated-ключ `gen:<srvr>/<ref>` verbatim стабилен между повторными
/// регистрациями.
#[test]
fn generated_identity_key_is_stable() {
    let storage = SqliteStorage::in_memory().unwrap();
    let identity = generated_identity();

    let (first_id, first, created) = storage.ensure_database(&identity).unwrap();
    assert!(created);
    assert_eq!(first.guid_source(), Some("generated"));
    assert_eq!(first.instance_id, "gen:onec-infra/gbig_pam_ai");

    let (second_id, second, created) = storage.ensure_database(&identity).unwrap();
    assert!(!created);
    assert_eq!(second_id, first_id);
    assert_eq!(second.instance_id, "gen:onec-infra/gbig_pam_ai");
}

/// O2: перехода generated→ras нет — ras-ключ тех же координат создаёт
/// отдельную запись, настройки gen-записи не переносятся (export/import).
#[test]
fn ras_key_does_not_absorb_generated_record() {
    let storage = SqliteStorage::in_memory().unwrap();
    let (gen_id, _, _) = storage.ensure_database(&generated_identity()).unwrap();
    assert!(storage
        .set_database_mode(gen_id, DatabaseMode::Enabled)
        .unwrap());

    let (cluster, infobase) = (Uuid::new_v4(), Uuid::new_v4());
    let (ras_id, settings, created) = storage
        .ensure_database(&ras_identity(cluster, infobase))
        .unwrap();
    assert!(created);
    assert_ne!(ras_id, gen_id);
    assert_eq!(settings.guid_source(), Some("ras"));
    // Новая запись не наследует настройки старой.
    assert_eq!(settings.mode, DatabaseMode::Unconfigured);

    // Обратный вызов по gen-ключу — та же gen-запись, режим сохранён.
    let (same, settings, created) = storage.ensure_database(&generated_identity()).unwrap();
    assert_eq!(same, gen_id);
    assert!(!created);
    assert_eq!(settings.mode, DatabaseMode::Enabled);
}

/// Два кластера с одинаковым Ref — разные ключи → разные записи,
/// склейки нет ни по координатам, ни по имени.
#[test]
fn two_clusters_with_same_ref_produce_distinct_records() {
    let storage = SqliteStorage::in_memory().unwrap();
    let ib = Uuid::new_v4();
    let (id_a, _, created) = storage
        .ensure_database(&ras_identity(Uuid::new_v4(), ib))
        .unwrap();
    assert!(created);

    let (id_b, _, created) = storage
        .ensure_database(&ras_identity(Uuid::new_v4(), ib))
        .unwrap();
    assert!(created);
    assert_ne!(id_a, id_b);
}

/// Авто-регистрация неизвестного ключа создаёт `unconfigured`-запись,
/// подписанную именем ИБ.
#[test]
fn unknown_key_auto_registers_unconfigured_labeled_record() {
    let storage = SqliteStorage::in_memory().unwrap();
    let (database_id, settings, created) = storage.ensure_database(&generated_identity()).unwrap();
    assert!(created);
    assert_eq!(settings.mode, DatabaseMode::Unconfigured);

    let label: Option<String> = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT display_label FROM databases WHERE id=?1",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(label.as_deref(), Some("gbig_pam_ai"));

    let total: i64 = storage
        .with_connection(|c| c.query_row("SELECT COUNT(*) FROM databases", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(total, 1);
}

/// Посадочная миграция (записи до ключевой эпохи не переписываются —
/// `instance_id` строки никогда не меняется): `insert_database` садит
/// новую запись под ключ, а legacy-строка остаётся нетронутой со своим
/// ключом и режимом — существующие базы не теряют конфигурацию.
#[test]
fn insert_database_seeds_keyed_record_and_keeps_legacy_row() {
    let storage = SqliteStorage::in_memory().unwrap();
    let database_id = Uuid::new_v4();
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT INTO databases(id, instance_id, mode, display_label, created_at, updated_at)
                 VALUES (?1, ?1, 'enabled', 'gbig_pam_ai', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                [database_id.to_string()],
            )
        })
        .unwrap();

    let (cluster, infobase) = (Uuid::new_v4(), Uuid::new_v4());
    let identity = ras_identity(cluster, infobase);
    let seeded = Uuid::new_v4();
    let settings = storage.insert_database(seeded, &identity).unwrap();
    assert_eq!(settings.guid_source(), Some("ras"));
    assert_eq!(settings.instance_id, format!("ras:{cluster}:{infobase}"));

    // Точный ключ попадает в посаженную запись, дублей нет.
    let (found_id, _, created) = storage.ensure_database(&identity).unwrap();
    assert_eq!(found_id, seeded);
    assert!(!created);

    // Legacy-строка нетронута: собственный ключ и режим сохранены.
    let (legacy_key, legacy_mode): (String, String) = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT instance_id, mode FROM databases WHERE id=?1",
                [database_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!(legacy_key, database_id.to_string());
    assert_eq!(legacy_mode, "enabled");
}

/// B2/admin-листинг возвращает координаты и источник ключа записи,
/// выведенный из префикса `instance_id`.
#[tokio::test]
async fn admin_listing_reports_identity_source() {
    use onec_masking_service::api::human::{HumanDataStore, SqliteHumanDataStore};

    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let (ras_id, _, _) = storage
        .ensure_database(&ras_identity(Uuid::new_v4(), Uuid::new_v4()))
        .unwrap();
    let (generated_id, _, _) = storage.ensure_database(&generated_identity()).unwrap();

    let state = AppState::new(storage.clone(), "https://masking.test");
    let data = SqliteHumanDataStore::new(storage.clone(), state.masking.clone());
    let rows = data.list_databases(&DatabaseScope::All).unwrap();
    let ras = rows.iter().find(|row| row.id == ras_id).unwrap();
    assert_eq!(ras.guid_source.as_deref(), Some("ras"));
    assert_eq!(ras.cluster_server.as_deref(), Some("onec-infra"));
    assert_eq!(ras.infobase_name.as_deref(), Some("gbig_pam_ai"));
    let generated = rows.iter().find(|row| row.id == generated_id).unwrap();
    assert_eq!(generated.guid_source.as_deref(), Some("generated"));
    assert_eq!(generated.infobase_name.as_deref(), Some("gbig_pam_ai"));
}
//++agent TASK-225
