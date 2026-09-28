use onec_masking_service::domain::{MappingLimits, MappingStore};
use uuid::Uuid;

#[test]
fn mapping_has_absolute_ttl_and_does_not_cross_database() {
    let database_id = Uuid::new_v4();
    let mut store = MappingStore::new(MappingLimits::default());
    let mut candidates = Vec::new();
    let token = store
        .plan_token(
            &mut candidates,
            database_id,
            "FIO",
            "Иванов Иван",
            Uuid::new_v4(),
            0,
        )
        .unwrap();
    store.publish(candidates).unwrap();
    assert_eq!(store.resolve(database_id, &token), None);
    assert_eq!(store.resolve(Uuid::new_v4(), &token), None);
}

#[test]
fn same_value_reuses_token_within_database_only() {
    let database_id = Uuid::new_v4();
    let other_database = Uuid::new_v4();
    let mut store = MappingStore::new(MappingLimits::default());
    let mut first = Vec::new();
    let token = store
        .plan_token(
            &mut first,
            database_id,
            "FIO",
            "Иванов Иван",
            Uuid::new_v4(),
            3600,
        )
        .unwrap();
    store.publish(first).unwrap();
    // Любой следующий вызов той же базы (другой клиент, другая сессия)
    // получает тот же токен: разговоров в ключе нет.
    let mut second = Vec::new();
    let reused = store
        .plan_token(
            &mut second,
            database_id,
            "FIO",
            "Иванов Иван",
            Uuid::new_v4(),
            3600,
        )
        .unwrap();
    let foreign = store
        .plan_token(
            &mut second,
            other_database,
            "FIO",
            "Иванов Иван",
            Uuid::new_v4(),
            3600,
        )
        .unwrap();
    let other_category = store
        .plan_token(
            &mut second,
            database_id,
            "ACCOUNT",
            "Иванов Иван",
            Uuid::new_v4(),
            3600,
        )
        .unwrap();
    assert_eq!(reused, token);
    assert_ne!(foreign, token);
    assert_ne!(other_category, token);
    store.publish(second).unwrap();
    assert_eq!(
        store.resolve(database_id, &token).as_deref(),
        Some("Иванов Иван")
    );
    // Токен базы A в вызове базы B не разрешается.
    assert_eq!(store.resolve(other_database, &token), None);
    assert_eq!(store.resolve(database_id, &foreign), None);
}

#[test]
fn unknown_or_forged_token_is_not_resolved() {
    let database_id = Uuid::new_v4();
    let mut store = MappingStore::new(MappingLimits::default());
    let mut batch = Vec::new();
    let token = store
        .plan_token(
            &mut batch,
            database_id,
            "FIO",
            "Петров Пётр",
            Uuid::new_v4(),
            3600,
        )
        .unwrap();
    store.publish(batch).unwrap();
    assert_eq!(
        store.resolve(
            database_id,
            "[MASK:v1:FIO:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]"
        ),
        None
    );
    // Та же случайная часть под чужой категорией — не та запись.
    let forged = token.replacen("[MASK:v1:FIO:", "[MASK:v1:ACCOUNT:", 1);
    assert_eq!(store.resolve(database_id, &forged), None);
}

#[test]
fn tokens_do_not_survive_process_restart() {
    let database_id = Uuid::new_v4();
    let mut first_process = MappingStore::new(MappingLimits::default());
    let mut batch = Vec::new();
    let token = first_process
        .plan_token(
            &mut batch,
            database_id,
            "FIO",
            "Сидоров",
            Uuid::new_v4(),
            3600,
        )
        .unwrap();
    first_process.publish(batch).unwrap();
    let mut second_process = MappingStore::new(MappingLimits::default());
    assert_eq!(second_process.resolve(database_id, &token), None);
    let mut batch = Vec::new();
    let fresh = second_process
        .plan_token(
            &mut batch,
            database_id,
            "FIO",
            "Сидоров",
            Uuid::new_v4(),
            3600,
        )
        .unwrap();
    assert_ne!(fresh, token);
}

#[test]
fn overflow_evicts_least_recently_used_instead_of_failing() {
    let database_id = Uuid::new_v4();
    let limits = MappingLimits {
        database_entries: 3,
        ..MappingLimits::default()
    };
    let mut store = MappingStore::new(limits);
    let mut tokens = Vec::new();
    for value in ["v1", "v2", "v3"] {
        let mut batch = Vec::new();
        tokens.push(
            store
                .plan_token(&mut batch, database_id, "DATA", value, Uuid::new_v4(), 3600)
                .unwrap(),
        );
        store.publish(batch).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // v1 использован последним — вытесняться должен v2, затем v3.
    assert_eq!(
        store.resolve(database_id, &tokens[0]).as_deref(),
        Some("v1")
    );
    for value in ["v4", "v5"] {
        let mut batch = Vec::new();
        store
            .plan_token(&mut batch, database_id, "DATA", value, Uuid::new_v4(), 3600)
            .unwrap();
        store.publish(batch).expect("overflow must evict, not fail");
    }
    assert_eq!(store.len(), 3);
    assert_eq!(
        store.resolve(database_id, &tokens[0]).as_deref(),
        Some("v1")
    );
    assert_eq!(store.resolve(database_id, &tokens[1]), None);
    assert_eq!(store.resolve(database_id, &tokens[2]), None);
}

#[test]
fn eviction_is_per_database() {
    let database_a = Uuid::new_v4();
    let database_b = Uuid::new_v4();
    let limits = MappingLimits {
        database_entries: 2,
        ..MappingLimits::default()
    };
    let mut store = MappingStore::new(limits);
    let mut batch = Vec::new();
    let token_a = store
        .plan_token(&mut batch, database_a, "DATA", "a1", Uuid::new_v4(), 3600)
        .unwrap();
    store.publish(batch).unwrap();
    for value in ["b1", "b2", "b3"] {
        let mut batch = Vec::new();
        store
            .plan_token(&mut batch, database_b, "DATA", value, Uuid::new_v4(), 3600)
            .unwrap();
        store.publish(batch).unwrap();
    }
    assert_eq!(store.resolve(database_a, &token_a).as_deref(), Some("a1"));
    assert_eq!(store.len(), 3);
}

#[test]
fn batch_larger_than_limit_is_rejected() {
    let database_id = Uuid::new_v4();
    let limits = MappingLimits {
        database_entries: 2,
        ..MappingLimits::default()
    };
    let mut store = MappingStore::new(limits);
    let mut batch = Vec::new();
    for value in ["x1", "x2", "x3"] {
        store
            .plan_token(&mut batch, database_id, "DATA", value, Uuid::new_v4(), 3600)
            .unwrap();
    }
    assert!(store.publish(batch).is_err());
    assert!(store.is_empty());
}

//++agent TASK-225 [27.09.2026 00:00:00] W: защита в глубину — записи,
// сохранённые до фикса слоя-1, хранят оригинал с вложенным токеном;
// reveal разворачивает токены рекурсивно в пределах своей партии.
#[test]
fn resolve_for_batch_expands_nested_tokens_recursively() {
    let database_id = Uuid::new_v4();
    let batch_id = Uuid::new_v4();
    let mut store = MappingStore::new(MappingLimits::default());
    let mut first = Vec::new();
    let fio_token = store
        .plan_token(
            &mut first,
            database_id,
            "FIO",
            "Иванов Иван Иванович",
            batch_id,
            3600,
        )
        .unwrap();
    store.publish(first).unwrap();
    // «Наследие»: ACCOUNT-запись хранит промежуточную форму с FIO-токеном.
    let mut second = Vec::new();
    let account_token = store
        .plan_token(
            &mut second,
            database_id,
            "ACCOUNT",
            &format!("{fio_token} / DEMOSPOT1"),
            batch_id,
            3600,
        )
        .unwrap();
    store.publish(second).unwrap();

    let engine = onec_masking_service::domain::MaskEngine::default();
    let resolved = engine
        .resolve_tokens_for_batch(
            &serde_json::json!({"Наименование": account_token}),
            database_id,
            batch_id,
            &mut store,
        )
        .unwrap();
    let rendered = serde_json::to_string(&resolved).unwrap();
    assert!(
        rendered.contains("Иванов Иван Иванович / DEMOSPOT1"),
        "{rendered}"
    );
    assert!(!rendered.contains("[MASK:"), "{rendered}");
}
//++agent TASK-225

/// Просроченных записей больше, чем чистит одна публикация: новый токен,
/// выданный вместо просроченного, обязан разрешаться, даже если старая
/// запись к моменту публикации ещё не вычищена.
#[test]
fn reissued_token_resolves_when_expired_entries_exceed_cleanup_batch() {
    let database_id = Uuid::new_v4();
    let mut store = MappingStore::new(MappingLimits::default());
    let values: Vec<String> = (0..3_000).map(|index| format!("value-{index}")).collect();
    let mut expired = Vec::new();
    for value in &values {
        store
            .plan_token(&mut expired, database_id, "FIO", value, Uuid::new_v4(), 0)
            .unwrap();
    }
    store.publish(expired).unwrap();

    let mut fresh = Vec::new();
    let tokens: Vec<String> = values
        .iter()
        .map(|value| {
            store
                .plan_token(&mut fresh, database_id, "FIO", value, Uuid::new_v4(), 3600)
                .unwrap()
        })
        .collect();
    store.publish(fresh).unwrap();

    for (value, token) in values.iter().zip(&tokens) {
        assert_eq!(store.resolve(database_id, token).as_deref(), Some(value.as_str()));
    }
    assert_eq!(store.len(), values.len());
}
