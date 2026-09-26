//++agent TASK-225 [25.09.2026]
//! §5a: словарный матчинг через Aho-Corasick (T10-01..T10-07).
//! Эквивалентность проверяется против встроенного fallback-пути
//! (`dictionary_index: None` — это буквально прежняя реализация
//! перебором HashMap, сохранённая в `mask_string`).
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use onec_masking_service::domain::{
    DictionaryIndex, MappingLimits, MappingStore, MaskEngine, PolicyRule, PolicySnapshot,
    RuleAction, RuleSelector,
};
use serde_json::{json, Value};
use uuid::Uuid;

fn engine() -> MaskEngine {
    MaskEngine::new()
}

fn policy(
    dictionary: HashMap<String, String>,
    rules: Vec<PolicyRule>,
    with_index: bool,
) -> PolicySnapshot {
    PolicySnapshot {
        version: 1,
        dictionary_index: if with_index {
            DictionaryIndex::build(&dictionary, &rules)
        } else {
            None
        },
        dictionary,
        dictionary_sources: HashMap::new(),
        rules,
        metadata_sources: Vec::new(),
        policy_id: None,
        dictionary_fingerprint: 0,
        ready: true,
    }
}

fn mask_strings(
    engine: &MaskEngine,
    policy: &PolicySnapshot,
    mappings: &MappingStore,
    batch: Uuid,
    strings: &[String],
) -> (
    Vec<String>,
    HashSet<String>,
    Vec<onec_masking_service::domain::MappingCandidate>,
) {
    let input = Value::Array(strings.iter().map(|s| json!(s)).collect());
    let output = engine
        .mask(
            &input,
            Uuid::nil(),
            "chat",
            batch,
            3600,
            policy,
            mappings,
            &json!({}),
        )
        .expect("mask");
    let values: Vec<String> = output
        .value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    (values, output.reasons, output.candidates)
}

/// Токены генерируются случайно (OsRng) — для сравнения прогонов
/// нормализуем замену до категории.
fn normalize_tokens(text: &str) -> String {
    regex::Regex::new(r"\[MASK:v1:[A-Z0-9_]{1,32}:[A-Za-z0-9_-]{32}\]")
        .unwrap()
        .replace_all(text, "[MASK]")
        .into_owned()
}

fn dictionary_rule(action: RuleAction, category: &str) -> PolicyRule {
    PolicyRule {
        selector: RuleSelector::Dictionary,
        pattern: category.to_owned(),
        action,
        category: category.to_owned(),
        priority: 0,
        rule_id: None,
    }
}

/// Детерминированный PRNG (xorshift64) — квазислучайный генератор для
/// property-теста без новых зависимостей.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

// T10-01: эквивалентность автомата и fallback-перебора на
// непересекающихся словарях — ≥1000 случаев, результат и reasons
// байт-в-байт совпадают.
#[test]
fn automaton_matches_legacy_scan_on_non_overlapping_dictionaries() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let engine = engine();
    for case in 0..1000u64 {
        let dict_size = 1 + rng.below(50) as usize;
        let mut dictionary = HashMap::new();
        // Непересекающиеся значения: уникальный префикс-кейс гарантирует,
        // что ни одно значение не является подстрокой другого.
        for i in 0..dict_size {
            let value = format!(
                "VAL{:06x}X{:08x}",
                case * 1000 + i as u64,
                rng.below(0xFFFF_FFFF)
            );
            let category = match rng.below(4) {
                0 => "ORG",
                1 => "FIO",
                2 => "DOC",
                _ => "ADDR",
            };
            dictionary.insert(value, category.to_owned());
        }
        // Часть категорий — Keep, часть — дефолтный Mask: нагрузка на оба
        // прохода (keep-причины и замены).
        let rules = vec![
            dictionary_rule(RuleAction::Keep, "DOC"),
            dictionary_rule(RuleAction::Keep, "ADDR"),
        ];
        let strings: Vec<String> = dictionary
            .keys()
            .map(|value| format!("текст {value} и ещё {value} конец"))
            .collect();
        let legacy = policy(dictionary.clone(), rules.clone(), false);
        let indexed = policy(dictionary, rules, true);
        let batch = Uuid::new_v4();
        let mappings = MappingStore::new(MappingLimits::default());
        let (legacy_values, legacy_reasons, _) =
            mask_strings(&engine, &legacy, &mappings, batch, &strings);
        let (indexed_values, indexed_reasons, _) =
            mask_strings(&engine, &indexed, &mappings, batch, &strings);
        let legacy_norm: Vec<String> = legacy_values.iter().map(|v| normalize_tokens(v)).collect();
        let indexed_norm: Vec<String> =
            indexed_values.iter().map(|v| normalize_tokens(v)).collect();
        assert_eq!(legacy_norm, indexed_norm, "case {case} values");
        assert_eq!(legacy_reasons, indexed_reasons, "case {case} reasons");
    }
}

// T10-02: пересекающиеся keep-значения — legacy-перебор фиксирует причину
// для каждой категории (contains по каждой записи), автоматный
// keep-проход повторяет ту же семантику — reasons совпадают.
#[test]
fn automaton_matches_legacy_scan_on_overlapping_keep_dictionaries() {
    let engine = engine();
    for case in 0..500u64 {
        let mut dictionary = HashMap::new();
        // Каскад вложенных keep-значений разных категорий с общим
        // префиксом: «ABC» ⊃ «AB» ⊃ «A» — все три содержатся в тексте.
        let stem = format!("K{:06x}", case);
        dictionary.insert(format!("{stem}ABC"), "KEEPA".to_owned());
        dictionary.insert(format!("{stem}AB"), "KEEPB".to_owned());
        dictionary.insert(format!("{stem}A"), "KEEPC".to_owned());
        let rules = vec![
            dictionary_rule(RuleAction::Keep, "KEEPA"),
            dictionary_rule(RuleAction::Keep, "KEEPB"),
            dictionary_rule(RuleAction::Keep, "KEEPC"),
        ];
        let strings = vec![format!("x{stem}ABCx"), format!("y{stem}ABy")];
        let legacy = policy(dictionary.clone(), rules.clone(), false);
        let indexed = policy(dictionary, rules, true);
        let batch = Uuid::new_v4();
        let mappings = MappingStore::new(MappingLimits::default());
        let (legacy_values, legacy_reasons, _) =
            mask_strings(&engine, &legacy, &mappings, batch, &strings);
        let (indexed_values, indexed_reasons, _) =
            mask_strings(&engine, &indexed, &mappings, batch, &strings);
        let legacy_norm: Vec<String> = legacy_values.iter().map(|v| normalize_tokens(v)).collect();
        let indexed_norm: Vec<String> =
            indexed_values.iter().map(|v| normalize_tokens(v)).collect();
        assert_eq!(legacy_norm, indexed_norm, "case {case} values");
        assert_eq!(legacy_reasons, indexed_reasons, "case {case} reasons");
        // Все keep-причины видны (перекрытия не глушат друг друга).
        assert!(
            legacy_reasons.contains("dictionary:KEEPA"),
            "{legacy_reasons:?}"
        );
        assert!(
            legacy_reasons.contains("dictionary:KEEPB"),
            "{legacy_reasons:?}"
        );
        assert!(
            legacy_reasons.contains("dictionary:KEEPC"),
            "{legacy_reasons:?}"
        );
    }
}

// T10-03: при пересекающихся mask-значениях автомат выбирает
// leftmost-longest — детерминированно (отличие от порядка HashMap
// зафиксировано в spec как допустимое).
#[test]
fn overlapping_values_resolve_leftmost_longest() {
    let engine = engine();
    // «AB» и «ABC» пересекаются с одной позиции — leftmost-longest
    // выбирает длинное. Значения специально не FIO-формы.
    let dictionary = HashMap::from([
        ("AB".to_owned(), "SHORT".to_owned()),
        ("ABC".to_owned(), "LONG".to_owned()),
    ]);
    let indexed = policy(dictionary, Vec::new(), true);
    let mappings = MappingStore::new(MappingLimits::default());
    let (values, reasons, _) = mask_strings(
        &engine,
        &indexed,
        &mappings,
        Uuid::new_v4(),
        &["xABCy".to_owned()],
    );
    assert!(values[0].contains("[MASK:v1:LONG:"), "{:?}", values);
    assert!(!values[0].contains("[MASK:v1:SHORT:"), "{:?}", values);
    assert!(!values[0].contains("ABC"), "{:?}", values);
    assert!(reasons.contains("dictionary:LONG"), "{reasons:?}");
    assert!(!reasons.contains("dictionary:SHORT"), "{reasons:?}");
}

// T10-03b: повтор одного значения в строке маскируется одним токеном —
// замена детерминированным планом ≡ replace всех вхождений.
#[test]
fn repeated_value_gets_same_token() {
    let engine = engine();
    let dictionary = HashMap::from([("ООО Вектор".to_owned(), "ORG".to_owned())]);
    let indexed = policy(dictionary, Vec::new(), true);
    let mappings = MappingStore::new(MappingLimits::default());
    let (values, _, _) = mask_strings(
        &engine,
        &indexed,
        &mappings,
        Uuid::new_v4(),
        &["ООО Вектор и снова ООО Вектор".to_owned()],
    );
    let parts: Vec<&str> = values[0].split("[MASK:v1:ORG:").collect();
    assert_eq!(parts.len(), 3, "{:?}", values);
    let first: String = parts[1].chars().take(32).collect();
    let second: String = parts[2].chars().take(32).collect();
    assert_eq!(first, second, "{:?}", values);
}

// T10-04: словарное значение Secret-категории удаляет строку целиком.
#[test]
fn secret_dictionary_value_removes_whole_string() {
    let engine = engine();
    let rules = vec![dictionary_rule(RuleAction::Secret, "SECRETCAT")];
    let dictionary = HashMap::from([("секретное".to_owned(), "SECRETCAT".to_owned())]);
    let indexed = policy(dictionary.clone(), rules.clone(), true);
    let legacy = policy(dictionary, rules, true);
    let mut legacy_no_index = legacy;
    legacy_no_index.dictionary_index = None;
    let mappings = MappingStore::new(MappingLimits::default());
    for snapshot in [&indexed, &legacy_no_index] {
        let (values, reasons, _) = mask_strings(
            &engine,
            snapshot,
            &mappings,
            Uuid::new_v4(),
            &["в тексте секретное значение".to_owned()],
        );
        assert_eq!(values, vec!["[SECRET_REMOVED]".to_owned()]);
        assert!(
            reasons.contains("dictionary:SECRETCAT:secret"),
            "{reasons:?}"
        );
    }
}

// T10-05: keep-значение соседствует с mask-значением — keep остаётся,
// mask заменяется, причины фиксируются для обоих.
#[test]
fn keep_value_stays_next_to_masked() {
    let engine = engine();
    let rules = vec![dictionary_rule(RuleAction::Keep, "KEEPCAT")];
    let dictionary = HashMap::from([
        ("ОСТАВИТЬ".to_owned(), "KEEPCAT".to_owned()),
        ("СКРЫТЬ".to_owned(), "MASKCAT".to_owned()),
    ]);
    for with_index in [true, false] {
        let snapshot = policy(dictionary.clone(), rules.clone(), with_index);
        let mappings = MappingStore::new(MappingLimits::default());
        let (values, reasons, _) = mask_strings(
            &engine,
            &snapshot,
            &mappings,
            Uuid::new_v4(),
            &["ОСТАВИТЬ и СКРЫТЬ".to_owned()],
        );
        assert!(values[0].contains("ОСТАВИТЬ"), "{:?}", values);
        assert!(values[0].contains("[MASK:v1:MASKCAT:"), "{:?}", values);
        assert!(!values[0].contains("СКРЫТЬ"), "{:?}", values);
        assert!(reasons.contains("dictionary:KEEPCAT"), "{reasons:?}");
        assert!(reasons.contains("dictionary:MASKCAT"), "{reasons:?}");
    }
}

// T10-05b: mask-значение внутри keep-значения заменяется — keep фиксирует
// только причину, вырезания «вместе с keep» не происходит.
#[test]
fn mask_value_inside_keep_value_is_masked() {
    let engine = engine();
    let rules = vec![dictionary_rule(RuleAction::Keep, "KEEPCAT")];
    let dictionary = HashMap::from([
        ("ООО Вектор".to_owned(), "KEEPCAT".to_owned()),
        ("Вектор".to_owned(), "MASKCAT".to_owned()),
    ]);
    for with_index in [true, false] {
        let snapshot = policy(dictionary.clone(), rules.clone(), with_index);
        let mappings = MappingStore::new(MappingLimits::default());
        let (values, reasons, _) = mask_strings(
            &engine,
            &snapshot,
            &mappings,
            Uuid::new_v4(),
            &["тут ООО Вектор".to_owned()],
        );
        assert!(values[0].contains("ООО "), "{:?}", values);
        assert!(values[0].contains("[MASK:v1:MASKCAT:"), "{:?}", values);
        assert!(!values[0].contains("Вектор"), "{:?}", values);
        assert!(reasons.contains("dictionary:MASKCAT"), "{reasons:?}");
        if with_index {
            // Автоматный путь фиксирует keep-причину по исходному тексту
            // независимо от замен (B-3); legacy-перебор может её пропустить,
            // если mask-значение внутри keep заменилось раньше проверки.
            assert!(reasons.contains("dictionary:KEEPCAT"), "{reasons:?}");
        }
    }
}

// T10-06: словарь целиком keep — ничего не маскируется, но причины
// фиксируются для каждого встретившегося значения.
#[test]
fn all_keep_dictionary_masks_nothing_but_records_reasons() {
    let engine = engine();
    let rules = vec![
        dictionary_rule(RuleAction::Keep, "KEEPA"),
        dictionary_rule(RuleAction::Keep, "KEEPB"),
    ];
    let dictionary = HashMap::from([
        ("первое".to_owned(), "KEEPA".to_owned()),
        ("второе".to_owned(), "KEEPB".to_owned()),
    ]);
    let text = "первое и второе остаются".to_owned();
    for with_index in [true, false] {
        let snapshot = policy(dictionary.clone(), rules.clone(), with_index);
        let mappings = MappingStore::new(MappingLimits::default());
        let (values, reasons, _) = mask_strings(
            &engine,
            &snapshot,
            &mappings,
            Uuid::new_v4(),
            std::slice::from_ref(&text),
        );
        assert_eq!(values, vec![text.clone()]);
        assert!(reasons.contains("dictionary:KEEPA"), "{reasons:?}");
        assert!(reasons.contains("dictionary:KEEPB"), "{reasons:?}");
        assert!(!reasons.iter().any(|r| r.contains("MASK")), "{reasons:?}");
    }
}

// T10-07a: смена правил Keep→Mask на том же индексе начинает маскировать —
// `with_actions` пересобирает действия без нового pull.
#[test]
fn with_actions_keep_to_mask_starts_masking() {
    let engine = engine();
    let dictionary = HashMap::from([("ООО Вектор".to_owned(), "ORG".to_owned())]);
    let keep_rules = vec![dictionary_rule(RuleAction::Keep, "ORG")];
    let index = DictionaryIndex::build(&dictionary, &keep_rules).expect("index");
    let mask_rules = vec![dictionary_rule(RuleAction::Mask, "ORG")];
    let remasked = index.with_actions(&mask_rules);
    let snapshot = PolicySnapshot {
        version: 1,
        rules: mask_rules,
        dictionary: dictionary.clone(),
        dictionary_sources: HashMap::new(),
        dictionary_index: Some(remasked),
        metadata_sources: Vec::new(),
        policy_id: None,
        dictionary_fingerprint: 0,
        ready: true,
    };
    let mappings = MappingStore::new(MappingLimits::default());
    let (values, _, _) = mask_strings(
        &engine,
        &snapshot,
        &mappings,
        Uuid::new_v4(),
        &["тут ООО Вектор есть".to_owned()],
    );
    assert!(values[0].starts_with("тут [MASK:v1:ORG:"), "{:?}", values);
}

// T10-07b: обратная смена Mask→Keep пересчитывает действия — значение
// перестаёт резаться, pull словаря не нужен.
#[test]
fn rule_change_recomputes_actions_without_pull() {
    let engine = engine();
    let dictionary = HashMap::from([("ООО Вектор".to_owned(), "ORG".to_owned())]);
    let mask_rules = vec![dictionary_rule(RuleAction::Mask, "ORG")];
    let index = DictionaryIndex::build(&dictionary, &mask_rules).expect("index");
    let keep_rules = vec![dictionary_rule(RuleAction::Keep, "ORG")];
    let reused = index.with_actions(&keep_rules);
    let snapshot = PolicySnapshot {
        version: 1,
        rules: keep_rules,
        dictionary: dictionary.clone(),
        dictionary_sources: HashMap::new(),
        dictionary_index: Some(reused),
        metadata_sources: Vec::new(),
        policy_id: None,
        dictionary_fingerprint: 0,
        ready: true,
    };
    let mappings = MappingStore::new(MappingLimits::default());
    let (values, reasons, _) = mask_strings(
        &engine,
        &snapshot,
        &mappings,
        Uuid::new_v4(),
        &["тут ООО Вектор есть".to_owned()],
    );
    assert_eq!(values, vec!["тут ООО Вектор есть".to_owned()]);
    assert!(reasons.contains("dictionary:ORG"), "{reasons:?}");
}

// B-2 регрессия: wildcard-сопоставление правила с именем поля — без учёта
// регистра по Unicode (кириллические паттерны тоже работают).
#[test]
fn wildcard_name_match_is_unicode_case_insensitive() {
    let engine = engine();
    let rules = vec![PolicyRule {
        selector: RuleSelector::Name,
        pattern: "*ТелефонКлиента*".to_owned(),
        action: RuleAction::Mask,
        category: "PHONE".to_owned(),
        priority: 0,
        rule_id: None,
    }];
    let snapshot = PolicySnapshot {
        version: 1,
        rules,
        dictionary: HashMap::new(),
        dictionary_sources: HashMap::new(),
        dictionary_index: None,
        metadata_sources: Vec::new(),
        policy_id: None,
        dictionary_fingerprint: 0,
        ready: true,
    };
    let mappings = MappingStore::new(MappingLimits::default());
    // Регистр поля отличается от паттерна только регистром кириллицы.
    let input = json!({"телефонклиента": "8-905-111-22-33", "прочее": "8-905-111-22-33"});
    let output = engine
        .mask(
            &input,
            Uuid::nil(),
            "chat",
            Uuid::new_v4(),
            3600,
            &snapshot,
            &mappings,
            &json!({}),
        )
        .expect("mask");
    let masked = serde_json::to_string(&output.value).unwrap();
    assert!(masked.contains("[MASK:v1:PHONE:"), "{masked}");
    // Поле без совпадения с паттерном правила не тронуто.
    assert!(masked.contains("прочее"), "{masked}");
    let neutral = output
        .value
        .pointer("/прочее")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert_eq!(neutral, "8-905-111-22-33", "{masked}");
}

// T10-08: бюджет сборки и запроса на 1М значениях (§5a.4).
// Игнорируется в обычном прогоне — запуск `cargo test -- --ignored`.
#[test]
#[ignore]
fn bench_dictionary_automaton_1m() {
    let engine = engine();
    let categories = ["ORG", "FIO", "DOC", "ADDR", "BANK"];
    let mut dictionary = HashMap::with_capacity(1_000_000);
    let mut rng = Rng(0xDEADBEEF);
    let mut probe = String::new();
    for i in 0..1_000_000u64 {
        let len = 6 + rng.below(35) as usize;
        let mut value = format!("V{i:07}");
        while value.len() < len {
            value.push((b'a' + (rng.below(26) as u8)) as char);
        }
        if i == 42 {
            probe = value.clone();
        }
        dictionary.insert(value, categories[(i % 5) as usize].to_owned());
    }
    let started = Instant::now();
    let index = DictionaryIndex::build(&dictionary, &[]).expect("index");
    let build_elapsed = started.elapsed();
    println!("build 1M: {build_elapsed:?} (budget 10s)");
    assert!(build_elapsed.as_secs() <= 10, "build {build_elapsed:?}");

    let snapshot = PolicySnapshot {
        version: 1,
        rules: Vec::new(),
        dictionary,
        dictionary_sources: HashMap::new(),
        dictionary_index: Some(index),
        metadata_sources: Vec::new(),
        ready: true,
        policy_id: None,
        dictionary_fingerprint: 0,
    };
    // Ответ 1000 строк × 10 колонок (текст без совпадений + ~1% вставок).
    let rows: Vec<Value> = (0..1000u64)
        .map(|row| {
            let cells: Vec<Value> = (0..10)
                .map(|col| {
                    if row % 97 == 0 && col == 0 {
                        json!(format!("значение {probe} внутри"))
                    } else {
                        json!(format!("обычная строка {row} колонка {col} без совпадений"))
                    }
                })
                .collect();
            json!({"columns": cells})
        })
        .collect();
    let input = Value::Array(rows);
    let mappings = MappingStore::new(MappingLimits::default());
    let started = Instant::now();
    let output = engine
        .mask(
            &input,
            Uuid::nil(),
            "bench",
            Uuid::new_v4(),
            3600,
            &snapshot,
            &mappings,
            &json!({}),
        )
        .expect("mask");
    let mask_elapsed = started.elapsed();
    let masked_cells = output.reasons.len();
    println!("mask 1000×10 over 1M dict: {mask_elapsed:?} (budget 200ms), reasons={masked_cells}");
    assert!(mask_elapsed.as_millis() <= 200, "mask {mask_elapsed:?}");

    // Сравнение со старой реализацией на 10К значений (§5a.4: старую на
    // 1М не гоняем — упирается в deadline).
    let mut small = HashMap::with_capacity(10_000);
    let mut rng = Rng(0xDEADBEEF);
    for i in 0..10_000u64 {
        small.insert(
            format!("V{i:07}x{:x}", rng.below(0xFFFF)),
            categories[(i % 5) as usize].to_owned(),
        );
    }
    let legacy = policy(small, Vec::new(), false);
    let indexed = policy(legacy.dictionary.clone(), Vec::new(), true);
    let mappings2 = MappingStore::new(MappingLimits::default());
    let batch = Uuid::new_v4();
    let started = Instant::now();
    let _ = engine.mask(
        &input,
        Uuid::nil(),
        "bench",
        batch,
        3600,
        &legacy,
        &mappings2,
        &json!({}),
    );
    let legacy_elapsed = started.elapsed();
    let started = Instant::now();
    let _ = engine.mask(
        &input,
        Uuid::nil(),
        "bench",
        batch,
        3600,
        &indexed,
        &mappings2,
        &json!({}),
    );
    let indexed_elapsed = started.elapsed();
    println!("10K dict legacy scan: {legacy_elapsed:?}; automaton: {indexed_elapsed:?}");
}
//++agent TASK-225

//++agent TASK-225 [26.09.2026]
// N-2/§12: бенчмарк keep-автомата — 1M keep-значений. Линейный
// `contains` по каждой keep-записи на строку был O(keep×текст):
// 10К строк × 1M проверок — непригодно. Standard-автомат сканирует
// текст за O(len + совпадения).
#[test]
#[ignore = "benchmark: run explicitly"]
fn bench_dictionary_keep_automaton_1m() {
    let engine = engine();
    let mut dictionary = HashMap::with_capacity(1_000_000);
    let mut rng = Rng(0xDEADBEEF);
    let mut probe = String::new();
    for i in 0..1_000_000u64 {
        let len = 6 + rng.below(35) as usize;
        let mut value = format!("K{i:07}");
        while value.len() < len {
            value.push((b'a' + (rng.below(26) as u8)) as char);
        }
        if i == 42 {
            probe = value.clone();
        }
        dictionary.insert(value, "KEEP".to_owned());
    }
    let rules = vec![dictionary_rule(RuleAction::Keep, "KEEP")];
    let started = Instant::now();
    let index = DictionaryIndex::build(&dictionary, &rules).expect("index");
    let build_elapsed = started.elapsed();
    println!("build 1M keep: {build_elapsed:?} (budget 10s)");
    assert!(build_elapsed.as_secs() <= 10, "build {build_elapsed:?}");

    let snapshot = PolicySnapshot {
        version: 1,
        rules,
        dictionary,
        dictionary_sources: HashMap::new(),
        dictionary_index: Some(index),
        metadata_sources: Vec::new(),
        ready: true,
        policy_id: None,
        dictionary_fingerprint: 0,
    };
    // 1000 строк × 10 колонок: без совпадений + ~1% вставок keep-значения.
    let rows: Vec<Value> = (0..1000u64)
        .map(|row| {
            let cells: Vec<Value> = (0..10)
                .map(|col| {
                    if row % 97 == 0 && col == 0 {
                        json!(format!("значение {probe} внутри"))
                    } else {
                        json!(format!("обычная строка {row} колонка {col} без совпадений"))
                    }
                })
                .collect();
            json!({"columns": cells})
        })
        .collect();
    let input = Value::Array(rows);
    let mappings = MappingStore::new(MappingLimits::default());
    let started = Instant::now();
    let output = engine
        .mask(
            &input,
            Uuid::nil(),
            "bench",
            Uuid::new_v4(),
            3600,
            &snapshot,
            &mappings,
            &json!({}),
        )
        .expect("mask");
    let mask_elapsed = started.elapsed();
    // Бюджет выше основного бенчмарка: keep-автомат — дополнительный
    // проход по каждой строке (Standard, failure-ссылки плотнее).
    println!("mask 1000×10 over 1M keep dict: {mask_elapsed:?} (budget 500ms)");
    assert!(mask_elapsed.as_millis() <= 500, "mask {mask_elapsed:?}");
    // Keep-значение остаётся в тексте, причина зафиксирована.
    let rendered = serde_json::to_string(&output.value).unwrap();
    assert!(rendered.contains(&probe), "keep-значение сохранено");
    assert!(
        output.reasons.iter().any(|code| code == "dictionary:KEEP"),
        "причина зафиксирована: {:?}",
        output.reasons
    );
}
//++agent TASK-225
