//++agent TASK-225 [26.09.2026]
//! Парсер и семантический валидатор файла `masking-setup/v1` (spec §1,
//! §1.3–§1.6, §12). Собирает ВСЕ ошибки (максимум SETUP_MAX_ERRORS,
//! дальше `truncated:true`); при наличии ошибок контент не нормализуется
//! и черновик не создаётся (§4 B4). Предупреждения (§3.6) вычисляет diff
//! — здесь только структурно-семантические ошибки файла.

use serde_json::Value;

use super::{
    content_hash, reason_valid, rule_key, source_key, DatabaseHint, DictionarySourceSpec,
    GeneratedBy, RuleSpec, RuleTestsSpec, SetupIssue, ToolSpec, VersionContent, VersionDictionary,
    SETUP_MAX_ERRORS, SETUP_MAX_RULES, SETUP_MAX_SOURCES, SETUP_MAX_TOOLS, SETUP_SCHEMA,
};

/// Результат успешного разбора файла импорта.
pub(crate) struct ParsedSetup {
    pub content: VersionContent,
    #[allow(dead_code)]
    pub generated_at: String,
    pub generated_by: GeneratedBy,
    pub database_hint: Option<DatabaseHint>,
    /// Сколько positive regex-тестов прогнано (для ответа B4).
    pub regex_tests_passed: usize,
}

/// Итог разбора тела: либо нормализованный контент, либо список ошибок.
pub(crate) struct ParseOutcome {
    pub parsed: Option<ParsedSetup>,
    pub errors: Vec<SetupIssue>,
    #[allow(dead_code)]
    pub truncated: bool,
}

struct Issues {
    list: Vec<SetupIssue>,
    truncated: bool,
}

impl Issues {
    fn new() -> Self {
        Self {
            list: Vec::new(),
            truncated: false,
        }
    }
    fn push(&mut self, code: &str, at: String, message: String, detail: Option<Value>) {
        if self.list.len() >= SETUP_MAX_ERRORS {
            self.truncated = true;
            return;
        }
        self.list.push(SetupIssue {
            code: code.to_string(),
            at,
            message,
            detail,
        });
    }
    fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

/// §1.5: разбор тела. `raw` — байты тела как получены (sha256 считается
/// в B4 от raw; здесь только разбор). Ошибка SETUP_NOT_JSON/SETUP_SCHEMA_*
/// завершает разбор (дальше нет смысла валидировать).
pub(crate) fn parse_setup_body(raw: &[u8]) -> ParseOutcome {
    let mut issues = Issues::new();
    let value: Value = match serde_json::from_slice::<Value>(raw) {
        Ok(value) if value.is_object() => value,
        _ => {
            issues.push(
                "SETUP_NOT_JSON",
                "$".to_string(),
                "тело должно быть UTF-8 JSON-объектом".to_string(),
                None,
            );
            return ParseOutcome {
                parsed: None,
                errors: issues.list,
                truncated: issues.truncated,
            };
        }
    };
    let root = value.as_object().expect("object checked");
    match root.get("schema") {
        Some(Value::String(schema)) if schema == SETUP_SCHEMA => {}
        Some(Value::String(schema)) => {
            issues.push(
                "SETUP_SCHEMA_UNSUPPORTED",
                "$.schema".to_string(),
                format!("неподдерживаемая версия формата: {schema}"),
                Some(serde_json::json!({"supported": [SETUP_SCHEMA]})),
            );
        }
        _ => issues.push(
            "SETUP_SCHEMA_MISSING",
            "$.schema".to_string(),
            "обязательное поле schema отсутствует или не строка".to_string(),
            None,
        ),
    }
    // §1.1/§12: неизвестные поля на любом уровне — строгий формат.
    for key in root.keys() {
        if ![
            "schema",
            "generated_at",
            "generated_by",
            "database_hint",
            "dictionary",
            "rules",
            "tools",
        ]
        .contains(&key.as_str())
        {
            issues.push(
                "SETUP_UNKNOWN_FIELD",
                format!("$.{key}"),
                format!("неизвестное поле: {key}"),
                None,
            );
        }
    }
    // Продолжаем только если схема и верхний уровень чистые — иначе
    // частичный разбор даст лавину вторичных ошибок без смысла.
    if !issues.is_empty() {
        return ParseOutcome {
            parsed: None,
            errors: issues.list,
            truncated: issues.truncated,
        };
    }
    let generated_at = parse_string_required(
        &mut issues,
        root.get("generated_at"),
        "$.generated_at",
        1,
        64,
        "generated_at",
    );
    if let Some(text) = &generated_at {
        if chrono::DateTime::parse_from_rfc3339(text).is_err() {
            issues.push(
                "SETUP_FIELD_INVALID",
                "$.generated_at".to_string(),
                "generated_at: RFC3339 (format date-time)".to_string(),
                None,
            );
        }
    }
    let generated_by = parse_generated_by(&mut issues, root.get("generated_by"));
    let database_hint = parse_database_hint(&mut issues, root.get("database_hint"));
    let dictionary = parse_dictionary(&mut issues, root.get("dictionary"));
    let rules = parse_rules(&mut issues, root.get("rules"));
    let tools = parse_tools(&mut issues, root.get("tools"));

    if !issues.is_empty() {
        return ParseOutcome {
            parsed: None,
            errors: issues.list,
            truncated: issues.truncated,
        };
    }
    let dictionary = dictionary.expect("validated");
    let rules = rules.expect("validated");
    let content = VersionContent {
        dictionary,
        rules: rules.rules,
        tools,
    };
    // Хэш здесь не для ответа (sha256 считается от raw), а как проверка
    // что контент канонизируется — дешёвая страховка единообразия.
    let _ = content_hash(&content);
    ParseOutcome {
        parsed: Some(ParsedSetup {
            content,
            generated_at: generated_at.unwrap_or_default(),
            generated_by: generated_by.expect("validated"),
            database_hint,
            regex_tests_passed: rules.regex_tests_passed,
        }),
        errors: Vec::new(),
        truncated: false,
    }
}

fn parse_string_required(
    issues: &mut Issues,
    value: Option<&Value>,
    at: &str,
    min_len: usize,
    max_len: usize,
    label: &str,
) -> Option<String> {
    match value {
        Some(Value::String(text)) => {
            let len = text.chars().count();
            if len < min_len || len > max_len {
                issues.push(
                    "SETUP_FIELD_INVALID",
                    at.to_string(),
                    format!("{label}: длина {min_len}..{max_len}, фактически {len}"),
                    None,
                );
                None
            } else {
                Some(text.clone())
            }
        }
        _ => {
            issues.push(
                "SETUP_FIELD_INVALID",
                at.to_string(),
                format!("{label}: обязательная строка"),
                None,
            );
            None
        }
    }
}

fn parse_reason(issues: &mut Issues, value: Option<&Value>, at: &str) -> Option<String> {
    match value {
        Some(Value::String(text)) if reason_valid(text) => Some(text.clone()),
        Some(Value::String(text)) => {
            let code = if text.is_empty() {
                "SETUP_REASON_MISSING"
            } else {
                "SETUP_FIELD_INVALID"
            };
            issues.push(
                code,
                at.to_string(),
                "reason: непустая строка 1..500 без управляющих символов кроме \\n".to_string(),
                None,
            );
            None
        }
        _ => {
            issues.push(
                "SETUP_REASON_MISSING",
                at.to_string(),
                "reason обязателен для каждого элемента".to_string(),
                None,
            );
            None
        }
    }
}

fn unknown_fields(
    issues: &mut Issues,
    object: &serde_json::Map<String, Value>,
    at: &str,
    known: &[&str],
) {
    for key in object.keys() {
        if !known.contains(&key.as_str()) {
            issues.push(
                "SETUP_UNKNOWN_FIELD",
                format!("{at}.{key}"),
                format!("неизвестное поле: {key}"),
                None,
            );
        }
    }
}

fn as_object<'a>(
    issues: &mut Issues,
    value: Option<&'a Value>,
    at: &str,
    label: &str,
) -> Option<&'a serde_json::Map<String, Value>> {
    match value {
        Some(Value::Object(map)) => Some(map),
        _ => {
            issues.push(
                "SETUP_FIELD_INVALID",
                at.to_string(),
                format!("{label}: обязателен объект"),
                None,
            );
            None
        }
    }
}

fn parse_generated_by(issues: &mut Issues, value: Option<&Value>) -> Option<GeneratedBy> {
    let map = as_object(issues, value, "$.generated_by", "generated_by")?;
    unknown_fields(
        issues,
        map,
        "$.generated_by",
        &["kind", "name", "tool", "note"],
    );
    let kind = parse_string_required(
        issues,
        map.get("kind"),
        "$.generated_by.kind",
        1,
        16,
        "kind",
    );
    if let Some(kind) = &kind {
        if !["agent", "human", "service"].contains(&kind.as_str()) {
            issues.push(
                "SETUP_FIELD_INVALID",
                "$.generated_by.kind".to_string(),
                "kind ∈ agent|human|service".to_string(),
                None,
            );
        }
    }
    let name = parse_optional_short(issues, map.get("name"), "$.generated_by.name", 128);
    let tool = parse_optional_short(issues, map.get("tool"), "$.generated_by.tool", 128);
    let note = parse_optional_short(issues, map.get("note"), "$.generated_by.note", 500);
    Some(GeneratedBy {
        kind: kind.unwrap_or_else(|| "service".to_string()),
        name,
        tool,
        note,
    })
}

fn parse_optional_short(
    issues: &mut Issues,
    value: Option<&Value>,
    at: &str,
    max_len: usize,
) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if text.chars().count() <= max_len => Some(text.clone()),
        _ => {
            issues.push(
                "SETUP_FIELD_INVALID",
                at.to_string(),
                format!("строка до {max_len} символов"),
                None,
            );
            None
        }
    }
}

fn parse_database_hint(issues: &mut Issues, value: Option<&Value>) -> Option<DatabaseHint> {
    let value = value?;
    if value.is_null() {
        return None;
    }
    let map = as_object(issues, Some(value), "$.database_hint", "database_hint")?;
    unknown_fields(
        issues,
        map,
        "$.database_hint",
        &["id", "label", "source_version"],
    );
    let id = match map.get("id") {
        Some(Value::String(text)) => {
            if uuid::Uuid::parse_str(text).is_err() {
                issues.push(
                    "SETUP_FIELD_INVALID",
                    "$.database_hint.id".to_string(),
                    "id должен быть UUID".to_string(),
                    None,
                );
            }
            Some(text.clone())
        }
        Some(_) => {
            issues.push(
                "SETUP_FIELD_INVALID",
                "$.database_hint.id".to_string(),
                "id должен быть строкой-UUID".to_string(),
                None,
            );
            None
        }
        None => None,
    };
    let label = parse_optional_short(issues, map.get("label"), "$.database_hint.label", 128);
    let source_version = match map.get("source_version") {
        Some(Value::Number(number)) if number.as_i64().is_some_and(|v| v >= 1) => number.as_i64(),
        Some(_) => {
            issues.push(
                "SETUP_FIELD_INVALID",
                "$.database_hint.source_version".to_string(),
                "source_version: целое >= 1".to_string(),
                None,
            );
            None
        }
        None => None,
    };
    Some(DatabaseHint {
        id,
        label,
        source_version,
    })
}

fn parse_dictionary(issues: &mut Issues, value: Option<&Value>) -> Option<VersionDictionary> {
    let map = as_object(issues, value, "$.dictionary", "dictionary")?;
    unknown_fields(issues, map, "$.dictionary", &["mode", "sources"]);
    let mode = parse_string_required(issues, map.get("mode"), "$.dictionary.mode", 1, 8, "mode");
    let mode = match mode.as_deref() {
        Some("all") | Some("part") => mode,
        _ => {
            if mode.is_some() {
                issues.push(
                    "SETUP_FIELD_INVALID",
                    "$.dictionary.mode".to_string(),
                    "mode ∈ all|part".to_string(),
                    None,
                );
            }
            mode.map(|_| "part".to_string())
        }
    };
    let sources_value = match map.get("sources") {
        Some(Value::Array(items)) => Some(items.clone()),
        _ => {
            issues.push(
                "SETUP_FIELD_INVALID",
                "$.dictionary.sources".to_string(),
                "sources: обязательный массив".to_string(),
                None,
            );
            None
        }
    };
    let mut sources = Vec::new();
    if let Some(items) = &sources_value {
        if items.len() > SETUP_MAX_SOURCES {
            issues.push(
                "SETUP_FIELD_INVALID",
                "$.dictionary.sources".to_string(),
                format!("источников больше {SETUP_MAX_SOURCES}"),
                None,
            );
        }
        let mut seen = std::collections::HashSet::new();
        let mut star_count = 0usize;
        for (index, item) in items.iter().enumerate() {
            let at = format!("$.dictionary.sources[{index}]");
            let Some(map) = as_object(issues, Some(item), &at, "источник") else {
                continue;
            };
            unknown_fields(
                issues,
                map,
                &at,
                &[
                    "source_path",
                    "category",
                    "filter",
                    "reason",
                    "estimated_values",
                ],
            );
            let source_path = parse_string_required(
                issues,
                map.get("source_path"),
                &format!("{at}.source_path"),
                1,
                512,
                "source_path",
            );
            if let Some(path) = &source_path {
                if path == "*" {
                    star_count += 1;
                }
                if !seen.insert(source_key(path)) {
                    issues.push(
                        "SETUP_DUPLICATE_SOURCE",
                        format!("{at}.source_path"),
                        format!("источник уже объявлен: {path}"),
                        Some(serde_json::json!({"source_path": path})),
                    );
                }
            }
            let category = parse_string_required(
                issues,
                map.get("category"),
                &format!("{at}.category"),
                1,
                32,
                "category",
            );
            let reason = parse_reason(issues, map.get("reason"), &format!("{at}.reason"));
            let filter_ast = match map.get("filter") {
                //++agent TASK-225 [26.09.2026] D7: `filter:null` в файле
                // ≡ отсутствие фильтра (как у stored-формы) — round-trip
                // экспорт→импорт не должен падать на явном null.
                Some(filter) if filter.is_null() => None,
                Some(filter) => {
                    if crate::storage::valid_filter_ast(filter) {
                        Some(filter.clone())
                    } else {
                        issues.push(
                            "SETUP_FILTER_INVALID",
                            format!("{at}.filter"),
                            "filter не является допустимым filter_ast".to_string(),
                            None,
                        );
                        None
                    }
                }
                None => None,
            };
            let estimated_values = match map.get("estimated_values") {
                Some(Value::Number(number)) if number.as_i64().is_some_and(|v| v >= 0) => {
                    number.as_i64()
                }
                Some(_) => {
                    issues.push(
                        "SETUP_FIELD_INVALID",
                        format!("{at}.estimated_values"),
                        "estimated_values: целое >= 0".to_string(),
                        None,
                    );
                    None
                }
                None => None,
            };
            if let (Some(source_path), Some(category), Some(reason)) =
                (source_path, category, reason)
            {
                sources.push(DictionarySourceSpec {
                    source_path,
                    category,
                    filter_ast,
                    reason,
                    estimated_values,
                });
            }
        }
        // §1.3 SETUP_DICTIONARY_MODE.
        if mode.as_deref() == Some("all") && !(items.len() == 1 && star_count == 1) {
            issues.push(
                "SETUP_DICTIONARY_MODE",
                "$.dictionary".to_string(),
                "mode=all требует ровно один источник с source_path=\"*\"".to_string(),
                None,
            );
        }
        if mode.as_deref() == Some("part") && star_count > 0 {
            issues.push(
                "SETUP_DICTIONARY_MODE",
                "$.dictionary".to_string(),
                "mode=part не допускает источник \"*\"".to_string(),
                None,
            );
        }
    }
    Some(VersionDictionary {
        mode: mode.unwrap_or_else(|| "part".to_string()),
        sources,
    })
}

struct ParsedRules {
    rules: Vec<RuleSpec>,
    regex_tests_passed: usize,
}

fn parse_rules(issues: &mut Issues, value: Option<&Value>) -> Option<ParsedRules> {
    let items = match value {
        Some(Value::Array(items)) => items,
        _ => {
            issues.push(
                "SETUP_FIELD_INVALID",
                "$.rules".to_string(),
                "rules: обязательный массив".to_string(),
                None,
            );
            return Some(ParsedRules {
                rules: Vec::new(),
                regex_tests_passed: 0,
            });
        }
    };
    if items.len() > SETUP_MAX_RULES {
        issues.push(
            "SETUP_FIELD_INVALID",
            "$.rules".to_string(),
            format!("правил больше {SETUP_MAX_RULES}"),
            None,
        );
    }
    let mut rules = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut regex_tests_passed = 0usize;
    for (index, item) in items.iter().enumerate() {
        let at = format!("$.rules[{index}]");
        let Some(map) = as_object(issues, Some(item), &at, "правило") else {
            continue;
        };
        unknown_fields(
            issues,
            map,
            &at,
            &[
                "selector", "value", "action", "category", "priority", "enabled", "reason", "tests",
            ],
        );
        let selector = parse_string_required(
            issues,
            map.get("selector"),
            &format!("{at}.selector"),
            1,
            16,
            "selector",
        );
        let selector = match selector.as_deref() {
            Some("source_path") | Some("name") | Some("type") | Some("dictionary")
            | Some("regex") => selector,
            _ => {
                if selector.is_some() {
                    issues.push(
                        "SETUP_FIELD_INVALID",
                        format!("{at}.selector"),
                        "selector ∈ source_path|name|type|dictionary|regex".to_string(),
                        None,
                    );
                }
                None
            }
        };
        let value_text = parse_string_required(
            issues,
            map.get("value"),
            &format!("{at}.value"),
            1,
            4096,
            "value",
        );
        let action = parse_string_required(
            issues,
            map.get("action"),
            &format!("{at}.action"),
            1,
            8,
            "action",
        );
        let action = match action.as_deref() {
            Some("keep") | Some("mask") | Some("secret") => action,
            _ => {
                if action.is_some() {
                    issues.push(
                        "SETUP_FIELD_INVALID",
                        format!("{at}.action"),
                        "action ∈ keep|mask|secret".to_string(),
                        None,
                    );
                }
                None
            }
        };
        let category = parse_string_required(
            issues,
            map.get("category"),
            &format!("{at}.category"),
            1,
            64,
            "category",
        );
        let priority = match map.get("priority") {
            Some(Value::Number(number)) => {
                let value = number.as_i64();
                if !value.is_some_and(|v| (-1_000_000..=1_000_000).contains(&v)) {
                    issues.push(
                        "SETUP_FIELD_INVALID",
                        format!("{at}.priority"),
                        "priority: целое в диапазоне ±1 000 000".to_string(),
                        None,
                    );
                }
                value.unwrap_or(0)
            }
            Some(_) => {
                issues.push(
                    "SETUP_FIELD_INVALID",
                    format!("{at}.priority"),
                    "priority: целое число".to_string(),
                    None,
                );
                0
            }
            None => 0,
        };
        let enabled = match map.get("enabled") {
            Some(Value::Bool(flag)) => *flag,
            Some(_) => {
                issues.push(
                    "SETUP_FIELD_INVALID",
                    format!("{at}.enabled"),
                    "enabled: булево".to_string(),
                    None,
                );
                true
            }
            None => true,
        };
        let reason = parse_reason(issues, map.get("reason"), &format!("{at}.reason"));

        // Шаблоны §1.6/F4: не-regex селектор допускает только `*` и `*x*`.
        if let (Some(selector), Some(value_text)) = (&selector, &value_text) {
            if selector != "regex" && !pattern_supported(value_text) {
                issues.push(
                    "SETUP_PATTERN_UNSUPPORTED",
                    format!("{at}.value"),
                    format!("шаблон вида {value_text:?} не поддерживается — только `*`, `*x*` или точная строка"),
                    None,
                );
            }
            if !seen.insert((selector.clone(), rule_key(selector, value_text))) {
                issues.push(
                    "SETUP_DUPLICATE_RULE",
                    at.clone(),
                    "правило с таким (selector, value) уже есть".to_string(),
                    Some(serde_json::json!({
                        "selector": selector,
                        "value": value_text,
                    })),
                );
            }
        }

        let tests = parse_rule_tests(issues, map.get("tests"), &at, selector.as_deref());

        // regex: компиляция и прогон тестов (§1.6, F1, валидация тем же
        // движком regex, что и mask-фаза — ограничение размера RegexBuilder).
        if let (Some(selector), Some(value_text)) = (&selector, &value_text) {
            if selector == "regex" {
                match regex::RegexBuilder::new(value_text)
                    .size_limit(1 << 20)
                    .build()
                {
                    Ok(compiled) => {
                        let positive_count = tests
                            .as_ref()
                            .map(|tests| tests.positive.len())
                            .unwrap_or(0);
                        if matches!(action.as_deref(), Some("mask") | Some("secret"))
                            && positive_count == 0
                        {
                            issues.push(
                                "SETUP_REGEX_TESTS_MISSING",
                                format!("{at}.tests"),
                                "regex-правило mask/secret требует хотя бы один tests.match"
                                    .to_string(),
                                None,
                            );
                        }
                        if let Some(tests) = &tests {
                            for (test_index, sample) in tests.positive.iter().enumerate() {
                                if !compiled.is_match(sample) {
                                    issues.push(
                                        "SETUP_REGEX_TEST_FAILED",
                                        format!("{at}.tests.match[{test_index}]"),
                                        "положительный тест не совпал с regex".to_string(),
                                        Some(serde_json::json!({
                                            "kind": "match",
                                            "index": test_index,
                                        })),
                                    );
                                } else {
                                    regex_tests_passed += 1;
                                }
                            }
                            for (test_index, sample) in tests.no_match.iter().enumerate() {
                                if compiled.is_match(sample) {
                                    issues.push(
                                        "SETUP_REGEX_TEST_FAILED",
                                        format!("{at}.tests.no_match[{test_index}]"),
                                        "отрицательный тест совпал с regex".to_string(),
                                        Some(serde_json::json!({
                                            "kind": "no_match",
                                            "index": test_index,
                                        })),
                                    );
                                }
                            }
                        }
                    }
                    Err(_) => issues.push(
                        "SETUP_REGEX_INVALID",
                        format!("{at}.value"),
                        "regex не компилируется".to_string(),
                        None,
                    ),
                }
            }
        }

        if let (Some(selector), Some(value_text), Some(action), Some(category), Some(reason)) =
            (selector, value_text, action, category, reason)
        {
            rules.push(RuleSpec {
                rule_id: None,
                selector,
                value: value_text,
                action,
                category,
                priority,
                enabled,
                reason,
                tests,
            });
        }
    }
    Some(ParsedRules {
        rules,
        regex_tests_passed,
    })
}

fn parse_rule_tests(
    issues: &mut Issues,
    value: Option<&Value>,
    at: &str,
    selector: Option<&str>,
) -> Option<RuleTestsSpec> {
    let value = value?;
    let map = as_object(issues, Some(value), &format!("{at}.tests"), "tests")?;
    unknown_fields(issues, map, &format!("{at}.tests"), &["match", "no_match"]);
    if selector != Some("regex") {
        issues.push(
            "SETUP_TESTS_NOT_REGEX",
            format!("{at}.tests"),
            "tests допустимы только для selector=regex".to_string(),
            None,
        );
        return None;
    }
    let parse_list = |issues: &mut Issues, key: &str| -> Vec<String> {
        match map.get(key) {
            Some(Value::Array(items)) => {
                if items.len() > 20 {
                    issues.push(
                        "SETUP_FIELD_INVALID",
                        format!("{at}.tests.{key}"),
                        "не более 20 строк".to_string(),
                        None,
                    );
                }
                items
                    .iter()
                    .enumerate()
                    .filter_map(|(index, item)| match item {
                        Value::String(text) if text.chars().count() <= 1024 => Some(text.clone()),
                        _ => {
                            issues.push(
                                "SETUP_FIELD_INVALID",
                                format!("{at}.tests.{key}[{index}]"),
                                "строка до 1024 символов".to_string(),
                                None,
                            );
                            None
                        }
                    })
                    .collect()
            }
            Some(_) => {
                issues.push(
                    "SETUP_FIELD_INVALID",
                    format!("{at}.tests.{key}"),
                    "массив строк".to_string(),
                    None,
                );
                Vec::new()
            }
            None => Vec::new(),
        }
    };
    Some(RuleTestsSpec {
        positive: parse_list(issues, "match"),
        no_match: parse_list(issues, "no_match"),
    })
}

fn parse_tools(issues: &mut Issues, value: Option<&Value>) -> Option<Vec<ToolSpec>> {
    let value = value?;
    if value.is_null() {
        return None;
    }
    let items = match value {
        Value::Array(items) => items,
        _ => {
            issues.push(
                "SETUP_FIELD_INVALID",
                "$.tools".to_string(),
                "tools: массив".to_string(),
                None,
            );
            return None;
        }
    };
    if items.len() > SETUP_MAX_TOOLS {
        issues.push(
            "SETUP_FIELD_INVALID",
            "$.tools".to_string(),
            format!("инструментов больше {SETUP_MAX_TOOLS}"),
            None,
        );
    }
    let mut tools = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (index, item) in items.iter().enumerate() {
        let at = format!("$.tools[{index}]");
        let Some(map) = as_object(issues, Some(item), &at, "инструмент") else {
            continue;
        };
        unknown_fields(issues, map, &at, &["tool", "mode", "reason"]);
        let tool = parse_string_required(
            issues,
            map.get("tool"),
            &format!("{at}.tool"),
            1,
            128,
            "tool",
        );
        if let Some(name) = &tool {
            if !name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':' | '-'))
            {
                issues.push(
                    "SETUP_FIELD_INVALID",
                    format!("{at}.tool"),
                    "tool: ^[A-Za-z0-9_.:-]{1,128}$".to_string(),
                    None,
                );
            }
            if !seen.insert(name.clone()) {
                issues.push(
                    "SETUP_DUPLICATE_TOOL",
                    format!("{at}.tool"),
                    format!("инструмент уже объявлен: {name}"),
                    None,
                );
            }
        }
        let mode = parse_string_required(
            issues,
            map.get("mode"),
            &format!("{at}.mode"),
            1,
            32,
            "mode",
        );
        let mode = match mode.as_deref() {
            Some("data-mask") | Some("no-mask") | Some("deny-pending-review") => mode,
            _ => {
                if mode.is_some() {
                    issues.push(
                        "SETUP_FIELD_INVALID",
                        format!("{at}.mode"),
                        "mode ∈ data-mask|no-mask|deny-pending-review".to_string(),
                        None,
                    );
                }
                None
            }
        };
        let reason = parse_reason(issues, map.get("reason"), &format!("{at}.reason"));
        if let (Some(tool), Some(mode), Some(reason)) = (tool, mode, reason) {
            tools.push(ToolSpec { tool, mode, reason });
        }
    }
    Some(tools)
}

/// §1.6/F4: для шаблонных селекторов поддерживаются только `*` (все) и
/// `*x*` (содержит); `*` в середине иначе — точная строка со `*` внутри,
/// но формы `x*`, `*x`, `*x*y*` запрещены явно как «неподдерживаемый
/// шаблон» (понятная ошибка вместо тихого точного совпадения).
fn pattern_supported(value: &str) -> bool {
    if !value.contains('*') {
        return true;
    }
    if value == "*" {
        return true;
    }
    value.starts_with('*')
        && value.ends_with('*')
        && value.len() > 2
        && !value[1..value.len() - 1].contains('*')
}
//++agent TASK-225

//++agent TASK-225 [26.09.2026]
// T1 (§9): unit-уровень парсера — схема, семантика §1.3, сбор всех
// ошибок одной стадии, точные пути `at`, детали без значений
// (T1-05), обрезка по SETUP_MAX_ERRORS.
#[cfg(test)]
mod tests {
    use super::*;

    fn base_body() -> Value {
        serde_json::json!({
            "schema": SETUP_SCHEMA,
            "generated_at": "2026-09-26T00:00:00Z",
            "generated_by": {"kind": "agent", "name": "t"},
            "dictionary": {
                "mode": "part",
                "sources": [
                    {
                        "source_path": "Справочник.ФизЛица.НаименованиеПолное",
                        "category": "FIO",
                        "reason": "ПДн"
                    }
                ]
            },
            "rules": [
                {
                    "selector": "name",
                    "value": "*ФИО*",
                    "action": "mask",
                    "category": "FIO",
                    "reason": "ПДн"
                },
                {
                    "selector": "regex",
                    "value": "\\d{3}-\\d{3}",
                    "action": "mask",
                    "category": "DOC",
                    "reason": "документ",
                    "tests": {"match": ["123-456"], "no_match": ["abc"]}
                }
            ],
            "tools": [
                {"tool": "query_run", "mode": "data-mask", "reason": "маскирование"}
            ]
        })
    }

    fn codes(outcome: &ParseOutcome) -> Vec<&str> {
        outcome
            .errors
            .iter()
            .map(|issue| issue.code.as_str())
            .collect()
    }

    fn find_issue<'a>(outcome: &'a ParseOutcome, code: &str) -> Option<&'a SetupIssue> {
        outcome.errors.iter().find(|issue| issue.code == code)
    }

    fn mutate(body: &mut Value, pointer: &str, value: Value) {
        let (parent_path, key) = pointer.rsplit_once('/').expect("pointer");
        if let Some(slot) = body.pointer_mut(pointer) {
            *slot = value;
            return;
        }
        let parent = body.pointer_mut(parent_path).expect("parent");
        match parent {
            Value::Object(map) => {
                map.insert(key.to_string(), value);
            }
            Value::Array(items) => {
                let index: usize = key.parse().expect("array index");
                if index == items.len() {
                    items.push(value);
                } else {
                    items[index] = value;
                }
            }
            _ => panic!("parent not container: {parent_path}"),
        }
    }

    // T1-01 (unit): валидный файл разбирается, счётчики верны.
    #[test]
    fn valid_file_parses() {
        let body = serde_json::to_vec(&base_body()).unwrap();
        let outcome = parse_setup_body(&body);
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        let parsed = outcome.parsed.expect("parsed");
        assert_eq!(parsed.content.dictionary.sources.len(), 1);
        assert_eq!(parsed.content.rules.len(), 2);
        assert_eq!(parsed.content.tools.as_ref().map(Vec::len), Some(1));
        assert_eq!(parsed.regex_tests_passed, 1);
    }

    // T1-02 (unit): схема — коды раннего выхода и пути.
    #[test]
    fn not_json_is_rejected_at_root() {
        let outcome = parse_setup_body(b"{not json");
        assert!(outcome.parsed.is_none());
        assert_eq!(codes(&outcome), vec!["SETUP_NOT_JSON"]);
        assert_eq!(outcome.errors[0].at, "$");
    }

    #[test]
    fn non_object_json_is_rejected_at_root() {
        let outcome = parse_setup_body(b"[1,2]");
        assert_eq!(codes(&outcome), vec!["SETUP_NOT_JSON"]);
        assert_eq!(outcome.errors[0].at, "$");
    }

    #[test]
    fn schema_missing_and_non_string() {
        for schema in [Value::Null, Value::from(1)] {
            let mut body = serde_json::json!({"schema": schema, "rules": []});
            let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
            assert_eq!(codes(&outcome), vec!["SETUP_SCHEMA_MISSING"]);
            assert_eq!(outcome.errors[0].at, "$.schema");
            body["x"] = Value::Null; // mute unused assignment warning
        }
        let mut body = serde_json::json!({"rules": []});
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        assert_eq!(codes(&outcome), vec!["SETUP_SCHEMA_MISSING"]);
        body["schema"] = Value::from(SETUP_SCHEMA);
    }

    #[test]
    fn schema_unsupported_lists_supported() {
        let mut body = base_body();
        mutate(&mut body, "/schema", Value::from("masking-setup/v2"));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_SCHEMA_UNSUPPORTED").expect("code");
        assert_eq!(found.at, "$.schema");
        assert_eq!(
            found.detail,
            Some(serde_json::json!({"supported": [SETUP_SCHEMA]}))
        );
    }

    #[test]
    fn unknown_fields_reported_top_and_nested() {
        // Верхний уровень: ранний выход — только верхнеуровневые ошибки.
        let mut body = base_body();
        body["bogus"] = Value::from(1);
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        assert_eq!(codes(&outcome), vec!["SETUP_UNKNOWN_FIELD"]);
        assert_eq!(outcome.errors[0].at, "$.bogus");

        // Вложенный уровень: собирается в общей фазе.
        let mut body = base_body();
        mutate(&mut body, "/rules/0/bogus", Value::from(1));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_UNKNOWN_FIELD").expect("code");
        assert_eq!(found.at, "$.rules[0].bogus");
    }

    // T1-02 (unit): каждый код §1.3 — отдельным кейсом, код + путь.
    #[test]
    fn field_invalid_paths() {
        // Невалидный enum mode.
        let mut body = base_body();
        mutate(&mut body, "/dictionary/mode", Value::from("bogus"));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_FIELD_INVALID").expect("code");
        assert_eq!(found.at, "$.dictionary.mode");

        // generated_at не RFC3339.
        let mut body = base_body();
        mutate(&mut body, "/generated_at", Value::from("не дата"));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_FIELD_INVALID").expect("code");
        assert_eq!(found.at, "$.generated_at");

        // priority вне диапазона.
        let mut body = base_body();
        mutate(&mut body, "/rules/0/priority", Value::from(2_000_000));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_FIELD_INVALID").expect("code");
        assert_eq!(found.at, "$.rules[0].priority");

        // Нет generated_at — обязательное поле.
        let mut body = base_body();
        body.as_object_mut().unwrap().remove("generated_at");
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_FIELD_INVALID").expect("code");
        assert_eq!(found.at, "$.generated_at");
    }

    #[test]
    fn reason_missing_absent_and_empty() {
        // Нет reason у источника.
        let mut body = base_body();
        body.pointer_mut("/dictionary/sources/0")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("reason");
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_REASON_MISSING").expect("code");
        assert_eq!(found.at, "$.dictionary.sources[0].reason");

        // Пустой reason у правила.
        let mut body = base_body();
        mutate(&mut body, "/rules/0/reason", Value::from(""));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_REASON_MISSING").expect("code");
        assert_eq!(found.at, "$.rules[0].reason");
    }

    #[test]
    fn dictionary_mode_both_directions() {
        // mode=all без ровно одного источника "*".
        let mut body = base_body();
        mutate(&mut body, "/dictionary/mode", Value::from("all"));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_DICTIONARY_MODE").expect("code");
        assert_eq!(found.at, "$.dictionary");

        // mode=part с источником "*".
        let mut body = base_body();
        mutate(
            &mut body,
            "/dictionary/sources/0/source_path",
            Value::from("*"),
        );
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_DICTIONARY_MODE").expect("code");
        assert_eq!(found.at, "$.dictionary");

        // mode=all + ровно один "*" — допустимо (ОВ-5).
        let mut body = base_body();
        mutate(&mut body, "/dictionary/mode", Value::from("all"));
        mutate(
            &mut body,
            "/dictionary/sources/0/source_path",
            Value::from("*"),
        );
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        assert!(
            find_issue(&outcome, "SETUP_DICTIONARY_MODE").is_none(),
            "{:?}",
            outcome.errors
        );
    }

    #[test]
    fn duplicate_source_case_insensitive() {
        let mut body = base_body();
        body.pointer_mut("/dictionary/sources")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "source_path": "справочник.физлица.наименованиеполное",
                "category": "FIO",
                "reason": "дубль"
            }));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_DUPLICATE_SOURCE").expect("code");
        assert_eq!(found.at, "$.dictionary.sources[1].source_path");
    }

    #[test]
    fn filter_invalid_ast() {
        let mut body = base_body();
        mutate(
            &mut body,
            "/dictionary/sources/0/filter",
            serde_json::json!({"op": "bogus"}),
        );
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_FILTER_INVALID").expect("code");
        assert_eq!(found.at, "$.dictionary.sources[0].filter");
    }

    // T1-04: `*.Код` и `Справочник.*` отклоняются; `*код*` и `*` проходят.
    #[test]
    fn pattern_unsupported_forms() {
        for value in ["*.Код", "Справочник.*", "x*y*z"] {
            let mut body = base_body();
            mutate(&mut body, "/rules/0/value", Value::from(value));
            let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
            let found = find_issue(&outcome, "SETUP_PATTERN_UNSUPPORTED")
                .unwrap_or_else(|| panic!("{value}: {:#?}", outcome.errors));
            assert_eq!(found.at, "$.rules[0].value");
        }
        for value in ["*код*", "*", "точная строка"] {
            let mut body = base_body();
            mutate(&mut body, "/rules/0/value", Value::from(value));
            let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
            assert!(
                find_issue(&outcome, "SETUP_PATTERN_UNSUPPORTED").is_none(),
                "{value}: {:?}",
                outcome.errors
            );
        }
    }

    #[test]
    fn regex_invalid_compile() {
        let mut body = base_body();
        mutate(&mut body, "/rules/1/value", Value::from("(незакрытая"));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_REGEX_INVALID").expect("code");
        assert_eq!(found.at, "$.rules[1].value");
    }

    // T1-05: detail провального regex-теста не содержит саму строку.
    #[test]
    fn regex_test_failed_without_sample_leak() {
        let mut body = base_body();
        mutate(
            &mut body,
            "/rules/1/tests",
            serde_json::json!({"match": ["ЗНАЧЕНИЕ-СЕКРЕТ-123"], "no_match": ["123-456"]}),
        );
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let issues: Vec<&SetupIssue> = outcome
            .errors
            .iter()
            .filter(|issue| issue.code == "SETUP_REGEX_TEST_FAILED")
            .collect();
        assert_eq!(issues.len(), 2);
        let positive = issues
            .iter()
            .find(|issue| issue.at == "$.rules[1].tests.match[0]")
            .expect("match issue");
        let negative = issues
            .iter()
            .find(|issue| issue.at == "$.rules[1].tests.no_match[0]")
            .expect("no_match issue");
        assert_eq!(
            positive.detail,
            Some(serde_json::json!({"kind": "match", "index": 0}))
        );
        assert_eq!(
            negative.detail,
            Some(serde_json::json!({"kind": "no_match", "index": 0}))
        );
        // Значение примера не протекает ни в detail, ни в message.
        let serialized = serde_json::to_string(&outcome.errors).unwrap();
        assert!(!serialized.contains("ЗНАЧЕНИЕ-СЕКРЕТ-123"));
    }

    #[test]
    fn tests_on_non_regex_rule() {
        let mut body = base_body();
        mutate(
            &mut body,
            "/rules/0/tests",
            serde_json::json!({"match": ["x"]}),
        );
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_TESTS_NOT_REGEX").expect("code");
        assert_eq!(found.at, "$.rules[0].tests");
    }

    #[test]
    fn regex_mask_requires_positive_tests() {
        // mask regex без tests → REGEX_TESTS_MISSING.
        let mut body = base_body();
        body.pointer_mut("/rules/1")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("tests");
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_REGEX_TESTS_MISSING").expect("code");
        assert_eq!(found.at, "$.rules[1].tests");

        // keep regex без tests — допустимо.
        let mut body = base_body();
        mutate(&mut body, "/rules/1/action", Value::from("keep"));
        body.pointer_mut("/rules/1")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("tests");
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        assert!(find_issue(&outcome, "SETUP_REGEX_TESTS_MISSING").is_none());
    }

    #[test]
    fn duplicate_rule_identity() {
        let mut body = base_body();
        body.pointer_mut("/rules")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "selector": "name",
                "value": "*ФИО*",
                "action": "mask",
                "category": "FIO",
                "reason": "дубль"
            }));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_DUPLICATE_RULE").expect("code");
        assert_eq!(found.at, "$.rules[2]");
    }

    #[test]
    fn duplicate_tool_name() {
        let mut body = base_body();
        body.pointer_mut("/tools")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "tool": "query_run",
                "mode": "data-mask",
                "reason": "дубль"
            }));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        let found = find_issue(&outcome, "SETUP_DUPLICATE_TOOL").expect("code");
        assert_eq!(found.at, "$.tools[1].tool");
    }

    // T1-03 (unit): файл с тремя разными ошибками — все три в errors[].
    #[test]
    fn all_errors_of_one_stage_collected() {
        let mut body = base_body();
        mutate(&mut body, "/dictionary/mode", Value::from("bogus")); // FIELD_INVALID
        mutate(&mut body, "/rules/0/value", Value::from("*.Код")); // PATTERN_UNSUPPORTED
        mutate(&mut body, "/tools/0/tool", Value::from("bad tool!")); // FIELD_INVALID
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        assert!(outcome.parsed.is_none());
        let codes = codes(&outcome);
        for expected in ["SETUP_FIELD_INVALID", "SETUP_PATTERN_UNSUPPORTED"] {
            assert!(codes.contains(&expected), "{expected}: {codes:?}");
        }
        assert!(outcome.errors.len() >= 3, "{:?}", outcome.errors);
    }

    // §1.5: ошибки сверх лимита обрезаются с флагом truncated.
    #[test]
    fn errors_truncated_at_limit() {
        let mut body = base_body();
        let mut rules = Vec::new();
        for index in 0..(SETUP_MAX_ERRORS + 10) {
            rules.push(serde_json::json!({
                "selector": "name",
                "value": format!("*v{index}*"),
                "action": "mask",
                "category": "C",
                // reason отсутствует — по ошибке на правило.
            }));
        }
        mutate(&mut body, "/rules", Value::Array(rules));
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        assert!(outcome.truncated);
        assert_eq!(outcome.errors.len(), SETUP_MAX_ERRORS);
    }

    //++agent TASK-225 [26.09.2026] L R4-8: переименованный класс
    // (миграция 0015) в файле отвергается — обратной совместимости со
    // старым именем нет.
    #[test]
    fn tool_mode_metadata_bypass_rejected() {
        let mut body = base_body();
        mutate(
            &mut body,
            "/tools",
            serde_json::json!([{
                "tool": "execute_query",
                "mode": "metadata-bypass",
                "reason": "старое имя"
            }]),
        );
        let outcome = parse_setup_body(&serde_json::to_vec(&body).unwrap());
        assert!(outcome.parsed.is_none());
        let found = find_issue(&outcome, "SETUP_FIELD_INVALID").expect("code");
        assert_eq!(found.at, "$.tools[0].mode");
    }
    //++agent TASK-225
}
//++agent TASK-225
