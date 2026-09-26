//++agent TASK-225 [26.09.2026]
//! Чистый diff версий настройки (spec §3): на входе два снимка контента
//! (from — active/N, to — draft/N/пустой), на выходе — детерминированные
//! изменения с классификацией (§3.2) и предупреждения (§3.6). Никакого
//! I/O — контекст (manifest, статистика источников, известные инструменты)
//! приходит снаружи; отсутствие manifest — MANIFEST_UNAVAILABLE, а не
//! тихий пропуск проверки путей.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use super::{
    canonical_value_bytes, change_id, rule_key, sha256_bytes_hex, source_key, ChangeClass,
    SetupChange, SetupWarning, ToolSpec, VersionContent,
};

/// Контекст diff — всё внешнее, что нужно для предупреждений §3.6.
pub(crate) struct DiffContext {
    /// Пути источников актуального manifest (lowercase). `None` —
    /// manifest недоступен → предупреждение MANIFEST_UNAVAILABLE, проверка
    /// путей не выполняется (fail-open по путям, но фиксируем).
    pub manifest_paths: Option<HashSet<String>>,
    //++agent TASK-225 [26.09.2026] §3.4/M-3
    /// Пути manifest, проходящие базовые критерии F9 (класс, строковый
    /// тип, не пароль, не секрет), в исходном регистре; allowlist
    /// mask-правил применяется отдельно по правилам каждой версии.
    /// `None` — manifest недоступен → S(all) = UNKNOWN
    /// (DICTIONARY_MODE_UNVERIFIABLE).
    pub manifest_expandable: Option<HashSet<String>>,
    //++agent TASK-225
    /// Известные инструменты (tool_classifications) для TOOL_NOT_SEEN.
    pub known_tools: Option<HashSet<String>>,
    //++agent TASK-225 [26.09.2026] §3.5/M-2: текущие режимы
    /// tool_classifications (tool → class); `before` берётся отсюда,
    /// а не из снимка версии `from`.
    pub tool_modes: Option<HashMap<String, String>>,
    //++agent TASK-225
    /// source_path(lowercase) → статистика последнего pull (§5a.3);
    /// нужен для SOURCE_LARGE.
    pub source_stats: Option<HashMap<String, super::SourceStat>>,
    /// Импорт: database_hint.id задан и не совпал с целевой базой.
    pub database_mismatch: bool,
}

/// Результат diff.
pub(crate) struct SetupDiff {
    pub changes: Vec<SetupChange>,
    pub warnings: Vec<SetupWarning>,
}

/// Ранг действия по строгости (больше — жёстче): согласован с порядком
/// `RuleAction` в движке и с §3.5 для инструментов.
fn action_rank(action: &str) -> i64 {
    match action {
        "secret" => 3,
        "mask" => 2,
        "keep" => 1,
        _ => 0,
    }
}

/// Покрытие шаблонов F4: `covers(a,b)` — всё, что матчит `b`, матчит и `a`.
/// Реализованы только доказуемые случаи; regex не покрывается (§3.3:
/// coverage regex не вычислим — изменения regex идут как added/removed).
fn covers(pattern: &str, other: &str) -> bool {
    if pattern == other {
        return true;
    }
    if pattern == "*" {
        return true;
    }
    let part = |p: &str| -> Option<String> {
        if p.len() > 2 && p.starts_with('*') && p.ends_with('*') {
            Some(p[1..p.len() - 1].to_lowercase())
        } else {
            None
        }
    };
    match (part(pattern), part(other)) {
        (Some(a), Some(b)) => b.contains(&a),
        (Some(a), None) => {
            if other == "*" {
                false
            } else {
                other.to_lowercase().contains(&a)
            }
        }
        (None, _) => false,
    }
}

/// §3.6: `id = "w_" + hex16(sha256(kind | canonical(subject)))`.
fn warning(
    kind: &str,
    subject: Value,
    label: String,
    detail: Option<Value>,
    excludable: bool,
) -> SetupWarning {
    let id = format!(
        "w_{}",
        &sha256_bytes_hex(&[kind.as_bytes(), b"|", &canonical_value_bytes(&subject)].concat())
            [..16]
    );
    SetupWarning {
        id,
        kind: kind.to_string(),
        subject,
        label,
        detail,
        excludable,
    }
}

fn change(
    area: &str,
    kind: &str,
    change_class: ChangeClass,
    label: String,
    subject: Value,
    before: Value,
    after: Value,
) -> SetupChange {
    SetupChange {
        id: change_id(kind, &subject, &before, &after),
        area: area.to_string(),
        kind: kind.to_string(),
        change_class,
        label,
        subject: Some(subject),
        before: if before.is_null() { None } else { Some(before) },
        after: if after.is_null() { None } else { Some(after) },
        detail: None,
        warning_ids: Vec::new(),
    }
}

fn rule_json(rule: &super::RuleSpec) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("selector".into(), rule.selector.clone().into());
    map.insert("value".into(), rule.value.clone().into());
    map.insert("action".into(), rule.action.clone().into());
    map.insert("category".into(), rule.category.clone().into());
    map.insert("priority".into(), rule.priority.into());
    map.insert("enabled".into(), rule.enabled.into());
    map.insert("reason".into(), rule.reason.clone().into());
    if let Some(tests) = &rule.tests {
        map.insert(
            "tests".into(),
            serde_json::to_value(tests).unwrap_or(Value::Null),
        );
    }
    Value::Object(map)
}

fn source_json(source: &super::DictionarySourceSpec) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("source_path".into(), source.source_path.clone().into());
    map.insert("category".into(), source.category.clone().into());
    map.insert("reason".into(), source.reason.clone().into());
    if let Some(filter) = &source.filter_ast {
        map.insert("filter_ast".into(), filter.clone());
    }
    if let Some(estimated) = source.estimated_values {
        map.insert("estimated_values".into(), estimated.into());
    }
    Value::Object(map)
}

fn tool_json(tool: &ToolSpec) -> Value {
    serde_json::json!({"tool": tool.tool, "mode": tool.mode, "reason": tool.reason})
}

/// §3: diff контента. Порядок обхода детерминирован (BTreeMap, сортировки)
/// — id изменений и порядок в ответе воспроизводимы.
pub(crate) fn compute_diff(
    from: &VersionContent,
    to: &VersionContent,
    context: &DiffContext,
) -> SetupDiff {
    let mut changes = Vec::new();
    let mut warnings = Vec::new();

    diff_rules(from, to, &mut changes, &mut warnings);
    diff_dictionary(from, to, &mut changes, &mut warnings, context);
    diff_tools(from, to, &mut changes, context);
    collect_warnings(from, to, context, &mut warnings);
    SetupDiff { changes, warnings }
}

/// §3.2: переходы effective-действия для source_path/name/type/dictionary.
fn transition_kind(before: &str, after: &str) -> Option<(&'static str, ChangeClass)> {
    use ChangeClass::*;
    Some(match (before, after) {
        ("none", "keep") => ("KEEP_ADDED", Weakening),
        ("none", "mask") => ("MASK_ADDED", Strengthening),
        ("none", "secret") => ("SECRET_ADDED", Strengthening),
        ("mask", "none") => ("MASK_REMOVED", Weakening),
        ("secret", "none") => ("SECRET_REMOVED", Weakening),
        ("secret", "mask") => ("SECRET_TO_MASK", Weakening),
        ("mask", "keep") => ("MASK_TO_KEEP", Weakening),
        ("secret", "keep") => ("SECRET_TO_KEEP", Weakening),
        ("mask", "secret") => ("MASK_TO_SECRET", Strengthening),
        ("keep", "none") => ("KEEP_REMOVED", Strengthening),
        ("keep", "mask") => ("KEEP_TO_MASK", Strengthening),
        ("keep", "secret") => ("KEEP_TO_SECRET", Strengthening),
        _ => return None,
    })
}

/// §3.2 поглощение: удаление mask/secret идентичности R — neutral
/// PATTERN_REPLACED, если в `to` есть enabled-правило того же селектора
/// с действием ≥ действия R и шаблоном, покрывающим R.
fn removal_absorbed(
    removed: &super::RuleSpec,
    to_rules: &[super::RuleSpec],
) -> Option<super::RuleSpec> {
    to_rules
        .iter()
        .filter(|rule| {
            rule.enabled
                && rule.selector == removed.selector
                && rule_key(&rule.selector, &rule.value)
                    != rule_key(&removed.selector, &removed.value)
                && action_rank(&rule.action) >= action_rank(&removed.action)
                && covers(&rule.value, &removed.value)
        })
        .max_by_key(|rule| (action_rank(&rule.action), rule.priority))
        .cloned()
}

/// §3.2 поглощение для KEEP_ADDED: добавление keep A — neutral
/// PATTERN_REPLACED, если в `from` было enabled keep того же селектора
/// с шаблоном, покрывающим A.
fn keep_addition_absorbed(
    added: &super::RuleSpec,
    from_rules: &[super::RuleSpec],
) -> Option<super::RuleSpec> {
    from_rules
        .iter()
        .find(|rule| {
            rule.enabled
                && rule.selector == added.selector
                && rule.action == "keep"
                && covers(&rule.value, &added.value)
        })
        .cloned()
}

/// §3.2/§3.3: правила. Идентичность — (selector, key); effective-состояние
/// — самое строгое действие среди enabled (§3.1). Пары расширение/сужение
/// шаблонов собираются после поштучной классификации.
fn diff_rules(
    from: &VersionContent,
    to: &VersionContent,
    changes: &mut Vec<SetupChange>,
    warnings: &mut Vec<SetupWarning>,
) {
    let index = |rules: &[super::RuleSpec]| -> BTreeMap<(String, String), Vec<super::RuleSpec>> {
        let mut map: BTreeMap<(String, String), Vec<super::RuleSpec>> = BTreeMap::new();
        for rule in rules {
            map.entry((rule.selector.clone(), rule_key(&rule.selector, &rule.value)))
                .or_default()
                .push(rule.clone());
        }
        map
    };
    let from_rules = index(&from.rules);
    let to_rules = index(&to.rules);

    // effective действие идентичности: максимум по рангу среди enabled,
    // при равенстве — больше priority (то же, что в движке F5).
    let effective = |rules: Option<&Vec<super::RuleSpec>>| -> Option<super::RuleSpec> {
        rules.and_then(|rules| {
            rules
                .iter()
                .filter(|rule| rule.enabled)
                .max_by_key(|rule| (action_rank(&rule.action), rule.priority))
                .cloned()
        })
    };

    //++agent TASK-225 [26.09.2026] M-3: коды/классы по таблицам §3.2-3.3.
    let mut removed: Vec<super::RuleSpec> = Vec::new();
    let mut added: Vec<super::RuleSpec> = Vec::new();

    let mut identities: BTreeMap<(String, String), ()> = BTreeMap::new();
    for key in from_rules.keys().chain(to_rules.keys()) {
        identities.insert(key.clone(), ());
    }
    for (identity, _) in identities {
        let (selector, key) = &identity;
        let eff_from = effective(from_rules.get(&identity));
        let eff_to = effective(to_rules.get(&identity));
        let raw_from = from_rules.get(&identity).map(|rules| &rules[0]);
        let raw_to = to_rules.get(&identity).map(|rules| &rules[0]);
        let subject = serde_json::json!({"area":"rule","selector":selector,"key":key});
        if selector == "regex" {
            // §3.3: regex — идентичность точная, coverage не вычисляется.
            let b = eff_from
                .as_ref()
                .map(|rule| rule.action.as_str())
                .unwrap_or("none");
            let a = eff_to
                .as_ref()
                .map(|rule| rule.action.as_str())
                .unwrap_or("none");
            let raw_changed = raw_from
                .zip(raw_to)
                .is_some_and(|(x, y)| rule_json(x) != rule_json(y));
            if b == "keep" || a == "keep" {
                if b != a || raw_changed {
                    let mut item = change(
                        "rule",
                        "REGEX_KEEP",
                        ChangeClass::Neutral,
                        format!(
                            "Regex {}: keep-правки без эффекта (F7)",
                            raw_to
                                .or(raw_from)
                                .map(|r| r.value.as_str())
                                .unwrap_or_default()
                        ),
                        subject.clone(),
                        eff_from.as_ref().map(rule_json).unwrap_or(Value::Null),
                        eff_to.as_ref().map(rule_json).unwrap_or(Value::Null),
                    );
                    attach_regex_keep_warning(
                        &mut item,
                        eff_to.as_ref().or(eff_from.as_ref()).unwrap(),
                        warnings,
                        false,
                    );
                    changes.push(item);
                }
                continue;
            }
            let transition = match (b, a) {
                (x, y) if x == y => None,
                ("none", "mask") => Some(("MASK_ADDED", ChangeClass::Strengthening)),
                ("none", "secret") => Some(("SECRET_ADDED", ChangeClass::Strengthening)),
                ("mask", "none") | ("secret", "none") => {
                    Some(("REGEX_REMOVED", ChangeClass::Weakening))
                }
                ("secret", "mask") => Some(("SECRET_TO_MASK", ChangeClass::Weakening)),
                ("mask", "secret") => Some(("MASK_TO_SECRET", ChangeClass::Strengthening)),
                _ => Some(("REGEX_REMOVED", ChangeClass::Weakening)),
            };
            if let Some((kind, class)) = transition {
                let mut item = change(
                    "rule",
                    kind,
                    class,
                    format!("Regex: действие {b} → {a}"),
                    subject.clone(),
                    eff_from.as_ref().map(rule_json).unwrap_or(Value::Null),
                    eff_to.as_ref().map(rule_json).unwrap_or(Value::Null),
                );
                // Удаление mask-regex требует подтверждения; keep-ветка
                // отсечена выше — здесь только осмысленные переходы.
                if kind == "REGEX_REMOVED" {
                    if let Some(before) = &eff_from {
                        attach_regex_keep_warning(&mut item, before, warnings, true);
                    }
                }
                changes.push(item);
            } else if raw_changed {
                // §3.3: то же действие — tests/reason правки neutral.
                let tests_changed = raw_from
                    .zip(raw_to)
                    .is_some_and(|(x, y)| x.tests != y.tests);
                changes.push(change(
                    "rule",
                    if tests_changed {
                        "TESTS_CHANGED"
                    } else {
                        "REASON_CHANGED"
                    },
                    ChangeClass::Neutral,
                    "Regex: уточнение без смены действия".to_string(),
                    subject.clone(),
                    raw_from.map(rule_json).unwrap_or(Value::Null),
                    raw_to.map(rule_json).unwrap_or(Value::Null),
                ));
            }
            continue;
        }
        match (eff_from, eff_to) {
            (Some(before), Some(after)) => {
                let b = before.action.as_str();
                let a = after.action.as_str();
                if let Some((kind, class)) = transition_kind(b, a) {
                    changes.push(change(
                        "rule",
                        kind,
                        class,
                        format!(
                            "{} {}: действие {} → {}",
                            selector_label(selector),
                            before.value,
                            b,
                            a
                        ),
                        subject.clone(),
                        rule_json(&before),
                        rule_json(&after),
                    ));
                } else {
                    // То же эффективное действие — нейтральные правки.
                    let raw_changed = raw_from
                        .zip(raw_to)
                        .is_some_and(|(x, y)| rule_json(x) != rule_json(y));
                    if before.category != after.category && selector != "dictionary" {
                        changes.push(change(
                            "rule",
                            "CATEGORY_CHANGED",
                            ChangeClass::Neutral,
                            format!(
                                "{} {}: категория {} → {}",
                                selector_label(selector),
                                before.value,
                                before.category,
                                after.category
                            ),
                            subject.clone(),
                            rule_json(&before),
                            rule_json(&after),
                        ));
                    } else if before.priority != after.priority {
                        changes.push(change(
                            "rule",
                            "PRIORITY_CHANGED",
                            ChangeClass::Neutral,
                            format!(
                                "{} {}: приоритет {} → {}",
                                selector_label(selector),
                                before.value,
                                before.priority,
                                after.priority
                            ),
                            subject.clone(),
                            rule_json(&before),
                            rule_json(&after),
                        ));
                    } else if raw_changed {
                        changes.push(change(
                            "rule",
                            "REASON_CHANGED",
                            ChangeClass::Neutral,
                            format!(
                                "{} {}: уточнение без смены покрытия",
                                selector_label(selector),
                                before.value
                            ),
                            subject.clone(),
                            rule_json(&before),
                            rule_json(&after),
                        ));
                    }
                }
            }
            (Some(before), None) => removed.push(before),
            (None, Some(after)) => added.push(after),
            (None, None) => {
                if raw_from
                    .zip(raw_to)
                    .is_some_and(|(x, y)| rule_json(x) != rule_json(y))
                {
                    changes.push(change(
                        "rule",
                        "REASON_CHANGED",
                        ChangeClass::Neutral,
                        format!(
                            "{} {}: уточнение без смены покрытия",
                            selector_label(selector),
                            raw_from.map(|r| r.value.as_str()).unwrap_or_default()
                        ),
                        subject.clone(),
                        raw_from.map(rule_json).unwrap_or(Value::Null),
                        raw_to.map(rule_json).unwrap_or(Value::Null),
                    ));
                }
            }
        }
    }

    // §3.2 пары: удалённая R и добавленная A одного селектора с
    // одинаковым действием — одно изменение при строгом покрытии.
    // Жадно по порядку идентичностей; regex пар не имеет.
    let mut paired_added: HashSet<usize> = HashSet::new();
    let mut removal_changes = Vec::new();
    for before in &removed {
        let mut pair: Option<usize> = None;
        if before.selector != "regex" {
            for (index, after) in added.iter().enumerate() {
                if paired_added.contains(&index)
                    || after.selector != before.selector
                    || after.action != before.action
                {
                    continue;
                }
                let strict_after =
                    covers(&after.value, &before.value) && !covers(&before.value, &after.value);
                let strict_before =
                    covers(&before.value, &after.value) && !covers(&after.value, &before.value);
                if strict_after || strict_before {
                    pair = Some(index);
                    break;
                }
            }
        }
        if let Some(index) = pair {
            paired_added.insert(index);
            let after = &added[index];
            let after_covers =
                covers(&after.value, &before.value) && !covers(&before.value, &after.value);
            let (kind, class, label) = if before.action == "keep" {
                if after_covers {
                    (
                        "KEEP_WIDENED",
                        ChangeClass::Weakening,
                        format!(
                            "«Не маскировать» расширено: {} → {}",
                            before.value, after.value
                        ),
                    )
                } else {
                    (
                        "KEEP_NARROWED",
                        ChangeClass::Strengthening,
                        format!(
                            "«Не маскировать» сужено: {} → {}",
                            before.value, after.value
                        ),
                    )
                }
            } else if after_covers {
                (
                    "PATTERN_WIDENED",
                    ChangeClass::Strengthening,
                    format!(
                        "{}: шаблон расширен {} → {}",
                        selector_label(&before.selector),
                        before.value,
                        after.value
                    ),
                )
            } else {
                (
                    "PATTERN_NARROWED",
                    ChangeClass::Weakening,
                    format!(
                        "{}: шаблон сужен {} → {}",
                        selector_label(&before.selector),
                        before.value,
                        after.value
                    ),
                )
            };
            removal_changes.push(change(
                "rule",
                kind,
                class,
                label,
                serde_json::json!({"area":"rule","selector":before.selector,"key":rule_key(&after.selector,&after.value)}),
                rule_json(before),
                rule_json(after),
            ));
        } else {
            // §3.2 поглощение mask/secret → PATTERN_REPLACED neutral.
            if before.action != "keep" {
                if let Some(absorber) = removal_absorbed(before, &to.rules) {
                    removal_changes.push(change(
                        "rule",
                        "PATTERN_REPLACED",
                        ChangeClass::Neutral,
                        format!(
                            "{} {}: покрыто правилом {}",
                            selector_label(&before.selector),
                            before.value,
                            absorber.value
                        ),
                        serde_json::json!({"area":"rule","selector":before.selector,"key":rule_key(&absorber.selector,&absorber.value)}),
                        rule_json(before),
                        rule_json(&absorber),
                    ));
                    continue;
                }
            }
            let kind = match before.action.as_str() {
                "mask" => "MASK_REMOVED",
                "secret" => "SECRET_REMOVED",
                _ => "KEEP_REMOVED",
            };
            let class = if before.action == "keep" {
                ChangeClass::Strengthening
            } else {
                ChangeClass::Weakening
            };
            let mut item = change(
                "rule",
                kind,
                class,
                format!(
                    "{} {}: правило удалено",
                    selector_label(&before.selector),
                    before.value
                ),
                serde_json::json!({"area":"rule","selector":before.selector,"key":rule_key(&before.selector,&before.value)}),
                rule_json(before),
                Value::Null,
            );
            attach_regex_keep_warning(&mut item, before, warnings, true);
            removal_changes.push(item);
        }
    }
    changes.extend(removal_changes);
    for (index, after) in added.iter().enumerate() {
        if paired_added.contains(&index) {
            continue;
        }
        // §3.2 поглощение KEEP_ADDED → PATTERN_REPLACED neutral.
        if after.action == "keep" {
            if let Some(absorber) = keep_addition_absorbed(after, &from.rules) {
                changes.push(change(
                    "rule",
                    "PATTERN_REPLACED",
                    ChangeClass::Neutral,
                    format!(
                        "{} {}: уже покрыто правилом {}",
                        selector_label(&after.selector),
                        after.value,
                        absorber.value
                    ),
                    serde_json::json!({"area":"rule","selector":after.selector,"key":rule_key(&absorber.selector,&absorber.value)}),
                    rule_json(&absorber),
                    rule_json(after),
                ));
                continue;
            }
        }
        let kind = match after.action.as_str() {
            "keep" => "KEEP_ADDED",
            "mask" => "MASK_ADDED",
            _ => "SECRET_ADDED",
        };
        let class = if after.action == "keep" {
            ChangeClass::Weakening
        } else {
            ChangeClass::Strengthening
        };
        changes.push(change(
            "rule",
            kind,
            class,
            format!(
                "{} {}: правило добавлено",
                selector_label(&after.selector),
                after.value
            ),
            serde_json::json!({"area":"rule","selector":after.selector,"key":rule_key(&after.selector,&after.value)}),
            Value::Null,
            rule_json(after),
        ));
    }
    //++agent TASK-225
}

fn selector_label(selector: &str) -> &'static str {
    match selector {
        "source_path" => "Источник",
        "name" => "Имя поля",
        "type" => "Тип",
        "dictionary" => "Словарь",
        "regex" => "Regex",
        _ => "Правило",
    }
}

/// REGEX_KEEP_NO_EFFECT (F7): regex с действием keep не изменяет
/// обработку — предупреждение вешается на карточку изменения.
fn attach_regex_keep_warning(
    item: &mut SetupChange,
    rule: &super::RuleSpec,
    warnings: &mut Vec<SetupWarning>,
    _removed: bool,
) {
    if rule.selector == "regex" && rule.action == "keep" {
        let w = warning(
            "REGEX_KEEP_NO_EFFECT",
            serde_json::json!({"area":"rule","selector":"regex","key":rule.value}),
            "regex с действием keep не имеет эффекта — движок его игнорирует".to_string(),
            None,
            true,
        );
        item.warning_ids.push(w.id.clone());
        warnings.push(w);
    }
}

/// §3.4: эффективный набор источников словаря S(v). `part` — источники
/// как есть; `all` — раскрытие по manifest и F9-allowlist из mask-правил
/// `source_path` той же версии. `None` = UNKNOWN (manifest недоступен,
/// набор недоказуем → DICTIONARY_MODE_UNVERIFIABLE).
fn effective_sources(
    version: &VersionContent,
    context: &DiffContext,
) -> Option<BTreeMap<String, super::DictionarySourceSpec>> {
    let dictionary = &version.dictionary;
    if dictionary.mode == "all" {
        let expandable = context.manifest_expandable.as_ref()?;
        // Категория/условие раскрытых источников наследуют wildcard-селектор
        // `{"source_path":"*"}` — как у pull (dictionary_feed all-expansion).
        let wildcard = dictionary
            .sources
            .iter()
            .find(|source| source.source_path == "*");
        let category = wildcard
            .map(|source| source.category.clone())
            .unwrap_or_else(|| "all".to_string());
        let filter = wildcard.and_then(|source| source.filter_ast.clone());
        // allowlist: enabled mask source_path-правила без '*' — как
        // all_allowed_source_paths в dictionary_feed.
        let allowed: HashSet<&str> = version
            .rules
            .iter()
            .filter(|rule| {
                rule.enabled
                    && rule.selector == "source_path"
                    && rule.action == "mask"
                    && !rule.value.contains('*')
            })
            .map(|rule| rule.value.as_str())
            .collect();
        let mut map = BTreeMap::new();
        for path in expandable {
            if allowed.contains(path.as_str()) {
                map.insert(
                    path.to_lowercase(),
                    super::DictionarySourceSpec {
                        source_path: path.clone(),
                        category: category.clone(),
                        filter_ast: filter.clone(),
                        reason: wildcard
                            .map(|source| source.reason.clone())
                            .unwrap_or_default(),
                        estimated_values: wildcard.and_then(|source| source.estimated_values),
                    },
                );
            }
        }
        return Some(map);
    }
    Some(
        dictionary
            .sources
            .iter()
            .map(|source| {
                (
                    source_key(&source.source_path),
                    super::DictionarySourceSpec {
                        source_path: source.source_path.clone(),
                        category: source.category.clone(),
                        filter_ast: source.filter_ast.clone(),
                        reason: source.reason.clone(),
                        estimated_values: source.estimated_values,
                    },
                )
            })
            .collect(),
    )
}

/// §3.4: переход условия источника → (kind, class).
fn filter_transition(
    before: &Option<Value>,
    after: &Option<Value>,
) -> Option<(&'static str, ChangeClass)> {
    use ChangeClass::*;
    match (before, after) {
        (None, Some(_)) => Some(("FILTER_NARROWED", Weakening)),
        (Some(_), None) => Some(("FILTER_WIDENED", Strengthening)),
        (Some(before), Some(after)) => {
            if before == after {
                return None;
            }
            let contains_arg = |node: &Value, needle: &Value| -> bool {
                node.get("args")
                    .and_then(|args| args.as_array())
                    .is_some_and(|args| args.iter().any(|arg| arg == needle))
            };
            if after.get("op").and_then(Value::as_str) == Some("and") && contains_arg(after, before)
            {
                return Some(("FILTER_NARROWED", Weakening));
            }
            if after.get("op").and_then(Value::as_str) == Some("or") && contains_arg(after, before)
            {
                return Some(("FILTER_WIDENED", Strengthening));
            }
            // Один узел `in` на то же `field`: сравнение множеств values.
            let is_in = |node: &Value| node.get("op").and_then(Value::as_str) == Some("in");
            if is_in(before) && is_in(after) {
                let field_eq = before.get("field") == after.get("field");
                let values = |node: &Value| -> HashSet<String> {
                    node.get("values")
                        .and_then(|items| items.as_array())
                        .map(|items| items.iter().map(|item| item.to_string()).collect())
                        .unwrap_or_default()
                };
                let b_values = values(before);
                let a_values = values(after);
                if field_eq {
                    if a_values.is_superset(&b_values) {
                        return Some(("FILTER_WIDENED", Strengthening));
                    }
                    if a_values.is_subset(&b_values) {
                        return Some(("FILTER_NARROWED", Weakening));
                    }
                }
            }
            Some(("FILTER_CHANGED", Weakening))
        }
        _ => None,
    }
}

/// §3.4: словарь — сравнение эффективных наборов источников S(from)/S(to);
/// UNKNOWN-сторона сводится к одному DICTIONARY_MODE_UNVERIFIABLE.
/// Действие категории — строжайшее из правил `dictionary`, чей шаблон
/// совпал (F6); понижение — DICTIONARY_CATEGORY_WEAKER.
fn diff_dictionary(
    from: &VersionContent,
    to: &VersionContent,
    changes: &mut Vec<SetupChange>,
    warnings: &mut Vec<SetupWarning>,
    context: &DiffContext,
) {
    //++agent TASK-225 [26.09.2026] M-3: S(v) по §3.4 + ОВ-5.
    let from_sources = effective_sources(from, context);
    let to_sources = effective_sources(to, context);
    // Сырые источники (wildcard-селектор all-версии тоже сравниваем) —
    // иначе all↔all с разными селекторами при UNKNOWN-манифесте
    // проскочил бы как «без изменений».
    let raw_equal = from
        .dictionary
        .sources
        .iter()
        .map(|source| {
            (
                source_key(&source.source_path),
                source.category.clone(),
                source.filter_ast.clone(),
            )
        })
        .collect::<Vec<_>>()
        == to
            .dictionary
            .sources
            .iter()
            .map(|source| {
                (
                    source_key(&source.source_path),
                    source.category.clone(),
                    source.filter_ast.clone(),
                )
            })
            .collect::<Vec<_>>();
    let dictionaries_equal =
        from.dictionary.mode == to.dictionary.mode && raw_equal && from_sources == to_sources;
    match (from_sources, to_sources) {
        (Some(from_map), Some(to_map)) => {
            let mut keys: BTreeMap<String, ()> = BTreeMap::new();
            for key in from_map.keys().chain(to_map.keys()) {
                keys.insert(key.clone(), ());
            }
            for (key, _) in keys {
                match (from_map.get(&key), to_map.get(&key)) {
                    (None, Some(after)) => {
                        let mut item = change(
                            "dictionary",
                            "SOURCE_ADDED",
                            ChangeClass::Strengthening,
                            format!("Новый источник словаря: {}", after.source_path),
                            serde_json::json!({"area":"dictionary","source_path": after.source_path}),
                            Value::Null,
                            source_json(after),
                        );
                        if let Some(w) = source_large_warning(after, context) {
                            item.warning_ids.push(w.id.clone());
                            warnings.push(w);
                        }
                        changes.push(item);
                    }
                    (Some(before), None) => changes.push(change(
                        "dictionary",
                        "SOURCE_REMOVED",
                        ChangeClass::Weakening,
                        format!("Источник словаря удалён: {}", before.source_path),
                        serde_json::json!({"area":"dictionary","source_path": before.source_path}),
                        source_json(before),
                        Value::Null,
                    )),
                    (Some(before), Some(after)) => {
                        //++agent TASK-225 [26.09.2026] D6: классификация по
                        // нормализованному AST — иначе `null`↔отсутствие и
                        // перестановка/регистр аргументов уходили бы в
                        // FILTER_*→weakening без смены семантики.
                        if let Some((kind, class)) = filter_transition(
                            &normalized_filter(&before.filter_ast),
                            &normalized_filter(&after.filter_ast),
                        ) {
                            let mut item = change(
                                "dictionary",
                                kind,
                                class,
                                format!("Условие источника изменено: {}", after.source_path),
                                serde_json::json!({"area":"dictionary","source_path": after.source_path}),
                                source_json(before),
                                source_json(after),
                            );
                            if let Some(w) = source_large_warning(after, context) {
                                item.warning_ids.push(w.id.clone());
                                warnings.push(w);
                            }
                            changes.push(item);
                        }
                        if before.category != after.category {
                            changes.push(change(
                                "dictionary",
                                "SOURCE_CATEGORY_CHANGED",
                                ChangeClass::Neutral,
                                format!(
                                    "Источник {}: категория {} → {}",
                                    after.source_path, before.category, after.category
                                ),
                                serde_json::json!({"area":"dictionary","source_path": after.source_path}),
                                source_json(before),
                                source_json(after),
                            ));
                        }
                        if before.reason != after.reason
                            || before.estimated_values != after.estimated_values
                        {
                            changes.push(change(
                                "dictionary",
                                "REASON_CHANGED",
                                ChangeClass::Neutral,
                                format!("Источник словаря уточнён: {}", after.source_path),
                                serde_json::json!({"area":"dictionary","source_path": after.source_path}),
                                source_json(before),
                                source_json(after),
                            ));
                        }
                    }
                    (None, None) => {}
                }
            }
        }
        _ => {
            // ОВ-5: сторона с mode=all при недоступном manifest — набор
            // недоказуем; любые различия → одно подтверждаемое ослабление.
            if !dictionaries_equal {
                changes.push(change(
                    "dictionary",
                    "DICTIONARY_MODE_UNVERIFIABLE",
                    ChangeClass::Weakening,
                    format!(
                        "Режим словаря {} → {}: manifest недоступен, набор источников не проверяем",
                        from.dictionary.mode, to.dictionary.mode
                    ),
                    serde_json::json!({"area":"dictionary"}),
                    serde_json::json!({"mode": from.dictionary.mode}),
                    serde_json::json!({"mode": to.dictionary.mode}),
                ));
            }
        }
    }

    // §3.4/§3.2 доп. правило F6: effective действие категории по правилам
    // `dictionary` ослабло для категории, присутствующей в источниках.
    let dict_action = |rules: &[super::RuleSpec], category: &str| -> i64 {
        rules
            .iter()
            .filter(|rule| {
                rule.enabled
                    && rule.selector == "dictionary"
                    && wildcard_covers(&rule.value, category)
            })
            .map(|rule| action_rank(&rule.action))
            .max()
            .unwrap_or(2) // F6: нет правил → mask
    };
    let mut categories: HashSet<String> = HashSet::new();
    for source in &to.dictionary.sources {
        categories.insert(source.category.clone());
    }
    for source in &from.dictionary.sources {
        categories.insert(source.category.clone());
    }
    for category in categories {
        let before = dict_action(&from.rules, &category);
        let after = dict_action(&to.rules, &category);
        if after < before {
            changes.push(change(
                "dictionary",
                "DICTIONARY_CATEGORY_WEAKER",
                ChangeClass::Weakening,
                format!("Действие категории словаря ослабло: {category}"),
                serde_json::json!({"area":"dictionary","category": category}),
                serde_json::json!({"rank": before}),
                serde_json::json!({"rank": after}),
            ));
        }
    }
}

//++agent TASK-225 [26.09.2026] D6
/// Семантическая нормализация filter_ast перед сравнением версий:
/// отсутствие фильтра и `null` — одно и то же; имена полей метаданных
/// регистронезависимы (1С); `and`/`or` коммутативны (args сортируются
/// и дедуплицируются); `in` — множество (values сортируются). Иначе
/// правка только обоснования или представления условия уходила в
/// FILTER_*→weakening (ложное подтверждение).
fn normalized_filter(filter_ast: &Option<Value>) -> Option<Value> {
    match filter_ast {
        Some(filter) if !filter.is_null() => Some(normalize_filter_node(filter)),
        _ => None,
    }
}

fn normalize_filter_node(node: &Value) -> Value {
    let Some(object) = node.as_object() else {
        return node.clone();
    };
    let op = object
        .get("op")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let field_key = |object: &serde_json::Map<String, Value>| -> String {
        object
            .get("field")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_lowercase()
    };
    match op {
        "and" | "or" => {
            let mut args: Vec<Value> = object
                .get("args")
                .and_then(|items| items.as_array())
                .map(|items| items.iter().map(normalize_filter_node).collect())
                .unwrap_or_default();
            args.sort_by_key(|item| item.to_string());
            args.dedup();
            serde_json::json!({"op": op, "args": args})
        }
        "not" => serde_json::json!({
            "op": "not",
            "arg": normalize_filter_node(object.get("arg").unwrap_or(&Value::Null)),
        }),
        "eq" | "ne" => serde_json::json!({
            "op": op,
            "field": field_key(object),
            "value": object.get("value").cloned().unwrap_or(Value::Null),
        }),
        "in" => {
            let mut values: Vec<Value> = object
                .get("values")
                .and_then(|items| items.as_array())
                .cloned()
                .unwrap_or_default();
            values.sort_by_key(|item| item.to_string());
            serde_json::json!({
                "op": "in",
                "field": field_key(object),
                "values": values,
            })
        }
        _ => node.clone(),
    }
}
//++agent TASK-225

/// Сопоставление шаблона dictionary-правила с категорией — тот же
/// `wildcard_match` контракт, что в движке (локальная копия F4).
/// Регистр — по Unicode `to_lowercase` (spec §12, B-2).
fn wildcard_covers(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(part) = pattern
        .strip_prefix('*')
        .and_then(|part| part.strip_suffix('*'))
    {
        return value.to_lowercase().contains(&part.to_lowercase());
    }
    value.to_lowercase() == pattern.to_lowercase()
}

/// §5a.3: порог предупреждения — env MASKING_SOURCE_LARGE_VALUES
/// (дефолт 100 000).
fn source_large_threshold() -> i64 {
    std::env::var("MASKING_SOURCE_LARGE_VALUES")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100_000)
}

fn source_large_warning(
    source: &super::DictionarySourceSpec,
    context: &DiffContext,
) -> Option<SetupWarning> {
    let pulled = context
        .source_stats
        .as_ref()
        .and_then(|stats| stats.get(&source.source_path.to_lowercase()))
        .copied();
    // §5a.3: max(values последнего pull, estimated_values файла).
    let (count, estimated) = match (pulled, source.estimated_values) {
        (Some(p), Some(e)) => (p.values.max(e), false),
        (Some(p), None) => (p.values, false),
        (None, Some(e)) => (e, true),
        (None, None) => return None,
    };
    if count < source_large_threshold() {
        return None;
    }
    // Оценки §5a.3. Загрузка: pull-скорость не хранится →
    // консервативные 20 000 значений/с. Память: bytes×2 + values×48;
    // без pull (estimated) байты оцениваются как values×48 (эмпирика
    // бенчмарка §5a.4: среднее значение ≈48 Б).
    const ESTIMATED_VALUE_BYTES: i64 = 48;
    let bytes = pulled
        .map(|stat| stat.bytes)
        .unwrap_or_else(|| count.saturating_mul(ESTIMATED_VALUE_BYTES));
    let load_s = (count as f64 / 20_000.0).ceil().max(1.0) as i64;
    let memory_bytes = bytes
        .saturating_mul(2)
        .saturating_add(count.saturating_mul(48));
    let human_count = human_count_label(count);
    let load_label = if load_s >= 60 {
        format!("~{} мин", load_s / 60)
    } else {
        format!("~{load_s} с")
    };
    Some(warning(
        "SOURCE_LARGE",
        serde_json::json!({"area":"dictionary","source_path":source.source_path}),
        format!(
            "Крупный источник ({human_count} значений): загрузка словаря займёт {load_label}, память ~{} МБ, каждая проверка ответа станет медленнее — см. замер сухого прогона",
            memory_bytes / 1_048_576
        ),
        Some(serde_json::json!({
            "values": count,
            "estimated": estimated,
            "load_time_estimate_s": load_s,
            "memory_estimate_bytes": memory_bytes,
            "per_check_cost": "рост времени каждой проверки ответа",
        })),
        true,
    ))
}

/// Компактный счётчик для label («~1,2 млн», «~150 тыс.», «999»).
fn human_count_label(count: i64) -> String {
    if count >= 1_000_000 {
        format!(
            "~{} млн",
            (count as f64 / 1_000_000.0 * 10.0).round() / 10.0
        )
    } else if count >= 1_000 {
        format!("~{} тыс.", (count / 1000).max(1))
    } else {
        format!("~{count}")
    }
}

/// §3.5: инструменты. Снимок `tools` версии сравнивается с `from`;
/// отсутствующий ранее инструмент трактуется как deny-pending-review
/// (дефолт автоклассификации) — добавление metadata-bypass/data-mask
/// тогда честно классифицируется ослаблением.
//++agent TASK-225 [26.09.2026] M-2: §3.5 — `before` это текущая строка
/// tool_classifications (отсутствие → deny-pending-review), а не снимок
/// from-версии. Иначе режим, изменённый вне версий, давал ложные
/// ослабления/усиления.
fn diff_tools(
    _from: &VersionContent,
    to: &VersionContent,
    changes: &mut Vec<SetupChange>,
    context: &DiffContext,
) {
    // Diff инструментов имеет смысл только если to-версия несёт снимок;
    // отсутствие инструмента в файле = «без изменений» (§3.5).
    let Some(tools) = &to.tools else {
        return;
    };
    let mut sorted: Vec<&ToolSpec> = tools.iter().collect();
    sorted.sort_by(|a, b| a.tool.cmp(&b.tool));
    for after in sorted {
        let before = context
            .tool_modes
            .as_ref()
            .and_then(|modes| modes.get(&after.tool).cloned())
            .unwrap_or_else(|| "deny-pending-review".to_string());
        let subject = serde_json::json!({"area":"tool","tool":after.tool});
        if before == after.mode {
            // reason-only правки инструментов таблица §3.5 не
            // классифицирует — изменений нет.
            continue;
        }
        let (kind, class, detail) = match (before.as_str(), after.mode.as_str()) {
            (_, "metadata-bypass") => (
                "TOOL_BYPASS",
                ChangeClass::Weakening,
                Some(serde_json::json!({
                    "name_looks_like_data": name_looks_like_data(&after.tool),
                })),
            ),
            ("deny-pending-review", "data-mask") => ("TOOL_ENABLED", ChangeClass::Neutral, None),
            ("data-mask", "deny-pending-review")
            | ("metadata-bypass", "data-mask")
            | ("metadata-bypass", "deny-pending-review") => {
                ("TOOL_RESTRICTED", ChangeClass::Strengthening, None)
            }
            // Остальные переходы консервативно считаются ослаблением.
            _ => (
                "TOOL_BYPASS",
                ChangeClass::Weakening,
                Some(serde_json::json!({
                    "name_looks_like_data": name_looks_like_data(&after.tool),
                })),
            ),
        };
        let mut item = change(
            "tool",
            kind,
            class,
            format!("Инструмент {}: {} → {}", after.tool, before, after.mode),
            subject,
            serde_json::json!({"mode": before}),
            tool_json(after),
        );
        item.detail = detail;
        changes.push(item);
    }
}

/// Эвристика §3.5/UI С4: имя инструмента похоже на работу с данными.
fn name_looks_like_data(tool: &str) -> bool {
    let name = tool.to_lowercase();
    [
        "query", "select", "data", "record", "history", "get_", "read",
    ]
    .iter()
    .any(|part| name.contains(part))
}

/// Предупреждения §3.6, зависящие от контекста.
fn collect_warnings(
    _from: &VersionContent,
    to: &VersionContent,
    context: &DiffContext,
    warnings: &mut Vec<SetupWarning>,
) {
    if context.database_mismatch {
        warnings.push(warning(
            "DATABASE_MISMATCH",
            serde_json::json!({"area":"file","field":"database_hint"}),
            "файл сформирован для другой базы — проверьте источники и правила".to_string(),
            None,
            false,
        ));
    }
    match &context.manifest_paths {
        None => warnings.push(warning(
            "MANIFEST_UNAVAILABLE",
            serde_json::json!({"area":"file"}),
            "manifest метаданных недоступен — пути источников не проверены".to_string(),
            None,
            false,
        )),
        Some(paths) => {
            // subject.source_path несёт элемент черновика — исключение
            // (B7 excluded_warnings / B8 revert) удаляет ровно его.
            let check_path = |subject: Value, path: &str, warnings: &mut Vec<SetupWarning>| {
                if path == "*" {
                    return;
                }
                if let Some(inner) = path.strip_prefix('*').and_then(|p| p.strip_suffix('*')) {
                    if !inner.is_empty()
                        && !paths
                            .iter()
                            .any(|known| known.contains(&inner.to_lowercase()))
                    {
                        warnings.push(warning(
                            "PATH_NOT_IN_MANIFEST",
                            subject,
                            format!("шаблону {path} не соответствует ни один путь manifest"),
                            None,
                            true,
                        ));
                    }
                    return;
                }
                if !paths.contains(&path.to_lowercase()) {
                    warnings.push(warning(
                        "PATH_NOT_IN_MANIFEST",
                        subject,
                        format!("путь {path} отсутствует в manifest метаданных"),
                        None,
                        true,
                    ));
                }
            };
            for source in &to.dictionary.sources {
                check_path(
                    serde_json::json!({"area":"dictionary","source_path":source.source_path}),
                    &source.source_path,
                    warnings,
                );
            }
            // §3.6: manifest-проверка только для source_path-правил —
            // name/type шаблоны путей не являются.
            for rule in &to.rules {
                if rule.selector == "source_path" {
                    check_path(
                        serde_json::json!({"area":"rule","selector":"source_path","key":rule_key(&rule.selector,&rule.value)}),
                        &rule.value,
                        warnings,
                    );
                }
            }
        }
    }
    if let Some(known) = &context.known_tools {
        if let Some(tools) = &to.tools {
            for tool in tools {
                if !known.contains(&tool.tool) {
                    warnings.push(warning(
                        "TOOL_NOT_SEEN",
                        serde_json::json!({"area":"tool","tool":tool.tool}),
                        format!("инструмент {} ни разу не вызывался", tool.tool),
                        None,
                        true,
                    ));
                }
            }
        }
    }
    //++agent TASK-225 [26.09.2026] §3.6: лимит и по списку part,
    // и по раскрытию all (pull упадёт FEED_LIMIT_EXCEEDED).
    //++agent TASK-225
    //++agent TASK-225 [26.09.2026] review MINOR-10: pull падает строго
    // ПРЕВЫШЕНИЕМ лимита — ровно SETUP_MAX_SOURCES легально (off-by-one).
    let limit_hit = to.dictionary.sources.len() > super::SETUP_MAX_SOURCES
        || (to.dictionary.mode == "all"
            && effective_sources(to, context)
                .is_some_and(|sources| sources.len() > super::SETUP_MAX_SOURCES));
    if limit_hit {
        warnings.push(warning(
            "DICTIONARY_LIMIT",
            serde_json::json!({"area":"dictionary"}),
            format!(
                "источников больше {} — pull завершится FEED_LIMIT_EXCEEDED",
                super::SETUP_MAX_SOURCES
            ),
            None,
            false,
        ));
    }
    if to
        .rules
        .iter()
        .any(|rule| rule.enabled && rule.action == "secret")
    {
        warnings.push(warning(
            "SECRET_ACTIVATION_BLOCKED",
            serde_json::json!({"area":"rule"}),
            "активация версии с secret-правилом запрещена (F8)".to_string(),
            None,
            false,
        ));
    }
}
//++agent TASK-225

//++agent TASK-225 [26.09.2026]
/// T10-08: предупреждение SOURCE_LARGE (§5a.3) — env-порог, detail-оценки,
/// excludable:true.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::setup::{DictionarySourceSpec, SourceStat, VersionDictionary};

    fn source(path: &str, estimated_values: Option<i64>) -> DictionarySourceSpec {
        DictionarySourceSpec {
            source_path: path.to_string(),
            category: "pii".to_string(),
            filter_ast: None,
            reason: "test".to_string(),
            estimated_values,
        }
    }

    fn content(sources: Vec<DictionarySourceSpec>) -> VersionContent {
        VersionContent {
            dictionary: VersionDictionary {
                mode: "part".to_string(),
                sources,
            },
            rules: Vec::new(),
            tools: None,
        }
    }

    fn context(stats: Option<HashMap<String, SourceStat>>) -> DiffContext {
        DiffContext {
            manifest_paths: Some(HashSet::new()),
            manifest_expandable: Some(HashSet::new()),
            known_tools: Some(HashSet::new()),
            tool_modes: Some(HashMap::new()),
            source_stats: stats,
            database_mismatch: false,
        }
    }

    fn large_warning(diff: &SetupDiff) -> Option<&SetupWarning> {
        diff.warnings.iter().find(|w| w.kind == "SOURCE_LARGE")
    }

    #[test]
    fn source_large_fires_on_pulled_values_with_spec_estimates() {
        let mut stats = HashMap::new();
        stats.insert(
            "spr.kontr".to_string(),
            SourceStat {
                values: 150_000,
                bytes: 6_000_000,
            },
        );
        let diff = compute_diff(
            &content(Vec::new()),
            &content(vec![source("Spr.Kontr", None)]),
            &context(Some(stats)),
        );
        let warning = large_warning(&diff).expect("SOURCE_LARGE expected");
        assert!(warning.excludable);
        let detail = warning.detail.clone().unwrap();
        assert_eq!(detail["values"], 150_000);
        assert_eq!(detail["estimated"], false);
        // 150k/20k = 7.5 → 8с; память = 6_000_000*2 + 150_000*48 = 19_200_000.
        assert_eq!(detail["load_time_estimate_s"], 8);
        assert_eq!(detail["memory_estimate_bytes"], 19_200_000);
        assert_eq!(
            detail["per_check_cost"],
            "рост времени каждой проверки ответа"
        );
        assert!(warning.label.contains("тыс."));
        // Предупреждение привязано к change SOURCE_ADDED.
        let change = diff
            .changes
            .iter()
            .find(|c| c.kind == "SOURCE_ADDED")
            .unwrap();
        assert!(change.warning_ids.contains(&warning.id));
    }

    #[test]
    fn source_large_marks_estimated_only_sources() {
        let diff = compute_diff(
            &content(Vec::new()),
            &content(vec![source("Spr.Agents", Some(200_000))]),
            &context(None),
        );
        let warning = large_warning(&diff).expect("SOURCE_LARGE expected");
        let detail = warning.detail.clone().unwrap();
        assert_eq!(detail["estimated"], true);
        // Без pull: bytes ≈ values*48 → память = 200_000*144 = 28_800_000.
        assert_eq!(detail["memory_estimate_bytes"], 28_800_000);
    }

    #[test]
    fn source_below_default_threshold_is_quiet() {
        let mut stats = HashMap::new();
        stats.insert(
            "spr.small".to_string(),
            SourceStat {
                values: 99_999,
                bytes: 1_000,
            },
        );
        let diff = compute_diff(
            &content(Vec::new()),
            &content(vec![source("Spr.Small", None)]),
            &context(Some(stats)),
        );
        assert!(large_warning(&diff).is_none());
    }

    #[test]
    fn source_large_threshold_respects_env_override() {
        // env — состояние процесса: проверяем в изолированном child,
        // чтобы не влиять на параллельные тесты.
        if std::env::var_os("T225_SOURCE_LARGE_CHILD").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "domain::setup::diff::tests::source_large_threshold_respects_env_override",
                    "--nocapture",
                ])
                .env("T225_SOURCE_LARGE_CHILD", "1")
                .env("MASKING_SOURCE_LARGE_VALUES", "5")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let mut stats = HashMap::new();
        stats.insert(
            "spr.tiny".to_string(),
            SourceStat {
                values: 10,
                bytes: 100,
            },
        );
        let diff = compute_diff(
            &content(Vec::new()),
            &content(vec![source("Spr.Tiny", None)]),
            &context(Some(stats)),
        );
        assert!(
            large_warning(&diff).is_some(),
            "MASKING_SOURCE_LARGE_VALUES=5 must trip on 10 values"
        );
    }

    //++agent TASK-225 [26.09.2026] D6: правка только обоснования или
    // представления условия источника — не ослабление.
    fn filtered_source(path: &str, filter: Option<Value>, reason: &str) -> DictionarySourceSpec {
        DictionarySourceSpec {
            source_path: path.to_string(),
            category: "pii".to_string(),
            filter_ast: filter,
            reason: reason.to_string(),
            estimated_values: None,
        }
    }

    fn filter_changes(diff: &SetupDiff) -> Vec<&SetupChange> {
        diff.changes
            .iter()
            .filter(|change| change.kind.starts_with("FILTER_"))
            .collect()
    }

    #[test]
    fn reason_only_source_change_is_neutral_not_weakening() {
        let before = vec![filtered_source("Spr.Kontr", None, "старое обоснование")];
        let after = vec![filtered_source("Spr.Kontr", None, "новое обоснование")];
        let diff = compute_diff(&content(before), &content(after), &context(None));
        assert!(filter_changes(&diff).is_empty());
        let change = diff
            .changes
            .iter()
            .find(|change| change.kind == "REASON_CHANGED")
            .expect("ожидалось REASON_CHANGED");
        assert_eq!(change.change_class, ChangeClass::Neutral);
        assert!(!diff
            .changes
            .iter()
            .any(|change| change.change_class == ChangeClass::Weakening));
    }

    #[test]
    fn null_filter_is_same_as_absent() {
        let before = vec![filtered_source("Spr.Kontr", None, "test")];
        let after = vec![filtered_source("Spr.Kontr", Some(Value::Null), "test")];
        let diff = compute_diff(&content(before), &content(after), &context(None));
        assert!(filter_changes(&diff).is_empty());
        assert!(!diff
            .changes
            .iter()
            .any(|change| change.change_class == ChangeClass::Weakening));
    }

    #[test]
    fn filter_representation_only_change_is_silent() {
        let eq = |field: &str, value: i64| serde_json::json!({"op": "eq", "field": field, "value": value});
        let before = vec![filtered_source(
            "Spr.Kontr",
            Some(serde_json::json!({
                "op": "and",
                "args": [eq("Ссылка", 1), eq("Код", 2)],
            })),
            "test",
        )];
        // Другой порядок args + другой регистр имён полей — та же семантика.
        let after = vec![filtered_source(
            "Spr.Kontr",
            Some(serde_json::json!({
                "op": "and",
                "args": [eq("код", 2), eq("ссылка", 1)],
            })),
            "test",
        )];
        let diff = compute_diff(&content(before), &content(after), &context(None));
        assert!(filter_changes(&diff).is_empty());
        assert!(!diff
            .changes
            .iter()
            .any(|change| change.change_class == ChangeClass::Weakening));
    }

    #[test]
    fn filter_in_values_reorder_is_silent() {
        let node =
            |values: &[&str]| serde_json::json!({"op": "in", "field": "Код", "values": values});
        let before = vec![filtered_source(
            "Spr.Kontr",
            Some(node(&["a", "b", "c"])),
            "test",
        )];
        let after = vec![filtered_source(
            "Spr.Kontr",
            Some(node(&["c", "a", "b"])),
            "test",
        )];
        let diff = compute_diff(&content(before), &content(after), &context(None));
        assert!(filter_changes(&diff).is_empty());
    }

    #[test]
    fn filter_narrowed_remains_weakening() {
        let before = vec![filtered_source("Spr.Kontr", None, "test")];
        let after = vec![filtered_source(
            "Spr.Kontr",
            Some(serde_json::json!({"op": "eq", "field": "Код", "value": "x"})),
            "test",
        )];
        let diff = compute_diff(&content(before), &content(after), &context(None));
        let change = diff
            .changes
            .iter()
            .find(|change| change.kind == "FILTER_NARROWED")
            .expect("ожидалось FILTER_NARROWED");
        assert_eq!(change.change_class, ChangeClass::Weakening);
    }

    #[test]
    fn filter_widened_remains_strengthening() {
        let before = vec![filtered_source(
            "Spr.Kontr",
            Some(serde_json::json!({"op": "eq", "field": "Код", "value": "x"})),
            "test",
        )];
        let after = vec![filtered_source("Spr.Kontr", None, "test")];
        let diff = compute_diff(&content(before), &content(after), &context(None));
        let change = diff
            .changes
            .iter()
            .find(|change| change.kind == "FILTER_WIDENED")
            .expect("ожидалось FILTER_WIDENED");
        assert_eq!(change.change_class, ChangeClass::Strengthening);
    }

    #[test]
    fn real_filter_change_is_weakening() {
        let eq = |value: i64| serde_json::json!({"op": "eq", "field": "Код", "value": value});
        let before = vec![filtered_source("Spr.Kontr", Some(eq(1)), "test")];
        let after = vec![filtered_source("Spr.Kontr", Some(eq(2)), "test")];
        let diff = compute_diff(&content(before), &content(after), &context(None));
        let change = diff
            .changes
            .iter()
            .find(|change| change.kind == "FILTER_CHANGED")
            .expect("ожидалось FILTER_CHANGED");
        assert_eq!(change.change_class, ChangeClass::Weakening);
    }
}
//--agent TASK-225
