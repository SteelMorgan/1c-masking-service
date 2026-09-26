//++agent TASK-225 [26.09.2026]
//! Ядро версионированной настройки (spec §1–§3): модель контента версии,
//! канонизация и `content_hash`, парсер/семантический валидатор формата
//! `masking-setup/v1`, чистый diff с классификацией изменений и
//! предупреждениями. Домен не знает про HTTP и SQLite — вся устойчивость
//! в `storage::setup` и `api::human::setup`.

mod diff;
mod parse;

pub(crate) use diff::{compute_diff, DiffContext, SetupDiff};
pub(crate) use parse::parse_setup_body;
#[allow(unused_imports)]
pub(crate) use parse::ParsedSetup;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Версия формата файла настройки.
pub(crate) const SETUP_SCHEMA: &str = "masking-setup/v1";
/// §1.1: максимальный размер тела импорта (байт).
pub(crate) const SETUP_MAX_BYTES: usize = 1_048_576;
/// §1.4: максимум источников словаря / правил / инструментов в файле.
pub(crate) const SETUP_MAX_SOURCES: usize = 100;
pub(crate) const SETUP_MAX_RULES: usize = 1000;
pub(crate) const SETUP_MAX_TOOLS: usize = 500;
/// §1.5: максимум ошибок валидации в ответе; дальше `truncated:true`.
pub(crate) const SETUP_MAX_ERRORS: usize = 200;
/// Причина, которой миграция §2.3 заполняет перенесённые источники/правила
/// без reason (старый формат её не имел).
pub(crate) const MIGRATION_REASON: &str = "перенос из миграции 0010";

/// §1.2 generated_by — кто сформировал файл.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedBy {
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// §1.2 database_hint — необязательная подсказка «файл про какую базу».
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DatabaseHint {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub source_version: Option<i64>,
}

/// Правило в формате файла и в снимке версии. `rule_id` — внутренняя
/// связь с `policy_rules.id` (§6.1): в файл не выгружается (§1.1 MUST NOT),
/// заполняется при загрузке из БД.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct RuleSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub selector: String,
    pub value: String,
    pub action: String,
    pub category: String,
    pub priority: i64,
    pub enabled: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tests: Option<RuleTestsSpec>,
}

/// §1.3 tests regex-правила.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleTestsSpec {
    #[serde(default, rename = "match", skip_serializing_if = "Vec::is_empty")]
    pub positive: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub no_match: Vec<String>,
}

/// Режим инструмента в файле/версии (`mode`) — строки те же, что в
/// `tool_classifications.class` (§3.5 map на class — тождественное имя).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ToolSpec {
    pub tool: String,
    pub mode: String,
    pub reason: String,
}

/// Полный контент версии настройки: словарь (stored-форма `filter_ast`),
/// правила, необязательный снимок инструментов. Единица diff и хэша.
#[derive(Debug, Clone)]
pub(crate) struct VersionContent {
    pub dictionary: VersionDictionary,
    pub rules: Vec<RuleSpec>,
    pub tools: Option<Vec<ToolSpec>>,
}

#[derive(Debug, Clone)]
pub(crate) struct VersionDictionary {
    pub mode: String,
    pub sources: Vec<DictionarySourceSpec>,
}

/// Источник словаря в stored-форме (`filter_ast` — уже проверенный AST).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DictionarySourceSpec {
    pub source_path: String,
    pub category: String,
    pub filter_ast: Option<serde_json::Value>,
    pub reason: String,
    pub estimated_values: Option<i64>,
}

/// §3.2: класс изменения при diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ChangeClass {
    Weakening,
    Strengthening,
    Neutral,
}

/// §3.1: одно изменение diff; `id` детерминирован (sha256), `label` —
/// готовый русский текст, warning_ids — связь с предупреждениями.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SetupChange {
    pub id: String,
    pub area: String,
    pub kind: String,
    #[serde(rename = "class")]
    pub change_class: ChangeClass,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    //++agent TASK-225 [26.09.2026] §3.5: дополнение изменения
    // (name_looks_like_data у TOOL_BYPASS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    //++agent TASK-225
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warning_ids: Vec<String>,
}

/// §3.6: предупреждение diff (не блокирует; exclusion через B8 `revert`
/// или `excluded_warnings` при активации). `excludable:true` только у
/// предупреждений с собственным элементом черновика (правило/источник/
/// инструмент) — сервер удаляет ровно эти элементы.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SetupWarning {
    pub id: String,
    pub kind: String,
    pub subject: serde_json::Value,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    pub excludable: bool,
}

//++agent TASK-225 [26.09.2026]
/// §5a.3: статистика источника словаря из последнего pull
/// (`cache_generations.source_stats_json`) — значения и суммарный
/// объём в байтах, нужны оценкам предупреждения SOURCE_LARGE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceStat {
    pub values: i64,
    pub bytes: i64,
}
//--agent TASK-225

/// §1.5: ошибка валидации файла — один элемент `errors[]`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SetupIssue {
    pub code: String,
    pub at: String,
    pub message: String,
    pub detail: Option<serde_json::Value>,
}

/// Канонизация JSON для sha256 (та же идея, что `canonical_value_bytes`
/// в dictionary_feed: рекурсивная сортировка ключей объекта, compact-
/// сериализация). Отдельная реализация — t226 держит свою копию в
/// dictionary_feed.rs, склеиваем при merge.
pub(crate) fn canonical_value_bytes(value: &serde_json::Value) -> Vec<u8> {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
            let mut bytes = Vec::with_capacity(128);
            bytes.push(b'{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    bytes.push(b',');
                }
                bytes.extend(serde_json::to_vec(key).unwrap_or_default());
                bytes.push(b':');
                bytes.extend(canonical_value_bytes(item));
            }
            bytes.push(b'}');
            bytes
        }
        serde_json::Value::Array(items) => {
            let mut bytes = Vec::with_capacity(128);
            bytes.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    bytes.push(b',');
                }
                bytes.extend(canonical_value_bytes(item));
            }
            bytes.push(b']');
            bytes
        }
        _ => serde_json::to_vec(value).unwrap_or_default(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// sha256 шестнадцатеричный от произвольных байтов (тело файла, §1.1).
pub(crate) fn sha256_bytes_hex(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// Ключ правила для дедупликации/diff: (selector, key), key — lowercase
/// для шаблонов/имён/путей, побайтно для regex (§1.6).
pub(crate) fn rule_key(selector: &str, value: &str) -> String {
    if selector == "regex" {
        value.to_string()
    } else {
        value.to_lowercase()
    }
}

/// Канонический снимок контента версии для хэша и diff-сравнения
/// (§2.4): словарь — отсортированные источники без служебных ключей
/// (reason сохраняется — он часть контента), правила — по (selector,
/// key, action, priority, category, enabled), инструменты — по имени.
/// Внутренние `rule_id` в хэш не входят.
pub(crate) fn canonical_content_value(content: &VersionContent) -> serde_json::Value {
    let mut sources: Vec<serde_json::Value> = content
        .dictionary
        .sources
        .iter()
        .map(|source| {
            let mut map = serde_json::Map::new();
            map.insert(
                "source_path".to_string(),
                serde_json::Value::String(source.source_path.clone()),
            );
            map.insert(
                "category".to_string(),
                serde_json::Value::String(source.category.clone()),
            );
            map.insert(
                "reason".to_string(),
                serde_json::Value::String(source.reason.clone()),
            );
            if let Some(filter) = &source.filter_ast {
                map.insert("filter_ast".to_string(), filter.clone());
            }
            if let Some(estimated) = source.estimated_values {
                map.insert(
                    "estimated_values".to_string(),
                    serde_json::Value::from(estimated),
                );
            }
            serde_json::Value::Object(map)
        })
        .collect();
    sources.sort_by(|a, b| {
        let pa = a["source_path"].as_str().unwrap_or("").to_lowercase();
        let pb = b["source_path"].as_str().unwrap_or("").to_lowercase();
        pa.cmp(&pb).then_with(|| {
            a["category"]
                .as_str()
                .unwrap_or("")
                .cmp(b["category"].as_str().unwrap_or(""))
        })
    });
    let mut rules: Vec<serde_json::Value> = content
        .rules
        .iter()
        .map(|rule| {
            let mut map = serde_json::Map::new();
            map.insert(
                "selector".to_string(),
                serde_json::Value::String(rule.selector.clone()),
            );
            map.insert(
                "value".to_string(),
                serde_json::Value::String(rule.value.clone()),
            );
            map.insert(
                "action".to_string(),
                serde_json::Value::String(rule.action.clone()),
            );
            map.insert(
                "category".to_string(),
                serde_json::Value::String(rule.category.clone()),
            );
            map.insert(
                "priority".to_string(),
                serde_json::Value::from(rule.priority),
            );
            map.insert("enabled".to_string(), serde_json::Value::Bool(rule.enabled));
            map.insert(
                "reason".to_string(),
                serde_json::Value::String(rule.reason.clone()),
            );
            if let Some(tests) = &rule.tests {
                map.insert(
                    "tests".to_string(),
                    serde_json::to_value(tests).unwrap_or(serde_json::Value::Null),
                );
            }
            serde_json::Value::Object(map)
        })
        .collect();
    rules.sort_by(|a, b| {
        let key = |value: &serde_json::Value| {
            (
                value["selector"].as_str().unwrap_or("").to_string(),
                rule_key(
                    value["selector"].as_str().unwrap_or(""),
                    value["value"].as_str().unwrap_or(""),
                ),
                value["action"].as_str().unwrap_or("").to_string(),
                value["priority"].as_i64().unwrap_or(0),
                value["category"].as_str().unwrap_or("").to_string(),
                value["enabled"].as_bool().unwrap_or(true),
            )
        };
        key(a).cmp(&key(b))
    });
    let tools = content.tools.as_ref().map(|tools| {
        let mut tools: Vec<serde_json::Value> = tools
            .iter()
            .map(|tool| {
                serde_json::json!({
                    "tool": tool.tool,
                    "mode": tool.mode,
                    "reason": tool.reason,
                })
            })
            .collect();
        tools.sort_by(|a, b| {
            a["tool"]
                .as_str()
                .unwrap_or("")
                .cmp(b["tool"].as_str().unwrap_or(""))
        });
        serde_json::Value::Array(tools)
    });
    serde_json::json!({
        "dictionary": {
            "mode": content.dictionary.mode,
            "sources": sources,
        },
        "rules": rules,
        "tools": tools.unwrap_or(serde_json::Value::Null),
    })
}

/// §2.4: `content_hash = "sha256:" + hex(sha256(canonical_json))`.
pub(crate) fn content_hash(content: &VersionContent) -> String {
    format!(
        "sha256:{}",
        sha256_hex(&canonical_value_bytes(&canonical_content_value(content)))
    )
}

/// Детерминированный id изменения diff (§3.1):
/// `c_` + 16 hex sha256(kind|subject|before|after — канонически).
pub(crate) fn change_id(
    kind: &str,
    subject: &serde_json::Value,
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> String {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend(kind.as_bytes());
    bytes.push(b'|');
    bytes.extend(canonical_value_bytes(subject));
    bytes.push(b'|');
    bytes.extend(canonical_value_bytes(before));
    bytes.push(b'|');
    bytes.extend(canonical_value_bytes(after));
    format!("c_{}", &sha256_hex(&bytes)[..16])
}

/// §1.6 identity источника: (source_path lowercase) — дубликат по пути
/// без учёта регистра.
pub(crate) fn source_key(source_path: &str) -> String {
    source_path.to_lowercase()
}

/// Проверка причины §1.1: 1..500 символов, без управляющих кроме `\n`.
pub(crate) fn reason_valid(reason: &str) -> bool {
    !reason.is_empty()
        && reason.chars().count() <= 500
        && reason.chars().all(|ch| ch == '\n' || !ch.is_control())
}

/// UUID из строки БД (setup_* таблицы хранят id текстом).
#[allow(dead_code)]
pub(crate) fn parse_uuid_text(text: &str) -> Option<Uuid> {
    Uuid::parse_str(text).ok()
}
//++agent TASK-225
