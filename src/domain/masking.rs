use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};
use serde_json::{Map, Value};
use uuid::Uuid;

use super::{FeedMetadataItem, MappingCandidate, MappingStore, ProcessingError};

pub const SECRET_REMOVED: &str = "[SECRET_REMOVED]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleAction {
    Keep,
    Mask,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSelector {
    SourcePath,
    Name,
    Type,
    Dictionary,
    Regex,
}

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub selector: RuleSelector,
    pub pattern: String,
    pub action: RuleAction,
    pub category: String,
    pub priority: i64,
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub version: i64,
    pub rules: Vec<PolicyRule>,
    pub dictionary: HashMap<String, String>,
    pub metadata_sources: Vec<FeedMetadataItem>,
    pub ready: bool,
}

impl Default for PolicySnapshot {
    fn default() -> Self {
        Self {
            version: 1,
            rules: Vec::new(),
            dictionary: HashMap::new(),
            metadata_sources: Vec::new(),
            ready: true,
        }
    }
}

#[derive(Debug)]
pub struct MaskingOutput {
    pub value: Value,
    pub candidates: Vec<MappingCandidate>,
    pub reasons: HashSet<String>,
}

pub struct MaskEngine {
    secret_name: Regex,
    secret_value: Regex,
    fio_name: Regex,
    fio_value: Regex,
    token: Regex,
    max_depth: usize,
    max_strings: usize,
    max_rows: usize,
    max_text_bytes: usize,
    processing_timeout: Duration,
}

struct WalkContext<'a> {
    database_id: Uuid,
    chat_id: &'a str,
    batch_id: Uuid,
    ttl_seconds: u64,
    policy: &'a PolicySnapshot,
    mappings: &'a MappingStore,
    candidates: Vec<MappingCandidate>,
    reasons: HashSet<String>,
    strings_seen: usize,
    cells_seen: usize,
    evidence: HashMap<String, FieldEvidence>,
    deadline: Instant,
}

#[derive(Default, Clone)]
struct FieldEvidence {
    source_path: Option<String>,
    field_type: Option<String>,
}

impl MaskEngine {
    pub fn new() -> Self {
        Self {
            secret_name: RegexBuilder::new(r"(^|[_\-.])(password|passwd|secret|access.?token|refresh.?token|api.?key|private.?key|authorization|парол|токен|секрет|ключ)([_\-.]|$)")
                .case_insensitive(true).build().expect("static regex"),
            secret_value: RegexBuilder::new(r"(?i)(bearer\s+[a-z0-9._~+/=-]{8,}|authorization\s*[:=]\s*\S+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
                .case_insensitive(true).build().expect("static regex"),
            fio_name: RegexBuilder::new(r"(^|[_\-.])(фио|full.?name|person.?name|employee.?name|контрагент|физлицо)([_\-.]|$)")
                .case_insensitive(true).build().expect("static regex"),
            fio_value: Regex::new(r"(?u)\b[А-ЯЁ][а-яё]{2,}(?:\s+[А-ЯЁ][а-яё]{2,}){1,2}\b").expect("static regex"),
            token: Regex::new(r"\[MASK:v1:[A-Z0-9_]{1,32}:[A-Za-z0-9_-]{32}\]").expect("static regex"),
            max_depth: bounded_env("MASKING_MAX_DEPTH", 64, 8, 128),
            max_strings: bounded_env("MASKING_MAX_CELLS", 200_000, 1_000, 1_000_000),
            max_rows: bounded_env("MASKING_MAX_ROWS", 10_000, 100, 100_000),
            max_text_bytes: bounded_env(
                "MASKING_MAX_TEXT_BYTES",
                2 * 1024 * 1024,
                1024,
                8 * 1024 * 1024,
            ),
            processing_timeout: Duration::from_millis(bounded_env(
                "MASKING_ENGINE_TIMEOUT_MS",
                10_000,
                100,
                300_000,
            ) as u64),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mask(
        &self,
        input: &Value,
        database_id: Uuid,
        chat_id: &str,
        batch_id: Uuid,
        ttl_seconds: u64,
        policy: &PolicySnapshot,
        mappings: &MappingStore,
        evidence: &Value,
    ) -> Result<MaskingOutput, ProcessingError> {
        validate_value_bounds(
            input,
            self.max_depth,
            self.max_strings,
            self.max_rows,
            self.max_text_bytes,
        )
        .map_err(|_| ProcessingError)?;
        let mut context = WalkContext {
            database_id,
            chat_id,
            batch_id,
            ttl_seconds,
            policy,
            mappings,
            candidates: Vec::new(),
            reasons: HashSet::new(),
            strings_seen: 0,
            cells_seen: 0,
            evidence: parse_evidence(evidence),
            deadline: Instant::now() + self.processing_timeout,
        };
        let value = self
            .walk(input, None, 0, &mut context)
            .map_err(|_| ProcessingError)?;
        Ok(MaskingOutput {
            value,
            candidates: context.candidates,
            reasons: context.reasons,
        })
    }

    pub fn cut_secrets(&self, input: &Value) -> Result<Value, ProcessingError> {
        validate_value_bounds(
            input,
            self.max_depth,
            self.max_strings,
            self.max_rows,
            self.max_text_bytes,
        )
        .map_err(|_| ProcessingError)?;
        self.cut_walk(
            input,
            None,
            0,
            &mut 0,
            Instant::now() + self.processing_timeout,
        )
        .map_err(|_| ProcessingError)
    }

    pub fn resolve_tokens(
        &self,
        value: &Value,
        database_id: Uuid,
        chat_id: &str,
        mappings: &mut MappingStore,
    ) -> Result<Value, ProcessingError> {
        validate_value_bounds(
            value,
            self.max_depth,
            self.max_strings,
            self.max_rows,
            self.max_text_bytes,
        )
        .map_err(|_| ProcessingError)?;
        let mut unique = HashSet::new();
        collect_tokens(value, &self.token, &mut unique, 0).map_err(|_| ProcessingError)?;
        if unique.len() > 1_000 {
            return Err(ProcessingError);
        }
        let mut resolved = HashMap::new();
        for token in unique {
            let original = mappings
                .resolve(database_id, chat_id, &token)
                .ok_or(ProcessingError)?;
            resolved.insert(token, original);
        }
        replace_tokens(value, &resolved, 0).map_err(|_| ProcessingError)
    }

    pub fn resolve_tokens_for_batch(
        &self,
        value: &Value,
        database_id: Uuid,
        chat_id: &str,
        batch_id: Uuid,
        mappings: &mut MappingStore,
    ) -> Result<Value, ProcessingError> {
        validate_value_bounds(
            value,
            self.max_depth,
            self.max_strings,
            self.max_rows,
            self.max_text_bytes,
        )
        .map_err(|_| ProcessingError)?;
        let mut unique = HashSet::new();
        collect_tokens(value, &self.token, &mut unique, 0).map_err(|_| ProcessingError)?;
        if unique.len() > 1_000 {
            return Err(ProcessingError);
        }
        let mut resolved = HashMap::new();
        for token in unique {
            let original = mappings
                .resolve_for_batch(database_id, chat_id, batch_id, &token)
                .ok_or(ProcessingError)?;
            resolved.insert(token, original);
        }
        replace_tokens(value, &resolved, 0).map_err(|_| ProcessingError)
    }

    fn walk(
        &self,
        value: &Value,
        field: Option<&str>,
        depth: usize,
        context: &mut WalkContext<'_>,
    ) -> Result<Value, ()> {
        if depth > self.max_depth {
            return Err(());
        }
        if Instant::now() > context.deadline {
            return Err(());
        }
        context.cells_seen = context.cells_seen.checked_add(1).ok_or(())?;
        if context.cells_seen > self.max_strings
            || matches!(value, Value::Array(rows) if rows.len() > 10_000)
        {
            return Err(());
        }
        match value {
            Value::Object(object) => {
                let mut output = Map::with_capacity(object.len());
                for (key, value) in object {
                    output.insert(
                        key.clone(),
                        self.walk(value, Some(key), depth + 1, context)?,
                    );
                }
                Ok(Value::Object(output))
            }
            Value::Array(array) => array
                .iter()
                .map(|value| self.walk(value, field, depth + 1, context))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            Value::String(text) => {
                context.strings_seen += 1;
                if context.strings_seen > self.max_strings || text.len() > self.max_text_bytes {
                    return Err(());
                }
                self.mask_string(text, field, context).map(Value::String)
            }
            scalar => Ok(scalar.clone()),
        }
    }

    fn mask_string(
        &self,
        text: &str,
        field: Option<&str>,
        context: &mut WalkContext<'_>,
    ) -> Result<String, ()> {
        let field = field.unwrap_or("");
        let normalized_field = field.to_lowercase();
        let evidence = context
            .evidence
            .get(&normalized_field)
            .cloned()
            .unwrap_or_default();
        if self.secret_name.is_match(field) {
            context.reasons.insert("secret:name".to_owned());
            return Ok(SECRET_REMOVED.to_owned());
        }
        if self.secret_value.is_match(text) {
            context.reasons.insert("secret:value".to_owned());
            return Ok(self
                .secret_value
                .replace_all(text, SECRET_REMOVED)
                .into_owned());
        }

        // An explicit irreversible action is evaluated before reversible FIO
        // masking so a secret can never enter the mapping store.
        for selector in [
            RuleSelector::SourcePath,
            RuleSelector::Name,
            RuleSelector::Type,
        ] {
            if let Some(rule) = strongest_matching_rule(context.policy, selector, field, &evidence)?
            {
                if rule.action == RuleAction::Secret {
                    context.reasons.insert(rule_reason(selector, rule));
                    return Ok(SECRET_REMOVED.to_owned());
                }
            }
        }
        let mut preprocessed = text.to_owned();
        for (known, category) in &context.policy.dictionary {
            if Instant::now() > context.deadline {
                return Err(());
            }
            if !known.is_empty()
                && preprocessed.contains(known)
                && strongest_dictionary_action(context.policy, category) == RuleAction::Secret
            {
                context
                    .reasons
                    .insert(format!("dictionary:{category}:secret"));
                preprocessed = preprocessed.replace(known, SECRET_REMOVED);
            }
        }
        for rule in context.policy.rules.iter().filter(|rule| {
            rule.selector == RuleSelector::Regex && rule.action == RuleAction::Secret
        }) {
            if Instant::now() > context.deadline {
                return Err(());
            }
            let regex = Regex::new(&rule.pattern).map_err(|_| ())?;
            if regex.is_match(&preprocessed) {
                context
                    .reasons
                    .insert(rule_reason(RuleSelector::Regex, rule));
                preprocessed = regex
                    .replace_all(&preprocessed, SECRET_REMOVED)
                    .into_owned();
            }
        }

        if self.fio_name.is_match(field) && !text.is_empty() {
            context.reasons.insert("mandatory:fio:name".to_owned());
            return if preprocessed == SECRET_REMOVED {
                Ok(preprocessed)
            } else {
                plan(context, "FIO", &preprocessed)
            };
        }
        let mut rendered = preprocessed;
        if self.fio_value.is_match(&rendered) {
            context.reasons.insert("mandatory:fio:text".to_owned());
            rendered = replace_matches(&self.fio_value, &rendered, |matched| {
                plan(context, "FIO", matched)
            })?;
        }

        for selector in [
            RuleSelector::SourcePath,
            RuleSelector::Name,
            RuleSelector::Type,
        ] {
            if let Some(rule) = strongest_matching_rule(context.policy, selector, field, &evidence)?
            {
                context.reasons.insert(rule_reason(selector, rule));
                match rule.action {
                    RuleAction::Secret => return Ok(SECRET_REMOVED.to_owned()),
                    RuleAction::Mask => return plan(context, &rule.category, &rendered),
                    RuleAction::Keep => return Ok(rendered),
                }
            }
        }

        for (known, category) in &context.policy.dictionary {
            if Instant::now() > context.deadline {
                return Err(());
            }
            if !known.is_empty() && rendered.contains(known) {
                context.reasons.insert(format!("dictionary:{category}"));
                let action = strongest_dictionary_action(context.policy, category);
                let replacement = match action {
                    RuleAction::Secret => SECRET_REMOVED.to_owned(),
                    RuleAction::Mask => plan(context, category, known)?,
                    RuleAction::Keep => continue,
                };
                rendered = rendered.replace(known, &replacement);
            }
        }
        for rule in context.policy.rules.iter().filter(|rule| {
            rule.selector == RuleSelector::Regex && rule.action != RuleAction::Secret
        }) {
            if Instant::now() > context.deadline {
                return Err(());
            }
            let regex = Regex::new(&rule.pattern).map_err(|_| ())?;
            if regex.is_match(&rendered) {
                match rule.action {
                    RuleAction::Secret => {
                        rendered = regex.replace_all(&rendered, SECRET_REMOVED).into_owned()
                    }
                    RuleAction::Mask => {
                        rendered = replace_matches(&regex, &rendered, |matched| {
                            plan(context, &rule.category, matched)
                        })?;
                    }
                    RuleAction::Keep => {}
                }
                context.reasons.insert(format!("regex:{}", rule.category));
            }
        }
        Ok(rendered)
    }

    fn cut_walk(
        &self,
        value: &Value,
        field: Option<&str>,
        depth: usize,
        strings: &mut usize,
        deadline: Instant,
    ) -> Result<Value, ()> {
        if depth > self.max_depth || Instant::now() > deadline {
            return Err(());
        }
        match value {
            Value::Object(object) => object
                .iter()
                .map(|(key, value)| {
                    Ok((
                        key.clone(),
                        self.cut_walk(value, Some(key), depth + 1, strings, deadline)?,
                    ))
                })
                .collect::<Result<Map<_, _>, _>>()
                .map(Value::Object),
            Value::Array(array) => array
                .iter()
                .map(|value| self.cut_walk(value, field, depth + 1, strings, deadline))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            Value::String(text) => {
                *strings += 1;
                if *strings > self.max_strings || text.len() > self.max_text_bytes {
                    return Err(());
                }
                if field.is_some_and(|name| self.secret_name.is_match(name)) {
                    Ok(Value::String(SECRET_REMOVED.to_owned()))
                } else {
                    Ok(Value::String(
                        self.secret_value
                            .replace_all(text, SECRET_REMOVED)
                            .into_owned(),
                    ))
                }
            }
            scalar => Ok(scalar.clone()),
        }
    }
}

fn strongest_matching_rule<'a>(
    policy: &'a PolicySnapshot,
    selector: RuleSelector,
    field: &str,
    evidence: &FieldEvidence,
) -> Result<Option<&'a PolicyRule>, ()> {
    let target = match selector {
        RuleSelector::SourcePath => evidence.source_path.as_deref().unwrap_or(""),
        RuleSelector::Name => field,
        RuleSelector::Type => evidence.field_type.as_deref().unwrap_or(""),
        _ => return Ok(None),
    };
    Ok(policy
        .rules
        .iter()
        .filter(|rule| rule.selector == selector && wildcard_match(&rule.pattern, target))
        // Restrictiveness is authoritative at one selector level; priority is
        // only a deterministic tie-breaker between equally restrictive rules.
        .max_by_key(|rule| (rule.action, rule.priority)))
}

fn strongest_dictionary_action(policy: &PolicySnapshot, category: &str) -> RuleAction {
    policy
        .rules
        .iter()
        .filter(|rule| {
            rule.selector == RuleSelector::Dictionary && wildcard_match(&rule.pattern, category)
        })
        .max_by_key(|rule| (rule.action, rule.priority))
        .map_or(RuleAction::Mask, |rule| rule.action)
}

fn rule_reason(selector: RuleSelector, rule: &PolicyRule) -> String {
    let selector = match selector {
        RuleSelector::SourcePath => "source_path",
        RuleSelector::Name => "name",
        RuleSelector::Type => "type",
        RuleSelector::Dictionary => "dictionary",
        RuleSelector::Regex => "regex",
    };
    format!("{selector}:{}:{:?}", rule.category, rule.action).to_lowercase()
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(part) = pattern
        .strip_prefix('*')
        .and_then(|part| part.strip_suffix('*'))
    {
        return value.to_lowercase().contains(&part.to_lowercase());
    }
    value.eq_ignore_ascii_case(pattern)
}

fn plan(context: &mut WalkContext<'_>, category: &str, original: &str) -> Result<String, ()> {
    context
        .mappings
        .plan_token(
            &mut context.candidates,
            context.database_id,
            context.chat_id,
            category,
            original,
            context.batch_id,
            context.ttl_seconds,
        )
        .map_err(|_| ())
}

fn replace_matches<F>(regex: &Regex, text: &str, mut replacement: F) -> Result<String, ()>
where
    F: FnMut(&str) -> Result<String, ()>,
{
    let mut output = String::with_capacity(text.len());
    let mut last = 0;
    for found in regex.find_iter(text) {
        output.push_str(&text[last..found.start()]);
        output.push_str(&replacement(found.as_str())?);
        last = found.end();
    }
    output.push_str(&text[last..]);
    Ok(output)
}

fn parse_evidence(value: &Value) -> HashMap<String, FieldEvidence> {
    let mut result = HashMap::new();
    let Some(object) = value.as_object() else {
        return result;
    };
    if let Some(columns) = object
        .get("schema")
        .and_then(|schema| schema.get("columns"))
        .and_then(Value::as_array)
    {
        for column in columns {
            if let Some(name) = column.get("name").and_then(Value::as_str) {
                result
                    .entry(name.to_lowercase())
                    .or_insert_with(FieldEvidence::default)
                    .field_type = column
                    .get("type")
                    .or_else(|| column.get("types"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
        }
    }
    if let Some(lineage) = object.get("lineage").and_then(Value::as_array) {
        for item in lineage {
            let name = item
                .get("result_name")
                .or_else(|| item.get("name"))
                .and_then(Value::as_str);
            if let Some(name) = name {
                let entry = result
                    .entry(name.to_lowercase())
                    .or_insert_with(FieldEvidence::default);
                entry.source_path = item
                    .get("source_path")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if entry.field_type.is_none() {
                    entry.field_type = item
                        .get("source_type")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                }
            }
        }
    }
    result
}

fn collect_tokens(
    value: &Value,
    regex: &Regex,
    output: &mut HashSet<String>,
    depth: usize,
) -> Result<(), ()> {
    if depth > 64 {
        return Err(());
    }
    match value {
        Value::Object(object) => {
            for value in object.values() {
                collect_tokens(value, regex, output, depth + 1)?;
            }
        }
        Value::Array(array) => {
            for value in array {
                collect_tokens(value, regex, output, depth + 1)?;
            }
        }
        Value::String(text) => {
            for found in regex.find_iter(text) {
                output.insert(found.as_str().to_owned());
            }
        }
        _ => {}
    }
    Ok(())
}

fn replace_tokens(
    value: &Value,
    replacements: &HashMap<String, String>,
    depth: usize,
) -> Result<Value, ()> {
    if depth > 64 {
        return Err(());
    }
    match value {
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| Ok((key.clone(), replace_tokens(value, replacements, depth + 1)?)))
            .collect::<Result<Map<_, _>, _>>()
            .map(Value::Object),
        Value::Array(array) => array
            .iter()
            .map(|value| replace_tokens(value, replacements, depth + 1))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::String(text) => {
            let mut output = text.clone();
            for (token, original) in replacements {
                output = output.replace(token, original);
            }
            Ok(Value::String(output))
        }
        scalar => Ok(scalar.clone()),
    }
}

impl Default for MaskEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn bounded_env(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .unwrap_or(default)
}

fn validate_value_bounds(
    value: &Value,
    max_depth: usize,
    max_cells: usize,
    max_rows: usize,
    max_text_bytes: usize,
) -> Result<(), ()> {
    #[allow(clippy::too_many_arguments)]
    fn visit(
        value: &Value,
        depth: usize,
        cells: &mut usize,
        max_depth: usize,
        max_cells: usize,
        max_rows: usize,
        text_bytes: &mut usize,
        max_text_bytes: usize,
    ) -> Result<(), ()> {
        if depth > max_depth {
            return Err(());
        }
        *cells = cells.checked_add(1).ok_or(())?;
        if *cells > max_cells {
            return Err(());
        }
        match value {
            Value::Object(object) => {
                for child in object.values() {
                    visit(
                        child,
                        depth + 1,
                        cells,
                        max_depth,
                        max_cells,
                        max_rows,
                        text_bytes,
                        max_text_bytes,
                    )?;
                }
            }
            Value::Array(array) => {
                if array.len() > max_rows {
                    return Err(());
                }
                for child in array {
                    visit(
                        child,
                        depth + 1,
                        cells,
                        max_depth,
                        max_cells,
                        max_rows,
                        text_bytes,
                        max_text_bytes,
                    )?;
                }
            }
            Value::String(text) => {
                *text_bytes = text_bytes.checked_add(text.len()).ok_or(())?;
                if text.len() > max_text_bytes || *text_bytes > max_text_bytes {
                    return Err(());
                }
            }
            _ => {}
        }
        Ok(())
    }

    visit(
        value,
        0,
        &mut 0,
        max_depth,
        max_cells,
        max_rows,
        &mut 0,
        max_text_bytes,
    )
}
