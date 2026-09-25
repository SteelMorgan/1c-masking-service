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
    //++agent TASK-224 [25.09.2026] ревью R1
    // Присвоение секретного литерала в свободном тексте (`Пароль = "…"`,
    // `api_key='…'`, `token: …`): durable-производные аргументов вызова не
    // имеют evidence, поэтому литерал распознаётся по имени ключа в тексте.
    secret_assignment: Regex,
    //--agent TASK-224
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
    fio_literals: Vec<String>,
    deadline: Instant,
}

struct CutContext<'a> {
    strings: usize,
    deadline: Instant,
    secret_fields: &'a HashSet<String>,
    literals: &'a HashSet<String>,
    //++agent TASK-224 [25.09.2026] ревью R1
    // Режим durable-производных аргументов (без evidence): имена ключей
    // проверяются и по компактной форме, а в строках дополнительно режутся
    // присвоения секретных литералов по имени ключа.
    strict_text: bool,
    //--agent TASK-224
}

#[derive(Default, Clone)]
struct FieldEvidence {
    source_paths: Vec<String>,
    field_types: Vec<String>,
    secret_cut: bool,
}

impl MaskEngine {
    pub fn new() -> Self {
        Self {
            secret_name: RegexBuilder::new(r"(^|[_\-.])(password|passwd|secret|access.?token|refresh.?token|api.?key|private.?key|authorization|парол|токен|секрет|ключ)([_\-.]|$)")
                .case_insensitive(true).build().expect("static regex"),
            secret_value: RegexBuilder::new(r"(?i)(bearer\s+[a-z0-9._~+/=-]{8,}|authorization\s*[:=]\s*\S+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
                .case_insensitive(true).build().expect("static regex"),
            //++agent TASK-224 [25.09.2026] ревью R1
            // Имена ключей — из secret_name; значение — кавычки либо
            // непробельный литерал. Левой границы нет: недорезание опаснее
            // лишнего среза в durable-заголовке.
            secret_assignment: RegexBuilder::new(r#"(password|passwd|secret|token|api.?key|private.?key|access.?token|refresh.?token|authorization|парол\w*|токен\w*|секрет\w*|ключ\w*)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;)]+)"#)
                .case_insensitive(true).build().expect("static regex"),
            //--agent TASK-224
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
        let evidence = parse_evidence(evidence);
        let fio_fields: HashSet<String> = evidence
            .iter()
            .filter(|(_, item)| self.is_fio_source(item))
            .map(|(name, _)| name.clone())
            .collect();
        let mut fio_literals = HashSet::new();
        collect_field_literals(input, &fio_fields, &mut fio_literals, 0)
            .map_err(|_| ProcessingError)?;
        let mut fio_literals: Vec<String> = fio_literals.into_iter().collect();
        fio_literals.sort_by_key(|value| std::cmp::Reverse(value.len()));
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
            evidence,
            fio_literals,
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

    pub fn cut_secrets(
        &self,
        input: &Value,
        evidence: &Value,
        policy: &PolicySnapshot,
    ) -> Result<Value, ProcessingError> {
        validate_value_bounds(
            input,
            self.max_depth,
            self.max_strings,
            self.max_rows,
            self.max_text_bytes,
        )
        .map_err(|_| ProcessingError)?;
        let fields = parse_evidence(evidence);
        let secret_fields: HashSet<String> = fields
            .iter()
            .filter(|(_, item)| self.is_secret_source(item, policy))
            .map(|(name, _)| name.clone())
            .collect();
        let mut literals = HashSet::new();
        collect_secret_literals(input, &secret_fields, &mut literals, 0)
            .map_err(|_| ProcessingError)?;
        let mut context = CutContext {
            strings: 0,
            deadline: Instant::now() + self.processing_timeout,
            secret_fields: &secret_fields,
            literals: &literals,
            strict_text: false,
        };
        self.cut_walk(input, None, 0, &mut context)
            .map_err(|_| ProcessingError)
    }

    //++agent TASK-224 [25.09.2026] ревью R1
    /// Необратимая зачистка аргументов вызова перед сохранением
    /// durable-производных (заголовок call_contexts → title отчёта истории).
    /// Тот же cut, что у результата (ключи по secret_name → SECRET_REMOVED,
    /// сигнатуры bearer/authorization/private-key в строках), плюс — так как
    /// evidence у аргументов нет — присвоения секретных литералов в свободном
    /// тексте (`Пароль = "…"`, `api_key=…`) и компактные имена ключей.
    /// Fail-closed: нарушение границ/таймаут → Err, заголовок не хранится.
    pub fn cut_call_arguments(&self, input: &Value) -> Result<Value, ProcessingError> {
        validate_value_bounds(
            input,
            self.max_depth,
            self.max_strings,
            self.max_rows,
            self.max_text_bytes,
        )
        .map_err(|_| ProcessingError)?;
        let secret_fields = HashSet::new();
        let literals = HashSet::new();
        let mut context = CutContext {
            strings: 0,
            deadline: Instant::now() + self.processing_timeout,
            secret_fields: &secret_fields,
            literals: &literals,
            strict_text: true,
        };
        self.cut_walk(input, None, 0, &mut context)
            .map_err(|_| ProcessingError)
    }
    //--agent TASK-224

    fn is_secret_source(&self, evidence: &FieldEvidence, policy: &PolicySnapshot) -> bool {
        evidence.secret_cut
            || evidence.source_paths.iter().any(|path| {
                self.secret_name.is_match(path)
                    || compact_secret_name(path)
                    || policy.metadata_sources.iter().any(|item| {
                        item.source_path.eq_ignore_ascii_case(path)
                            && (item.password_mode
                                || self.secret_name.is_match(&item.field_name)
                                || compact_secret_name(&item.field_name))
                    })
            })
    }

    fn is_fio_source(&self, evidence: &FieldEvidence) -> bool {
        evidence.source_paths.iter().any(|path| {
            let name = path.rsplit('.').next().unwrap_or(path);
            //++agent TASK-221 2026-09-23
            // Полное имя может быть опубликовано под нейтральным псевдонимом;
            // проверяем именно подтверждённый источник, а не имя колонки.
            self.fio_name.is_match(name) || name.to_lowercase() == "наименованиеполное"
            //--agent TASK-221
        })
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

    //++agent TASK-225 [25.09.2026]
    /// Проверка «в аргументах есть mask-токен» без обращения к mapping
    /// store — для классов, которым резолв запрещён (metadata-bypass,
    /// data-mask вне режима Enabled): то же ограничение bounds и тот же
    /// обход, что у `resolve_tokens`, но возвращает только факт наличия.
    /// Ошибка bounds трактуется вызывающим как невалидные аргументы.
    pub fn contains_tokens(&self, value: &Value) -> Result<bool, ProcessingError> {
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
        Ok(!unique.is_empty())
    }
    //++agent TASK-225

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
        if text == SECRET_REMOVED {
            return Ok(SECRET_REMOVED.to_owned());
        }
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
        for (known, category) in &context.policy.dictionary {
            if Instant::now() > context.deadline {
                return Err(());
            }
            if !known.is_empty()
                && text.contains(known)
                && strongest_dictionary_action(context.policy, category) == RuleAction::Secret
            {
                context
                    .reasons
                    .insert(format!("dictionary:{category}:secret"));
                return Ok(SECRET_REMOVED.to_owned());
            }
        }
        for rule in context.policy.rules.iter().filter(|rule| {
            rule.selector == RuleSelector::Regex && rule.action == RuleAction::Secret
        }) {
            if Instant::now() > context.deadline {
                return Err(());
            }
            let regex = Regex::new(&rule.pattern).map_err(|_| ())?;
            if regex.is_match(text) {
                context
                    .reasons
                    .insert(rule_reason(RuleSelector::Regex, rule));
                return Ok(SECRET_REMOVED.to_owned());
            }
        }

        if (self.fio_name.is_match(field) || self.is_fio_source(&evidence)) && !text.is_empty() {
            context.reasons.insert("mandatory:fio:name".to_owned());
            return plan(context, "FIO", text);
        }
        let mut rendered = text.to_owned();
        for literal in context.fio_literals.clone() {
            if rendered.contains(&literal) {
                context.reasons.insert("mandatory:fio:source".to_owned());
                let replacement = plan(context, "FIO", &literal)?;
                rendered = rendered.replace(&literal, &replacement);
            }
        }
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
                        return Ok(SECRET_REMOVED.to_owned());
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
        context: &mut CutContext<'_>,
    ) -> Result<Value, ()> {
        if depth > self.max_depth || Instant::now() > context.deadline {
            return Err(());
        }
        if field.is_some_and(|name| {
            self.secret_name.is_match(name)
                || context.secret_fields.contains(&name.to_lowercase())
                //++agent TASK-224 [25.09.2026] ревью R1: без evidence ключ
                // вида `myApiKey`/`ПарольПользователя` опознаётся только по
                // компактной форме имени.
                || (context.strict_text && compact_secret_name(name))
            //--agent TASK-224
        }) {
            return Ok(Value::String(SECRET_REMOVED.to_owned()));
        }
        match value {
            Value::Object(object) => object
                .iter()
                .map(|(key, value)| {
                    Ok((
                        key.clone(),
                        self.cut_walk(value, Some(key), depth + 1, context)?,
                    ))
                })
                .collect::<Result<Map<_, _>, _>>()
                .map(Value::Object),
            Value::Array(array) => array
                .iter()
                .map(|value| self.cut_walk(value, field, depth + 1, context))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            Value::String(text) => {
                context.strings += 1;
                if context.strings > self.max_strings || text.len() > self.max_text_bytes {
                    return Err(());
                }
                let mut cut = self
                    .secret_value
                    .replace_all(text, SECRET_REMOVED)
                    .into_owned();
                //++agent TASK-224 [25.09.2026] ревью R1: литерал может быть
                // вписан в свободный текст запроса присвоением — режется по
                // имени ключа (`Пароль = "…"` → `[SECRET_REMOVED]`).
                if context.strict_text {
                    cut = self
                        .secret_assignment
                        .replace_all(&cut, SECRET_REMOVED)
                        .into_owned();
                }
                //--agent TASK-224
                for literal in context.literals {
                    if !literal.is_empty() {
                        cut = cut.replace(literal, SECRET_REMOVED);
                        let escaped = serde_json::to_string(literal).map_err(|_| ())?;
                        if escaped.len() > 2 {
                            cut = cut.replace(&escaped[1..escaped.len() - 1], SECRET_REMOVED);
                        }
                    }
                }
                Ok(Value::String(cut))
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
    Ok(policy
        .rules
        .iter()
        .filter(|rule| {
            rule.selector == selector
                && match selector {
                    RuleSelector::SourcePath => {
                        //++agent TASK-221 2026-09-23
                        // Для составной колонки более строгий источник не должен
                        // проигрывать первому перечисленному источнику с Keep.
                        evidence
                            .source_paths
                            .iter()
                            .any(|path| wildcard_match(&rule.pattern, path))
                        //--agent TASK-221
                    }
                    RuleSelector::Name => wildcard_match(&rule.pattern, field),
                    RuleSelector::Type => evidence
                        .field_types
                        .iter()
                        .any(|field_type| wildcard_match(&rule.pattern, field_type)),
                    _ => false,
                }
        })
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
                    .field_types = column
                    .get("type")
                    .or_else(|| column.get("types"))
                    .map(parse_types)
                    .unwrap_or_default();
            }
        }
    }
    if let Some(lineage) = object.get("lineage").and_then(Value::as_array) {
        for item in lineage {
            let name = item
                .get("column")
                .or_else(|| item.get("result_name"))
                .or_else(|| item.get("name"))
                .and_then(Value::as_str);
            if let Some(name) = name {
                let entry = result
                    .entry(name.to_lowercase())
                    .or_insert_with(FieldEvidence::default);
                if let Some(path) = item.get("source_path").and_then(Value::as_str) {
                    if !entry.source_paths.iter().any(|known| known == path) {
                        entry.source_paths.push(path.to_owned());
                    }
                    entry.secret_cut |= compact_secret_name(path);
                }
                entry.secret_cut |= item.get("secret_cut").and_then(Value::as_bool) == Some(true);
                if entry.field_types.is_empty() {
                    entry.field_types = item
                        .get("source_type")
                        .or_else(|| item.get("source_types"))
                        .map(parse_types)
                        .unwrap_or_default();
                }
            }
        }
    }
    result
}

fn parse_types(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn collect_field_literals(
    value: &Value,
    fields: &HashSet<String>,
    literals: &mut HashSet<String>,
    depth: usize,
) -> Result<(), ()> {
    if depth > 64 {
        return Err(());
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if fields.contains(&key.to_lowercase()) {
                    if let Some(text) = child.as_str() {
                        if !text.is_empty() && text != SECRET_REMOVED {
                            literals.insert(text.to_owned());
                        }
                    } else if !child.is_null() {
                        return Err(());
                    }
                }
                collect_field_literals(child, fields, literals, depth + 1)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_field_literals(child, fields, literals, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn compact_secret_name(name: &str) -> bool {
    let compact: String = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();
    [
        "password",
        "passwd",
        "secret",
        "accesstoken",
        "refreshtoken",
        "apikey",
        "privatekey",
        "authorization",
        "пароль",
        "токен",
        "секрет",
        "приватныйключ",
    ]
    .iter()
    .any(|marker| compact.contains(marker))
}

fn collect_secret_literals(
    value: &Value,
    secret_fields: &HashSet<String>,
    literals: &mut HashSet<String>,
    depth: usize,
) -> Result<(), ()> {
    if depth > 64 {
        return Err(());
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if secret_fields.contains(&key.to_lowercase()) {
                    if let Some(text) = child.as_str() {
                        if !text.is_empty() && text != SECRET_REMOVED {
                            literals.insert(text.to_owned());
                        }
                    } else if !child.is_null() {
                        // Without a scalar literal, another serialized public copy
                        // cannot be proven free of the same source value.
                        return Err(());
                    }
                }
                collect_secret_literals(child, secret_fields, literals, depth + 1)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_secret_literals(child, secret_fields, literals, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
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
