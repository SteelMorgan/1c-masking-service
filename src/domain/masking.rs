use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};
use serde::Serialize;
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
    //++agent TASK-225 [26.09.2026]
    /// §6.1: связь с policy_rules.id — детальные причины ячеек ссылаются
    /// на правило; встроенные правила (секретные пути) — None.
    //++agent TASK-225
    pub rule_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub version: i64,
    pub rules: Vec<PolicyRule>,
    pub dictionary: HashMap<String, String>,
    //++agent TASK-225 [26.09.2026] D8: категория → source_path источника
    /// словаря (§6.3: причина `dictionary` несёт `source_path` для
    /// link/panel UI). Заполняется при pull из `FeedDictionaryValue`;
    /// у категории с несколькими источниками — первый по порядку feed.
    //++agent TASK-225
    pub dictionary_sources: HashMap<String, String>,
    //++agent TASK-225 [25.09.2026]
    /// §5a.2: предпостроенный индекс словаря (Aho-Corasick). Строится вне
    /// горячего пути при замене снимка; `None` — fallback на прямой
    /// перебор `dictionary` (тестовые снимки, пустой словарь).
    //++agent TASK-225
    pub dictionary_index: Option<std::sync::Arc<DictionaryIndex>>,
    pub metadata_sources: Vec<FeedMetadataItem>,
    //++agent TASK-225 [26.09.2026]
    /// §6.1: id строки `policies` активной версии — пишется в
    /// `history.policy_id` для связи записи с версией (B9).
    //++agent TASK-225
    pub policy_id: Option<Uuid>,
    //++agent TASK-225 [26.09.2026] review MINOR-9
    /// Отпечаток содержимого `dictionary` (XOR-свертка хешей записей —
    /// порядок итерации не важен). 0 = «не посчитан»; вычисляется вне
    /// write-блокировки. Сравнение отпечатков вместо O(n) `HashMap::eq`
    /// под `policy_cache.write()`.
    //++agent TASK-225
    pub dictionary_fingerprint: u64,
    pub ready: bool,
}

impl Default for PolicySnapshot {
    fn default() -> Self {
        Self {
            version: 1,
            rules: Vec::new(),
            dictionary: HashMap::new(),
            dictionary_sources: HashMap::new(),
            dictionary_index: None,
            metadata_sources: Vec::new(),
            policy_id: None,
            dictionary_fingerprint: 0,
            ready: true,
        }
    }
}

//++agent TASK-225 [26.09.2026] review MINOR-9
/// Дешёвый отпечаток словаря: XOR хешей отдельных записей — порядок
/// итерации HashMap не влияет. Только in-memory (сравнение «тот же
/// словарь» при слиянии снимков), не персистится.
pub fn dictionary_fingerprint(dictionary: &HashMap<String, String>) -> u64 {
    use std::hash::{Hash, Hasher};
    dictionary.iter().fold(0u64, |acc, (key, value)| {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        value.hash(&mut hasher);
        acc ^ hasher.finish()
    })
}
//++agent TASK-225

//++agent TASK-225 [25.09.2026]
/// §5a.2: индекс словаря на Aho-Corasick. `automaton` — только
/// не-keep значения (LeftmostLongest — детерминированный выбор при
/// пересекающихся значениях): keep-значение не заменяет текст и не
/// должно глушить mask-совпадение внутри него (семантика legacy-скана,
/// B-3). `keep_automaton` — отдельный Standard-автомат по
/// keep-значениям для фиксации причины `dictionary:<cat>` (legacy
/// записывал её и при keep; overlapping-итерация видит все совпадения,
/// включая перекрытые keep-значения разных категорий). N-2: линейный
/// `contains` на каждую keep-запись — O(keep×текст) на строку, тот же
/// порядок сложности, от которого уходит §5a. `entries` —
/// значение/категория/предвычисленное действие; `automaton_entry`/
/// `keep_entry`/`secret_entry` отображают pattern_id автоматов в
/// `entries`. `secret_automaton` — Standard-автомат по secret-значениям:
/// проход «любое совпадение удаляет строку» должен видеть и перекрытые
/// совпадения, которые LeftmostLongest отбрасывает.
pub struct DictionaryIndex {
    automaton: std::sync::Arc<aho_corasick::AhoCorasick>,
    /// pattern_id основного автомата → индекс в `entries`.
    automaton_entry: Vec<usize>,
    /// Standard-автомат по keep-значениям (в основной не входят);
    /// `Arc` — переиспользование в `with_actions` при неизменном
    /// keep-множестве; None — keep-записей нет.
    keep_automaton: Option<std::sync::Arc<aho_corasick::AhoCorasick>>,
    /// pattern_id keep-автомата → индекс в `entries`.
    keep_entry: Vec<usize>,
    secret_automaton: Option<aho_corasick::AhoCorasick>,
    /// pattern_id secret-автомата → индекс в `entries`.
    secret_entry: Vec<usize>,
    entries: Vec<DictionaryEntry>,
}

#[derive(Debug)]
struct DictionaryEntry {
    // Arc<str>: пересчёт действий (with_actions) клонирует ссылки,
    // а не сами значения словаря.
    value: std::sync::Arc<str>,
    category: std::sync::Arc<str>,
    action: RuleAction,
}

impl std::fmt::Debug for DictionaryIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DictionaryIndex")
            .field("entries", &self.entries.len())
            .field("secret_entries", &self.secret_entry.len())
            .finish()
    }
}

impl DictionaryIndex {
    /// Строит автоматы по значениям словаря и правилам снимка.
    /// `None` — словарь пуст (индекс не нужен).
    pub fn build(
        dictionary: &HashMap<String, String>,
        rules: &[PolicyRule],
    ) -> Option<std::sync::Arc<Self>> {
        let entries: Vec<DictionaryEntry> = dictionary
            .iter()
            .filter(|(value, _)| !value.is_empty())
            .map(|(value, category)| DictionaryEntry {
                value: std::sync::Arc::from(value.as_str()),
                category: std::sync::Arc::from(category.as_str()),
                action: Self::action_for(rules, category),
            })
            .collect();
        if entries.is_empty() {
            return None;
        }
        Some(std::sync::Arc::new(Self::assemble(entries)))
    }

    /// Пересчёт действий при смене правил без нового pull. Автоматы
    /// переиспользуются, пока не-keep/keep множества значений не
    /// изменились; при переходе категории keep↔не-keep (B-3) автоматы
    /// пересобираются — значения те же, множества другие.
    pub fn with_actions(&self, rules: &[PolicyRule]) -> std::sync::Arc<Self> {
        let entries: Vec<DictionaryEntry> = self
            .entries
            .iter()
            .map(|entry| DictionaryEntry {
                value: entry.value.clone(),
                category: entry.category.clone(),
                action: Self::action_for(rules, &entry.category),
            })
            .collect();
        let active_ids = Self::active_entry_ids(&entries);
        let (automaton, automaton_entry) = if active_ids == self.automaton_entry {
            (self.automaton.clone(), self.automaton_entry.clone())
        } else {
            (
                std::sync::Arc::new(Self::build_automaton(
                    &entries,
                    &active_ids,
                    aho_corasick::MatchKind::LeftmostLongest,
                )),
                active_ids,
            )
        };
        let keep_ids = Self::keep_entry_ids(&entries);
        let keep_automaton = if keep_ids == self.keep_entry {
            self.keep_automaton.clone()
        } else {
            Self::build_keep_automaton(&entries, &keep_ids)
        };
        let mut index = Self {
            automaton,
            automaton_entry,
            keep_automaton,
            keep_entry: keep_ids,
            secret_automaton: None,
            secret_entry: Vec::new(),
            entries,
        };
        index.rebuild_secret();
        std::sync::Arc::new(index)
    }

    /// §5: память автоматов + вектора записей — для отчёта сухого
    /// прогона (`timing.dictionary_memory.automaton_bytes`).
    pub fn heap_bytes(&self) -> u64 {
        let mut total = self.automaton.memory_usage() as u64;
        if let Some(keep) = &self.keep_automaton {
            total += keep.memory_usage() as u64;
        }
        if let Some(secret) = &self.secret_automaton {
            total += secret.memory_usage() as u64;
        }
        // entries: Arc-указатели + строки значений/категорий.
        total += self
            .entries
            .iter()
            .map(|entry| entry.value.len() + entry.category.len() + 48)
            .sum::<usize>() as u64;
        total
    }

    /// Действие категории — тот же `strongest_dictionary_action`,
    /// по списку правил без полного снимка.
    fn action_for(rules: &[PolicyRule], category: &str) -> RuleAction {
        rules
            .iter()
            .filter(|rule| {
                rule.selector == RuleSelector::Dictionary && wildcard_match(&rule.pattern, category)
            })
            .max_by_key(|rule| (rule.action, rule.priority))
            .map_or(RuleAction::Mask, |rule| rule.action)
    }

    fn assemble(entries: Vec<DictionaryEntry>) -> Self {
        let active_ids = Self::active_entry_ids(&entries);
        let automaton = Self::build_automaton(
            &entries,
            &active_ids,
            aho_corasick::MatchKind::LeftmostLongest,
        );
        let keep_ids = Self::keep_entry_ids(&entries);
        let mut index = Self {
            automaton: std::sync::Arc::new(automaton),
            automaton_entry: active_ids,
            keep_automaton: Self::build_keep_automaton(&entries, &keep_ids),
            keep_entry: keep_ids,
            secret_automaton: None,
            secret_entry: Vec::new(),
            entries,
        };
        index.rebuild_secret();
        index
    }

    /// Индексы записей, попадающих в основной автомат (всё, кроме keep).
    fn active_entry_ids(entries: &[DictionaryEntry]) -> Vec<usize> {
        entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.action != RuleAction::Keep)
            .map(|(id, _)| id)
            .collect()
    }

    /// Индексы keep-записей — для keep-автомата фиксации причин.
    fn keep_entry_ids(entries: &[DictionaryEntry]) -> Vec<usize> {
        entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.action == RuleAction::Keep)
            .map(|(id, _)| id)
            .collect()
    }

    fn build_automaton(
        entries: &[DictionaryEntry],
        ids: &[usize],
        kind: aho_corasick::MatchKind,
    ) -> aho_corasick::AhoCorasick {
        aho_corasick::AhoCorasickBuilder::new()
            .match_kind(kind)
            .build(ids.iter().map(|id| entries[*id].value.as_ref()))
            .expect("dictionary automaton build")
    }

    /// Секрет-проход требует overlapping-семантики (любое совпадение,
    /// даже перекрытое более длинным): отдельный автомат Standard-семантики
    /// только по secret-значениям — их обычно мало.
    fn rebuild_secret(&mut self) {
        let secret_ids: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.action == RuleAction::Secret)
            .map(|(id, _)| id)
            .collect();
        if secret_ids.is_empty() {
            self.secret_automaton = None;
            self.secret_entry = Vec::new();
            return;
        }
        self.secret_automaton = Some(
            aho_corasick::AhoCorasickBuilder::new()
                .match_kind(aho_corasick::MatchKind::Standard)
                .build(secret_ids.iter().map(|id| self.entries[*id].value.as_ref()))
                .expect("secret automaton build"),
        );
        self.secret_entry = secret_ids;
    }

    /// Первое secret-совпадение в `text` — для прохода «вся строка
    /// [SECRET_REMOVED]». Возвращает категорию совпавшего значения.
    fn find_secret(&self, text: &str) -> Option<&str> {
        let automaton = self.secret_automaton.as_ref()?;
        let mat = automaton.find(text)?;
        Some(&self.entries[self.secret_entry[mat.pattern().as_usize()]].category)
    }

    /// Непересекающиеся совпадения словаря (leftmost-longest):
    /// `(start, end, entry_id)` в порядке следования в `text`.
    fn matches<'a>(&'a self, text: &'a str) -> impl Iterator<Item = (usize, usize, usize)> + 'a {
        self.automaton.find_iter(text).map(|mat| {
            (
                mat.start(),
                mat.end(),
                self.automaton_entry[mat.pattern().as_usize()],
            )
        })
    }

    /// Keep-автомат по `ids` (Standard — overlapping-итерация);
    /// `None` — keep-записей нет, сканировать нечего.
    fn build_keep_automaton(
        entries: &[DictionaryEntry],
        ids: &[usize],
    ) -> Option<std::sync::Arc<aho_corasick::AhoCorasick>> {
        if ids.is_empty() {
            return None;
        }
        Some(std::sync::Arc::new(Self::build_automaton(
            entries,
            ids,
            aho_corasick::MatchKind::Standard,
        )))
    }

    /// Индексы keep-записей, чьи значения встречаются в `text`
    /// (для фиксации причины `dictionary:<cat>`; текст не меняется).
    /// Standard-автомат с overlapping-итерацией — семантика
    /// legacy-перебора: видны и перекрытые keep-значения разных
    /// категорий. Повторные совпадения одного значения выдаются на
    /// каждую позицию — дедупликация на вызывающей стороне.
    fn keep_matches<'a>(&'a self, text: &'a str) -> impl Iterator<Item = usize> + 'a {
        self.keep_automaton
            .iter()
            .flat_map(move |automaton| automaton.find_overlapping_iter(text))
            .map(|mat| self.keep_entry[mat.pattern().as_usize()])
    }

    fn entry(&self, entry_id: usize) -> &DictionaryEntry {
        &self.entries[entry_id]
    }
}

//++agent TASK-225

//++agent TASK-225 [26.09.2026]
/// §6.1: структурная причина маскирования — строка `code` совпадает с
/// legacy `mask_reasons_json`; `kind` = rule|dictionary|builtin;
/// `rule_id` — ссылка на policy_rules.id (встроенные — None).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReasonEntry {
    pub code: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    //++agent TASK-225 [26.09.2026]
    /// §6.1: путь источника — для `source_path`-правил это `pattern`
    /// (точный путь); у dictionary-причин остаётся `category`.
    //++agent TASK-225
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}
//++agent TASK-225

#[derive(Debug)]
pub struct MaskingOutput {
    pub value: Value,
    pub candidates: Vec<MappingCandidate>,
    pub reasons: HashSet<String>,
    //++agent TASK-225 [26.09.2026]
    /// §6.1: дедуплицированные причины и привязка ячеек —
    /// (json_pointer, reason_idx). Только для записей истории нового
    /// формата; значений ячеек тут нет.
    //++agent TASK-225
    pub reason_entries: Vec<ReasonEntry>,
    pub cell_reasons: Vec<(String, u32)>,
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
    batch_id: Uuid,
    ttl_seconds: u64,
    policy: &'a PolicySnapshot,
    mappings: &'a MappingStore,
    candidates: Vec<MappingCandidate>,
    reasons: HashSet<String>,
    //++agent TASK-225 [26.09.2026]
    /// §6.1: текущий JSON-pointer обхода и таблица причин
    /// (reason_index — дедупликация по сериализованному entry).
    //++agent TASK-225
    pointer: String,
    reason_entries: Vec<ReasonEntry>,
    reason_index: HashMap<String, u32>,
    cell_reasons: Vec<(String, u32)>,
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
    //++agent TASK-225 [25.09.2026]
    // Строгий режим: колонка помечена границей как unverified — её
    // происхождение недоказуемо, значение маскируется целиком.
    //++agent TASK-225
    unverified: bool,
}

impl MaskEngine {
    pub fn new() -> Self {
        Self {
            //++agent TASK-225 [27.09.2026] Y4 консолидация
            // Alternation расширена до набора SECRET_NAME_COMPACT_MARKERS
            // (bounded-варианты; `ключ` остаётся только здесь и только
            // с границами слова). Зеркало — ЭтоИмяСекрета границы 1С.
            secret_name: RegexBuilder::new(r"(^|[_\-.])(password|passwd|passphrase|секретнаяфраза|secret|access.?token|refresh.?token|token|api.?key|ключapi|ключапи|private.?key|приватныйключ|access.?key|refresh.?key|authorization|авторизац|парол|токен|секрет|ключ)([_\-.]|$)")
                .case_insensitive(true).build().expect("static regex"),
            secret_value: RegexBuilder::new(r"(?i)(bearer\s+[a-z0-9._~+/=-]{8,}|authorization\s*[:=]\s*\S+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
                .case_insensitive(true).build().expect("static regex"),
            //++agent TASK-224 [25.09.2026] ревью R1
            // Имена ключей — из secret_name; значение — кавычки либо
            // непробельный литерал. Левой границы нет: недорезание опаснее
            // лишнего среза в durable-заголовке.
            secret_assignment: RegexBuilder::new(r#"(password|passwd|passphrase|секретнаяфраза|secret|token|api.?key|private.?key|access.?token|refresh.?token|authorization|парол\w*|токен\w*|секрет\w*|ключ\w*)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;)]+)"#)
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
            batch_id,
            ttl_seconds,
            policy,
            mappings,
            candidates: Vec::new(),
            reasons: HashSet::new(),
            //++agent TASK-225 [26.09.2026]
            pointer: String::new(),
            reason_entries: Vec::new(),
            reason_index: HashMap::new(),
            cell_reasons: Vec::new(),
            //++agent TASK-225
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
            //++agent TASK-225 [26.09.2026]
            reason_entries: context.reason_entries,
            cell_reasons: context.cell_reasons,
            //++agent TASK-225
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
                .resolve(database_id, &token)
                .ok_or(ProcessingError)?;
            resolved.insert(token, original);
        }
        replace_tokens(value, &resolved, 0).map_err(|_| ProcessingError)
    }

    //++agent TASK-225 [25.09.2026]
    /// Проверка «в аргументах есть mask-токен» без обращения к mapping
    /// store — для классов, которым резолв запрещён (no-mask,
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
                .resolve_for_batch(database_id, batch_id, &token)
                .ok_or(ProcessingError)?;
            resolved.insert(token, original);
        }
        let mut output = replace_tokens(value, &resolved, 0).map_err(|_| ProcessingError)?;
        //++agent TASK-225 [27.09.2026 00:00:00] W: защита в глубину при
        // reveal — записи, созданные до фикса слоя-1, могут хранить
        // оригинал с вложенным токеном; разворачиваем рекурсивно в
        // пределах партии (тот же resolve_for_batch: база+чат+партия).
        // Токен вне партии остаётся текстом — разворачивать нечего.
        for _ in 0..8 {
            let mut nested = HashSet::new();
            collect_tokens(&output, &self.token, &mut nested, 0).map_err(|_| ProcessingError)?;
            if nested.is_empty() {
                break;
            }
            let mut resolved = HashMap::new();
            for token in nested {
                if let Some(original) = mappings.resolve_for_batch(database_id, batch_id, &token) {
                    resolved.insert(token, original);
                }
            }
            if resolved.is_empty() {
                break;
            }
            output = replace_tokens(&output, &resolved, 0).map_err(|_| ProcessingError)?;
        }
        Ok(output)
        //++agent TASK-225
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
        //++agent TASK-225 [25.09.2026]
        // Строгий режим: ячейка unverified-колонки заменяется одним
        // обратимым токеном целиком — любой JSON-тип, без рекурсии в
        // объект/массив (их внутренние ключи недоказуемы вместе с
        // колонкой). Категория токена следует фактическому типу
        // значения: объявленные output_types — только evidence.
        if let Some(name) = field {
            if context
                .evidence
                .get(&name.to_lowercase())
                .is_some_and(|item| item.unverified)
            {
                //++agent TASK-225 [26.09.2026]
                context.record(ReasonEntry {
                    code: format!("unverified:{name}"),
                    kind: "builtin".to_owned(),
                    rule_id: None,
                    selector: None,
                    pattern: None,
                    source_path: None,
                    category: Some(name.to_owned()),
                    action: Some("mask".to_owned()),
                });
                //++agent TASK-225
                return plan(
                    context,
                    unverified_category(value),
                    &unverified_original(value),
                )
                .map(Value::String);
            }
        }
        //++agent TASK-225
        match value {
            Value::Object(object) => {
                let mut output = Map::with_capacity(object.len());
                for (key, value) in object {
                    //++agent TASK-225 [26.09.2026]
                    // §6.1: JSON-pointer текущего узла — привязка причин
                    // к ячейке отчёта. RFC 6901 escape ~0/~1.
                    //++agent TASK-225
                    let base = context.pointer.len();
                    context.pointer.push('/');
                    context.pointer.push_str(&pointer_escape(key));
                    let walked = self.walk(value, Some(key), depth + 1, context);
                    context.pointer.truncate(base);
                    output.insert(key.clone(), walked?);
                }
                Ok(Value::Object(output))
            }
            Value::Array(array) => {
                let mut output = Vec::with_capacity(array.len());
                for (index, value) in array.iter().enumerate() {
                    let base = context.pointer.len();
                    context.pointer.push('/');
                    context.pointer.push_str(&index.to_string());
                    let walked = self.walk(value, field, depth + 1, context);
                    context.pointer.truncate(base);
                    output.push(walked?);
                }
                Ok(Value::Array(output))
            }
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
            context.record(builtin_entry("secret:name", "secret", None));
            return Ok(SECRET_REMOVED.to_owned());
        }
        if self.secret_value.is_match(text) {
            context.record(builtin_entry("secret:value", "secret", None));
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
                    context.record(rule_entry(selector, rule));
                    return Ok(SECRET_REMOVED.to_owned());
                }
            }
        }
        //++agent TASK-225 [25.09.2026]
        // §5a.2: секрет-проход словаря. С автоматом — O(len(text)) и
        // перекрытые совпадения видны (Standard-автомат); снимок без
        // индекса — прежний полный перебор, семантика та же.
        if let Some(index) = context.policy.dictionary_index.clone() {
            if Instant::now() > context.deadline {
                return Err(());
            }
            if let Some(category) = index.find_secret(text) {
                context.record(dictionary_entry(
                    context.policy,
                    format!("dictionary:{category}:secret"),
                    category,
                    RuleAction::Secret,
                ));
                return Ok(SECRET_REMOVED.to_owned());
            }
        } else {
            for (known, category) in &context.policy.dictionary {
                if Instant::now() > context.deadline {
                    return Err(());
                }
                if !known.is_empty()
                    && text.contains(known)
                    && strongest_dictionary_action(context.policy, category) == RuleAction::Secret
                {
                    context.record(dictionary_entry(
                        context.policy,
                        format!("dictionary:{category}:secret"),
                        category,
                        RuleAction::Secret,
                    ));
                    return Ok(SECRET_REMOVED.to_owned());
                }
            }
        }
        //++agent TASK-225
        for rule in context.policy.rules.iter().filter(|rule| {
            rule.selector == RuleSelector::Regex && rule.action == RuleAction::Secret
        }) {
            if Instant::now() > context.deadline {
                return Err(());
            }
            let regex = Regex::new(&rule.pattern).map_err(|_| ())?;
            if regex.is_match(text) {
                context.record(rule_entry(RuleSelector::Regex, rule));
                return Ok(SECRET_REMOVED.to_owned());
            }
        }

        if (self.fio_name.is_match(field) || self.is_fio_source(&evidence)) && !text.is_empty() {
            context.record(builtin_entry("mandatory:fio:name", "mask", Some("FIO")));
            return plan(context, "FIO", text);
        }
        let mut rendered = text.to_owned();
        for literal in context.fio_literals.clone() {
            if rendered.contains(&literal) {
                context.record(builtin_entry("mandatory:fio:source", "mask", Some("FIO")));
                let replacement = plan(context, "FIO", &literal)?;
                rendered = rendered.replace(&literal, &replacement);
            }
        }
        if self.fio_value.is_match(&rendered) {
            context.record(builtin_entry("mandatory:fio:text", "mask", Some("FIO")));
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
                context.record(rule_entry(selector, rule));
                match rule.action {
                    RuleAction::Secret => return Ok(SECRET_REMOVED.to_owned()),
                    RuleAction::Mask => return plan(context, &rule.category, &rendered),
                    //++agent TASK-225 [26.09.2026] фаза-2 B
                    // keep(б) «строжайшее»: keep снимает только
                    // структурное действие селектора (маску/секрет всего
                    // поля); словарь и regex внутри значения продолжают
                    // действовать — раннего возврата больше нет.
                    //--agent TASK-225
                    // RuleAction::Keep => return Ok(rendered),
                    //--agent TASK-225
                    RuleAction::Keep => break,
                    //++agent TASK-225
                }
            }
        }

        //++agent TASK-225 [25.09.2026]
        // §5a.2: основной проход словаря — автоматные непересекающиеся
        // (leftmost-longest) совпадения вместо O(|словарь|) перебора.
        // Замена каждого вхождения детерминированным токеном ≡
        // `replace` всех вхождений; при пересекающихся значениях выбор
        // становится детерминированным (самое длинное слева) — зафиксировано
        // в spec как допустимое отличие от порядка HashMap.
        if let Some(index) = context.policy.dictionary_index.clone() {
            rendered = replace_dictionary_matches(&index, &rendered, context)?;
        } else {
            for (known, category) in &context.policy.dictionary {
                if Instant::now() > context.deadline {
                    return Err(());
                }
                if !known.is_empty() && rendered.contains(known) {
                    let action = strongest_dictionary_action(context.policy, category);
                    context.record(dictionary_entry(
                        context.policy,
                        format!("dictionary:{category}"),
                        category,
                        action,
                    ));
                    let replacement = match action {
                        RuleAction::Secret => SECRET_REMOVED.to_owned(),
                        RuleAction::Mask => plan(context, category, known)?,
                        RuleAction::Keep => continue,
                    };
                    rendered = rendered.replace(known, &replacement);
                }
            }
        }
        //++agent TASK-225
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
                context.record(ReasonEntry {
                    code: format!("regex:{}", rule.category),
                    kind: "rule".to_owned(),
                    rule_id: rule.rule_id.map(|id| id.to_string()),
                    selector: Some("regex".to_owned()),
                    pattern: Some(rule.pattern.clone()),
                    source_path: None,
                    category: Some(rule.category.clone()),
                    action: Some(
                        match rule.action {
                            RuleAction::Secret => "secret",
                            RuleAction::Mask => "mask",
                            RuleAction::Keep => "keep",
                        }
                        .to_owned(),
                    ),
                });
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

//++agent TASK-225 [26.09.2026]
/// §6.1: запись причины текущей ячейки — дедуплицированная таблица
/// `reason_entries` + привязка (pointer, idx) для mask_detail_json.
/// Лимит таблицы причин — §6.2 (256): сверху причина деградирует до
/// legacy-строки `reasons` без детальной записи.
impl WalkContext<'_> {
    fn record(&mut self, entry: ReasonEntry) {
        self.reasons.insert(entry.code.clone());
        if self.reason_entries.len() >= 256 {
            return;
        }
        let key = serde_json::to_string(&entry).unwrap_or_else(|_| entry.code.clone());
        let idx = match self.reason_index.get(&key) {
            Some(idx) => *idx,
            None => {
                let idx = self.reason_entries.len() as u32;
                self.reason_index.insert(key, idx);
                self.reason_entries.push(entry);
                idx
            }
        };
        let pair = (self.pointer.clone(), idx);
        if self.cell_reasons.last() != Some(&pair) {
            self.cell_reasons.push(pair);
        }
    }
}

/// Причина движка-правила для §6 (kind=rule).
fn rule_entry(selector: RuleSelector, rule: &PolicyRule) -> ReasonEntry {
    ReasonEntry {
        code: rule_reason(selector, rule),
        kind: "rule".to_owned(),
        rule_id: rule.rule_id.map(|id| id.to_string()),
        selector: Some(selector_name_of(selector).to_owned()),
        pattern: Some(rule.pattern.clone()),
        source_path: (selector == RuleSelector::SourcePath).then(|| rule.pattern.clone()),
        category: Some(rule.category.clone()),
        action: Some(
            match rule.action {
                RuleAction::Secret => "secret",
                RuleAction::Mask => "mask",
                RuleAction::Keep => "keep",
            }
            .to_owned(),
        ),
    }
}

fn builtin_entry(code: &str, action: &str, category: Option<&str>) -> ReasonEntry {
    ReasonEntry {
        code: code.to_owned(),
        kind: "builtin".to_owned(),
        rule_id: None,
        selector: None,
        pattern: None,
        source_path: None,
        category: category.map(str::to_owned),
        action: Some(action.to_owned()),
    }
}

fn dictionary_entry(
    policy: &PolicySnapshot,
    code: String,
    category: &str,
    action: RuleAction,
) -> ReasonEntry {
    ReasonEntry {
        code,
        kind: "dictionary".to_owned(),
        rule_id: None,
        selector: None,
        pattern: None,
        //++agent TASK-225 [26.09.2026] D8: путь источника категории
        // (§6.3) — при его отсутствии в снимке поле опускается, как
        // прежде остаётся `category`.
        source_path: policy.dictionary_sources.get(category).cloned(),
        //++agent TASK-225
        category: Some(category.to_owned()),
        action: Some(
            match action {
                RuleAction::Secret => "secret",
                RuleAction::Mask => "mask",
                RuleAction::Keep => "keep",
            }
            .to_owned(),
        ),
    }
}

fn selector_name_of(selector: RuleSelector) -> &'static str {
    match selector {
        RuleSelector::SourcePath => "source_path",
        RuleSelector::Name => "name",
        RuleSelector::Type => "type",
        RuleSelector::Dictionary => "dictionary",
        RuleSelector::Regex => "regex",
    }
}

/// RFC 6901 escape для JSON-pointer сегмента.
fn pointer_escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}
//++agent TASK-225

//++agent TASK-225 [25.09.2026]
/// §5a.2: замена словарных совпадений через автомат. Каждое
/// непересекающееся совпадение: `secret` → врезка `[SECRET_REMOVED]`
/// (строка целиком уже вырезана секрет-проходом по исходному тексту —
/// ветка нужна для значений, ставших secret только после замен FIO),
/// `mask` → детерминированный токен `plan`, `keep` → текст без изменений.
/// Deadline проверяется не реже раза в 4096 совпадений.
fn replace_dictionary_matches(
    index: &DictionaryIndex,
    rendered: &str,
    context: &mut WalkContext<'_>,
) -> Result<String, ()> {
    let mut output = String::with_capacity(rendered.len());
    let mut cursor = 0usize;
    let mut matched = 0u32;
    for (start, end, entry_id) in index.matches(rendered) {
        matched += 1;
        if matched.is_multiple_of(4096) && Instant::now() > context.deadline {
            return Err(());
        }
        let entry = index.entry(entry_id);
        context.record(dictionary_entry(
            context.policy,
            format!("dictionary:{}", entry.category),
            &entry.category,
            entry.action,
        ));
        output.push_str(&rendered[cursor..start]);
        match entry.action {
            RuleAction::Secret => output.push_str(SECRET_REMOVED),
            RuleAction::Mask => output.push_str(&plan(context, &entry.category, &entry.value)?),
            // Недостижимо: keep-записей в основном автомате нет (B-3);
            // ветка оставлена на случай рассинхронизации действий.
            RuleAction::Keep => output.push_str(&rendered[start..end]),
        }
        cursor = end;
    }
    //++agent TASK-225 [26.09.2026]
    // B-3: keep-значения в основной автомат не входят (не глушат mask
    // внутри себя — семантика legacy-скана), но причину
    // `dictionary:<cat>` фиксируем, как это делал legacy-перебор.
    // N-2: перебор заменён keep-автоматом — дедлайн проверяется на шаге
    // сканирования (сырые совпадения), а причину записываем один раз
    // на значение, как legacy.
    let mut keep_seen = HashSet::new();
    for (step, entry_id) in index.keep_matches(rendered).enumerate() {
        if (step as u32).is_multiple_of(4096) && Instant::now() > context.deadline {
            return Err(());
        }
        if !keep_seen.insert(entry_id) {
            continue;
        }
        let entry = index.entry(entry_id);
        context.record(dictionary_entry(
            context.policy,
            format!("dictionary:{}", entry.category),
            &entry.category,
            entry.action,
        ));
    }
    //++agent TASK-225
    output.push_str(&rendered[cursor..]);
    Ok(output)
}
//++agent TASK-225

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
    //++agent TASK-225 [26.09.2026]
    // B-2: точное совпадение — без учёта регистра по Unicode
    // (кириллица тоже; решение spec §12 — только усиливает).
    value.to_lowercase() == pattern.to_lowercase()
}

fn plan(context: &mut WalkContext<'_>, category: &str, original: &str) -> Result<String, ()> {
    //++agent TASK-225 [27.09.2026 00:00:00] W: mapping хранит исходное
    // значение, а не промежуточную форму — `original` может содержать
    // токены более ранних проходов этой же партии (FIO-литералы/текст
    // до структурной маски ячейки, regex поверх токена); разворачиваем
    // их здесь, иначе reveal снимал бы один уровень и показывал
    // вложенный [MASK:…]. Токены не из этой партии остаются — их
    // разворот выполняет защита слоя-2 в resolve_tokens_for_batch.
    let original = expand_batch_tokens(original, &context.candidates);
    //++agent TASK-225
    context
        .mappings
        .plan_token(
            &mut context.candidates,
            context.database_id,
            category,
            &original,
            context.batch_id,
            context.ttl_seconds,
        )
        .map_err(|_| ())
}

//++agent TASK-225 [27.09.2026 00:00:00] W: токены той же партии в
// сохраняемом оригинале разворачиваются в исходные значения — иначе
// mapping хранил бы промежуточную форму и reveal отдавал вложенный
// токен. Токен не из партии остаётся текстом (слой-2 при reveal).
// Глубина ограничена — цепочки длиннее отрезаются детерминированно.
fn expand_batch_tokens(text: &str, candidates: &[MappingCandidate]) -> String {
    const MAX_PASSES: usize = 8;
    let mut current = text.to_owned();
    for _ in 0..MAX_PASSES {
        if !current.contains("[MASK:v1:") {
            break;
        }
        let mut output = String::with_capacity(current.len());
        let mut cursor = 0usize;
        let mut expanded = false;
        while let Some(rel) = current[cursor..].find("[MASK:v1:") {
            let open = cursor + rel;
            let Some(rel_close) = current[open..].find(']') else {
                break;
            };
            let close = open + rel_close + 1;
            let token = &current[open..close];
            if let Some(found) = candidates.iter().find(|c| c.token == token) {
                output.push_str(&current[cursor..open]);
                output.push_str(&found.original);
                cursor = close;
                expanded = true;
            } else {
                // Не наш токен — фрагмент до следующей позиции переносим
                // без подстановки.
                cursor = open;
                output.push_str(&current[cursor..cursor + "[MASK:v1:".len()]);
                cursor += "[MASK:v1:".len();
            }
        }
        output.push_str(&current[cursor..]);
        current = output;
        if !expanded {
            break;
        }
    }
    current
}
//++agent TASK-225

//++agent TASK-225 [25.09.2026]
// Типизация токена unverified-ячейки по фактическому JSON-типу:
// bool/NULL/числа получают собственную категорию и не проходят
// незамаскированными. `output_types` (платформенные имена) в категорию
// не идут — категория должна следовать значению, а не декларации.
fn unverified_category(value: &Value) -> &'static str {
    match value {
        Value::Null => "UNVERIFIED_NULL",
        Value::Bool(_) => "UNVERIFIED_BOOL",
        Value::Number(_) => "UNVERIFIED_NUMBER",
        Value::String(_) => "UNVERIFIED_STRING",
        Value::Array(_) => "UNVERIFIED_ARRAY",
        Value::Object(_) => "UNVERIFIED_OBJECT",
    }
}

// Каноническая форма значения для дедупликации mapping: одинаковые
// значения unverified-колонки получают один токен.
fn unverified_original(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => "null".to_owned(),
        scalar => serde_json::to_string(scalar).unwrap_or_default(),
    }
}
//++agent TASK-225

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
                let entry = result
                    .entry(name.to_lowercase())
                    .or_insert_with(FieldEvidence::default);
                entry.field_types = column
                    .get("type")
                    .or_else(|| column.get("types"))
                    .map(parse_types)
                    .unwrap_or_default();
                //++agent TASK-225 [25.09.2026]
                entry.unverified |= column.get("unverified").and_then(Value::as_bool) == Some(true);
                //++agent TASK-225
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
                        //++agent TASK-225 [27.09.2026 00:00:00] U: ячейка
                        // FIO-поля может быть ссылкой — граница
                        // сериализует её плоским объектом `_objectRef`
                        // (контракт колонок). Литералом идёт
                        // человекочитаемое представление; uuid/имя типа
                        // именем не являются. Ссылка без представления —
                        // литерала нет, но и отказа нет. Не-ссылочный
                        // объект или массив — прежний отказ (fail-closed).
                        if is_object_ref(child) {
                            if let Some(literal) = object_ref_literal(child) {
                                if !literal.is_empty() && literal != SECRET_REMOVED {
                                    literals.insert(literal);
                                }
                            }
                        } else {
                            return Err(());
                        }
                        //++agent TASK-225
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

//++agent TASK-225 [27.09.2026 00:00:00] U: ссылочная ячейка по контракту
// границы — плоский объект с `_objectRef: true`.
fn is_object_ref(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.get("_objectRef") == Some(&Value::Bool(true)))
}

/// Строковое представление ссылочной ячейки — человекочитаемое имя
/// объекта по тем же ключам, что в отчёте (`report_cell`). Не-строковое
/// или отсутствующее представление → `None`.
fn object_ref_literal(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    for key in [
        "Представление",
        "presentation",
        "ПредставлениеСсылки",
        "name",
        "text",
        "value",
    ] {
        if let Some(text) = object.get(key).and_then(Value::as_str) {
            return Some(text.to_owned());
        }
    }
    None
}
//++agent TASK-225 [27.09.2026] Y4 консолидация
/// Единый компакт-список маркеров секретных имён полей: подстрока в
/// имени после нормализации (lower + удаление не-алфанумерики).
/// Зеркало — `ЭтоИмяСекрета` в mcp_ROCTUPГраницаДанныхСервер (1C);
/// держать синхронно. Используется здесь и в
/// domain/service/dictionary_feed.rs::metadata_is_secret.
/// accesstoken/refreshtoken не нужны отдельно — покрываются `token`.
/// Голый `ключ` отсутствует намеренно: подстрочная проверка без границ
/// слова ложноположительна (КлючНастройки); в сервисе он остаётся только
/// в `secret_name`-regex с границами [_\-.].
pub(crate) const SECRET_NAME_COMPACT_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "пароль",
    "секретнаяфраза",
    "secret",
    "секрет",
    "token",
    "токен",
    "apikey",
    "ключapi",
    "ключапи",
    "privatekey",
    "приватныйключ",
    "accesskey",
    "refreshkey",
    "authorization",
    "авторизац",
];

fn compact_secret_name(name: &str) -> bool {
    let compact: String = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();
    SECRET_NAME_COMPACT_MARKERS
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
