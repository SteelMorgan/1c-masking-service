# 1c-masking-service

Внешний сервис маскирования ответов 1С-инструментов для ИИ-агента. Реализация —
`onec-masking-service` 0.1.0 (Rust/Axum): SQLite-хранилище, internal API на
Unix socket, human API/UI на отдельном TCP-listener.

Сервис получает результат вызова инструмента до его отдачи агенту: ФИО и
значения из словаря/правил заменяются обратимыми токенами вида
`[MASK:v1:<CAT>:<token>]`. Секреты вырезаются ещё в 1С на границе данных и
доезжают до сервиса как `[SECRET_REMOVED]` — это нормальное значение, не
сигнал. Раскрытие исходных значений возможно только человеку с ролью `Viewer`
через UI; агент и `Admin` раскрытия не получают. В историю и логи пишется
только замаскированная форма.

## Зависимости

Сервис не самодостаточен: managed-поток проходит через
[v8-session-manager](https://github.com/1c-neurofish/v8-session-manager), а
граница данных и внутренние feed-инструменты живут в расширении 1С
[1c-mcp-tools](https://github.com/SteelMorgan/1c-mcp-tools).

### v8-session-manager — шлюз

- На каждый managed-вызов агента (`masking.managed_tools`) вызывает сервис:
  `preflight` → tool.call в 1С → `finalize` по UDS `masking.socket_path`
  (service.sock); идемпотентные терминальные события — `terminal`.
- Поднимает UDS-listener `masking.internal_listen_path` (manager.sock) с
  единственным маршрутом `POST /internal/v1/tools/call`
  `{database_id, name, arguments}` — через него сервис загружает метаданные и
  словарь. Доступ ограничен peer UID `masking.service_expected_uid`.
- Скрывает internal-инструменты от агента: имена из `masking.internal_tools`
  не попадают в `tools/list`, `tools/call` от агента отклоняется.
- Сопоставляет сессию с базой сервиса по имени: `masking.identity_bindings`
  (`session` → `database_id`, база = сервер+имя).
- Отдельно проверяет conversation-assertions агента (ключи `broker_*`) — на
  стороне сервиса криптографии агента нет.

### 1c-mcp-tools — расширение 1С

- ROCTUP-инструменты с границей данных: секреты вырезаются **всегда**
  (без флагов), ответ — конверт
  `{schema_version:1, result:<бизнес-JSON>, field_sources:{schema, lineage}}`,
  сериализованный в `content[0].text`.
- Внутренние инструменты `mcp_internal_masking_metadata_feed` и
  `mcp_internal_masking_dictionary_feed`: аргументы `{selector, cursor}`,
  страница `{success, metadata | dictionary_values, next_cursor, final_chunk}`.

### Транспорт 1С ↔ менеджер

wt-mcp-adapter + web-transport-addin используются как есть; сервис от них
напрямую не зависит.

## Поток данных

**Вызов агента:**

```
агент → manager /mcp
      → POST service.sock /internal/v1/calls/preflight   (разрешение MASK-токенов в аргументах)
      → 1С tool.call → граница вырезает секреты ([SECRET_REMOVED])
      → конверт {schema_version:1, result, field_sources{schema,lineage}}
      → POST service.sock /internal/v1/calls/finalize    (маскирование, запись masked history)
      → агент получает замаскированный result в content[0].text
```

Недоступность сервиса или отказ границы — fail-closed: агенту возвращается
нейтральная ошибка, сырые данные наружу не выходят.

**Загрузка метаданных/словаря (pull, инициирует сервис):**

```
pull worker (тик MASKING_PULL_INTERVAL_SECONDS) → durable-очередь v2_refresh_intents
→ POST manager.sock /internal/v1/tools/call {database_id, name, arguments:{selector,cursor}}
→ 1С internal feed → страницы до final_chunk
→ PolicySnapshot + строка cache_generations → атомарная замена RAM-снапшота → intent снят
```

Снапшот публикуется только после полного успешного прогона; при сбое остаётся
прежний активный. `cache_generations` — журнал прогонов (version, digest,
счётчики), `v2_refresh_intents` — durable-очередь «нужен refresh» (старое имя
таблицы сохранено). На старте сервис ставит intent на каждую enabled-базу,
Admin-мутации добавляют свои.

## Internal API (UDS `MASKING_SOCKET_PATH`)

Не публикуется TCP, не для браузера; каждый peer проверяется по UID
(`MASKING_MANAGER_UID`). Лимит JSON body — `MASKING_MAX_BODY_BYTES`
(8 МиБ по умолчанию).

- `POST /internal/v1/calls/preflight` — readiness базы/инструмента, резолв
  ранее выданных mask-токенов в аргументах;
- `POST /internal/v1/calls/finalize` — `outcome`:
  `{kind:"tool_result", result:<Value>}` (непрозрачный бизнес-JSON; сервис
  маскирует его и сам оборачивает в публичную форму
  `{content:[{type:"text",text}], is_error}`) или
  `{kind:"transport_error", error}` (нейтральный sanitized-ответ);
  опциональный `field_sources` для маскирования по source_path;
- `POST /internal/v1/calls/terminal` — идемпотентный ledger терминальных
  событий (`scope.kind`: `verified`/`unverified`);
- `GET /internal/v1/health/live`, `GET /internal/v1/health/ready?database_id=`.

Неизвестная база создаётся в режиме `unconfigured` (`ACTION_REQUIRED`);
неизвестный инструмент — `deny-pending-review`. Стартовая классификация
(сидится при открытии БД): `data-mask` — `execute_query`,
`find_references_to_object`, `get_object_by_link`; `metadata-bypass` —
`get_metadata`, `get_access_rights`, `get_link_of_object`.

## Конфигурация (ENV)

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `MASKING_DATABASE_PATH` | `/var/lib/1c-masking/service.sqlite3` | SQLite (WAL, foreign keys, mode `0600`) |
| `MASKING_SOCKET_PATH` | `/run/1c-masking/service.sock` | internal API, mode `0660` |
| `MASKING_CONTROL_SOCKET_PATH` | `/run/1c-masking/control.sock` | bootstrap первого Admin, mode `0600` |
| `MASKING_HUMAN_BIND` | `127.0.0.1:8787` | TCP listener human API/UI |
| `MASKING_EXPECTED_ORIGIN` | обязательна | точный Origin human API (буквальное сравнение) |
| `MASKING_MANAGER_UID` | euid процесса | ожидаемый peer UID на `service.sock` и при подключении к `manager.sock` |
| `MASKING_MANAGER_SOCKET_PATH` | обязательна | UDS-listener менеджера (`POST /internal/v1/tools/call`) — путь pull worker-а |
| `MASKING_PULL_INTERVAL_SECONDS` | `10` (1–300) | период тика pull worker; за тик до 10 intents |
| `MASKING_MANAGER_CALL_TIMEOUT_SECONDS` | `30` (1–120) | дедлайн одного tool.call к менеджеру |
| `MASKING_MAX_BODY_BYTES` | `8388608` (1 КиБ–64 МиБ) | лимит JSON body internal API |
| `MASKING_PREFLIGHT_TIMEOUT_SECONDS` | `3` (1–60) | дедлайн preflight |
| `MASKING_FINALIZE_TIMEOUT_SECONDS` | `15` (1–300) | дедлайн finalize |
| `MASKING_MAX_IN_FLIGHT` | `80` (1–10000) | admission-семафор finalize |
| `MASKING_WORKERS` | `16` (1–1000) | пул worker-ов finalize |
| `MASKING_PER_DATABASE_WORKERS` | `4` (1–100) | concurrent workers на базу |
| `MASKING_MAX_DEPTH` | `64` (8–128) | глубина обхода JSON |
| `MASKING_MAX_CELLS` | `200000` (1000–1e6) | строковых значений на вызов |
| `MASKING_MAX_ROWS` | `10000` (100–100000) | строк таблицы на вызов |
| `MASKING_MAX_TEXT_BYTES` | `2097152` (1 КиБ–8 МиБ) | размер одного текстового значения |
| `MASKING_ENGINE_TIMEOUT_MS` | `10000` (100–300000) | дедлайн движка маскирования |
| `RUST_LOG` | `info` | фильтр `tracing`, compact без timestamp |

Родительские каталоги сокетов и БД создаются процессом. Если
`MASKING_MANAGER_UID` не задан, gate доверяет UID самого сервиса — это не
замена отдельному service account.

## Сборка и запуск

Нужны Rust stable + Cargo и Unix-подобная ОС (UDS, peer credentials, file
permissions). SQLite идёт через bundled `rusqlite`.

```sh
cargo fmt --check
cargo build --release
cargo test --all-targets
```

Бинарник — `target/release/masking-service`. Миграции применяются при старте;
создаётся пользователь `Admin` без пароля — войти нельзя до bootstrap.

DEV-запуск — через `Dockerfile` + `compose.dev.yml` (проект
`onec-masking-service-dev`, внешние volumes `onec-masking-service-dev-state`
и shared `agent-work-sandbox-1c` с `/run/1c-masking`):

```sh
docker volume create onec-masking-service-dev-state
docker compose -f compose.dev.yml up -d --build
```

`down` данных не удаляет. Локально (без прав на `/var/lib`, `/run`) — свои
пути через ENV, затем bootstrap первого Admin в интерактивном TTY:

```sh
export MASKING_CONTROL_SOCKET_PATH="$PWD/.local/run/control.sock"
cargo run -- admin bootstrap        # пароль 12–1024, спрашивается дважды
```

Bootstrap работает только через control socket; HTTP route у него нет,
после успеха он необратимо закрывается. Human listener рассчитан на localhost
или HTTPS reverse proxy: session cookie — `Secure`, поэтому прямой HTTP из
браузера не является рабочей схемой.

## Human UI и API

Контракт — [web/API.md](web/API.md). UI: `/`, `/viewer`, `/admin`,
`/activate/{token}`; статика `human.js`/`human.css` отдаётся сервисом.
Аутентификация локальная: ровно две роли `Admin`/`Viewer`, Argon2id,
activation-токены (15 минут), отзываемые сессии (30 мин idle / 8 ч absolute),
CSRF + точный Origin, cookie `__Host-mask_session` (Secure, HttpOnly,
SameSite=Strict). Login/bootstrap rate limit — 5/мин и 20/час на ключ.

- `Viewer`: базы → чаты → последние 30–50 masked reports; online reveal
  конкретного history ID в своём database/chat scope — neutral report v1
  (`text`/`table`), `Cache-Control: no-store`, не записывается обратно,
  аудируется. `Admin` reveal не получает.
- `Admin`: пользователи, режим базы и оба TTL, refresh, классификация
  инструментов, dictionary selectors (до 100, только configuration с
  `filter_ast` — не raw values), immutable policy versions.

Mapping токенов живёт только в RAM: scope = database+chat, reverse key —
HMAC-SHA-256 с process-local ключом. Рестарт сохраняет masked history, но
reveal старых токенов становится недоступным; pull worker заново поднимает
снапшоты enabled-баз через менеджер.

## Лимиты обработки

- Превышение любого лимита — fail-closed (ошибка, а не частичный результат).
- Mapping: до 100 000 записей всего, 20 000 на базу, 10 000 на чат; до
  10 000 кандидатов маскирования на вызов. Maintenance-тик каждые 300 с:
  до 2 000 mapping, 500 history, 500 unscoped terminal, 500 audit записей.
  TTL mapping и history задаются на базу (по умолчанию 86 400 с).
- Pull: до 10 000 страниц на поток, до 1 000 000 значений словаря / 1 ГиБ,
  до 100 source paths и 100 selectors, cursor ≤ 1 МиБ, значение ≤ 2 МиБ.
- Движок не делает NER/морфологию: FIO — по именам полей, source-literals из
  `field_sources` и ограниченному regex (`Фамилия Имя [Отчество]`), словарь —
  по точным строкам. Склонения, опечатки и перестановки не гарантируются —
  администратор задаёт явные правила под фактические данные.
- Значение `[SECRET_REMOVED]`, пришедшее от 1С, сохраняется как есть;
  `cut_secrets` в сервисе — defence-in-depth поверх 1С-границы (имена полей,
  secret-паттерны, `Secret`-правила, `password_mode` source paths).

## Миграции

`migrations/0001`–`0008`, применяются автоматически при старте:

| Миграция | Содержимое |
|---|---|
| `0001_core` | schema_migrations, databases, policies, policy_rules, tool_classifications, dictionary_configs, cache_generations, history, audit_events, users, activation_capabilities, sessions, service_state |
| `0002_terminal_history` | `unscoped_terminal_events` |
| `0003`–`0006` | таблицы отменённого feed/lease-протокола (v2 receipts/snapshots/leases) — исторические |
| `0007_v2_refresh_intents` | durable-очередь refresh + `cache_generations.selectors_json` — используется pull worker-ом |
| `0008_drop_v2_feed` | `DROP` feed_jobs и v2-таблиц 0003–0006 |

## Тесты и статус

`cargo test --all-targets` — интеграционные файлы `tests/` (core service,
internal API, mapping, human auth) плюс unit-тесты. `cargo fmt --check` и
`cargo build --release` — обязательные gate-ы.

Проверено: локальный service-only путь и DEV E2E с менеджером и 1С (pull
словаря через `manager.sock`, маскирование ФИО, fail-closed при остановке,
Viewer reveal, фильтры словаря `part`/`filter_ast`).

Не поставляется: TLS в бинарнике, reverse proxy, systemd unit, OS service
account, backup/rotation, SQLite-шифрование, мониторинг. Сервис доверяет
границе менеджера и `database_id` из его конфигурации; peer-UID gate не
заменяет бизнес-авторизацию 1С. Production deployment не заявляется.

## Благодарности/Происхождение

Подробный поединичный реестр — [THIRD_PARTY.md](THIRD_PARTY.md).

### ROCTUP/1c-mcp-toolkit

Используемая ссылка — [закреплённый commit
`fe12903af7a367a9d67dd055c13f4b59bb59d83c`](https://github.com/ROCTUP/1c-mcp-toolkit/tree/fe12903af7a367a9d67dd055c13f4b59bb59d83c).
Указанный upstream распространяется по GPL-3.0. TASK-221 документирует точные
server tool cores, masking helpers и RegexHelper/QueryLineageAnalyzer, которые
уже были перенесены в 1С-контур GBIG PAM с адаптацией обвязки. Эта атрибуция
описывает состояние 1С-расширения, а не наличие ROCTUP-кода в текущем сервисе.

Если код ROCTUP будет добавлен в этот репозиторий, нужно сохранить исходные
copyright/license/NOTICE, указать этот pin, обеспечить доступность
соответствующих исходников и выполнить downstream obligations GPL-3.0. Пока
исходников ROCTUP здесь нет, поэтому настоящий README не объявляет сервис
GPL-компонентом и не выдаёт отсутствующие LICENSE/NOTICE за уже установленные.

### alonehobo/1c-trusted-gateway

Ссылка — [закреплённый commit
`a5cc656e3f3763800706ec752fd33fb2e18318e4`](https://github.com/alonehobo/1c-trusted-gateway/tree/a5cc656e3f3763800706ec752fd33fb2e18318e4).
Для этого pin лицензия не обнаружена (в GitHub API — `license=null`), поэтому
репозиторий не считается источником разрешения на копирование. Отмечается
только концептуальное влияние: recursive JSON, exact/prefix/composite type
policy, forced field names, contextual regex, masked-column UX и идентификация
отчёта. Ни один файл или фрагмент его кода в этот сервис не копировался; такие
идеи, если будут реализованы, должны иметь независимую реализацию.

## Что считать доказательством

Для границы между 1С-переносом и новым сервисом следует сверять:

- спецификацию TASK-221 `tasks/221-roctup-mcp-tools-port/masking-service-spec.md`, §8 и MUST-28/29/34, в рабочем checkout GBIG PAM;
- документы provenance TASK-221 `copy-provenance.md` и `.context/copy-provenance.md` в рабочем репозитории GBIG PAM;
- этот реестр, где для каждого донора отдельно указаны `copied`, `adapted` и
  `concept`.

Наличие исходников сервиса не меняет границу provenance: запланированная
интеграция, концептуальное влияние и существующий 1С-перенос не должны
описываться как donor code в `1c-masking-service`, пока это не подтверждено
отдельным source manifest и license record.
