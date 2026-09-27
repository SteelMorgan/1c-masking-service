# Human API v1

Все маршруты предназначены только для человека за HTTPS reverse proxy. Cookie
`__Host-mask_session` имеет `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`.
Изменяющие запросы требуют точный `Origin` и `X-CSRF-Token`.

## Authentication

- `POST /auth/login` — `{login,password}`; возвращает `{user_id,role,login,
  csrf_token}` и session cookie.
- `POST /auth/logout` — отзывает server-side session.
- `GET /api/v1/session` — возвращает `{user_id,role,login,csrf_token}` живой
  сессии; CSRF привязан к session token, поэтому тот же токен приходит при
  повторном запросе. Клиент держит его только в памяти вкладки — не в
  `localStorage`/`sessionStorage`.
- `GET /api/v1/status` — публичный `{bootstrap_required,version}`; показывает
  только факт незавершённого bootstrap первого Admin.
- `POST /api/v1/session/password` — аутентифицированная смена собственного
  пароля для `Admin` и `Viewer`: `{current_password,new_password}`. Требует
  точные `Origin` и CSRF, проверяет текущий пароль и политику 12–1024 символа,
  не принимает прежний пароль как новый. При успехе атомарно увеличивает
  `auth_epoch`, отзывает все прежние сеансы, аудирует событие без паролей и
  возвращает новый session cookie и CSRF token.
- `GET /activate/{token}` — страница установки собственного пароля.
- `GET /auth/activate/{token}` — предпроверка приглашения без побочных эффектов:
  `{login,expires_at}` либо generic `400 ACTIVATION_FAILED` (истёк, использован
  или неизвестен — не различается).
- `POST /auth/activate/{token}` — одноразовая activation; token также передаётся
  в `X-CSRF-Token`. Rate limit 5/мин → `429`. При валидном коде слабый пароль
  даёт отдельный `400 PASSWORD_POLICY`; при успехе сразу выдаётся session
  cookie и ответ `{user_id,role,login,csrf_token}` (автовход). Token не
  журналируется.

Первичный `Admin` устанавливает пароль только через локальный control socket;
HTTP bootstrap route отсутствует намеренно.

## Viewer (только роль `Viewer`)

- `GET /api/v1/databases`
- `GET /api/v1/chats?database_id=<uuid>`
- `GET /api/v1/history?database_id=<uuid>&chat_id=<id>&limit=30..50`
- `POST /api/v1/history/{history_id}/reveal`

Reveal возвращает только neutral report v1 (`text` и `table`, scalar cells),
имеет `Cache-Control: no-store`, не сохраняет раскрытый результат и **не
аудируется** (раскрытие автоматическое при открытии записи —
audit-событие выродилось бы в «запись просмотрена»). Роль `Admin` не имеет
доступа к reveal.

Формат neutral report v1: `{version:1, title?, blocks[]}` — `title` это
текст запроса/описание вызова, сохранённый на preflight (в `call_contexts`;
у старых записей и безаргументных terminal-событий `null`). Блоки:
`{kind:"text",text}` и `{kind:"table",columns[],rows[]}`; колонка —
`{id,label,type,masked}` — `masked:true` означает, что колонка содержит
маскированные значения (токены `[MASK:v1:…]`/`[SECRET_REMOVED]`), порядок
колонок повторяет порядок запроса из `field_sources.schema.columns`;
нескалярные значения ячеек приводятся к читаемому скаляру (представление
ссылочного объекта либо компактный JSON).

Хранение: запись истории живёт не дольше mapping — эффективный TTL записи
и контекста вызова равен `min(history_ttl_seconds, mapping_ttl_seconds)`
базы. Mapping токенов живёт только в RAM, поэтому при старте сервиса
таблицы `history` и `call_contexts` очищаются полностью — после перезапуска
reveal старых записей в принципе невозможен.

## Admin (только роль `Admin`)

- users: `GET/POST /api/v1/admin/users`, `PATCH /api/v1/admin/users/{id}`,
  `DELETE /api/v1/admin/users/{id}`,
  `POST /api/v1/admin/users/{id}/invitation`,
  `POST /api/v1/admin/users/{id}/password-reset`;
- DB: `GET /api/v1/admin/databases` (каждая запись — `id`, `label`,
  `display_label`, `mode`, TTL, `refresh_stage`),
  `PATCH /api/v1/admin/databases/{id}` — `mode`, `mapping_ttl_seconds`,
  `history_ttl_seconds`, `display_label`. `display_label` — отображаемое имя
  базы (≤128 символов, без управляющих символов); отсутствие поля не трогает
  имя, `null`/пустая строка сбрасывают его. Без имени `label` ответа —
  fallback на полный `id` (UI показывает короткий GUID + «без названия»);
  имени из identity-binding менеджера у сервиса нет.
- refresh: `POST /api/v1/admin/databases/{id}/refresh` → `202`, ставит
  durable intent полного pull (метаданные + словарь).
- delete: `DELETE /api/v1/admin/databases/{id}` → `204` — снимает запись
  базы из реестра: в одной транзакции удаляются все строки по `database_id`
  (политики и правила, классификации инструментов, словарные конфиги,
  поколения кэша, refresh intents, импорты и журнал настройки, история и
  контексты вызовов), RAM-состояние сервиса по базе сбрасывается; аудит
  `database.delete` (с именем записи в `code`) переживает удаление. На
  несуществующую запись — `404`. Повторный вызов удалённой базы
  регистрирует её заново как не настроенную.
- metadata tree: `GET .../{id}/metadata` — ленивая выдача RAM-manifest для
  вкладки «Справочники»: без параметров — корневые группы,
  `?path=<путь>` — дочерние узлы уровня (`path` — префикс `source_path`),
  `?q=<строка>` — плоский поиск по `source_path`/`field_name` (перекрывает
  `path`). Ответ `{manifest_ready, completed_at, nodes[], truncated}`; узел —
  `{name, path, kind:"group"|"field", field_count, password_count,
  field_type?, password_mode?}`. `manifest_ready:false` — manifest не
  получен (рестарт/refresh не завершён): валидный ответ, не ошибка.
  Лимиты: `path` ≤512, `q` ≤128 символов, до 1000 узлов на уровень и 200
  совпадений поиска (`truncated:true`). Только чтение — CSRF не требуется.
- tool classes: `GET .../{id}/tools`, `PUT .../{id}/tools/{tool}`,
  `DELETE .../{id}/tools/{tool}` (снимает запись классификации — для
  инструментов, удалённых из 1С; `204`, на несуществующую — `404`,
  аудит `tool.delete`);
- dictionary config: `GET .../{id}/dictionaries`,
  `PUT .../{id}/dictionaries/{config_id}`. В GET-ответе у каждого selector —
  вычисляемый `in_manifest` (`true`/`false` — есть ли путь в RAM-manifest,
  `null` — manifest не загружен); `in_manifest` в PUT не принимается и в
  durable JSON не пишется.
- immutable policy versions: `GET/POST .../{id}/policies`,
  `POST .../{id}/policies/{policy_id}/activate`.


Tool class допускает только `data-mask`, `no-mask` и
`deny-pending-review`. Dictionary endpoint принимает только configuration:
`mode` и до 100 selectors вида `{source_path, category, filter_ast}`. Категория
обязательна для каждого selector, а его AST ограничен операциями `and`, `or`,
`not`, `eq`, `ne`, `in`; raw dictionary values не являются частью API и не сохраняются.
Форма операндов AST: `and`/`or` — `{op,args:[…]}`, `not` — `{op:"not",arg:…}`,
`eq`/`ne` — `{op,field,value}` (скаляр), `in` — `{op:"in",field,values:[…]}`
(массив ≤100 скаляров; **`values`, не `value`**). Policy rules
принимают только известные selector/action, а regex компилируется до записи.
Для `mode=all` допускается ровно один selector с `source_path="*"`; для
`mode=part` wildcard запрещён.

## Версионированная настройка (setup)

Версия настройки (`policies`) объединяет правила, словарь
(`dictionary_json`) и инструменты (`tools_json`); статусы `draft`
(≤1 на базу), `active` (≤1), `retired`. Откат — копия архивной версии
новым черновиком, архив не мутирует.

- `GET .../{id}/setup/export?version=active|draft|<n>&include_tools=0|1` —
  выгрузка `masking-setup/v1` (`Content-Disposition` attachment,
  `Cache-Control: no-store`); также `GET /api/v1/databases/{id}/setup/export`.
- `POST .../{id}/setup/imports?replace_draft=0|1` — импорт файла в
  черновик; `409 DRAFT_EXISTS` при `replace_draft=0`.
- `GET .../{id}/setup/diff?from=active|<n>&to=draft|<n>` —
  классифицированный diff (`weakening|strengthening|neutral` +
  warnings). `from=active` при отсутствии активной версии — сравнение с
  пустой настройкой: `from_version:null`, все элементы — добавления
  (усиления). Отсутствующий `to` — `409 NO_DRAFT`/`404 VERSION_NOT_FOUND`. При наличии у to-версии секции `tools` классифицированные
  инструменты, отсутствующие в ней, идут отдельным neutral-изменением
  `TOOL_REMOVED` (before=текущий режим, after=null); секции нет или
  `null` — удалений нет, `"tools":[]` — удаление всех.
- Черновик: `POST .../setup/draft {from:"active"|"empty"}`,
  `GET .../setup/draft`, `PUT .../setup/draft/{dictionary|rules|tools}`
  и `DELETE` — все под `If-Match: "<draft_hash>"` (`409 DRAFT_CHANGED`);
  `POST .../setup/draft/revert {change_ids,warning_ids}` — возврат
  элементов к состоянию active / исключение предупреждений.
- `POST .../setup/activate {version,draft_hash,confirmed_weakenings,
  accepted_strengthenings,excluded_warnings,declined_tool_removals,
  comment?}` — серверная
  перепроверка diff в одной транзакции: `409 WEAKENING_NOT_CONFIRMED`,
  `409 STALE_CONFIRMATION`, `400 WARNING_NOT_EXCLUDABLE`,
  `409 DRAFT_CHANGED`, `409 SECRET_POLICY_UNSUPPORTED` (F8).
  `declined_tool_removals` — id изменений `TOOL_REMOVED`, от которых
  отказались: их записи классификации остаются; неотказанные удаляются
  той же транзакцией (аудит `tool.delete` на каждый), ответ несёт
  `tool_removals` — список применённых имён.
- `POST .../setup/rollback {version,replace_draft}` — `201`, черновик
  `origin='rollback'` (только неактивная версия: активная →
  `409 VERSION_IS_ACTIVE`).
- `GET .../setup/versions` — список версий `{version,status,origin,
  author,created_at,activated_at?,discarded_at?}` для экрана истории;
  `GET .../setup/versions/{version}` — полное содержимое версии
  (`dictionary/rules/tools`). Оба маршрута read-only: не пишут
  журнал и audit.
- `POST .../setup/dry-run {version:"draft"|<n>, limit:1..50}` — сухой
  прогон последних записей истории активной версией и целевой;
  `409 DRY_RUN_BUSY`. Ответ без значений: `records[]` с маскированной
  сеткой `grid{columns,cells[]}` — у ячейки только координаты
  (block/row/column) и статусы `before|after ∈ open|masked|secret|
  unknown` + `reason` (pointer), ни значений, ни токенов; счётчики
  `became_masked|became_open|unevaluable`, `timing` (median/p_max/
  over_budget на версию, `dictionary_memory`, `top_sources`),
  `dictionary_not_loaded`, `skipped[].mapping_expired`. Пустая история →
  `{history_empty:true, reason:"no_records"|"no_lineage"}`.
- `GET .../setup/journal?limit` — журнал `setup_versions_journal`.
- `GET .../setup/draft`, PUT'ы и activate пишут строки журнала и audit
  в одной транзакции.
- `GET /api/v1/history/{id}/reasons` (Viewer) — детальные причины
  по ячейкам (`detailed:true`, `policy_version`, `policy_state`,
  `active_version`, `reasons[]` с `cells`-счётчиками и `link.admin_path`,
  `cells[]` — только координаты); старая запись без `mask_detail_json` →
  `{detailed:false, legacy_reasons:[…]}`; истёкшая запись →
  `410 HISTORY_EXPIRED`.
- `GET .../{id}/metadata?fields_of=<объект>` — поля объекта из
  RAM-manifest (`{object, fields:[{name,type,password_mode}],
  manifest_ready}`), без значений.
- `GET .../admin/databases` дополнительно отдаёт `setup_state`,
  `active_version`, `draft_version`; `PATCH` принимает `strict_mode`
  (строгий режим, по умолчанию включён).

Legacy-маршруты продолжают работать поверх версий: `PUT dictionaries`
правит черновик (создаёт из активной при отсутствии) и отвечает
`{draft_version}` — активная политика не мутирует; `POST policies`
создаёт черновик (`409 DRAFT_EXISTS`); `POST policies/{id}/activate`
активирует **только черновик** (любой другой статус цели → `409`,
retired поднимается лишь через `setup/rollback` + `setup/activate`)
и проходит ту же проверку ослаблений, что и `setup/activate` — при наличии
неподтверждённых ослаблений `409 WEAKENING_NOT_CONFIRMED`;
`PUT tools/{tool}` с `class:"no-mask"` требует
`confirm_bypass:true` (`400 BYPASS_NOT_CONFIRMED`).

`POST /admin/users` и оба invitation-маршрута возвращают
`{user_id,login,role,activation_token,activation_url,expires_in_seconds}`;
`activation_url` собирается сервером из `MASKING_EXPECTED_ORIGIN`. Перевыпуск
(`.../invitation`) и сброс пароля (`.../password-reset`) атомарно гасят прежние
коды; сброс дополнительно отзывает сеансы и обнуляет пароль. `DELETE`
допустим только для пользователя, который ни разу не входил — логин
освобождается; иначе `409`. `GET /admin/users` дополнительно возвращает
`activated`, `invitation_expires_at`, `last_login_at`.

Для отключённого пользователя (`status:"disabled"`) `.../invitation` и
`.../password-reset` возвращают `409` с `error.code="USER_DISABLED"` —
отдельный код вместо generic conflict, чтобы UI объяснял «сначала включите
пользователя».

## Страницы и статика

`/viewer` и `/admin` отдаются только живой сессии соответствующей роли:
без сессии — `303` на `/`, с чужой ролью — `303` в собственный раздел; `/` при
живой сессии редиректит в раздел. Статика UI — `/app.js`, `/grid.js`,
`/app.css` (same-origin CSP, без inline); `/favicon.ico` — `204`.
`/grid.js` — изолированный табличный модуль viewer (`window.MaskingGrid`),
заменяемый независимо от backend.
