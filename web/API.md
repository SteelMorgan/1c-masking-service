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
аудируется** (итерация 3: раскрытие автоматическое при открытии записи —
audit-событие выродилось бы в «запись просмотрена»). Роль `Admin` не имеет
доступа к reveal.

<!--++agent TASK-224 [08.10.2026] итерация 4-->
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
<!----agent TASK-224-->

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
- tool classes: `GET .../{id}/tools`, `PUT .../{id}/tools/{tool}`;
- dictionary config: `GET .../{id}/dictionaries`,
  `PUT .../{id}/dictionaries/{config_id}`. В GET-ответе у каждого selector —
  вычисляемый `in_manifest` (`true`/`false` — есть ли путь в RAM-manifest,
  `null` — manifest не загружен); `in_manifest` в PUT не принимается и в
  durable JSON не пишется.
- immutable policy versions: `GET/POST .../{id}/policies`,
  `POST .../{id}/policies/{policy_id}/activate`.

Tool class допускает только `data-mask`, `metadata-bypass` и
`deny-pending-review`. Dictionary endpoint принимает только configuration:
`mode` и до 100 selectors вида `{source_path, category, filter_ast}`. Категория
обязательна для каждого selector, а его AST ограничен операциями `and`, `or`,
`not`, `eq`, `ne`, `in`; raw dictionary values не являются частью API и не сохраняются. Policy rules
принимают только известные selector/action, а regex компилируется до записи.
Для `mode=all` допускается ровно один selector с `source_path="*"`; для
`mode=part` wildcard запрещён.

`POST /admin/users` и оба invitation-маршрута возвращают
`{user_id,login,role,activation_token,activation_url,expires_in_seconds}`;
`activation_url` собирается сервером из `MASKING_EXPECTED_ORIGIN`. Перевыпуск
(`.../invitation`) и сброс пароля (`.../password-reset`) атомарно гасят прежние
коды; сброс дополнительно отзывает сеансы и обнуляет пароль. `DELETE`
допустим только для пользователя, который ни разу не входил — логин
освобождается; иначе `409`. `GET /admin/users` дополнительно возвращает
`activated`, `invitation_expires_at`, `last_login_at`.

<!--++agent TASK-224 [08.10.2026] итерация 4-->
Для отключённого пользователя (`status:"disabled"`) `.../invitation` и
`.../password-reset` возвращают `409` с `error.code="USER_DISABLED"` —
отдельный код вместо generic conflict, чтобы UI объяснял «сначала включите
пользователя».
<!----agent TASK-224-->

## Страницы и статика

`/viewer` и `/admin` отдаются только живой сессии соответствующей роли:
без сессии — `303` на `/`, с чужой ролью — `303` в собственный раздел; `/` при
живой сессии редиректит в раздел. Статика UI — `/app.js`, `/grid.js`,
`/app.css` (same-origin CSP, без inline); `/favicon.ico` — `204`.
`/grid.js` — изолированный табличный модуль viewer (`window.MaskingGrid`),
заменяемый независимо от backend.
