# Human API v1

Все маршруты предназначены только для человека за HTTPS reverse proxy. Cookie
`__Host-mask_session` имеет `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`.
Изменяющие запросы требуют точный `Origin` и `X-CSRF-Token`.

## Authentication

- `POST /auth/login` — `{login,password}`; возвращает роль и CSRF token.
- `POST /auth/logout` — отзывает server-side session.
- `POST /api/v1/session/password` — аутентифицированная смена собственного
  пароля для `Admin` и `Viewer`: `{current_password,new_password}`. Требует
  точные `Origin` и CSRF, проверяет текущий пароль и политику 12–1024 символа,
  не принимает прежний пароль как новый. При успехе атомарно увеличивает
  `auth_epoch`, отзывает все прежние сеансы, аудирует событие без паролей и
  возвращает новый session cookie и CSRF token.
- `GET /activate/{token}` — безопасная форма установки собственного пароля.
- `POST /auth/activate/{token}` — одноразовая activation; token также передаётся
  в `X-CSRF-Token`. Ошибки generic, token не журналируется.

Первичный `Admin` устанавливает пароль только через локальный control socket;
HTTP bootstrap route отсутствует намеренно.

## Viewer (только роль `Viewer`)

- `GET /api/v1/databases`
- `GET /api/v1/chats?database_id=<uuid>`
- `GET /api/v1/history?database_id=<uuid>&chat_id=<id>&limit=30..50`
- `POST /api/v1/history/{history_id}/reveal`

Reveal возвращает только neutral report v1 (`text` и `table`, scalar cells),
имеет `Cache-Control: no-store`, не сохраняет раскрытый результат и всегда
аудитируется. Роль `Admin` не имеет доступа к reveal.

## Admin (только роль `Admin`)

- users: `GET/POST /api/v1/admin/users`, `PATCH /api/v1/admin/users/{id}`;
- DB mode/TTL: `GET /api/v1/admin/databases`,
  `PATCH /api/v1/admin/databases/{id}`;
- refresh: `POST /api/v1/admin/databases/{id}/refresh`;
- tool classes: `GET .../{id}/tools`, `PUT .../{id}/tools/{tool}`;
- dictionary config: `GET .../{id}/dictionaries`,
  `PUT .../{id}/dictionaries/{config_id}`;
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
