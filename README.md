# 1c-masking-service

Внешний сервис маскирования для доверенного менеджера 1С. Репозиторий содержит
локальную реализацию на Rust/Axum (`onec-masking-service` 0.1.0): SQLite storage,
внутренний Unix API, human Viewer/Admin API и минимальный статический UI.
Production deployment и live manager+1С E2E пока не подтверждены.

## Назначение и границы приватности

Сервис предназначен для обработки результата вызова выбранного инструмента 1С
до его публикации агенту: применения настроенной policy, маскирования
чувствительных значений и автоматического сохранения только маскированной
истории. Human viewer/admin и agent/service principal являются разными
идентичностями. Сервис не заменяет бизнес-права 1С и не должен использоваться
как механизм выдачи таких прав.

Целевой внешний контракт для агента сохраняет имя инструмента и обычную форму
ответа. Управление masking, раскрытие, receipts и внутренние history ID не
являются частью agent payload. Исходные значения не должны попадать в логи,
ошибки, preview или маскированную history; раскрытие допускается только
аутентифицированному человеку и не сохраняется обратно в history. Полный
административный доступ агента к инфраструктуре всё равно разрушает эту
границу — сервис не заявляет абсолютную изоляцию от такого доступа.

Фактический прототип принимает internal-вызовы только через Unix socket и
human HTTP-вызовы через отдельный TCP listener. TLS в бинарник не встроен:
human listener предназначен для localhost или доверенного HTTPS reverse proxy.
Эта документация описывает текущий код, но не выдаёт его за production-ready
развёртывание.

## Текущий статус

- Реализованы internal `preflight`/`finalize`, bounded metadata/dictionary feed,
  автоматическая masked history, online human reveal и SQLite-backed policy,
  database/tool/dictionary configuration.
- Есть локальная human authentication с ровно двумя ролями `Admin` и `Viewer`,
  Argon2id password hashes, activation capabilities, revocable sessions,
  CSRF и Origin checks. Обе роли могут сменить собственный пароль с проверкой
  текущего; успешная смена отзывает остальные сеансы и ротирует текущий.
- Не реализованы в этом репозитории 1С-адаптер/manager, production reverse
  proxy, systemd unit, backup/rotation policy и production deployment
automation. DEV container packaging поставляется в `Dockerfile` и
`compose.dev.yml`, но наличие internal API или DEV image само по себе не
доказывает production-подключение к GBIG PAM.

DEV Compose использует постоянное имя проекта `onec-masking-service-dev` и
внешний volume `onec-masking-service-dev-data`. Перед первым запуском создайте
volume командой `docker volume create onec-masking-service-dev-data`, затем
запускайте `docker compose -f compose.dev.yml up -d --build`. `down` не удаляет
данные; номер задачи в имени контейнера не используется.
- Provenance граница сохраняется: ROCTUP `copied`/`adapted` units находятся в
  отдельном 1С-расширении TASK-221; donor source files в Rust-сервис не
  переносились. Trusted gateway остаётся только `concept`.

## Локальная сборка и запуск

Нужны Rust stable с Cargo и Unix-подобная ОС: runtime использует Unix sockets,
peer credentials и Unix file permissions. SQLite поставляется через bundled
feature `rusqlite`, отдельный системный SQLite для сборки не требуется.

Из каталога репозитория:

```sh
cargo fmt --check
cargo build --release
cargo test --all-targets
```

Бинарник после успешной сборки — `target/release/masking-service`. При первом
старте SQLite migration применяется автоматически, создаётся локальный
пользователь `Admin` с ролью `Admin` и unset password. Такой пользователь не
может войти до bootstrap.

Для разработки без прав на системные `/var/lib` и `/run` задайте локальные
пути. Human listener всё равно следует публиковать через HTTPS reverse proxy:

```sh
mkdir -p .local/data .local/run
export MASKING_DATABASE_PATH="$PWD/.local/data/service.sqlite3"
export MASKING_SOCKET_PATH="$PWD/.local/run/service.sock"
export MASKING_CONTROL_SOCKET_PATH="$PWD/.local/run/control.sock"
export MASKING_HUMAN_BIND="127.0.0.1:8787"
export MASKING_EXPECTED_ORIGIN="https://masking.local"
export RUST_LOG=info
cargo run
```

`MASKING_EXPECTED_ORIGIN` сравнивается с заголовком `Origin` буквально.
Значение должно совпадать с публичным HTTPS origin reverse proxy; trailing
slash и другой порт меняют строку и будут отклонены. Прямой HTTP-доступ из
браузера не является рабочей human-схемой: session cookie имеет `Secure`.

В отдельном интерактивном TTY, пока сервер запущен, установите пароль первого
Admin через mode-0600 control socket:

```sh
MASKING_CONTROL_SOCKET_PATH="$PWD/.local/run/control.sock" \
  cargo run -- admin bootstrap
```

Команда запрашивает пароль дважды, принимает 12–1024 символа и не принимает
неинтерактивный stdin/stderr. Bootstrap не имеет HTTP route, хранит только
Argon2id hash и после успеха необратимо закрывается. Для release binary
используется та же команда с `./target/release/masking-service`.

## Runtime configuration

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `MASKING_DATABASE_PATH` | `/var/lib/1c-masking/service.sqlite3` | SQLite database; при открытии включаются WAL и foreign keys, файл переводится в mode `0600` |
| `MASKING_SOCKET_PATH` | `/run/1c-masking/service.sock` | internal manager API; после bind mode `0660` |
| `MASKING_CONTROL_SOCKET_PATH` | `/run/1c-masking/control.sock` | только первый Admin bootstrap; mode `0600` |
| `MASKING_HUMAN_BIND` | `127.0.0.1:8787` | plain TCP listener для human reverse proxy |
| `MASKING_EXPECTED_ORIGIN` | обязательна | точный публичный origin human API; пустое значение отклоняется |
| `MASKING_MANAGER_UID` | effective UID процесса | ожидаемый Unix peer UID для internal API; задайте UID доверенного manager явно |
| `RUST_LOG` | `info` | фильтр `tracing`; формат compact без timestamp |

Родительские каталоги создаются самим процессом. Системные defaults требуют
подходящих прав; для локального запуска используйте writable paths, как в
примере выше. Если `MASKING_MANAGER_UID` не задан, socket gate доверяет UID,
под которым запущен сервис, поэтому это не замена отдельному service account и
изоляции ОС.

## Internal API и поток данных

Internal API не публикуется TCP listener-ом и не предназначен для браузера:

- `POST /internal/v1/calls/preflight` — проверка database/tool readiness и
  разрешение ранее выданных mask tokens в аргументах;
- `POST /internal/v1/calls/finalize` — обработка tool result или transport error,
  возврат того же public result contract и automatic masked history;
- `GET /internal/v1/health/live` и `GET /internal/v1/health/ready` — liveness и
  database-specific readiness;
- `/internal/v1/feed/jobs` и `/chunks/{index}`, `/activate`, `/fail` — bounded
  metadata/dictionary feed с digest/count validation и atomic activation.

JSON body limit internal API — 8 MiB. При заданном `MASKING_MANAGER_UID`
каждый Unix peer проверяется до маршрута. Неизвестный database identity
создаётся в режиме `unconfigured` и получает `ACTION_REQUIRED`; неизвестный
tool получает `deny-pending-review`. Шесть начальных классификаций:

- `data-mask`: `execute_query`, `find_references_to_object`,
  `get_object_by_link`;
- `metadata-bypass`: `get_metadata`, `get_access_rights`, `get_link_of_object`;
- любой неизвестный tool — `deny-pending-review` до явной проверки Admin.

Для enabled `data-mask` базы preflight/finalize требуют `policy.ready`; после
появления active cache generation readiness зависит от загруженного snapshot.
`disabled` и metadata-bypass режимы не отменяют secret cut. Transport errors
превращаются в нейтральный sanitized error; raw errors, raw preview и binary/
HTML/script/formatter result формы не принимаются.

## Human UI и API

Контракт подробно описан в [web/API.md](web/API.md). UI доступен маршрутами
`/`, `/viewer`, `/admin`, `/activate/{token}`; статические `human.js` и
`human.css` отдаются самим сервисом.

Viewer видит базы → чаты → последние 30–50 masked reports и может отдельно
запросить online reveal конкретного history ID. Reveal требует роль `Viewer`,
точный database/chat scope, выдаёт только neutral report v1 (`text`/`table`),
отдаётся с `Cache-Control: no-store` и не записывается обратно. `Admin` reveal
не разрешён автоматически.

Admin управляет пользователями, режимом базы и обоими TTL, refresh, tool
classification, dictionary selectors и immutable policy versions. Dictionary API
сохраняет только configuration (до 100 selectors и ограниченный filter AST), а
не raw dictionary values. Одноразовый activation token нового пользователя
живёт 15 минут и возвращается в ответе создания пользователя; его нельзя
логировать или передавать через agent API.

На страницах обеих ролей есть форма смены собственного пароля. Новый пароль
должен содержать 12–1024 символа и отличаться от текущего. Пароли не выводятся
в UI и не включаются в audit; после успеха браузер получает новую session cookie
и CSRF token, а все ранее выданные сеансы этого пользователя становятся
недействительными.

## Реализованные privacy/processing limits

- Mapping хранится только в RAM процесса; token scope связан с database и chat,
  reverse key — HMAC-SHA-256 с process-local key. Перезапуск оставляет masked
  history, но делает reveal старых tokens недоступным.
- Mapping TTL и history retention независимы; defaults обоих — 86 400 секунд.
  Cleanup запускается каждые 300 секунд; один tick ограничен 2 000 mapping,
  500 history и 500 audit rows.
- Секреты режутся необратимо до обратимого tokenization: чувствительные имена
  (`password`, token/key/authorization и русские варианты) и известные secret
  value patterns получают `[SECRET_REMOVED]`. FIO, field/name/type/source-path,
  dictionary и regex detectors применяются рекурсивно.
- Сервис не реализует NER или морфологический анализ. FIO detector основан на
  именах полей и ограниченном regex, dictionary detector — на точных известных
  строках. Склонения, опечатки, перестановки частей имени и все возможные
  свободнотекстовые варианты не гарантируются; администратор должен задавать
  явные source/name/type/dictionary/regex rules для фактических данных базы.
- Bounded engine: depth 64, до 200 000 string values, до 2 MiB на text value,
  до 10 000 mask candidates/call; mapping capacity — 100 000 service, 20 000
  database и 10 000 chat entries. Exceeding a limit fails closed.
- Finalize ограничен admission 80, worker pool 16 и четырьмя concurrent workers
  на database. Login/bootstrap rate limit — 5 попыток/минуту и 20/час на key;
  human session — 30 минут idle и 8 часов absolute TTL.

## Ограничения и статус проверки

Это WIP-реализация для локальной DEV-проверки, а не production release. В частности:

- TLS, reverse-proxy hardening, OS service account, backup/restore, SQLite
  encryption, monitoring and log retention deployment не поставляются;
- service trusts the manager boundary and supplied stable `database_id`; local
  peer UID gate не заменяет 1С business authorization или audited production
  identity binding;
- raw non-secret result может кратковременно находиться в bounded process-local
  retry cache для `disabled`/bypass projection, но не записывается в history;
- mapping, feed staging, policy cache и retry cache теряются при restart;
- 1С extension, manager route closure, production direct-route inventory и
  live manager+1С E2E в рамках этого репозитория не проверялись.

На снимке 23.09.2026 `cargo fmt --check` проходит, `cargo test --all-targets`
проходит (33/33), `cargo build --release` проходит. DEV-only runtime smoke для
bootstrap, feed и finalize также пройден. Это проверка локального service-only
пути; она не является доказательством live manager+1С E2E или production
deployment.

## Благодарности/Происхождение

Подробный поединичный реестр находится в [THIRD_PARTY.md](THIRD_PARTY.md).

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
- evidence TASK-221 `copy-provenance.md` и `.context/copy-provenance.md` в
  рабочем репозитории GBIG PAM;
- этот реестр, где для каждого донора отдельно указаны `copied`, `adapted` и
  `concept`.

Наличие исходников сервиса не меняет границу provenance: запланированная
интеграция, концептуальное влияние и существующий 1С-перенос не должны
описываться как donor code в `1c-masking-service`, пока это не подтверждено
отдельным source manifest и license record.
