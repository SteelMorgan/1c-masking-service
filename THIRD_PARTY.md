# Third-party и provenance

Этот реестр относится к репозиторию `SteelMorgan/1c-masking-service` и
зафиксирован как development snapshot (23.09.2026). Исходники сервиса уже существуют,
но в них не обнаружены source files или дословные units доноров. Реестр намеренно
отделяет фактически скопированный код отдельного 1С-расширения GBIG PAM от
самостоятельной Rust-реализации этого сервиса.

## Собственный код сервиса

`Cargo.toml` объявляет пакет `onec-masking-service` версии `0.1.0`, edition 2021
и license metadata `MIT`. Эта декларация относится только к написанному для
сервиса Rust-коду и не перелицензирует GPL-код TASK-221 в отдельном 1С-контуре.
Текущие service-owned области — `src/` (Axum/SQLite/auth/masking domain),
`web/` (human UI и API description) и `migrations/`. Использование crates.io
dependencies через Cargo не является копированием исходников перечисленных
доноров; отдельный полный license inventory зависимостей в этом документе не
утверждается.

В Rust-сервисе нет ROCTUP-файлов, native/template assets или фрагментов
`1c-trusted-gateway`. Наличие сходных security/masking идей не превращает
самостоятельную реализацию в `copied` или `adapted` unit без отдельного
source-level доказательства.

В tree сервиса не найдено файлов `LICENSE`, `NOTICE` или `COPYING`. Это
согласуется с отсутствием скопированного donor source: `Cargo.toml` содержит
только license metadata для собственного пакета. При фактическом добавлении
ROCTUP units соответствующие GPL-3.0 notices и source availability должны быть
добавлены одновременно.

## Реестр доноров

| Донор и pinned URL | Commit | License status | Компоненты и идеи | Статус в GBIG PAM / этом сервисе | Изменения и границы |
|---|---|---|---|---|---|
| [ROCTUP/1c-mcp-toolkit](https://github.com/ROCTUP/1c-mcp-toolkit/tree/fe12903af7a367a9d67dd055c13f4b59bb59d83c) | `fe12903af7a367a9d67dd055c13f4b59bb59d83c` | GPL-3.0; license upstream должна сопровождать фактические copied units | Выбранные tool cores (`execute_query`, `get_metadata`, `get_object_by_link`, `get_link_of_object`, `find_references_to_object`, `get_access_rights`), transitive masking/policy/dictionary/regex closure, RegexHelper и QueryLineageAnalyzer, включая native/template assets | В 1С-расширении TASK-221 зафиксированы `copied` units/assets и `adapted` context/обвязка. В текущем `1c-masking-service` **нет copied/adapted ROCTUP units**: Rust `MaskEngine`/`MappingStore` являются service-owned implementation | В расширении адаптированы server/service context, собственный WS transport, state и secret precedence. Не переносятся upstream transport, client-form state как policy owner и старый mapper как владелец изменяемой policy. Если ROCTUP code появится в сервисе, нужно добавить неизменённые GPL copyright/LICENSE/NOTICE и обеспечить source availability. |
| [alonehobo/1c-trusted-gateway](https://github.com/alonehobo/1c-trusted-gateway/tree/a5cc656e3f3763800706ec752fd33fb2e18318e4) | `a5cc656e3f3763800706ec752fd33fb2e18318e4` | LICENSE не обнаружена; GitHub API для pin сообщает `license=null`. Это не разрешение на копирование | Только `concept`: recursive JSON, exact/prefix/composite type policy, forced field names, contextual regex, masked-column UX и идентификация отчёта | В текущем `1c-masking-service` и в 1С-расширении **code copy отсутствует**; зафиксированы только attribution и идеи | Любая реализация должна быть независимой. Code copy остаётся BLOCKED до письменного разрешения или обнаружения применимой лицензии. Нельзя называть собственные Rust modules `copied` или `adapted` от этого проекта. |

## Детали ROCTUP: что уже есть в 1С-контуре

TASK-221 содержит evidence для отдельного 1С-переноса:

- серверные корни `ВыполнитьЗапрос`, `ПолучитьМетаданные`,
  `ПолучитьОбъектПоНавигационнойСсылке`, `ПолучитьНавигационнуюСсылкуПоОписанию`,
  `НайтиСсылкиНаОбъект`, `ПолучитьПраваДоступа`;
- closure автоматического маскирования, обратной подстановки, policy,
  dictionary и regex;
- templates/native assets `RegexHelper` и `QueryLineageAnalyzer`.

В том же evidence явно отделены context adapters: registration/dispatch,
server/service context, per-call state, защищённое TTL-сопоставление,
irreversible secret cut и sanitized error boundary. Эти сведения описывают
1С-расширение и не доказывают source parity с Rust-сервисом. Реализованные в
сервисе internal `preflight`/`finalize`, human API, history и local auth — свои
модули текущего service snapshot, а не автоматически перенесённые ROCTUP units.
`submit_for_deanonymization` не является разрешением добавлять agent-facing
control в сервис: по спецификации его назначение заменено service-internal
automatic history.

Проверяемые материалы TASK-221 находятся в рабочем репозитории GBIG PAM:

- `tasks/221-roctup-mcp-tools-port/copy-provenance.md`;
- `tasks/221-roctup-mcp-tools-port/.context/copy-provenance.md`;
- `tasks/221-roctup-mcp-tools-port/.tmp/port-stage/manifest.json` и сохранённый
  `LICENSE.ROCTUP-GPL-3.0.txt` (если staging доступен в конкретном checkout).

## License gate и правила будущего переноса

1. `ROCTUP/1c-mcp-toolkit`: при фактическом копировании в сервис сохранить
   GPL-3.0, copyright, LICENSE/NOTICE и ссылку на pinned source. Адаптированную
   обвязку пометить как `adapted`; дословные единицы — как `copied`. Нельзя
   объявлять эти исходники MIT или смешивать их с отсутствующим provenance.
2. `alonehobo/1c-trusted-gateway`: до снятия license block разрешены только
   `concept` и independently implemented code. Нельзя переносить source files,
   фрагменты, имена реализации или выдавать концептуальное влияние за code
   borrowing.
3. Любой будущий copied code должен быть добавлен вместе с соответствующими
   notices в том же изменении и пройти отдельную license/provenance проверку.
4. Agent-facing service contract не должен раскрывать masking controls,
   receipts, history IDs, policy versions или внутренние причины срабатывания;
   это требование MUST-34 не меняется от происхождения реализации.

## Текущий implementation snapshot

- Human API contract находится в `web/API.md`; runtime configuration и
  bootstrap описаны в README.
- Runtime хранит persistent policy/history/auth в SQLite, а mapping/feed staging
  и policy/retry caches — в памяти процесса. Это реализация текущего snapshot, не
  доказательство production hardening.
- На snapshot 23.09.2026 `cargo fmt --check` проходит, `cargo test
  --all-targets` проходит (22/22), `cargo build --release` проходит; DEV-only
  runtime smoke для bootstrap, feed и finalize также пройден.
- Это service-only DEV-проверка: ни production deployment, ни live manager+1С
  integration/E2E, ни inventory direct routes не подтверждены этим
  репозиторием.

## Источники и граница утверждений

- `tasks/221-roctup-mcp-tools-port/masking-service-spec.md`, §8, в рабочем
  checkout GBIG PAM задаёт матрицу `take / adapt / reject`, MUST-28/29 и
  ограничения agent contract из MUST-34.
- [ROCTUP pinned tree](https://github.com/ROCTUP/1c-mcp-toolkit/tree/fe12903af7a367a9d67dd055c13f4b59bb59d83c)
  — источник GPL-3.0 units, когда они действительно копируются.
- [trusted-gateway pinned tree](https://github.com/alonehobo/1c-trusted-gateway/tree/a5cc656e3f3763800706ec752fd33fb2e18318e4)
  — источник концептуального сравнения, не источник разрешения на code copy.

Текущий документ и README фиксируют attribution и запреты. Они также описывают
реальный development snapshot, но не являются доказательством production deployment,
установленного runtime в 1С или переноса донорского кода в этот репозиторий.
