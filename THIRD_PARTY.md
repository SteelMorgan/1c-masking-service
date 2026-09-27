# Third-party и provenance

Реестр происхождения кода репозитория `1c-masking-service`. В исходниках
сервиса не обнаружены source files или дословные units доноров. Реестр
намеренно отделяет фактически перенесённый код отдельного 1С-расширения
[1c-mcp-tools](https://github.com/SteelMorgan/1c-mcp-tools) от самостоятельной
Rust-реализации этого сервиса.

## Собственный код сервиса

`Cargo.toml` объявляет пакет `onec-masking-service` версии `0.1.0`, edition 2021
и license metadata `PolyForm-Small-Business-1.0.0` (текст — `LICENSE`). Эта декларация относится только к написанному для
сервиса коду и не перелицензирует GPL-код, перенесённый в 1С-расширение.
Service-owned области — `src/` (Axum/SQLite/auth/masking domain), `web/`
(human UI и описание API) и `migrations/`. Использование crates.io
dependencies через Cargo не является копированием исходников перечисленных
доноров; полный license inventory зависимостей в этом документе не
утверждается.

В Rust-сервисе нет ROCTUP-файлов, native/template assets или фрагментов
`1c-trusted-gateway`. Наличие сходных security/masking идей не превращает
самостоятельную реализацию в `copied` или `adapted` unit без отдельного
source-level доказательства.

В дереве сервиса нет файлов `LICENSE`, `NOTICE` или `COPYING`. Это
согласуется с отсутствием скопированного donor source: `Cargo.toml` содержит
только license metadata собственного пакета. При фактическом добавлении
ROCTUP units соответствующие GPL-3.0 notices и source availability должны быть
добавлены одновременно.

## Реестр доноров

| Донор и pinned URL | Commit | License status | Компоненты и идеи | Статус в 1С-расширении / этом сервисе | Изменения и границы |
|---|---|---|---|---|---|
| [ROCTUP/1c-mcp-toolkit](https://github.com/ROCTUP/1c-mcp-toolkit/tree/fe12903af7a367a9d67dd055c13f4b59bb59d83c) | `fe12903af7a367a9d67dd055c13f4b59bb59d83c` | GPL-3.0; license upstream должна сопровождать фактические copied units | Выбранные tool cores (`execute_query`, `get_metadata`, `get_object_by_link`, `get_link_of_object`, `find_references_to_object`, `get_access_rights`), transitive masking/policy/dictionary closure, QueryLineageAnalyzer, включая native/template assets | В 1С-расширении 1c-mcp-tools — `copied` units/assets и `adapted` context/обвязка. В `1c-masking-service` **нет copied/adapted ROCTUP units**: Rust `MaskEngine`/`MappingStore` являются service-owned implementation | В расширении адаптированы server/service context, собственный WS transport, state и secret precedence. Не переносятся upstream transport, client-form state как policy owner и старый mapper как владелец изменяемой policy. Если ROCTUP code появится в сервисе, нужно добавить неизменённые GPL copyright/LICENSE/NOTICE и обеспечить source availability. |
| [alonehobo/1c-trusted-gateway](https://github.com/alonehobo/1c-trusted-gateway/tree/a5cc656e3f3763800706ec752fd33fb2e18318e4) | `a5cc656e3f3763800706ec752fd33fb2e18318e4` | LICENSE не обнаружена; GitHub API для pin сообщает `license=null`. Это не разрешение на копирование | Только `concept`: recursive JSON, exact/prefix/composite type policy, forced field names, contextual regex, masked-column UX и идентификация отчёта | В `1c-masking-service` и в 1С-расширении **code copy отсутствует**; зафиксированы только attribution и идеи | Любая реализация должна быть независимой. Копирование кода запрещено до письменного разрешения или обнаружения применимой лицензии. Нельзя называть собственные Rust modules `copied` или `adapted` от этого проекта. |

## Детали ROCTUP: что перенесено в 1С-расширение

В 1С-расширение перенесены:

- серверные корни `ВыполнитьЗапрос`, `ПолучитьМетаданные`,
  `ПолучитьОбъектПоНавигационнойСсылке`, `ПолучитьНавигационнуюСсылкуПоОписанию`,
  `НайтиСсылкиНаОбъект`, `ПолучитьПраваДоступа`;
- closure автоматического маскирования, обратной подстановки, policy,
  dictionary и regex;
- templates/native assets `QueryLineageAnalyzer` (`RegexHelper` удалён
  вместе с мёртвым regex-путём — его единственным потребителем).

Отдельно от перенесённого кода написаны context adapters: registration/dispatch,
server/service context, per-call state, защищённое TTL-сопоставление,
irreversible secret cut и sanitized error boundary. Эти сведения описывают
1С-расширение и не означают source parity с Rust-сервисом. Internal
`preflight`/`finalize`, human API, history и local auth сервиса — собственные
модули, а не перенесённые ROCTUP units. Agent-facing инструмент
`submit_for_deanonymization` из upstream в сервис не переносится: его
назначение заменено внутренней автоматической историей сервиса.

Поединичный манифест перенесённых файлов и копия
`LICENSE` (GPL-3.0) upstream должны сопровождать 1С-расширение в его
репозитории.

## License gate и правила будущего переноса

1. `ROCTUP/1c-mcp-toolkit`: при фактическом копировании в сервис сохранить
   GPL-3.0, copyright, LICENSE/NOTICE и ссылку на pinned source. Адаптированную
   обвязку пометить как `adapted`; дословные единицы — как `copied`. Нельзя
   объявлять эти исходники под лицензией сервиса (PolyForm Small Business) или смешивать их с отсутствующим provenance.
2. `alonehobo/1c-trusted-gateway`: до снятия license block разрешены только
   `concept` и независимо написанный код. Нельзя переносить source files,
   фрагменты, имена реализации или выдавать концептуальное влияние за code
   borrowing.
3. Любой будущий copied code добавляется вместе с соответствующими notices в
   том же изменении и проходит отдельную license/provenance проверку.
4. Agent-facing контракт сервиса не раскрывает masking controls, receipts,
   history IDs, policy versions или внутренние причины срабатывания — это
   требование не зависит от происхождения реализации.

## Граница утверждений

- [ROCTUP pinned tree](https://github.com/ROCTUP/1c-mcp-toolkit/tree/fe12903af7a367a9d67dd055c13f4b59bb59d83c)
  — источник GPL-3.0 units, когда они действительно копируются.
- [trusted-gateway pinned tree](https://github.com/alonehobo/1c-trusted-gateway/tree/a5cc656e3f3763800706ec752fd33fb2e18318e4)
  — источник концептуального сравнения, не источник разрешения на копирование.

Этот документ и README фиксируют attribution и запреты. Они не являются
доказательством production deployment или переноса донорского кода в этот
репозиторий; проверяемый след — этот реестр и история репозитория.
