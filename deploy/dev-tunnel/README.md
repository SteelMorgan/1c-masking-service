# Пример: reverse-туннель к v8-session-manager (тестовый стенд)

Пример для тестового стенда, а не часть поставки сервиса. Контейнер поднимает
только loopback reverse forwarding с сервера 1С к менеджеру, работающему в
контейнере агента:

```text
сервер 1С 127.0.0.1:4000 -> SSH -> контейнер менеджера 127.0.0.1:4000
```

Имена контейнеров, volume, образ, учётная запись, адрес сервера 1С и порты
задаются через ENV — образец в [.env.example](.env.example); скопируйте его в
`.env` рядом с `compose.yml`. Дефолты в `compose.yml` — заглушки
(`onec-host`, `tunnel-user`, `manager-container`), без замены туннель не
поднимется. Проверка подстановки: `docker compose -f deploy/dev-tunnel/compose.yml config`.

Туннель не публикует порт во внешнюю сеть и не содержит ключей в Git или image.
Контейнер использует отдельный внешний read-only volume с файлами
`id_ed25519` (`0600`) и `known_hosts` (`0644`), принадлежащими UID/GID
контейнера.

## Защитный контракт

- Отдельная системная учётная запись на сервере 1С без sudo, с shell
  `/usr/sbin/nologin`.
- Единственный authorized key ограничен опциями
  `restrict,port-forwarding,permitlisten="127.0.0.1:4000"` и адресом источника.
- `sshd` оставляет `GatewayPorts no`, поэтому listener доступен только на
  loopback сервера 1С.
- Host key сервера проверяется строго (`StrictHostKeyChecking=yes`);
  fingerprint в `known_hosts` сверяется с сервером при подготовке.
- Контейнер делит network namespace с контейнером менеджера, чтобы
  destination `127.0.0.1:4000` (порт — `TUNNEL_REMOTE_PORT`/`MANAGER_PORT`) указывал на локальный менеджер.

## Проверка перед запуском

1. Контейнер менеджера запущен, менеджер слушает `127.0.0.1:4000` в его
   network namespace.
2. Внешний volume существует и содержит только два файла с указанными mode.
3. На сервере 1С свободен `127.0.0.1:4000`.
4. Fingerprint в `known_hosts` совпадает с fingerprint host key сервера.
5. `manager_url` в 1С переключается на `ws://127.0.0.1:4000/sessions` только
   после успешного WebSocket Upgrade через постоянный туннель.

## Переключение

Если порт на сервере уже занят временным (диагностическим) туннелем,
постоянный контейнер не запускать. При переключении:

1. остановить временный SSH;
2. подтвердить, что `127.0.0.1:4000` на сервере 1С свободен;
3. запустить `docker compose -f deploy/dev-tunnel/compose.yml up -d`;
4. проверить `docker inspect` (`running`, `restart=unless-stopped`) и remote
   listener `127.0.0.1:4000`;
5. выполнить только HTTP WebSocket Upgrade `/sessions`, ожидая `101`, без
   JSON-RPC;
6. убедиться, что серверная сессия базы активна, а internal-инструменты
   отсутствуют в agent-facing `session_list`.

При неуспешном Upgrade контейнер останавливается командой:

```bash
docker compose -f deploy/dev-tunnel/compose.yml down
```

`manager_url` в 1С автоматически не откатывается: решение принимается
отдельно по фактическим параметрам и журналу серверного канала.
