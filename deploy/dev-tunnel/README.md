# DEV reverse tunnel для 1С server channel

Артефакт поднимает только loopback reverse forwarding:

```text
onec-infra 127.0.0.1:4000 -> SSH -> 1c-ai-sandbox 127.0.0.1:4000
```

Туннель не публикует порт во внешнюю сеть и не содержит ключей в Git или image.
Контейнер использует отдельный read-only volume
`onec-v8sm-dev-tunnel-secrets` с файлами `id_ed25519` (`0600`) и
`known_hosts` (`0644`), принадлежащими UID/GID `1000:1000`.

## Защитный контракт

- DEV account: `onec-v8sm-dev-tunnel`, system account без sudo и с shell
  `/usr/sbin/nologin`.
- Единственный authorized key ограничен опциями
  `restrict,port-forwarding,permitlisten="127.0.0.1:4000"` и source address
  `192.168.250.1`.
- `sshd` оставляет `GatewayPorts no`, поэтому listener доступен только на
  loopback `onec-infra`.
- Host key `onec-infra` проверяется строго. Зафиксированный при подготовке
  ED25519 fingerprint:
  `SHA256:IKDnDpVRQochIHXHrFR/6vU3gW3NawxqynFVz7kPLII`.
- Контейнер делит network namespace с `1c-ai-sandbox`, чтобы destination
  `127.0.0.1:4000` указывал на локальный session manager.

## Проверка перед запуском

1. `1c-ai-sandbox` запущен, а manager слушает `127.0.0.1:4000` в его network
   namespace.
2. Внешний volume существует и содержит только два файла с указанными mode.
3. На `onec-infra` свободен `127.0.0.1:4000`.
4. Fingerprint в `known_hosts` совпадает с fingerprint host key на сервере.
5. В `manager_url` DEV используется `ws://127.0.0.1:4000/sessions` только после
   успешного WebSocket Upgrade через persistent tunnel.

## Coordinated cutover

Пока диагностический tunnel занимает remote port, persistent sidecar не
запускать. При согласованном переключении:

1. остановить диагностический SSH по сохранённому PID/session handle;
2. подтвердить, что `127.0.0.1:4000` на `onec-infra` свободен;
3. запустить `docker compose -f deploy/dev-tunnel/compose.yml up -d`;
4. проверить `docker inspect` (`running`, `restart=unless-stopped`) и remote
   listener `127.0.0.1:4000`;
5. выполнить только HTTP WebSocket Upgrade `/sessions`, ожидая `101`, без
   JSON-RPC;
6. убедиться, что DEV `server-gbig_pam_ai` active и internal tools отсутствуют
   в agent-facing `session_list`.

При неуспешном Upgrade контейнер останавливается командой:

```bash
docker compose -f deploy/dev-tunnel/compose.yml down
```

DEV `manager_url` не откатывается автоматически: решение принимается отдельно
по readback параметров и журналу server channel. PROD tunnel и PROD база не
затрагиваются.
