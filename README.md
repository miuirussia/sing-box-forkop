# sing-box-forkop

Форк sing-box, который Forkop использует на OpenWrt.

- WireGuard с AmneziaWG 2.0 и 3.x, клиент Phobos, Cloudflare WARP с поддержкой AmneziaWG.
- TrustTunnel и mieru (клиент и сервер), VLESS Encryption на входе и выходе, XHTTP в том числе поверх HTTP/3.
- Подписки из списков ссылок, в base64 и в форматах Clash/mihomo, sing-box, Xray и SIP008. Отдельный сервер тоже можно задать ссылкой.
- Fallback выбирает первый рабочий сервер по приоритету. Замер задержки учитывает время запроса без установки соединения. DNS Fallback переключает DNS-сервер при сбое.
- Текстовые наборы правил принимают домены и подсети по одному на строку. Clash API отдаёт подсети для nftables, IP и страну выхода, состояние Tailscale и его выходной узел, а также позволяет пинговать устройства Tailscale.

## Desync

Прямой outbound `desync` поддерживает TCP/TLS/HTTP и UDP/QUIC, Adaptive с безопасным ClientHello-only retry и обучением в cache.db. Формат стратегий, требования Linux, ограничения и диагностический CLI описаны в [DESYNC.md](DESYNC.md). Поддержку ядра проверяет `sing-box desync capabilities`.

## Сборка

Нужны Linux или WSL и git, для APK ещё `apk-tools`. Скрипт сам скачает Go. Результат будет в `dist/`.

```sh
./build.sh --list                      # варианты, теги и архитектуры
./build.sh --arch aarch64_cortex-a53    # IPK и APK для архитектуры OpenWrt
./build.sh arm64 mipsle                # пакеты для двух целей
./build.sh --variant full arm64
./build.sh --binary-only amd64
```

| Вариант | Что входит |
| --- | --- |
| `tiny` | QUIC, Hysteria, Hysteria2, TUIC, DNS over QUIC и HTTP/3, XHTTP поверх HTTP/3 |
| `base` (по умолчанию) | Всё из `tiny` плюс gVisor, WireGuard, AmneziaWG, Phobos, WARP, OpenVPN, TrustTunnel, VMess и AnyTLS |
| `full` | Всё из `base` плюс Tailscale, OpenConnect, NaiveProxy, mieru, Snell, SSH, ShadowTLS и Tor |

Clash API и uTLS есть во всех вариантах. `full` с NaiveProxy при первой сборке скачивает несколько гигабайт исходников cronet и тулчейна Chromium. На целях без библиотеки cronet скрипт исключает NaiveProxy. Эти цели перечислены в `./build.sh --list`.

Через `--tags` можно задать весь список необязательных тегов или изменить набор выбранного варианта знаками `+` и `-`. Метка `custom` означает, что набор отличается от всех трёх вариантов. Для `with_wireguard`, `with_openvpn`, `with_openconnect` и `with_tailscale` нужен `with_gvisor`.

```sh
./build.sh --tags +with_openconnect arm64
./build.sh --variant full --tags -with_tor,-with_ssh arm64
./build.sh --tags with_quic,with_gvisor,with_wireguard arm64
```

## Геоданные V2Ray/Xray

`geodata` читает DAT потоком и экспортирует теги прямо в SRS. Команды `geosite` и `geoip` работают с форматом `.db`.

```sh
sing-box geodata fetch --url URL --output geosite.dat
sing-box geodata list --kind geosite --file geosite.dat --output index.json
sing-box geodata tags --index index.json --search youtube --offset 0
sing-box geodata export --kind geosite --file geosite.dat --index index.json --tag youtube --output youtube.srs
sing-box geodata export --kind geoip --file geoip.dat --tag ru --output ru.srs
printf '%s\n' '["youtube", "google@!cn"]' > tags.json
mkdir -p rulesets
sing-box geodata export --kind geosite --file geosite.dat --index index.json --tags-file tags.json --output rulesets
```

Индекс привязан к размеру и времени изменения DAT. Поиск выдаёт до 200 тегов на страницу. Для geosite можно указать тег с фильтром по атрибуту, например `--tag 'google@!cn'`. Экспорт сохраняет типы доменов и IPv4/IPv6 CIDR, включая `/0`. Для GeoIP поддерживаются только прямые совпадения (`inverse_match: false`).

Пакетный экспорт принимает JSON-массив тегов, читает индекс один раз и последовательно записывает `<тег>.srs` в существующий каталог `--output`. Каждый файл заменяется атомарно после успешной компиляции. При ошибке команда останавливается, а уже записанные файлы остаются в каталоге.

Файл списка тегов ограничен 16 МиБ и 32 768 уникальными тегами с учётом фильтров по атрибутам.

Лимит `fetch` составляет 128 МиБ, тайм-аут 10 минут. Загрузку через выбранный outbound выполняет локальный `POST /geodata/download` Clash API с авторизацией.

## Autodetect

Для недавних соединений с признаками сбоя Autodetect сравнивает HTTPS-запросы через прямой выход и прокси. Укажите два разных тега в `experimental.clash_api.autodetect`.

```json
{
  "direct": "direct-out",
  "proxy": "Main",
  "ports": [443, 8443]
}
```

`ports` принимает один порт или список портов от 1 до 65535. По умолчанию проверяется порт 443. Проверки сохраняют SNI и порт исходного соединения, проверяют сертификат и пропускают локальные адреса и UDP. Результаты возвращает `GET /autodetect` с обычной авторизацией Clash API.

## Проверка UDP в URLTest

Для группы `urltest`, используемой как `detour` UDP-туннеля, можно задать `"udp_probe": {"server": "1.1.1.1", "domain": "example.com"}`. Группа будет выбирать UDP-выходы по ответам на DNS-запрос через каждый выход. `server` задаётся IP-адресом, `server_port` по умолчанию равен 53. Для TCP группа продолжает использовать HTTP-проверку.

## WireGuard в ядре Linux

Добавьте `"kernel": true` в endpoint `wireguard`, `amneziawg`, `phobos` или `warp`. Нужны `CAP_NET_ADMIN` и модуль `wireguard` либо `amneziawg`. WARP с обфускацией пробует `amneziawg`, обычный WARP использует `wireguard`.

При недоступном модуле, нехватке прав или несовместимых настройках sing-box пишет причину в лог и переключается на userspace. Там туннель использует gVisor по умолчанию или системный TUN с `"system": true`. WARP сохраняет обфускацию при переключении.

- WARP в режиме Kernel поддерживает `detour` через outbound с UDP. Шифрование выполняет ядро, а sing-box передаёт зашифрованные пакеты через выбранный outbound. WARP с каскадом и Phobos используют отдельное сетевое пространство имён для внутреннего UDP-порта. Для его создания нужен `CAP_SYS_ADMIN`.
- WireGuard и AmneziaWG переключаются на userspace при `detour` или ненулевом `reserved`. Для прямых подключений WireGuard, AmneziaWG и WARP переход также вызывают `bind_interface` и `auto_detect_interface` без марки auto-redirect. Phobos поддерживает `detour` и привязку внешнего UDP-сокета.
- При прямом подключении ядро принимает один IP для домена пира. Если DNS возвращает несколько IP, укажите доступный IP в `address`. При каскаде WARP передаёт домен выбранному outbound, если в настройках WARP не указан `domain_resolver`. Если `port` не задан, порт берётся из профиля.
- Занятый локальный IPv4-адрес туннеля в том же сетевом пространстве имён приводит к переключению на gVisor. При `"system": true` такой конфликт прерывает запуск.
- Ядро обрабатывает входящие IP-пакеты. Отдельная таблица маршрутов применяется к сокетам, привязанным к VPN-интерфейсу, и к трафику с его IP. Внешние пакеты WireGuard и AmneziaWG следуют системным маршрутам с учётом `routing_mark`. Для пересылки ICMP между endpoint’ами sing-box нужен userspace.

## Phobos

Клиент Phobos со встроенным обфускатором входит в сборки с `with_wireguard` и `with_gvisor`. Перенесите параметры WireGuard из профиля вручную. Для `address` и `port` пира используйте публичный адрес обфускатора из `target` секции `[instance]`. Поле `source-lport` можно пропустить.

```json
{
  "endpoints": [
    {
      "type": "phobos",
      "tag": "phobos-vpn",
      "address": ["10.8.0.2/32"],
      "private_key": "<WireGuard private key>",
      "peers": [
        {
          "address": "vpn.example.com",
          "port": 51822,
          "public_key": "<WireGuard server public key>",
          "allowed_ips": ["0.0.0.0/0", "::/0"],
          "persistent_keepalive_interval": 25
        }
      ],
      "obfuscation": {
        "key": "<preset XOR key>",
        "masking": "STUN"
      }
    }
  ]
}
```

- `key` обязателен, от 1 до 255 байт без NUL. `masking` задаётся по пресету сервера. Доступны `STUN` (по умолчанию), `MEDIA`, `NONE` и `AUTO`. Клиент AUTO начинает без маскировки. Сервер AUTO распознаёт STUN, а для MEDIA нужен отдельный режим.
- `max_dummy` соответствует `max-dummy` (0–1024, по умолчанию 4). `obfuscate_bytes` задаёт число первых байт для обработки и соответствует `obfuscate-bytes`. По умолчанию это 16 для MEDIA и 0 для остальных режимов. Явный 0 обрабатывает весь пакет и требует того же на сервере. В указанной ниже версии Phobos режим MEDIA заменяет 0 на 16.
- Для MEDIA доступны `media_pt` (0–127), `media_ssrc` (uint32) и `media_clock` (0–1000 кадров/с). Ноль выбирает пресет для `media_pt` и `media_clock` и случайное значение для `media_ssrc`.
- Настройки обфускации общие для всех пиров endpoint. `reserved` должен содержать только нули. MTU по умолчанию 1280.

Поддерживается клиент WireGuard-пресетов [Phobos версии 22aedef](https://github.com/Ground-Zerro/Phobos/tree/22aedefda053062dc58c036072d2da6e216d5a34/src/phobos-obfuscator). Чтобы проверить совместимость, соберите `transport/phobos/testdata/reference.c` с `-I`, указывающим на каталог обфускатора этой версии. Укажите путь к собранному файлу в `PHOBOS_REFERENCE`, а к оригинальному `wg-obfuscator` в `PHOBOS_OBFUSCATOR`.

```sh
go test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor,badlinkname,with_utls ./transport/phobos ./transport/wireguard ./protocol/wireguard ./include
```

## Лицензия

[GPL-3.0-or-later](LICENSE). Изменённые зависимости лежат в [`third_party`](third_party).
