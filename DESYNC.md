# Desync: формат и сетевые гарантии

`type: "desync"` — самостоятельный прямой outbound. `sing-box desync capabilities`
возвращает JSON с `capability: "forkop-desync-v1"`, `version: 1`, списками режимов,
пресетов и доступных probe-протоколов. Обычный `version` также печатает marker.
Наличие marker проверяют вместо сравнения строк версии.

```json
{
  "type": "desync",
  "tag": "dpi",
  "preset": "auto",
  "routing_mark": 128,
  "domain_resolver": "dns-direct",
  "adaptive": {"max_attempts": 3, "ttl": "24h", "max_entries": 1024}
}
```

Поля стратегии находятся прямо в outbound, без дополнительного `desync_options`.
Это имя используется только для хранения JSON в UCI Forkop. Dialer сохраняет
обычные DNS, IPv4/IPv6, интерфейс, netns, mark и timeout. Марка применяется к
настоящему сокету и наследуется raw-инъекцией. FakeIP и запрет QUIC применяет
обычная маршрутизация до выбора outbound. TCP Fast Open, multipath и `detour`
отклоняются: движку нужен собственный обычный TCP-сокет. Другой outbound может
использовать desync как прямой dialer до своего сервера; обратный каскад через
чужой туннель не поддерживается. Запрос HTTP CONNECT или иной начальный обмен
такого протокола анализируется как его собственные байты, поэтому TLS-специфичный
режим требует, чтобы первой записью действительно был TLS ClientHello.

## Приоритет и значения

Порядок: defaults → preset → строка `strategy` → явно указанные JSON-поля.
В том числе `false`, `0`, пустая строка и пустой список являются явными значениями;
после подстановки они проходят ту же строгую проверку. Неизвестные поля и
несовместимые сочетания отклоняются. Имена регистрозависимы; неявных алиасов нет.
`auto_tune: false` отключает Adaptive даже у `preset: auto`.

| Пресет | TCP | UDP | Adaptive |
| --- | --- | --- | --- |
| отсутствует, custom | split / midsld | none | выключен |
| auto | split / midsld | none | включён, если не переопределён |
| split, disorder, tlsrec, fake, fake_split, oob | одноимённый mode | none | выключен |
| GT1, GT2, GT3, GT4 | none | auto; N повторов на дейтаграммах 1..N | выключен |

| Режим | Действие над первым обменом |
| --- | --- |
| none | TCP без преобразования |
| split, multi_split | последовательные записи по границам `split_pos` |
| disorder, multi_disorder | raw-сегменты в обратном порядке; затем ядро ведёт ACK и retransmit |
| tlsrec | разбиение TLS records с пересчётом длин |
| fake | raw fake перед исходным первым обменом |
| fake_split, hostfakesplit | fake ClientHello/HTTP Host и последовательное разбиение |
| fake_disorder | fake и обратный порядок сегментов |
| oob, disoob | raw fake с urgent, disoob также меняет порядок |

`split_pos` — до 16 границ через запятую. Положительное число — смещение в
исходном первом обмене от нулевого байта; граница 1 отделяет первый байт.
`sni` / `host` обозначают начало имени TLS SNI / HTTP Host; `midsld` — середину
значимой метки домена; `endhost` — конец имени; `sniext` и `extlen` — начало
SNI extension и поля общей длины extensions. Доступны целочисленные `+N`/`-N` смещения.
Граница должна существовать в конкретном сообщении. Движок собирает несколько
Write ограниченным первым буфером и таймером; дальнейший поток передаётся как
обычный TCP. `tlsrec_first` применяет TLS records перед повторным вычислением
границ. В fake/oob с `tlsrec_first: true` поле `split_pos` задаёт границы
TLS records; неуказанная граница остаётся `midsld`. Для HTTP стадия изменения
TLS records пропускается: `tlsrec` передаёт HTTP как есть, а с `tlsrec_first`
продолжают применяться остальные преобразования выбранного TCP mode.

## Fake и начальные параметры сокета

`fake_sni`, `fake_host`, `fake_payload` (base64), `fake_sni_pool` (до 64 имён)
меняют только raw fake. Пул выбирается по кругу. Имя в ClientHello меняется с
пересчётом длин. `repeats` — 1..16 fake-повторов; `delay` — 0..1s между
начальными отправками. `ttl` — 1..255, default 3 для fake-режимов.
`fooling` допускает `none`, `badseq`, `badack`, `badsum`, `md5`, `md5_badack`,
`badseq_badack_badsum`, `datanoack`, `hopbyhop`, `destopt`, `ipfrag`, `ts`,
`badtimestamp`, а также пустую строку. `badtimestamp` — синоним `ts` на проводе;
обе записи сохраняются при импорте и экспорте и требуют согласованных TCP timestamps.
`ipfrag` фрагментирует fake с размером 48 байт, если не задан отдельный `ipfrag`.
Пустая строка и `none` отключают дополнительные методы fooling, сохраняя защиту
sequence range. Допустимы только перечисленные значения и две указанные
комбинации; произвольное объединение токенов отклоняется всеми валидаторами.
IPv6 extension headers требуют IPv6 назначения. Fake-параметры требуют fake mode.

Fake никогда не передаётся обычным TCP Write: его raw sequence range полностью
предшествует началу настоящего потока независимо от TTL и fooling. Настоящие raw
сегменты могут дублироваться на проводе при передаче ядром, но серверный поток
собирается без дубликатов. Для raw-режимов нужны Linux и соответствующие
CAP_NET_RAW/CAP_NET_ADMIN. Ошибки ядра и прав возвращаются явно.

`seqovl` задаёт перекрытие настоящих сегментов исходными байтами, до 4096.
`ipfrag` — размер фрагмента IP, кратный 8, с учётом ограничений семейства адреса.
`wsize` задаёт начальное окно; `wscale` — scale в SYN (0..14), в том числе
явный `wscale: 0`. Pre-connect hook выполняется вместе с обычными mark/interface
controls. Положительный scale и точный малый `wsize` несовместимы в Linux
TCP_WINDOW_CLAMP и отклоняются. После согласования scale исходный SO_RCVBUF
восстанавливается; Linux сохраняет ручную блокировку размера receive buffer,
что отключает его autotuning для этого сокета. `syndata` — base64 fake SYN payload 1..1200 байт:
raw SYN с заведомо неверной checksum отправляется на том же tuple перед
настоящим SYN; это не прикладные данные TCP Fast Open. Эти механизмы нельзя
эмулировать обработкой первого Write.

`autottl` использует ограниченное наблюдение SYN-ACK перед connect; reverse TTL
даёт оценку, а не доказанное расстояние до фильтра. Наблюдение ограничено по
времени и числу capture-сокетов, результаты разделяются по namespace и tuple.
При отсутствии наблюдения применяется настроенный фиксированный TTL. Оценка
никогда не снимает sequence-защиту fake. Эффективность у провайдера проверяется
отдельно от сохранности потока.

## UDP

`udp_mode`: none / quic / stun / auto. Fake применяется только к распознанным
QUIC Initial и STUN; исходные дейтаграммы сохраняют назначение и байты.
`udp_fake_payload` — base64; иначе создаётся protocol-specific fake.
`udp_ttl` (default 3) выбирается по семейству фактического назначения и
восстанавливается после серии, в том числе для IPv4 на dual-stack IPv6 socket;
`udp_repeats` — 1..16.
На Darwin обычные IPv4 и IPv6 UDP-сокеты поддерживаются; fake TTL для IPv4 через
dual-stack IPv6 socket отклоняется до изменения состояния: ядро не позволяет
безопасно восстановить исходный IPv4 TTL. Используйте IPv4 socket для этого пути.
`udp_out_range: "start:end"` — включительный диапазон исходящих дейтаграмм,
нумерация с 1, максимум 1024. Счётчики независимы для каждого назначения и
сокета; максимум 1024 назначений на socket. Диапазон считает все исходящие
дейтаграммы, отправляет fake только для подходящих протоколов внутри него.
Оба пути, DialContext UDP и ListenPacket, используют исходный socket и порт.
Домен разрешается один раз при создании сессии через настроенный dialer DNS,
с сохранением interface/mark/family. В ListenPacket преобразование домена в IP
расположено снаружи движка: engine и raw injector получают числовое назначение,
а вызывающая сторона получает исходный логический домен в адресах ответов.
На каждую дейтаграмму DNS не запускается; system DNS/FakeIP не подменяет
явно выбранный resolver.

`udplen` добавляет STUN PADDING либо пересобирает защищённый
QUIC Initial: снимает header protection, проверяет AEAD, добавляет PADDING,
обновляет длины и повторно шифрует пакет. Поддерживаются QUIC v1/v2/draft29;
coalesced tail сохраняется побайтно. Handshake/0RTT/1RTT не изменяются. Для STUN с MESSAGE-INTEGRITY padding располагается после integrity,
а последний FINGERPRINT пересчитывается. Длина ограничена MTU/UDP и проверкой
целостности; произвольное дописывание байтов к AEAD-пакету не применяется. `udp_keep_socket: true` (default) отправляет fake через исходный socket с
временной TTL и её восстановлением. Явный `false` использует отдельный raw UDP
injector на одну серию и закрывает его даже при ошибке; tuple, checksum, mark
и interface сохраняются, socket приложения не меняется. Нужны Linux и CAP_NET_RAW.
Raw injector не получает ответы приложения и не перехватывает их у исходного socket.

`quic_desync` (default true в quic/auto) отдельно отключает QUIC fake/resize,
сохраняя STUN в auto. `quic_repeats` (0..16) переопределяет число fake только
для QUIC; 0 наследует udp_repeats. QUIC-поля вне quic/auto отклоняются.

## Adaptive и replay

Каталог содержит исходный mode, split, tlsrec, multi_split, disorder, fake_split;
недоступные и несовместимые кандидаты отфильтровываются engine.Validate.
Рейтинг использует успешные ответы, ошибки connect/write/read, ранние EOF/RST,
тайм-аут начального ответа и повторные наблюдения медленных активных чтений.
TLS alert учитывается как неуспех. Успешный транспортный ответ ещё не доказывает
успешность прикладного TLS/HTTP; отдельный probe проверяет настоящий handshake.

Первым используется точный host:port; родительский registrable domain и подсеть
IPv4 /24, IPv6 /56 допускаются лишь после ≥3 разных хостов и ≥8 успехов.
Общий рейтинг задаёт осторожный порядок новых адресов. Все записи разделены
хешем outbound tag, конфигурации, dialer и network_id, а также текущим сетевым
fingerprint. После смены сети прежний рейтинг не применяется.

После route resolve имя берётся из исходного назначения или sniff-контекста,
если оно соответствует фактическому адресу соединения. Статистика двух имён
на одном IP остаётся раздельной; числовой адрес используется для самого dial
и повторных попыток, а подсеть — только для осторожного общего рейтинга.

Replay текущего соединения разрешён только для **полного одиночного
ClientHello**, возможно разбитого на несколько TLS handshake records, пока
клиенту не передан ни один байт ответа. Проверяются границы records, длины
ClientHello, векторы и extension; early_data extension запрещён. HTTP, TLS
application data, второй handshake, неполный/лишний хвост и произвольный UDP
никогда не повторяются. Любая частичная/ошибочная Write закрывает replay.
После начала ответа ошибки влияют только на будущий рейтинг.
TCP half-close завершает возможность replay и сохраняет чтение ответа сервера.
Общий timeout включает dial, первую запись, задержки сегментов и отложенную
сборку первого обмена. После начального обмена восстанавливаются дедлайны клиента.
Тайм-аут чтения отдельной попытки включается только после полного безопасного
ClientHello. HTTP, бинарные протоколы и TLS application data не получают лимит
ожидания ответа от Adaptive: при запрете replay восстанавливается последний
дедлайн клиента, включая уже ожидающее параллельное Read. Лимит первой записи,
сегментации и отложенной сборки при этом сохраняется.

| adaptive | Default | Допустимо |
| --- | --- | --- |
| max_attempts | 3 | 1..8, включая исходное соединение |
| max_concurrent | 2 | 1..16 проб на назначение; суммарно 16× этот лимит |
| timeout | 10s | 1s..60s, общий бюджет всех попыток |
| max_buffer | 32768 | 512..65536 байт |
| max_entries | 1024 | 16..16384 записей |
| ttl | 24h | 1m..168h |
| network_id | пусто | дополнительный идентификатор сети, до 256 байт |

Места для проб освобождаются после ответа, запрета replay, ошибки, cancel и
Close. При исчерпании мест обычное соединение получает выбранный mode без
повтора. Дедлайны клиента сохраняются при смене сокета; cancel закрывает его.
Медленный поток требует нескольких наблюдений и не вызывает replay приложения.

## cache.db и диагностика

Без `experimental.cache_file.enabled` обучение работает в памяти. С включённым
cache.db используется version 1 snapshot; устаревшие версии и expired записи
игнорируются. Adaptive объединяет изменения на 5 секунд, cachefile также
объединяет snapshots на 5 секунд; shutdown сохраняет их до закрытия базы.
До 128 сохранённых partitions / 64 MiB и 32 MiB ожидающих snapshots;
неиспользованные partitions старше 7 дней удаляются при записи.

Clash API использует обычную авторизацию:

- `GET /desync?outbound=TAG` — `{capability,outbounds:{TAG:{version,partition,entries,entry_count,entries_truncated,active,current,reason}}}`.
- `DELETE /desync?outbound=TAG` — очищает память и сохранённый partition активного outbound.
- Без `outbound` операция охватывает все активные desync outbounds.

Для rpcd ответ диагностики ограничен примерно 60 KiB: до 64 последних записей,
с общим `entry_count` и признаком `entries_truncated`. При запросе всех outbound
в ответ входят до 32 секций; `outbound_count` и `outbounds_truncated` показывают
ограничение выборки. Очистка без фильтра по-прежнему очищает все секции.
Выборка не меняет полные snapshots в памяти или `cache.db`.

```sh
sing-box desync capabilities
sing-box desync import 'preset=auto auto_tune=false mode=split split_pos=midsld'
sing-box desync check '{"preset":"fake_split","fake_sni":"example.org"}'
sing-box desync export '{"preset":"split","auto_tune":false}'
sing-box desync probe --options strategy.json --target example.org:443 --protocol tls --routing-mark 128 --timeout 10s
sing-box desync probe --options strategy.json --target https://example.org/ --protocol http --max-bytes 65536
```

`import`, `export`, `check` принимают один аргумент либо stdin; input ≤128 KiB.
`import` проверяет синтаксис; `export` нормализует переносимый формат; `check` дополнительно валидирует
engine/platform. Строка стратегии состоит из key=value; значения с пробелами
нуждаются в JSON-кавычках, повторный ключ отклоняется. fake_sni_pool задаётся
списком через запятую. `adaptive={...}` и `fake_sni_pool=[...]` принимают JSON с пробелами; dialer передаётся только в JSON outbound.
`export` исключает dialer, сохраняя nested adaptive, списки и auto_tune.

`--interface IFACE` привязывает и probe, и DNS к интерфейсу. Повторяемый
`--dns-server URI` задаёт независимые direct DNS endpoints (udp/tcp/tls/https/quic/h3),
до 8, с последовательным fallback. Default — `udp://1.1.1.1`; system DNS/FakeIP
не используется. Именному encrypted endpoint нужен numeric bootstrap в том же
списке. Mark, bind interface и netns наследуются DNS-сокетами.

`probe` (`test` — alias) создаёт отдельный Box с тем же production dialer и
движком, без изменения активной конфигурации. Разрешены tls, http, а при
with_quic — quic. Проверка TLS/QUIC проверяет сертификат, HTTP отправляет один
GET без redirects и читает ограниченный body. Время 1..15s, body 1KiB..1MiB,
один outbound и одна проба. SIGTERM/SIGINT отменяют задачу. `--sni` переопределяет
имя сертификата; `--output` записывает JSON результата. Network failure —
`success:false` с причиной; некорректные аргументы дают ошибку процесса.
Throughput показывается только для HTTP body; TLS/QUIC handshake не даёт
замера скорости или устойчивости. Backend может выполнить ограниченную серию
отдельных проб для оценки устойчивости и применения выбранного custom mode.
