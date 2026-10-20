# DNS-сервер

Домашнее задание: DNS-сервер на Go, который обслуживает A-записи (и другие типы) из конфигурационного
файла. Его можно указать вместо системного DNS: имена из конфига отдаются из него, остальные запросы
пересылаются на обычный DNS-сервер (upstream).

Используется только стандартная библиотека Go, разбор и сборка DNS-пакетов написаны вручную.

Поддерживаемые типы записей: A, AAAA, CNAME, NS, SOA, PTR, MX, TXT, SRV, HINFO, CAA и запрос ANY.

Также поддерживаются: UDP и TCP, EDNS0, сжатие имён в ответах, флаг TC при переполнении UDP-ответа,
wildcard-записи (`*.dev.test`), цепочки CNAME, автоматические PTR для A/AAAA, ответы NXDOMAIN и NODATA
с SOA в authority-секции, glue-записи для MX/SRV/NS.

## Требования

Go 1.26 или новее. `make` необязателен.

```sh
brew install go      # macOS; на Linux — пакет golang или https://go.dev/dl
go version
```

Для проверки нужны `dig` или `nslookup` (на macOS есть из коробки, на Debian/Ubuntu — `apt install dnsutils`).

## Сборка и запуск

```sh
cd dns
make build    # go build -o bin/dnsd ./cmd/dnsd
make test     # go test ./...
make run      # ./bin/dnsd -config dns.conf -listen 127.0.0.1:5300
```

Порт 5300 выбран для запуска без root. Сервер пишет каждый запрос в лог, остановка — `Ctrl+C`.

Проверка из второго терминала:

```sh
dig @127.0.0.1 -p 5300 example.com A
dig @127.0.0.1 -p 5300 lab.test ANY
dig @127.0.0.1 -p 5300 www.lab.test A
dig @127.0.0.1 -p 5300 lab.test MX
dig @127.0.0.1 -p 5300 _sip._tcp.lab.test SRV
dig @127.0.0.1 -p 5300 -x 10.1.0.20
dig @127.0.0.1 -p 5300 +tcp lab.test TXT
dig @127.0.0.1 -p 5300 github.com A
nslookup -port=5300 www.lab.test 127.0.0.1
```

## Флаги

| Флаг | По умолчанию | Назначение |
|------|--------------|------------|
| `-config` | `dns.conf` | файл с записями |
| `-listen` | `127.0.0.1:53` | адрес для UDP и TCP |
| `-upstream` | `auto` | куда пересылать неизвестные имена: `auto` — первый nameserver из `/etc/resolv.conf`, адрес вида `8.8.8.8:53`, или `""` чтобы отвечать REFUSED |
| `-timeout` | `3s` | таймаут запроса к upstream |
| `-ttl` | `300` | TTL по умолчанию |
| `-auto-ptr` | `true` | генерировать PTR для всех A/AAAA |
| `-quiet` | `false` | не логировать запросы |

## Формат конфига

Одна запись на строку: `<имя> [ttl] <тип> <значение>`. Комментарии начинаются с `#` или `;`.
Имя без точки на конце дополняется текущим `$ORIGIN`, `@` обозначает сам `$ORIGIN`.
TTL можно писать с суффиксами `s`, `m`, `h`, `d`, `w`.

```
$TTL 300

example.com        A      93.184.216.34
www.example.com    CNAME  example.com
myservice.test     A      127.0.0.1
myservice.test     A      127.0.0.2
*.dev.test         A      10.0.0.5

$ORIGIN lab.test.
@          SOA    ns1 hostmaster 2026101901 3600 600 86400 300
@          NS     ns1
ns1        A      10.1.0.1
@          MX     10 mail
mail       A      10.1.0.20
@          TXT    "v=spf1 mx -all"
_sip._tcp  SRV    10 60 5060 sip
sip        A      10.1.0.30
```

Если у зоны есть SOA, сервер считает себя авторитативным для неё и на несуществующие имена внутри
зоны отвечает NXDOMAIN. Полный пример со всеми типами — в [`dns.conf`](dns.conf).

## Использование вместо системного DNS

Порт 53 привилегированный, поэтому нужен `sudo`. Сервер надо запустить до переключения системного DNS,
чтобы режим `-upstream auto` успел прочитать адрес настоящего DNS-сервера из `/etc/resolv.conf`.

```sh
sudo ./bin/dnsd -config dns.conf -listen 127.0.0.1:53
```

### macOS

Скрипт запускает сервер, переключает DNS на `127.0.0.1`, делает несколько запросов и возвращает
настройки обратно:

```sh
./scripts/try-system-dns.sh            # имя сетевого сервиса, если не Wi-Fi: ./scripts/try-system-dns.sh Ethernet
```

То же самое вручную:

```sh
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder

ping myservice.test
dig www.lab.test A
curl -I https://github.com

sudo networksetup -setdnsservers Wi-Fi empty
```

Зона `.local` на macOS обслуживается через Bonjour (multicast DNS), поэтому для своих имён в примерах
используется `.test`.

### Linux

```sh
sudo resolvectl dns eth0 127.0.0.1
sudo resolvectl flush-caches
sudo resolvectl revert eth0
```

Без systemd-resolved — строка `nameserver 127.0.0.1` в `/etc/resolv.conf`.

## Структура

```
cmd/dnsd           запуск, флаги
internal/dnsmsg    разбор и сборка DNS-сообщений (RFC 1035), сжатие имён, EDNS
internal/zone      парсер конфига и хранилище записей
internal/server    обработка запросов, форвардинг на upstream, UDP/TCP-сервер
scripts/           проверка подмены системного DNS на macOS
```

Обработка запроса: разобрать пакет, найти имя в зоне (с учётом wildcard и CNAME), если не нашли и
зона не наша — переслать пакет на upstream и вернуть ответ как есть, иначе собрать свой ответ.
Если ответ не помещается в UDP-лимит клиента, отдаётся только заголовок с флагом TC, и клиент
повторяет запрос по TCP.
