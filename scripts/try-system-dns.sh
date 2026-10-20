#!/bin/sh
# Запускает dnsd на порту 53, делает его системным DNS, проверяет и возвращает настройки обратно.
# Использование: ./scripts/try-system-dns.sh [сетевой сервис, по умолчанию Wi-Fi]
set -u
cd "$(dirname "$0")/.."

SVC=${1:-Wi-Fi}
OLD=$(networksetup -getdnsservers "$SVC" | grep '^[0-9]' | tr '\n' ' ')
[ -z "$OLD" ] && OLD=empty
echo "Интерфейс: $SVC, текущие DNS: $OLD"

go build -o bin/dnsd ./cmd/dnsd || exit 1
sudo -v || exit 1

sudo ./bin/dnsd -config dns.conf -listen 127.0.0.1:53 &
SRV=$!
sleep 1
kill -0 "$SRV" 2>/dev/null || { echo "dnsd не запустился"; exit 1; }

flush() { sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder; }
rollback() {
  echo; echo "--- откат"
  sudo networksetup -setdnsservers "$SVC" $OLD
  flush
  sudo kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
  echo "DNS восстановлен: $(networksetup -getdnsservers "$SVC" | tr '\n' ' ')"
}
trap rollback EXIT INT TERM

sudo networksetup -setdnsservers "$SVC" 127.0.0.1
flush
sleep 1
EFFECTIVE=$(scutil --dns | awk '/^resolver #1/{f=1} f && /nameserver\[0\]/{print $3; exit}')
if [ "$EFFECTIVE" != "127.0.0.1" ]; then
  echo "системный резолвер не переключился (сейчас $EFFECTIVE)"
  exit 1
fi
echo "--- системный DNS = 127.0.0.1, проверка"

echo "myservice.test A   -> $(dig +short myservice.test A | tr '\n' ' ')   (ожидаем 127.0.0.1 127.0.0.2)"
echo "www.lab.test A     -> $(dig +short www.lab.test A | tr '\n' ' ')   (ожидаем lab.test. 10.1.0.10)"
echo "anything.dev.test  -> $(dig +short anything.dev.test A | tr '\n' ' ')   (ожидаем 10.0.0.5)"
echo "lab.test MX        -> $(dig +short lab.test MX | tr '\n' ' ')"
echo "ping myservice.test: $(ping -c1 myservice.test 2>&1 | head -1)"
echo "github.com через upstream: $(curl -sI https://github.com | head -1 | tr -d '\r')   (ожидаем HTTP/2 200)"
