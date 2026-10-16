# tg-exec

**Запустил команду — получил итог в Telegram.** Код выхода, длительность, хост, хвост вывода, а если вывод не влез — полный лог файлом. Для cron, systemd-таймеров, бэкапов, деплоев и CI.

Часть набора инструментов [RunStack](https://runstack.ru/p/tg-exec) · *Нет проблем. Есть задачи.*

```
❌ Ошибка · код 2 · backup-db01
  pg_dump app | gzip > /backup/app.sql.gz
🕒 2026-10-16 03:00:00 → 03:02:03 MSK · 2 мин 3 с
💬 Вывод:
  pg_dump: error: connection to server on socket "/run/postgresql/.s.PGSQL.5432" failed
```

- один статический бинарник без зависимостей: Linux amd64/arm64/armv7/386, macOS;
- код выхода команды пробрасывается как есть — обёртка не ломает cron и CI;
- кривые настройки уведомлений **не мешают** самой задаче: команда выполнится, ошибка уйдёт в stderr;
- прокси HTTP/HTTPS/SOCKS5, свой адрес Bot API и свой CA — для закрытого контура;
- токен из конфига, файла, команды (`vault`, `pass`, …) или systemd-creds с TPM2;
- мастер настройки сам находит chat_id, включая темы форумов.

[English version below](#english)

## Установка

**Скрипт** — сам выберет deb, rpm, apk или бинарник и проверит SHA-256:

```sh
curl -fsSL https://github.com/WithoutCowards/tg_exec/releases/latest/download/install.sh | sudo sh
```

**Пакеты** из [релизов](https://github.com/WithoutCowards/tg_exec/releases/latest):

```sh
# Debian / Ubuntu
curl -fsSLO https://github.com/WithoutCowards/tg_exec/releases/latest/download/tg-exec_amd64.deb
sudo apt install ./tg-exec_amd64.deb
# RHEL / AlmaLinux / Rocky / Fedora
sudo dnf install https://github.com/WithoutCowards/tg_exec/releases/latest/download/tg-exec.x86_64.rpm
# Alpine
wget https://github.com/WithoutCowards/tg_exec/releases/latest/download/tg-exec_x86_64.apk
sudo apk add --allow-untrusted tg-exec_x86_64.apk
```

Для arm64 — `tg-exec_arm64.deb`, `tg-exec.aarch64.rpm`, `tg-exec_aarch64.apk`; для Raspberry Pi 32-bit — `armhf`/`armv7hl`/`armv7`. Бинарники без пакетов: `tg-exec_linux_<arch>.tar.gz`, `tg-exec_darwin_<arch>.tar.gz`. Контрольные суммы — `SHA256SUMS`.

## Быстрый старт

```sh
sudo tg-exec --setup     # токен → выбор чата → подпись → тестовое сообщение
tg-exec --check          # что откуда взялось + тест доставки
```

Бота создаёт [@BotFather](https://t.me/BotFather) (`/newbot`). Мастер попросит написать боту любое сообщение и покажет список чатов, откуда оно пришло: личка, группа, канал, тема форума. От root настройки пишутся в `/etc/tg-exec/config.conf`, от пользователя — в `~/.config/tg-exec/config.conf`.

## Использование

```sh
tg-exec -- apt-get -y upgrade                         # программа с аргументами, кавычки не теряются
tg-exec "pg_dump app | gzip > /backup/app.sql.gz"     # одна строка → bash -c (пайпы, &&, >)
tg-exec --on-failure -n nightly-backup -- /opt/backup.sh   # писать только при ошибке
tg-exec -t 2h -- rsync -a /data/ backup:/data/        # таймаут: SIGTERM, через 10 с SIGKILL, код 124
tg-exec --silent --output failure -- make deploy      # успех без звука, вывод только при ошибке
```

**cron:**

```cron
0 3 * * *  root  tg-exec -n backup -t 3h -- /usr/local/bin/backup.sh
```

**systemd** (токен расшифровывает сам systemd, процесс видит только файл в tmpfs, доступный этой службе):

```ini
[Service]
ExecStart=/usr/bin/tg-exec -n certbot -- certbot renew
LoadCredentialEncrypted=tg-exec-token:/etc/tg-exec/token.cred
```

**CI (GitLab, GitHub Actions):**

```sh
TELEGRAM_BOT_TOKEN=$TG_TOKEN TELEGRAM_CHAT_ID=-100123 tg-exec -n "deploy $CI_COMMIT_SHORT_SHA" -- ./deploy.sh
```

### Опции

| Опция | Что делает |
|---|---|
| `-n, --note TEXT` | подпись в сообщении (по умолчанию имя хоста) |
| `--chat ID`, `--thread ID` | куда отправить; тема форума |
| `--notify always\|failure`, `--on-failure` | когда отправлять |
| `--output always\|failure\|never` | когда прикладывать вывод |
| `--attach auto\|always\|never` | полный лог файлом (`auto` — если не влез в сообщение, до 45 МБ) |
| `--silent` | успешные запуски — без звука |
| `-t, --timeout 30m` | остановить команду по таймауту, код 124 |
| `--lang ru\|en` | язык сообщений |
| `--proxy URL` | `http://`, `https://`, `socks5://`, `socks5h://user:pass@host:port` или `none` |
| `--config FILE` | дополнительный конфиг с наивысшим приоритетом среди файлов |
| `-c, --shell` | склеить аргументы и выполнить через shell |
| `--dry-run` | показать сообщение, не отправляя |
| `--strict` | код 70, если задача прошла, а уведомление не ушло |
| `--setup`, `--check`, `--seal` | мастер, диагностика, шифрование токена |

## Настройки

Приоритет (снизу вверх): `/etc/tg-exec/config.conf` → `~/.config/tg-exec/config.conf` → `--config` → переменные `TG_EXEC_<KEY>` → флаги. Формат — `KEY="value"`, `$(hostname)` подставляется. Полный шаблон с комментариями ставится пакетом в `/etc/tg-exec/config.conf`.

| Ключ | По умолчанию | Описание |
|---|---|---|
| `TOKEN` / `TOKEN_FILE` / `TOKEN_CMD` | — | токен, файл с токеном или команда, которая его печатает |
| `CHAT_ID`, `THREAD_ID` | — | чат (`-100…` для групп, `@channel`) и тема форума |
| `NOTE` | имя хоста | подпись |
| `NOTIFY` | `always` | `always` / `failure` |
| `OUTPUT` | `always` | `always` / `failure` / `never` |
| `ATTACH` | `auto` | `auto` / `always` / `never` |
| `SILENT_SUCCESS` | `0` | успех без звука |
| `LANG` | `auto` | `ru` / `en` / по локали системы |
| `TIMEZONE` | системный | например `Europe/Moscow` |
| `TIMEOUT` | — | `90s`, `30m`, `2h` |
| `SHELL` | `bash`, иначе `/bin/sh` | для режима «одна строка» |
| `PROXY` | из `HTTPS_PROXY`/`ALL_PROXY` | `http(s)://`, `socks5(h)://`, `none` |
| `API_URL` | `https://api.telegram.org` | свой [Bot API server](https://github.com/tdlib/telegram-bot-api) или reverse proxy |
| `CA_FILE` | — | дополнительный PEM CA (корпоративный TLS-прокси, внутренний API) |
| `HTTP_TIMEOUT`, `RETRIES`, `BACKOFF` | `15`, `3`, `2` | таймаут запроса, число попыток, первая пауза (удваивается; `retry_after` от 429 учитывается) |
| `STRICT`, `DEBUG` | `0` | см. `--strict`, `--debug` |

Совместимость с 1.x: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TG_NOTE`, `TG_EXEC_TZ`, `DEBUG`, `ALWAYS=1|0` и ключи с префиксом `TG_EXEC_` в файлах работают как раньше.

## Где хранить токен

Честно о модели угроз: если программа читает токен без пароля (а в cron иначе нельзя), его прочитает и тот, кто получил права этой учётки. Шифрование спасает от утёкших бэкапов, образов дисков и соседних пользователей, но не от root на живом сервере. Поэтому:

1. **Отдельный бот только для уведомлений** — утечка не затронет ничего, кроме этого канала.
2. **Права 0600.** tg-exec предупреждает, если конфиг с токеном читается группой или всеми.
3. **`sudo tg-exec --seal`** — шифрует токен через `systemd-creds` (ключ хоста и TPM2, если есть) в `/etc/tg-exec/token.cred`, убирает открытый токен из конфига и прописывает `TOKEN_CMD`. Копия диска или бэкапа без этого сервера бесполезна.
4. **`TOKEN_CMD`** — как `credential_process` в aws-cli: токен отдаёт внешний менеджер секретов.

   ```sh
   TOKEN_CMD="vault kv get -field=token secret/tg-exec"
   TOKEN_CMD="pass show infra/tg-exec"
   ```

5. **systemd `LoadCredentialEncrypted=`** — токен видит только конкретная служба.

## Закрытый контур и прокси

- `PROXY=socks5h://user:pass@proxy:1080` — DNS резолвится на стороне прокси; `http://`/`https://` — через CONNECT. Без `PROXY` действуют стандартные `HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` (удобно, но в cron их обычно нет — лучше прописать в конфиг).
- `API_URL=https://tg-gw.corp.local` — свой [telegram-bot-api](https://github.com/tdlib/telegram-bot-api) или nginx, проксирующий `api.telegram.org`; `CA_FILE` — если у шлюза внутренний сертификат.
- Ничего не нужно, кроме доступа к выбранному адресу API: ни внешних сервисов, ни зависимостей.

## Коды выхода

Код команды; `128+N`, если её убил сигнал N; `124` — таймаут; `127`/`126` — не нашлась / нет прав на запуск; `70` — только с `--strict`, если успешный запуск не удалось сообщить; `2` — ошибка в аргументах tg-exec.

## Что изменилось в 2.0

Исправлено: пользовательский конфиг теперь главнее системного; `HTTP_TIMEOUT`/`RETRIES`/`BACKOFF`/`STRICT`/`DEBUG` читаются из файла; длинный вывод больше не ломает сообщение (обрезка по UTF-16 и границе строки, без разрыва HTML-сущностей); аргументы с пробелами и кавычками не теряются; пауза между попытками удваивается. Подробно — [CHANGELOG](CHANGELOG.md).

Два поведения изменились: несколько аргументов без кавычек выполняются напрямую, без `bash -c` (одна строка в кавычках — как раньше, через shell; старое поведение — флаг `-c`), а `STRICT=1` при упавшей команде возвращает код команды, а не 70.

## Сборка

```sh
go test ./...
CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=dev" -o tg-exec ./cmd/tg-exec
VERSION=2.0.0 scripts/dist.sh        # все архивы и пакеты (нужен nfpm)
```

Релиз собирает GitHub Actions по тегу `v*`.

## Лицензия

[CC BY-NC 4.0](LICENSE) — бесплатно для личного и внутреннего использования.

---

## English

**tg-exec runs a command and reports the result to Telegram**: status, exit code, duration, host and the output tail; the full log is attached as a file when it does not fit. The command's exit code is passed through, and broken notification settings never stop the job itself.

**Install:**

```sh
curl -fsSL https://github.com/WithoutCowards/tg_exec/releases/latest/download/install.sh | sudo sh
sudo tg-exec --setup   # token → pick a chat from recent messages → test message
```

Packages: `tg-exec_<arch>.deb`, `tg-exec.<arch>.rpm`, `tg-exec_<arch>.apk`, tarballs for Linux and macOS, `SHA256SUMS`.

**Use:**

```sh
tg-exec -- apt-get -y upgrade                        # direct exec, arguments kept intact
tg-exec "pg_dump app | gzip > /backup/app.sql.gz"    # one string → bash -c
tg-exec --on-failure -t 2h -n backup -- /opt/backup.sh
```

**Config** — `/etc/tg-exec/config.conf` < `~/.config/tg-exec/config.conf` < `--config` < `TG_EXEC_<KEY>` < flags. Keys: `TOKEN`/`TOKEN_FILE`/`TOKEN_CMD`, `CHAT_ID`, `THREAD_ID`, `NOTE`, `NOTIFY`, `OUTPUT`, `ATTACH`, `SILENT_SUCCESS`, `LANG`, `TIMEZONE`, `TIMEOUT`, `SHELL`, `PROXY`, `API_URL`, `CA_FILE`, `HTTP_TIMEOUT`, `RETRIES`, `BACKOFF`, `STRICT`, `DEBUG`. See `man tg-exec`.

**Token storage:** use a dedicated bot, keep the config at 0600, and on servers run `sudo tg-exec --seal` (systemd-creds, TPM2 when available) or use `TOKEN_CMD` like aws-cli `credential_process` (`vault`, `pass`, …). Encryption protects disks and backups, not a compromised live root — no tool can promise that for a token read without a password.

**Closed networks:** `PROXY` supports `http`, `https`, `socks5`, `socks5h` (with auth); `API_URL` points to your own Bot API server or reverse proxy; `CA_FILE` adds an internal CA.

License: [CC BY-NC 4.0](LICENSE). Part of [RunStack](https://runstack.pro).
