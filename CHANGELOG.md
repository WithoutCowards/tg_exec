## 2.0.0

### New
* `--setup` — interactive setup: proxy, token check via getMe, chat discovery from recent messages (private chats, groups, channels, forum topics), label, language, test message; config written with mode 0600.
* `--check` — effective settings with the source of each value, token check, silent test message.
* `--seal` — encrypt the token with systemd-creds (host key / TPM2) into `/etc/tg-exec/token.cred`; the config gets a `TOKEN_CMD` instead of the plain token.
* Token sources: `TOKEN_FILE`, `TOKEN_CMD` (like aws-cli `credential_process`), systemd credential `tg-exec-token` (`LoadCredentialEncrypted=`). Warning when a config with a token is readable by group/others.
* Proxy: `PROXY` = `http://`, `https://`, `socks5://`, `socks5h://` with optional auth, or `none`; `HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` still work.
* Closed networks: `API_URL` (own Bot API server or reverse proxy) and `CA_FILE` (extra PEM CA).
* Full output as a `.log` file when it does not fit into the message (`ATTACH=auto|always|never`, up to 45 MB).
* `--timeout` / `TIMEOUT`: SIGTERM, then SIGKILL after 10 s, exit code 124.
* `NOTIFY=failure` / `--on-failure`, `OUTPUT=always|failure|never`, `SILENT_SUCCESS`, `THREAD_ID` (forum topics), `LANG=ru|en|auto`.
* Command-line options for every setting, `--dry-run`, `--version`, `--help`.
* New message layout: status, label, command, start → end with time zone, human-readable duration, host, output with line counts.
* Messages are re-sent as plain text if Telegram rejects the markup; group → supergroup migration is followed automatically.
* Packages: deb, rpm, apk for amd64/arm64/armv7; tarballs for Linux (incl. 386) and macOS; `install.sh` with SHA-256 verification; releases built by GitHub Actions.

### Fixed
* The user config (`~/.config/tg-exec/config.conf`) now overrides `/etc/tg-exec/config.conf` (it was the other way round).
* `HTTP_TIMEOUT`, `RETRIES`, `BACKOFF`, `STRICT`, `DEBUG` are read from config files, not only from the environment.
* Long output could break the message: the tail is now cut by UTF-16 length on a line boundary before HTML escaping, so entities and Cyrillic characters are never split, and the command and header count towards the 4096 limit.
* Arguments with spaces and quotes are preserved (direct exec instead of joining into `bash -c`).
* Exponential backoff actually doubles, no pause after the last attempt, `retry_after` of HTTP 429 is respected, 4xx errors are not retried, the last error is reported instead of "retries exceeded". The token never appears in error messages.
* Exit code is 128+N when the command is killed by a signal (was -1); SIGTERM/SIGHUP are forwarded to the command.
* Only the output tail is kept in memory (64 KiB ring buffer) instead of the whole output.
* ANSI colours and carriage-return progress bars are cleaned up in the message.
* `#` inside a value (`NOTE=build#5`) is no longer treated as a comment; quoted values support `\"` escapes.
* Missing token or chat no longer prevents the command from running.

### Changed
* Several unquoted arguments are executed directly; a single argument is run via `bash -c` as before; `-c` restores the old joining behaviour.
* `STRICT=1` returns 70 only if the command itself succeeded; a failing command keeps its exit code.
* `RETRIES` is the total number of attempts (default 3, as before).
* `PARSE_MODE` is ignored: messages are always HTML with a plain-text fallback.
* Packaging moved from debhelper to nfpm.

## 1.0.3
* Added smart truncation for long command outputs (keeps last lines)
* Prevented Telegram 400 errors for messages >4096 chars
* Improved reliability for large CI logs and cron jobs

## 1.0.2
* Fixed: ALWAYS=0 now sends minimal message without output
* Fixed: NOTE="$(hostname)" now correctly resolves hostname
* Added: DEBUG=1 environment variable to show debug info
* Cleaned up internal logging and message logic

## 1.0.1
* Added DEBUG=1 flag to enable debug logs
* Fixed ALWAYS=1 behavior to include command output
* Improved config parser to ignore inline comments

## 1.0.0
- Initial Go release
