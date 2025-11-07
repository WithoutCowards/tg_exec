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