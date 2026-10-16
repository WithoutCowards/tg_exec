//go:build unix

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"tg-exec/internal/config"
	"tg-exec/internal/message"
	"tg-exec/internal/secret"
	"tg-exec/internal/telegram"
)

var stdin = bufio.NewReader(os.Stdin)

func uiLang() string {
	for _, k := range []string{"TG_EXEC_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "ru") {
				return "ru"
			}
			return "en"
		}
	}
	return "en"
}

func tr(ru, en string) string {
	if uiLang() == "ru" {
		return ru
	}
	return en
}

func ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	line, err := stdin.ReadString('\n')
	line = strings.TrimSpace(line)
	if err != nil && line == "" {
		fmt.Println()
		return def
	}
	if line == "" {
		return def
	}
	return line
}

func askYes(prompt string, def bool) bool {
	d := "Y/n"
	if !def {
		d = "y/N"
	}
	v := strings.ToLower(ask(prompt+" ("+d+")", ""))
	if v == "" {
		return def
	}
	return strings.HasPrefix(v, "y") || strings.HasPrefix(v, "д")
}

// askSecret reads a line without echo when stdin is a terminal.
func askSecret(prompt string) string {
	fmt.Printf("%s: ", prompt)
	if isTerminal(os.Stdin) {
		if err := stty("-echo"); err == nil {
			defer func() {
				_ = stty("echo")
				fmt.Println()
			}()
		}
	}
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(line)
}

func stty(arg string) error {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func ok(s string)   { fmt.Println("  ✓ " + s) }
func fail(s string) { fmt.Println("  ✗ " + s) }
func info(s string) { fmt.Println("  · " + s) }

func setupClient(proxy, apiURL, caFile, token string) (*telegram.Client, error) {
	if apiURL == "" {
		apiURL = "https://api.telegram.org"
	}
	return telegram.New(telegram.Options{
		Token: token, APIURL: apiURL, Proxy: proxy, CAFile: caFile,
		Timeout: 15 * time.Second, Retries: 2, Backoff: time.Second, UA: "tg-exec/" + version,
	})
}

func runSetup(cfgPath string, flags map[string]string) int {
	if !isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, "tg-exec --setup is interactive; edit the config file or use TG_EXEC_* variables instead")
		return 2
	}
	path := cfgPath
	if path == "" {
		if os.Geteuid() == 0 {
			path = config.SystemPath
		} else {
			path = config.UserPath(os.Getenv)
		}
	}
	text := config.DefaultFile
	existing := map[string]string{}
	if b, err := os.ReadFile(path); err == nil {
		text = string(b)
		if entries, err := config.Parse(strings.NewReader(text)); err == nil {
			for _, e := range entries {
				existing[strings.TrimPrefix(e.Key, "TG_EXEC_")] = e.Value
			}
		}
	}

	fmt.Println(tr("Настройка tg-exec", "tg-exec setup"), version)
	fmt.Println(tr("Файл конфигурации: ", "Config file: ") + path)
	if os.Geteuid() == 0 && cfgPath == "" {
		fmt.Println(tr("  (общий для всех пользователей; личный — ~/.config/tg-exec/config.conf)",
			"  (system-wide; per-user file is ~/.config/tg-exec/config.conf)"))
	}
	fmt.Println()

	// 1. Network
	fmt.Println(tr("1/4 Сеть", "1/4 Network"))
	proxy := flags["PROXY"]
	if proxy == "" {
		def := existing["PROXY"]
		hint := tr("Прокси (http://, socks5://user:pass@host:port; Enter — ", "Proxy (http://, socks5://user:pass@host:port; Enter — ")
		if env := firstEnv("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"); env != "" && def == "" {
			hint += tr("из окружения: ", "from environment: ") + telegram.RedactURL(env) + ")"
		} else {
			hint += tr("без прокси)", "none)")
		}
		proxy = ask(hint, def)
	}
	if _, desc, err := telegram.ProxyFunc(proxy); err != nil {
		fail(err.Error())
		return 1
	} else {
		info(tr("прокси: ", "proxy: ") + desc)
	}
	apiURL := existing["API_URL"]
	caFile := existing["CA_FILE"]
	if apiURL != "" {
		info("API_URL: " + apiURL)
	}

	// 2. Token
	fmt.Println()
	fmt.Println(tr("2/4 Токен бота (@BotFather → /newbot)", "2/4 Bot token (@BotFather → /newbot)"))
	var token string
	var client *telegram.Client
	keepCmd := existing["TOKEN_CMD"] != "" || existing["TOKEN_FILE"] != ""
	if keepCmd {
		if c, err := config.Load(config.Options{ConfigPath: path, SystemPath: "-", UserPath: "-"}); err == nil {
			if t, err := secret.Resolve(c, nil, nil); err == nil {
				token = t.Value
				info(tr("токен берётся из ", "token comes from ") + t.Source)
			}
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		if token == "" || attempt > 0 {
			p := tr("Токен", "Token")
			cur := existing["TOKEN"]
			if cur != "" && attempt == 0 {
				p += tr(" (Enter — оставить ", " (Enter — keep ") + secret.Mask(cur) + ")"
			}
			t := askSecret(p)
			if t == "" && attempt == 0 {
				t = cur // keep the saved token only on the first prompt
			}
			if t == "" {
				continue
			}
			token = t
			keepCmd = false
		}
		if !secret.LooksValid(token) {
			fail(tr("не похоже на токен вида 123456:ABC…", "does not look like a 123456:ABC… token"))
		}
		c, err := setupClient(proxy, apiURL, caFile, token)
		if err != nil {
			fail(err.Error())
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		me, err := c.GetMe(ctx)
		cancel()
		if err != nil {
			fail(tr("Telegram не принял токен: ", "Telegram rejected the token: ") + err.Error())
			var ae *telegram.APIError
			if !errors.As(err, &ae) {
				info(tr("нет связи с API — проверьте прокси или API_URL", "cannot reach the API — check the proxy or API_URL"))
				return 1
			}
			continue
		}
		ok(tr("бот ", "bot ") + "@" + me.Username)
		client = c
		break
	}
	if client == nil {
		return 1
	}

	// 3. Chat
	fmt.Println()
	fmt.Println(tr("3/4 Куда отправлять", "3/4 Where to send"))
	chat, thread := flags["CHAT_ID"], flags["THREAD_ID"]
	if chat == "" {
		chat, thread = pickChat(client, existing["CHAT_ID"], existing["THREAD_ID"])
	}
	if chat == "" {
		fail(tr("чат не выбран", "no chat selected"))
		return 1
	}

	// 4. Message
	fmt.Println()
	fmt.Println(tr("4/4 Сообщения", "4/4 Messages"))
	host, _ := os.Hostname()
	note := flags["NOTE"]
	if note == "" {
		def := existing["NOTE"]
		if def == "" {
			def = host
		}
		note = ask(tr("Подпись в сообщениях", "Label in messages"), def)
	}
	lang := flags["LANG"]
	if lang == "" {
		def := existing["LANG"]
		if def == "" || def == "auto" {
			def = uiLang()
		}
		for {
			lang = strings.ToLower(ask(tr("Язык сообщений (ru/en)", "Message language (ru/en)"), def))
			if lang == "ru" || lang == "en" {
				break
			}
		}
	}

	set := map[string]string{"CHAT_ID": chat, "THREAD_ID": thread, "NOTE": note, "LANG": lang, "PROXY": proxy}
	if note == host {
		set["NOTE"] = "$(hostname)"
	}
	remove := []string{}
	if !keepCmd {
		set["TOKEN"] = token
		remove = append(remove, "TOKEN_FILE", "TOKEN_CMD")
	}
	newText := config.Update(text, set, remove)
	// Quote() escapes $, but $(hostname) must stay expandable.
	newText = strings.ReplaceAll(newText, `NOTE="\$(hostname)"`, `NOTE="$(hostname)"`)
	if err := config.WriteFile(path, newText); err != nil {
		fail(err.Error())
		return 1
	}
	fmt.Println()
	ok(tr("сохранено: ", "saved: ") + path + " (0600)")

	if !keepCmd && os.Geteuid() == 0 && path == config.SystemPath && secret.SystemdCredsAvailable() {
		if askYes(tr("Зашифровать токен через systemd-creds (расшифровать сможет только root на этом сервере)?",
			"Encrypt the token with systemd-creds (only root on this host can decrypt it)?"), true) {
			if code := sealInto(path, token); code != 0 {
				return code
			}
		}
	}

	// Test message.
	t := telegram.Target{ChatID: chat}
	if n, err := strconv.ParseInt(thread, 10, 64); err == nil {
		t.ThreadID = n
	}
	msg := "🔔 <b>tg-exec</b> · " + message.Esc(strings.ReplaceAll(note, "$(hostname)", host)) + "\n" +
		tr("Настройка завершена, уведомления будут приходить сюда.", "Setup complete: notifications will arrive here.")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := sendWithMigrate(&t, func(t telegram.Target) error { return client.SendHTML(ctx, t, msg, message.Plain(msg)) }); err != nil {
		fail(tr("тестовое сообщение не отправлено: ", "test message failed: ") + err.Error())
		info(tr("бот должен быть участником чата и иметь право писать", "the bot must be a member of the chat and allowed to post"))
		return 1
	}
	if t.ChatID != chat {
		// Re-read: --seal may have rewritten the file after newText was built.
		if b, err := os.ReadFile(path); err == nil {
			_ = config.WriteFile(path, config.Update(string(b), map[string]string{"CHAT_ID": t.ChatID}, nil))
		}
	}
	ok(tr("тестовое сообщение отправлено", "test message sent"))
	fmt.Println()
	fmt.Println(tr("Готово. Примеры:", "Done. Examples:"))
	fmt.Println(`  tg-exec -- apt-get -y upgrade`)
	fmt.Println(`  tg-exec --on-failure "pg_dump mydb | gzip > /backup/db.sql.gz"`)
	fmt.Println(`  0 3 * * * tg-exec -n backup -t 2h -- /usr/local/bin/backup.sh`)
	return 0
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func pickChat(c *telegram.Client, curChat, curThread string) (string, string) {
	fmt.Println(tr(
		"  Напишите боту любое сообщение в личку — или добавьте его в группу/канал и напишите там.",
		"  Send the bot any message in a private chat — or add it to a group/channel and post there."))
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		chats, err := c.RecentChats(ctx)
		cancel()
		if err != nil {
			var ae *telegram.APIError
			if errors.As(err, &ae) && ae.Code == 409 {
				info(tr("у бота включён webhook — список чатов недоступен, введите chat_id вручную",
					"the bot has a webhook — cannot list chats, enter chat_id manually"))
			} else {
				fail(err.Error())
			}
		}
		for i, ch := range chats {
			label := fmt.Sprintf("  %d) %s  %s  [%d]", i+1, ch.Chat.Name(), ch.Chat.Type, ch.Chat.ID)
			if ch.ThreadID > 0 {
				label += fmt.Sprintf(tr(" тема %d", " topic %d"), ch.ThreadID)
			}
			fmt.Println(label)
		}
		hint := tr("Номер из списка, chat_id или @channel (Enter — обновить список)", "Number, chat_id or @channel (Enter — refresh)")
		def := ""
		if curChat != "" {
			hint = tr("Номер из списка, chat_id или @channel", "Number, chat_id or @channel")
			def = curChat
		}
		v := ask(hint, def)
		if v == "" {
			continue
		}
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= len(chats) {
			ch := chats[n-1]
			th := ""
			if ch.ThreadID > 0 {
				th = strconv.FormatInt(ch.ThreadID, 10)
			}
			return strconv.FormatInt(ch.Chat.ID, 10), th
		}
		if v == curChat {
			return v, curThread
		}
		if strings.HasPrefix(v, "@") || isInt(v) {
			for {
				th := ask(tr("ID темы форума (Enter — нет)", "Forum topic id (Enter — none)"), "")
				if th == "" || isInt(th) {
					return v, th
				}
				fail(tr("нужно число", "a number is expected"))
			}
		}
		fail(tr("не понял, попробуйте ещё раз", "not understood, try again"))
	}
}

func isInt(s string) bool {
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}

// runSeal encrypts the token from the config with systemd-creds.
func runSeal(cfgPath string) int {
	path := cfgPath
	if path == "" {
		path = config.SystemPath
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "tg-exec --seal: run as root (the sealed token is readable only by root)")
		return 2
	}
	if !secret.SystemdCredsAvailable() {
		fmt.Fprintln(os.Stderr, "tg-exec --seal: systemd-creds not found (systemd 250+); use TOKEN_FILE or TOKEN_CMD instead")
		return 2
	}
	var token string
	if !isTerminal(os.Stdin) {
		b, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		token = strings.TrimSpace(b)
	}
	if token == "" {
		if c, err := config.Load(config.Options{ConfigPath: path, SystemPath: "-", UserPath: "-"}); err == nil {
			if t, err := secret.Resolve(c, func(string) string { return "" }, nil); err == nil {
				token = t.Value
			}
		}
	}
	if token == "" && isTerminal(os.Stdin) {
		token = askSecret(tr("Токен бота", "Bot token"))
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "tg-exec --seal: no token (put it in the config, pipe it to stdin or type it)")
		return 2
	}
	return sealInto(path, token)
}

func sealInto(path, token string) int {
	if err := secret.Seal(token, secret.SealedPath); err != nil {
		fail(err.Error())
		return 1
	}
	out, err := exec.Command("/bin/sh", "-c", secret.SealedCmd(secret.SealedPath)).Output()
	if err != nil || strings.TrimSpace(string(out)) != token {
		fail(tr("проверка расшифровки не прошла, конфиг не изменён", "decrypt check failed, config left unchanged"))
		return 1
	}
	text := config.DefaultFile
	if b, err := os.ReadFile(path); err == nil {
		text = string(b)
	}
	text = config.Update(text, map[string]string{"TOKEN_CMD": secret.SealedCmd(secret.SealedPath)}, []string{"TOKEN", "TOKEN_FILE"})
	if err := config.WriteFile(path, text); err != nil {
		fail(err.Error())
		return 1
	}
	ok(tr("токен зашифрован: ", "token sealed: ") + secret.SealedPath)
	ok(path + ": TOKEN_CMD=" + secret.SealedCmd(secret.SealedPath))
	info(tr("открытого токена в конфиге больше нет; не забудьте про старые бэкапы конфига",
		"the plain token is gone from the config; mind old backups of it"))
	return 0
}

// runCheck prints the effective configuration and tests delivery.
func runCheck(cfgPath string, flags map[string]string) int {
	fmt.Println("tg-exec", version)
	cfg, err := config.Load(config.Options{ConfigPath: cfgPath, Flags: flags, SystemPath: systemConfig})
	if err != nil {
		fail(err.Error())
		return 1
	}
	fmt.Println(tr("Файлы:", "Files:"))
	for _, f := range cfg.Files {
		switch {
		case f.Loaded:
			ok(fmt.Sprintf("%s (%04o)", f.Path, f.Mode))
		case errors.Is(f.Err, os.ErrNotExist):
			info(f.Path + tr(" — нет", " — not found"))
		default:
			fail(f.Path + ": " + f.Err.Error())
		}
	}
	for _, w := range cfg.Warnings {
		fail(w)
	}
	bad := false
	fmt.Println(tr("Настройки:", "Settings:"))
	tok, err := secret.Resolve(cfg, nil, func(w string) { fail(w) })
	if err != nil {
		fail(err.Error())
		bad = true
	} else {
		ok(tr("токен ", "token ") + secret.Mask(tok.Value) + "  ← " + tok.Source)
		if !secret.LooksValid(tok.Value) {
			fail(tr("токен не похож на 123456:ABC…", "token does not look like 123456:ABC…"))
		}
	}
	if cfg.ChatID == "" {
		fail(tr("CHAT_ID не задан", "CHAT_ID is not set"))
		bad = true
	} else {
		s := "chat " + cfg.ChatID
		if cfg.ThreadID > 0 {
			s += fmt.Sprintf(" / topic %d", cfg.ThreadID)
		}
		ok(s + "  ← " + cfg.Raw["CHAT_ID"].Source)
	}
	_, pdesc, perr := telegram.ProxyFunc(cfg.Proxy)
	if perr != nil {
		fail(perr.Error())
		bad = true
	} else {
		if cfg.Proxy == "" {
			if env := firstEnv("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"); env != "" {
				pdesc += ": " + telegram.RedactURL(env)
			} else {
				pdesc += tr(": не задан", ": not set")
			}
		}
		info("proxy: " + pdesc)
	}
	info("api: " + cfg.APIURL)
	if cfg.CAFile != "" {
		info("ca: " + cfg.CAFile)
	}
	info(fmt.Sprintf("notify=%s output=%s attach=%s lang=%s tz=%s timeout=%v", cfg.Notify, cfg.Output, cfg.Attach,
		cfg.Lang, cfg.Location, cfg.Timeout))
	if bad {
		return 1
	}

	fmt.Println(tr("Связь:", "Connectivity:"))
	client, err := newClient(cfg, tok.Value, func(string, ...any) {})
	if err != nil {
		fail(err.Error())
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	me, err := client.GetMe(ctx)
	if err != nil {
		fail("getMe: " + err.Error())
		return 1
	}
	ok("bot @" + me.Username)
	host, _ := os.Hostname()
	note := cfg.Note
	if note == "" {
		note = host
	}
	msg := "🔔 <b>tg-exec --check</b> · " + message.Esc(note) + "\n" +
		tr("Проверка связи: уведомления работают.", "Connectivity check: notifications work.")
	t := telegram.Target{ChatID: cfg.ChatID, ThreadID: cfg.ThreadID, Silent: true}
	if err := sendWithMigrate(&t, func(t telegram.Target) error { return client.SendHTML(ctx, t, msg, message.Plain(msg)) }); err != nil {
		fail("sendMessage: " + err.Error())
		return 1
	}
	ok(tr("тестовое сообщение доставлено", "test message delivered"))
	return 0
}
