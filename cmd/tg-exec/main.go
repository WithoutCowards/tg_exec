package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Token     string
	ChatID    string
	Note      string
	Always    string
	ParseMode string
	Timeout   time.Duration
	Retries   int
	Backoff   time.Duration
	Strict    bool
	Timezone  string
	Debug     bool
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: tg-exec <command ...>")
		os.Exit(2)
	}

	cfg := loadConfig()
	if cfg.Token == "" || cfg.ChatID == "" {
		fmt.Fprintln(os.Stderr, "tg-exec: TOKEN/CHAT_ID not set (config or env)")
		os.Exit(2)
	}

	loc := resolveLocation(cfg.Timezone)
	cmdLine := strings.Join(os.Args[1:], " ")
	start := time.Now().In(loc)

	var buf bytes.Buffer
	cmd := exec.Command("bash", "-c", cmdLine)
	cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
	err := cmd.Run()
	rc := exitCode(err)
	end := time.Now().In(loc)
	duration := int(end.Sub(start).Seconds())

	esc := func(s string) string {
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
		return r.Replace(s)
	}
	escCmd := esc(cmdLine)
	escNote := esc(cfg.Note)
	escOut := esc(buf.String())

	if len(escOut) > 3500 {
		escOut = tailString(escOut, 3500)
	}

	tfmt := "2006-01-02 15:04:05 MST"
	var msg string
	if rc != 0 {
		msg = fmt.Sprintf("❌ <b>Command failed</b>\nCommand: <pre>%s</pre>\n", escCmd)
	} else {
		msg = fmt.Sprintf("✅ <b>Command completed successfully</b>\nCommand: <pre>%s</pre>\n", escCmd)
	}
	if escNote != "" {
		msg += fmt.Sprintf("Note: <b>%s</b>\n", escNote)
	}
	msg += fmt.Sprintf("Start time: %s\nEnd time: %s\nDuration: %d sec.\nExit code: %d",
		start.Format(tfmt), end.Format(tfmt), duration, rc)

	if rc != 0 || cfg.Always == "1" {
		msg += fmt.Sprintf("\nOutput:\n<pre>%s</pre>", escOut)
	}

	debug(cfg, "Sending Telegram message to %s", cfg.ChatID)
	if err := sendTelegram(cfg, msg); err != nil {
		fmt.Fprintf(os.Stderr, "tg-exec: failed to send Telegram message: %v\n", err)
		if cfg.Strict {
			os.Exit(70)
		}
	}
	os.Exit(rc)
}

func tailString(s string, maxChars int) string {
	if len(s) <= maxChars {
		return s
	}
	s = s[len(s)-maxChars:]
	lines := strings.SplitN(s, "\n", 2)
	if len(lines) == 2 {
		s = lines[1]
	}
	return fmt.Sprintf("[output truncated, showing last %d chars]\n%s", maxChars, s)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			return ws.ExitStatus()
		}
	}
	return 1
}

func resolveLocation(tz string) *time.Location {
	if tz == "" {
		tz = getenv("TZ", "")
	}
	if tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			return loc
		}
	}
	if time.Local != nil {
		return time.Local
	}
	return time.UTC
}

func loadConfig() Config {
	kv := map[string]string{}
	userCfg := filepath.Join(os.Getenv("HOME"), ".config", "tg-exec", "config.conf")
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		userCfg = filepath.Join(xdg, "tg-exec", "config.conf")
	}
	loadKV(userCfg, kv)
	loadKV("/etc/tg-exec/config.conf", kv)

	get := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		if v := kv[k]; v != "" {
			return v
		}
		return def
	}

	return Config{
		Token:     firstNonEmpty(get("TELEGRAM_BOT_TOKEN", ""), kv["TOKEN"]),
		ChatID:    firstNonEmpty(get("TELEGRAM_CHAT_ID", ""), kv["CHAT_ID"]),
		Note:      firstNonEmpty(get("TG_NOTE", ""), kv["NOTE"]),
		Always:    firstNonEmpty(get("TG_EXEC_ALWAYS", kv["ALWAYS"]), "1"),
		ParseMode: firstNonEmpty(get("TG_EXEC_PARSE_MODE", ""), firstNonEmpty(kv["PARSE_MODE"], "HTML")),
		Timeout:   time.Duration(parseInt(firstNonEmpty(os.Getenv("TG_EXEC_HTTP_TIMEOUT"), "10"))) * time.Second,
		Retries:   parseInt(firstNonEmpty(os.Getenv("TG_EXEC_RETRIES"), "3")),
		Backoff:   time.Duration(parseInt(firstNonEmpty(os.Getenv("TG_EXEC_BACKOFF"), "2"))) * time.Second,
		Strict:    firstNonEmpty(os.Getenv("TG_EXEC_STRICT"), "0") == "1",
		Timezone:  firstNonEmpty(os.Getenv("TG_EXEC_TZ"), kv["TIMEZONE"]),
		Debug:     firstNonEmpty(os.Getenv("DEBUG"), "") == "1",
	}
}

func loadKV(path string, kv map[string]string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i != -1 {
			line = strings.TrimSpace(line[:i])
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		v = strings.TrimSpace(v)
		if strings.Contains(v, "$(hostname)") {
			host, _ := os.Hostname()
			v = strings.ReplaceAll(v, "$(hostname)", host)
		}
		kv[k] = v
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func debug(cfg Config, format string, args ...interface{}) {
	if cfg.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}

func sendTelegram(cfg Config, text string) error {
	form := url.Values{}
	form.Set("chat_id", cfg.ChatID)
	form.Set("text", text)
	form.Set("parse_mode", cfg.ParseMode)
	client := &http.Client{}
	for i := 0; i < cfg.Retries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		req, _ := http.NewRequestWithContext(ctx, "POST",
			"https://api.telegram.org/bot"+cfg.Token+"/sendMessage", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && bytes.Contains(body, []byte(`"ok":true`)) {
				cancel()
				return nil
			}
			err = fmt.Errorf("http %d: %s", resp.StatusCode, string(body))
		}
		cancel()
		time.Sleep(cfg.Backoff)
	}
	return fmt.Errorf("retries exceeded")
}