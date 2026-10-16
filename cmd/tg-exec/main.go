//go:build unix

// tg-exec runs a command and reports the result to Telegram.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf8"

	"tg-exec/internal/config"
	"tg-exec/internal/message"
	"tg-exec/internal/runner"
	"tg-exec/internal/secret"
	"tg-exec/internal/telegram"
)

var version = "dev"

// systemConfig is overridden in tests so the host's /etc config never leaks in.
var systemConfig = config.SystemPath

// Telegram accepts documents up to 50 MB from bots on the public API.
const spoolLimit int64 = 45 << 20

const usageText = `tg-exec %s — run a command and report the result to Telegram

Usage:
  tg-exec [options] -- program [args...]   run directly, arguments kept as is
  tg-exec [options] program [args...]      same, without "--"
  tg-exec [options] "command line"         one argument: run via bash -c (pipes, &&, >)
  tg-exec [options] -c program args...     join arguments and run via bash -c

Setup:
  --setup            interactive setup: token, chat, proxy, test message
  --check            show effective settings, check token and send a test message
  --seal             encrypt the token with systemd-creds (root; TPM2 if present)
  --version          print version

Options (override config and environment):
  -n, --note TEXT        label in the message (default: host name)
  --chat ID              chat id
  --thread ID            forum topic id
  --notify MODE          always | failure — when to send
  --on-failure           shortcut for --notify failure
  --output MODE          always | failure | never — when to include output
  --attach MODE          auto | always | never — full log as a file
  --silent               no sound for successful runs
  -t, --timeout DUR      stop the command after 90s, 30m, 2h… (exit 124)
  --lang ru|en           message language
  --proxy URL            http://, https://, socks5://, socks5h:// or none
  --config FILE          extra config file (highest file priority)
  --dry-run              print the message instead of sending it
  --strict               exit 70 if the notification could not be sent
  --debug                verbose diagnostics on stderr

Config: /etc/tg-exec/config.conf, ~/.config/tg-exec/config.conf, --config;
environment TG_EXEC_<KEY> overrides files. See man tg-exec.
The command's exit code is passed through.
`

type opts struct {
	note, chat, thread, notify, output, attach, timeout, lang, proxy, cfgPath string
	onFailure, silent, dryRun, strict, debug, shell                           bool
	setup, check, seal, version                                               bool
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	var o opts
	fs := flag.NewFlagSet("tg-exec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	str := func(p *string, names ...string) {
		for _, n := range names {
			fs.StringVar(p, n, "", "")
		}
	}
	boolean := func(p *bool, names ...string) {
		for _, n := range names {
			fs.BoolVar(p, n, false, "")
		}
	}
	str(&o.note, "n", "note")
	str(&o.chat, "chat")
	str(&o.thread, "thread")
	str(&o.notify, "notify")
	str(&o.output, "output")
	str(&o.attach, "attach")
	str(&o.timeout, "timeout", "t")
	str(&o.lang, "lang")
	str(&o.proxy, "proxy")
	str(&o.cfgPath, "config")
	boolean(&o.onFailure, "on-failure")
	boolean(&o.silent, "silent")
	boolean(&o.dryRun, "dry-run")
	boolean(&o.strict, "strict")
	boolean(&o.debug, "debug")
	boolean(&o.shell, "c", "shell")
	boolean(&o.setup, "setup")
	boolean(&o.check, "check")
	boolean(&o.seal, "seal")
	boolean(&o.version, "version", "V")
	help := false
	boolean(&help, "h", "help")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "tg-exec: %v\nRun tg-exec --help for usage.\n", err)
		return 2
	}
	rest := fs.Args()
	consumed := len(args) - len(rest)
	dashdash := consumed > 0 && args[consumed-1] == "--"

	switch {
	case help:
		fmt.Printf(usageText, version)
		return 0
	case o.version:
		fmt.Println("tg-exec", version)
		return 0
	}

	flags := map[string]string{}
	set := func(k, v string) {
		if v != "" {
			flags[k] = v
		}
	}
	set("NOTE", o.note)
	set("CHAT_ID", o.chat)
	set("THREAD_ID", o.thread)
	set("NOTIFY", o.notify)
	if o.onFailure {
		flags["NOTIFY"] = "failure"
	}
	set("OUTPUT", o.output)
	set("ATTACH", o.attach)
	set("TIMEOUT", o.timeout)
	set("LANG", o.lang)
	set("PROXY", o.proxy)
	if o.silent {
		flags["SILENT_SUCCESS"] = "1"
	}
	if o.strict {
		flags["STRICT"] = "1"
	}
	if o.debug {
		flags["DEBUG"] = "1"
	}

	switch {
	case o.setup:
		return runSetup(o.cfgPath, flags)
	case o.check:
		return runCheck(o.cfgPath, flags)
	case o.seal:
		return runSeal(o.cfgPath)
	}

	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, usageText, version)
		return 2
	}
	return execute(o, flags, rest, dashdash)
}

func execute(o opts, flags map[string]string, rest []string, dashdash bool) int {
	tty := isTerminal(os.Stderr)
	var notifyErr error

	cfg, err := config.Load(config.Options{ConfigPath: o.cfgPath, Flags: flags, SystemPath: systemConfig})
	if err != nil {
		notifyErr = err
		cfg = nil
	}
	debugf := func(format string, args ...any) {
		if cfg != nil && cfg.Debug {
			fmt.Fprintf(os.Stderr, "[tg-exec] "+format+"\n", args...)
		}
	}
	warn := func(w string) {
		if tty || (cfg != nil && cfg.Debug) {
			fmt.Fprintln(os.Stderr, "tg-exec: warning:", w)
		}
	}
	if cfg != nil {
		for _, w := range cfg.Warnings {
			warn(w)
		}
	}

	var tok secret.Token
	if notifyErr == nil {
		tok, err = secret.Resolve(cfg, nil, warn)
		if err != nil && !o.dryRun {
			notifyErr = err
		}
		if notifyErr == nil && cfg.ChatID == "" && !o.dryRun {
			notifyErr = errors.New("chat is not set (CHAT_ID or --chat); run: tg-exec --setup")
		}
	}
	if notifyErr != nil {
		// Never block the job itself because of notification settings.
		fmt.Fprintf(os.Stderr, "tg-exec: notification disabled: %v\n", notifyErr)
	}

	spec := runner.Spec{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	var display string
	if !dashdash && (o.shell || len(rest) == 1) {
		spec.Command = strings.Join(rest, " ")
		spec.Shell = pickShell(cfg)
		display = spec.Command
	} else {
		spec.Args = rest
		display = runner.ShellQuote(rest)
	}
	if cfg != nil {
		spec.Timeout = cfg.Timeout
		if notifyErr == nil && cfg.Attach != "never" && cfg.Output != "never" {
			spec.SpoolLimit = spoolLimit
		}
	}
	debugf("run: %s (shell=%q, timeout=%v)", display, spec.Shell, spec.Timeout)

	res := runner.Run(spec)
	if res.SpoolPath != "" {
		defer os.Remove(res.SpoolPath)
	}
	if res.StartErr != nil {
		fmt.Fprintf(os.Stderr, "tg-exec: %v\n", res.StartErr)
	}
	code := res.ExitCode
	failCode := func() int {
		if cfg != nil && cfg.Strict && code == 0 {
			return 70
		}
		return code
	}
	if notifyErr != nil {
		return failCode()
	}
	if cfg.Notify == "failure" && !res.Failed() {
		debugf("success and NOTIFY=failure: not sending")
		return code
	}

	host, _ := os.Hostname()
	note := cfg.Note
	if note == "" {
		note = host
	}
	include := cfg.Output == "always" || (cfg.Output == "failure" && res.Failed())
	rep := message.Report{
		Command: display, Note: note, Host: host,
		Start: res.Start, End: res.End, ExitCode: code, Signal: res.Signal,
		TimedOut: res.TimedOut, Timeout: cfg.Timeout,
		IncludeOutput: include, Output: res.Tail,
		OutputPartial: res.TotalBytes > int64(len(res.Tail)),
		TotalLines:    res.TotalLines, TotalBytes: res.TotalBytes,
		Lang: cfg.Lang, Location: cfg.Location,
	}
	if res.StartErr != nil {
		rep.StartErr = res.StartErr.Error()
	}
	if include && res.SpoolPath != "" {
		switch cfg.Attach {
		case "always":
			rep.Attached = true
		case "auto":
			rep.Attached = rep.OutputPartial || utf8.RuneCountInString(message.CleanOutput(res.Tail)) > 3000
		}
	}
	text := rep.Build()

	if o.dryRun {
		fmt.Fprintln(os.Stderr, "----- tg-exec: message (dry run) -----")
		fmt.Fprintln(os.Stderr, text)
		if rep.Attached {
			fmt.Fprintf(os.Stderr, "----- + file %s (%s) -----\n", res.SpoolPath, message.HumanBytes(res.TotalBytes))
		}
		return code
	}

	client, err := newClient(cfg, tok.Value, debugf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tg-exec: %v\n", err)
		return failCode()
	}
	target := telegram.Target{ChatID: cfg.ChatID, ThreadID: cfg.ThreadID, Silent: cfg.SilentSuccess && !res.Failed()}
	ctx := context.Background()
	debugf("sending to chat %s via %s", cfg.ChatID, cfg.APIURL)
	err = sendWithMigrate(&target, func(t telegram.Target) error {
		return client.SendHTML(ctx, t, text, message.Plain(text))
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tg-exec: failed to send Telegram message: %v\n", err)
		return failCode()
	}
	debugf("message sent")
	if rep.Attached {
		limit := int64(0)
		if res.SpoolTruncated {
			limit = spoolLimit
		}
		name := "tg-exec-" + res.Start.In(cfg.Location).Format("20060102-150405") + ".log"
		target.Silent = true
		if err := client.SendDocument(ctx, target, res.SpoolPath, name, rep.Caption(limit)); err != nil {
			fmt.Fprintf(os.Stderr, "tg-exec: failed to attach the log: %v\n", err)
		}
	}
	return code
}

// sendWithMigrate retries once if the group was upgraded to a supergroup.
func sendWithMigrate(t *telegram.Target, send func(telegram.Target) error) error {
	err := send(*t)
	var ae *telegram.APIError
	if errors.As(err, &ae) && ae.MigrateTo != 0 {
		t.ChatID = strconv.FormatInt(ae.MigrateTo, 10)
		fmt.Fprintf(os.Stderr, "tg-exec: the group became a supergroup; set CHAT_ID=%s in the config\n", t.ChatID)
		err = send(*t)
	}
	return err
}

func newClient(cfg *config.Config, token string, debugf func(string, ...any)) (*telegram.Client, error) {
	return telegram.New(telegram.Options{
		Token: token, APIURL: cfg.APIURL, Proxy: cfg.Proxy, CAFile: cfg.CAFile,
		Timeout: cfg.HTTPTimeout, Retries: cfg.Retries, Backoff: cfg.Backoff,
		Debug: debugf, UA: "tg-exec/" + version,
	})
}

func pickShell(cfg *config.Config) string {
	if cfg != nil && cfg.Shell != "" {
		return cfg.Shell
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	return "/bin/sh"
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
