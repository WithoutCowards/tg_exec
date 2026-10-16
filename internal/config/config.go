package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SystemPath is the global config file.
const SystemPath = "/etc/tg-exec/config.conf"

// Keys lists every supported setting. Files may also use the TG_EXEC_ prefix.
var Keys = []string{
	"TOKEN", "TOKEN_FILE", "TOKEN_CMD",
	"CHAT_ID", "THREAD_ID", "NOTE",
	"NOTIFY", "OUTPUT", "SILENT_SUCCESS", "ATTACH", "LANG", "TIMEZONE",
	"TIMEOUT", "SHELL",
	"PROXY", "API_URL", "CA_FILE", "HTTP_TIMEOUT", "RETRIES", "BACKOFF",
	"STRICT", "DEBUG",
	// legacy, still accepted
	"ALWAYS", "PARSE_MODE",
}

// tokenKeys are resolved as a group: the highest-priority layer that sets any
// of them wins, so a user config can override a sealed system token.
var tokenKeys = []string{"TOKEN", "TOKEN_FILE", "TOKEN_CMD"}

// legacyEnv maps old/foreign environment names to keys.
var legacyEnv = [][2]string{
	{"TELEGRAM_BOT_TOKEN", "TOKEN"},
	{"TELEGRAM_CHAT_ID", "CHAT_ID"},
	{"TG_NOTE", "NOTE"},
	{"TG_EXEC_TZ", "TIMEZONE"},
	{"DEBUG", "DEBUG"},
}

// Value is a setting together with where it came from.
type Value struct {
	V      string
	Source string // file path, "env TG_EXEC_X", "flag --x" or "default"
}

// Set is the merged view of all layers.
type Set map[string]Value

func (s Set) Get(k string) string { return s[k].V }

// FileInfo describes a config file that was looked at.
type FileInfo struct {
	Path     string
	Loaded   bool
	Mode     fs.FileMode
	HasToken bool
	Err      error
}

// Config is the resolved, typed configuration.
type Config struct {
	Raw   Set
	Files []FileInfo

	ChatID        string
	ThreadID      int64
	Note          string
	Notify        string // always | failure
	Output        string // always | failure | never
	SilentSuccess bool
	Attach        string // auto | always | never
	Lang          string // ru | en
	Location      *time.Location
	Timeout       time.Duration
	Shell         string

	Proxy       string // "" = from environment, "none" = direct
	APIURL      string
	CAFile      string
	HTTPTimeout time.Duration
	Retries     int
	Backoff     time.Duration

	Strict bool
	Debug  bool

	Warnings []string

	env func(string) string
}

// Options controls Load.
type Options struct {
	ConfigPath string            // explicit --config (also TG_EXEC_CONFIG)
	Flags      map[string]string // highest priority, key -> value
	Env        func(string) string
	SystemPath string // for tests; defaults to SystemPath
	UserPath   string // for tests; defaults to XDG location
}

// UserPath returns the per-user config file location.
func UserPath(env func(string) string) string {
	if x := env("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "tg-exec", "config.conf")
	}
	home := env("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "tg-exec", "config.conf")
}

// Load merges defaults < system file < user file < --config file < env < flags.
func Load(o Options) (*Config, error) {
	if o.Env == nil {
		o.Env = os.Getenv
	}
	if o.SystemPath == "" {
		o.SystemPath = SystemPath
	}
	if o.UserPath == "" {
		o.UserPath = UserPath(o.Env)
	}
	if o.ConfigPath == "" {
		o.ConfigPath = o.Env("TG_EXEC_CONFIG")
	}

	cfg := &Config{Raw: Set{}, env: o.Env}
	paths := []string{o.SystemPath, o.UserPath}
	if o.ConfigPath != "" {
		paths = append(paths, o.ConfigPath)
	}
	for i, p := range paths {
		if p == "" || p == "-" {
			continue
		}
		explicit := o.ConfigPath != "" && i == len(paths)-1
		fi := cfg.loadFile(p)
		// A missing file, or a root-only system file read by a normal user, is expected.
		quiet := errors.Is(fi.Err, fs.ErrNotExist) || errors.Is(fi.Err, fs.ErrPermission)
		if fi.Err != nil && (explicit || !quiet) {
			if explicit {
				return nil, fmt.Errorf("config %s: %w", p, fi.Err)
			}
			cfg.warn("config %s: %v", p, fi.Err)
		}
		cfg.Files = append(cfg.Files, fi)
	}

	env := Set{}
	for _, l := range legacyEnv {
		if v := o.Env(l[0]); v != "" {
			env[l[1]] = Value{v, "env " + l[0]}
		}
	}
	if v := o.Env("TG_EXEC_ALWAYS"); v != "" {
		env["ALWAYS"] = Value{v, "env TG_EXEC_ALWAYS"}
	}
	for _, k := range Keys {
		if v := o.Env("TG_EXEC_" + k); v != "" {
			env[k] = Value{v, "env TG_EXEC_" + k}
		}
	}
	cfg.merge(env)

	flags := Set{}
	for k, v := range o.Flags {
		flags[k] = Value{v, "flag"}
	}
	cfg.merge(flags)

	return cfg, cfg.resolve()
}

func (c *Config) warn(format string, args ...any) {
	c.Warnings = append(c.Warnings, fmt.Sprintf(format, args...))
}

func (c *Config) loadFile(path string) FileInfo {
	fi := FileInfo{Path: path}
	f, err := os.Open(path)
	if err != nil {
		fi.Err = err
		return fi
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil {
		fi.Mode = st.Mode().Perm()
	}
	entries, err := Parse(f)
	if err != nil {
		fi.Err = err
		return fi
	}
	fi.Loaded = true
	layer := Set{}
	known := map[string]bool{}
	for _, k := range Keys {
		known[k] = true
	}
	for _, e := range entries {
		k := strings.TrimPrefix(e.Key, "TG_EXEC_")
		switch e.Key {
		case "TELEGRAM_BOT_TOKEN":
			k = "TOKEN"
		case "TELEGRAM_CHAT_ID":
			k = "CHAT_ID"
		case "TG_EXEC_TZ":
			k = "TIMEZONE"
		}
		if !known[k] {
			c.warn("%s:%d: unknown setting %s (ignored)", path, e.Line, e.Key)
			continue
		}
		if k == "TOKEN" && e.Value != "" {
			fi.HasToken = true
		}
		layer[k] = Value{e.Value, fmt.Sprintf("%s:%d", path, e.Line)}
	}
	if fi.HasToken && fi.Mode&0o077 != 0 {
		c.warn("%s contains TOKEN and is readable by group/others (mode %04o): run chmod 600 %s", path, fi.Mode, path)
	}
	c.merge(layer)
	return fi
}

func (c *Config) merge(layer Set) {
	for _, k := range tokenKeys {
		if v, ok := layer[k]; ok && v.V != "" {
			for _, tk := range tokenKeys {
				delete(c.Raw, tk)
			}
			break
		}
	}
	for k, v := range layer {
		c.Raw[k] = v
	}
}

func (c *Config) resolve() error {
	r := c.Raw
	var errs []string
	bad := func(k, msg string) {
		errs = append(errs, fmt.Sprintf("%s=%q (%s): %s", k, r.Get(k), r[k].Source, msg))
	}

	c.ChatID = strings.TrimSpace(r.Get("CHAT_ID"))
	if v := r.Get("THREAD_ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			bad("THREAD_ID", "expected a positive number")
		}
		c.ThreadID = n
	}
	c.Note = r.Get("NOTE")

	c.Notify = choice(r, "NOTIFY", "always", []string{"always", "failure"}, bad)

	output := r.Get("OUTPUT")
	if output == "" {
		switch r.Get("ALWAYS") {
		case "", "1", "true", "yes":
			output = "always"
		case "0", "false", "no":
			output = "failure"
		default:
			bad("ALWAYS", "expected 1 or 0")
		}
		if output != "" {
			r["OUTPUT"] = Value{output, r["ALWAYS"].Source}
		}
	}
	c.Output = choice(r, "OUTPUT", "always", []string{"always", "failure", "never"}, bad)
	c.Attach = choice(r, "ATTACH", "auto", []string{"auto", "always", "never"}, bad)
	c.SilentSuccess = boolean(r, "SILENT_SUCCESS", false, bad)
	c.Strict = boolean(r, "STRICT", false, bad)
	c.Debug = boolean(r, "DEBUG", false, bad)

	switch l := strings.ToLower(r.Get("LANG")); l {
	case "ru", "en":
		c.Lang = l
	case "", "auto":
		c.Lang = "en"
		for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
			if v := c.env(k); v != "" {
				if strings.HasPrefix(strings.ToLower(v), "ru") {
					c.Lang = "ru"
				}
				break
			}
		}
	default:
		bad("LANG", "expected ru, en or auto")
	}

	c.Location = time.Local
	tz := r.Get("TIMEZONE")
	if tz == "" {
		tz = c.env("TZ")
	}
	if tz != "" {
		if loc, err := time.LoadLocation(strings.TrimPrefix(tz, ":")); err == nil {
			c.Location = loc
		} else if r.Get("TIMEZONE") != "" {
			bad("TIMEZONE", "unknown time zone")
		}
	}

	c.Timeout = duration(r, "TIMEOUT", 0, bad)
	c.Shell = r.Get("SHELL")

	c.Proxy = strings.TrimSpace(r.Get("PROXY"))
	if p := strings.ToLower(c.Proxy); p == "none" || p == "direct" || p == "off" {
		c.Proxy = "none"
	}
	c.APIURL = strings.TrimRight(strings.TrimSpace(r.Get("API_URL")), "/")
	if c.APIURL == "" {
		c.APIURL = "https://api.telegram.org"
	} else if !strings.HasPrefix(c.APIURL, "https://") && !strings.HasPrefix(c.APIURL, "http://") {
		bad("API_URL", "expected http:// or https:// URL")
	}
	c.CAFile = r.Get("CA_FILE")

	c.HTTPTimeout = duration(r, "HTTP_TIMEOUT", 15*time.Second, bad)
	c.Backoff = duration(r, "BACKOFF", 2*time.Second, bad)
	c.Retries = 3
	if v := r.Get("RETRIES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 20 {
			bad("RETRIES", "expected 1..20 (total attempts)")
		} else {
			c.Retries = n
		}
	}
	if r.Get("PARSE_MODE") != "" && !strings.EqualFold(r.Get("PARSE_MODE"), "HTML") {
		c.warn("PARSE_MODE is no longer used: messages are always sent as HTML")
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("invalid configuration:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

func choice(r Set, k, def string, allowed []string, bad func(string, string)) string {
	v := strings.ToLower(strings.TrimSpace(r.Get(k)))
	if v == "" {
		return def
	}
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	bad(k, "expected one of "+strings.Join(allowed, ", "))
	return def
}

func boolean(r Set, k string, def bool, bad func(string, string)) bool {
	switch strings.ToLower(strings.TrimSpace(r.Get(k))) {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	bad(k, "expected 1 or 0")
	return def
}

// duration accepts plain seconds ("10") or Go durations ("90s", "1h30m").
func duration(r Set, k string, def time.Duration, bad func(string, string)) time.Duration {
	v := strings.TrimSpace(r.Get(k))
	if v == "" {
		return def
	}
	return ParseDuration(v, def, func(msg string) { bad(k, msg) })
}

// ParseDuration parses seconds or a Go duration; calls bad on error.
func ParseDuration(v string, def time.Duration, bad func(string)) time.Duration {
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		bad("expected seconds or a duration like 90s, 30m, 2h")
		return def
	}
	return d
}
