//go:build unix

// Package secret resolves the Telegram bot token from the configured source.
//
// Sources, first match wins:
//  1. $CREDENTIALS_DIRECTORY/tg-exec-token — systemd LoadCredential= /
//     LoadCredentialEncrypted= (the unit decrypts, the file lives in a
//     private tmpfs only this service can read);
//  2. the highest-priority config layer that sets TOKEN_CMD, TOKEN_FILE or TOKEN
//     (TOKEN_CMD > TOKEN_FILE > TOKEN within it). Environment variables
//     TELEGRAM_BOT_TOKEN / TG_EXEC_TOKEN form the top layer.
//
// TOKEN_CMD works like aws-cli credential_process: the command prints the
// token to stdout (vault, pass, systemd-creds decrypt, a KMS client…).
package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"tg-exec/internal/config"
)

// CredentialName is the systemd credential / sealed token name.
const CredentialName = "tg-exec-token"

// SealedPath is where --seal stores the encrypted token.
const SealedPath = "/etc/tg-exec/token.cred"

// Token is a resolved bot token.
type Token struct {
	Value  string
	Source string // human description, never the secret itself
}

var tokenRe = regexp.MustCompile(`^[0-9]{5,}:[A-Za-z0-9_-]{30,}$`)

// LooksValid reports whether t has the usual bot token shape.
func LooksValid(t string) bool { return tokenRe.MatchString(t) }

// Mask shows the bot id and the last 4 characters.
func Mask(t string) string {
	if i := strings.IndexByte(t, ':'); i > 0 && len(t) > i+8 {
		return t[:i] + ":…" + t[len(t)-4:]
	}
	if t == "" {
		return ""
	}
	return "…"
}

// Resolve finds the token. warn receives non-fatal problems.
func Resolve(c *config.Config, env func(string) string, warn func(string)) (Token, error) {
	if env == nil {
		env = os.Getenv
	}
	if dir := env("CREDENTIALS_DIRECTORY"); dir != "" {
		p := filepath.Join(dir, CredentialName)
		if b, err := os.ReadFile(p); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				return Token{t, "systemd credential " + CredentialName}, nil
			}
		}
	}
	r := c.Raw
	if cmd := strings.TrimSpace(r.Get("TOKEN_CMD")); cmd != "" {
		t, err := runCmd(cmd)
		if err != nil {
			return Token{}, fmt.Errorf("TOKEN_CMD (%s): %w", r["TOKEN_CMD"].Source, err)
		}
		return Token{t, "TOKEN_CMD (" + r["TOKEN_CMD"].Source + ")"}, nil
	}
	if path := strings.TrimSpace(r.Get("TOKEN_FILE")); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return Token{}, fmt.Errorf("TOKEN_FILE (%s): %w", r["TOKEN_FILE"].Source, err)
		}
		if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 && warn != nil {
			warn(fmt.Sprintf("token file %s is readable by group/others (mode %04o): run chmod 600 %s", path, st.Mode().Perm(), path))
		}
		t := strings.TrimSpace(string(b))
		if t == "" {
			return Token{}, fmt.Errorf("TOKEN_FILE %s is empty", path)
		}
		return Token{t, "TOKEN_FILE " + path}, nil
	}
	if t := strings.TrimSpace(r.Get("TOKEN")); t != "" {
		return Token{t, r["TOKEN"].Source}, nil
	}
	return Token{}, errors.New("bot token is not set (TOKEN, TOKEN_FILE, TOKEN_CMD or TELEGRAM_BOT_TOKEN); run: tg-exec --setup")
}

func runCmd(cmdline string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdline)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	cmd.Stdin = nil
	// Kill the whole group on timeout and do not wait for stray children.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		if ctx.Err() != nil {
			return "", errors.New("timed out after 15s")
		}
		if msg != "" {
			return "", fmt.Errorf("%v: %s", err, msg)
		}
		return "", err
	}
	t := strings.TrimSpace(out.String())
	if i := strings.IndexByte(t, '\n'); i >= 0 {
		t = strings.TrimSpace(t[:i])
	}
	if t == "" {
		return "", errors.New("command printed nothing")
	}
	return t, nil
}

// SystemdCredsAvailable reports whether systemd-creds can be used.
func SystemdCredsAvailable() bool {
	_, err := exec.LookPath("systemd-creds")
	return err == nil
}

// Seal encrypts token with systemd-creds into path (host key and/or TPM2,
// chosen by systemd). Only root on this host can decrypt it afterwards.
func Seal(token, path string) error {
	if !SystemdCredsAvailable() {
		return errors.New("systemd-creds not found (systemd 250+ required)")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	cmd := exec.Command("systemd-creds", "encrypt", "--name="+CredentialName, "-", tmp)
	cmd.Stdin = strings.NewReader(token)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("systemd-creds encrypt: %v %s", err, strings.TrimSpace(errb.String()))
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// SealedCmd is the TOKEN_CMD that decrypts a sealed token.
func SealedCmd(path string) string {
	return "systemd-creds decrypt --name=" + CredentialName + " " + path + " -"
}

// Redact removes the token from s (URLs in errors contain it).
func Redact(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "<token>")
}
