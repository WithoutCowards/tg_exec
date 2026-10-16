// Package config loads tg-exec settings from config files, the environment
// and command-line flags, in that order of increasing priority.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Entry is one KEY=VALUE pair from a config file.
type Entry struct {
	Key   string
	Value string
	Line  int
}

// Parse reads a shell-like KEY=VALUE file.
//
//   - blank lines and lines starting with # are ignored;
//   - an optional "export " prefix is accepted;
//   - values may be "double quoted" (with \" and \\ escapes) or 'single quoted';
//   - in unquoted values a comment starts at " #" (a # preceded by whitespace),
//     so values such as build#5 are kept intact;
//   - $(hostname), ${HOSTNAME} and $HOSTNAME expand to the host name
//     (not inside single quotes).
func Parse(r io.Reader) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(strings.TrimSuffix(sc.Text(), "\r"))
		if n == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return out, fmt.Errorf("line %d: expected KEY=VALUE", n)
		}
		key := strings.TrimSpace(line[:eq])
		if !validKey(key) {
			return out, fmt.Errorf("line %d: invalid key %q", n, key)
		}
		val, err := parseValue(strings.TrimSpace(line[eq+1:]))
		if err != nil {
			return out, fmt.Errorf("line %d: %v", n, err)
		}
		out = append(out, Entry{Key: strings.ToUpper(key), Value: val, Line: n})
	}
	return out, sc.Err()
}

func validKey(k string) bool {
	for i, c := range k {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return k != ""
}

func parseValue(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	switch s[0] {
	case '"':
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			c := s[i]
			if c == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\' || s[i+1] == '$') {
				if s[i+1] == '$' {
					b.WriteByte(0) // escaped $: never expanded
				} else {
					b.WriteByte(s[i+1])
				}
				i++
				continue
			}
			if c == '"' {
				if err := trailingOK(s[i+1:]); err != nil {
					return "", err
				}
				return strings.ReplaceAll(expandHost(b.String()), "\x00", "$"), nil
			}
			b.WriteByte(c)
		}
		return "", fmt.Errorf("unterminated double quote")
	case '\'':
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			return "", fmt.Errorf("unterminated single quote")
		}
		if err := trailingOK(s[end+2:]); err != nil {
			return "", err
		}
		return s[1 : end+1], nil
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			s = s[:i]
			break
		}
	}
	return expandHost(strings.TrimSpace(s)), nil
}

// trailingOK allows only whitespace and a comment after a closing quote.
func trailingOK(rest string) error {
	rest = strings.TrimSpace(rest)
	if rest == "" || strings.HasPrefix(rest, "#") {
		return nil
	}
	return fmt.Errorf("unexpected text after closing quote: %q", rest)
}

var hostname = func() string {
	h, _ := os.Hostname()
	return h
}

func expandHost(v string) string {
	if !strings.Contains(v, "$") {
		return v
	}
	h := hostname()
	for _, p := range []string{"$(hostname)", "${HOSTNAME}", "$HOSTNAME"} {
		v = strings.ReplaceAll(v, p, h)
	}
	return v
}
