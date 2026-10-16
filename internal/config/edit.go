package config

import (
	_ "embed"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// DefaultFile is the commented template installed as /etc/tg-exec/config.conf.
//
//go:embed default.conf
var DefaultFile string

// Quote renders a value for a config file.
func Quote(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`)
	return `"` + r.Replace(v) + `"`
}

var assignRe = regexp.MustCompile(`^\s*(?:export\s+)?(?:TG_EXEC_)?([A-Za-z_][A-Za-z0-9_]*)\s*=`)

// Update rewrites a config text: keys in set are assigned (first active
// assignment replaced in place, otherwise a commented "#KEY=" template line is
// activated, otherwise appended), keys in remove are dropped. Comments and
// unrelated lines are kept.
func Update(text string, set map[string]string, remove []string) string {
	drop := map[string]bool{}
	for _, k := range remove {
		drop[k] = true
	}
	done := map[string]bool{}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	var out []string
	for _, l := range lines {
		if m := assignRe.FindStringSubmatch(l); m != nil {
			k := strings.ToUpper(m[1])
			if v, ok := set[k]; ok {
				if !done[k] {
					out = append(out, k+"="+Quote(v))
					done[k] = true
				}
				continue
			}
			if drop[k] {
				continue
			}
		}
		out = append(out, l)
	}
	// Activate commented template lines ("#KEY=...") for the rest.
	for i, l := range out {
		t := strings.TrimSpace(l)
		if !strings.HasPrefix(t, "#") {
			continue
		}
		if m := assignRe.FindStringSubmatch(strings.TrimPrefix(t, "#")); m != nil {
			k := strings.ToUpper(m[1])
			if v, ok := set[k]; ok && !done[k] {
				out[i] = k + "=" + Quote(v)
				done[k] = true
			}
		}
	}
	var rest []string
	for k := range set {
		if !done[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		out = append(out, k+"="+Quote(set[k]))
	}
	return strings.Join(out, "\n") + "\n"
}

// WriteFile atomically writes a private (0600) config file.
func WriteFile(path, text string) error {
	dir := filepath.Dir(path)
	mode := os.FileMode(0o700)
	if strings.HasPrefix(path, "/etc/") {
		mode = 0o755
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".config.conf.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
