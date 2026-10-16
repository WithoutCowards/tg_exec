package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	hostname = func() string { return "web01" }
	in := `
# comment
export TOKEN="12345:abc#def"   # trailing comment
NOTE=build #5 is a comment
NOTE2=build#5
NOTE3='$(hostname) literal'
NOTE4="on $(hostname) \"q\""
EMPTY=
TG_EXEC_RETRIES=5
`
	es, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range es {
		got[e.Key] = e.Value
	}
	want := map[string]string{
		"TOKEN": "12345:abc#def", "NOTE": "build", "NOTE2": "build#5",
		"NOTE3": "$(hostname) literal", "NOTE4": `on web01 "q"`, "EMPTY": "", "TG_EXEC_RETRIES": "5",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, err := Parse(strings.NewReader(`A="x`)); err == nil {
		t.Error("unterminated quote must fail")
	}
	if _, err := Parse(strings.NewReader(`A="x" y`)); err == nil {
		t.Error("garbage after quote must fail")
	}
}

func write(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestPriority(t *testing.T) {
	d := t.TempDir()
	sys := write(t, d, "sys.conf", "TOKEN=\"1:sys\"\nCHAT_ID=1\nNOTE=sys\nALWAYS=0\nRETRIES=4\n", 0o600)
	usr := write(t, d, "usr.conf", "CHAT_ID=2\nNOTE=user\n", 0o600)
	c, err := Load(Options{SystemPath: sys, UserPath: usr, Env: envOf(map[string]string{"TG_EXEC_NOTE": "env"}),
		Flags: map[string]string{"CHAT_ID": "3"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.ChatID != "3" || c.Note != "env" || c.Raw.Get("TOKEN") != "1:sys" {
		t.Fatalf("priority broken: chat=%s note=%s token=%s", c.ChatID, c.Note, c.Raw.Get("TOKEN"))
	}
	if c.Output != "failure" {
		t.Errorf("legacy ALWAYS=0 should mean OUTPUT=failure, got %s", c.Output)
	}
	if c.Retries != 4 {
		t.Errorf("RETRIES from file ignored: %d", c.Retries)
	}
	// User file beats system file (the old version had it backwards).
	c, _ = Load(Options{SystemPath: sys, UserPath: usr, Env: envOf(nil)})
	if c.ChatID != "2" || c.Note != "user" {
		t.Errorf("user config must override system: chat=%s note=%s", c.ChatID, c.Note)
	}
}

func TestTokenGroup(t *testing.T) {
	d := t.TempDir()
	sys := write(t, d, "sys.conf", "TOKEN_CMD=\"echo 1:sealed\"\n", 0o600)
	usr := write(t, d, "usr.conf", "TOKEN=\"1:user\"\n", 0o600)
	c, err := Load(Options{SystemPath: sys, UserPath: usr, Env: envOf(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if c.Raw.Get("TOKEN_CMD") != "" || c.Raw.Get("TOKEN") != "1:user" {
		t.Errorf("user TOKEN must replace system TOKEN_CMD: %+v", c.Raw)
	}
	c, _ = Load(Options{SystemPath: sys, UserPath: usr, Env: envOf(map[string]string{"TELEGRAM_BOT_TOKEN": "1:env"})})
	if c.Raw.Get("TOKEN") != "1:env" {
		t.Errorf("env token must win, got %q", c.Raw.Get("TOKEN"))
	}
}

func TestWarnings(t *testing.T) {
	d := t.TempDir()
	sys := write(t, d, "sys.conf", "TOKEN=\"1:x\"\nCHATID=1\n", 0o644)
	c, err := Load(Options{SystemPath: sys, UserPath: "-", Env: envOf(nil)})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(c.Warnings, "\n")
	if !strings.Contains(all, "unknown setting CHATID") || !strings.Contains(all, "chmod 600") {
		t.Errorf("expected typo and permission warnings, got:\n%s", all)
	}
}

func TestValidation(t *testing.T) {
	c, err := Load(Options{SystemPath: "-", UserPath: "-", Env: envOf(nil),
		Flags: map[string]string{"TIMEOUT": "1h30m", "HTTP_TIMEOUT": "20", "LANG": "ru"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Timeout != 90*time.Minute || c.HTTPTimeout != 20*time.Second || c.Lang != "ru" {
		t.Errorf("parsed %v %v %s", c.Timeout, c.HTTPTimeout, c.Lang)
	}
	_, err = Load(Options{SystemPath: "-", UserPath: "-", Env: envOf(nil),
		Flags: map[string]string{"NOTIFY": "sometimes", "RETRIES": "0", "TIMEOUT": "soon"}})
	if err == nil || !strings.Contains(err.Error(), "NOTIFY") || !strings.Contains(err.Error(), "RETRIES") || !strings.Contains(err.Error(), "TIMEOUT") {
		t.Errorf("expected validation errors, got %v", err)
	}
	if _, err := Load(Options{ConfigPath: "/nonexistent/x.conf", SystemPath: "-", UserPath: "-", Env: envOf(nil)}); err == nil {
		t.Error("missing explicit --config must fail")
	}
}

func TestLangAuto(t *testing.T) {
	c, _ := Load(Options{SystemPath: "-", UserPath: "-", Env: envOf(map[string]string{"LANG": "ru_RU.UTF-8"})})
	if c.Lang != "ru" {
		t.Errorf("LANG=ru_RU → %s", c.Lang)
	}
	c, _ = Load(Options{SystemPath: "-", UserPath: "-", Env: envOf(map[string]string{"LC_ALL": "C", "LANG": "ru_RU.UTF-8"})})
	if c.Lang != "en" {
		t.Errorf("LC_ALL=C must win → %s", c.Lang)
	}
}

func TestUpdate(t *testing.T) {
	in := "# head\nTOKEN=\"old\"\n#THREAD_ID=\"\"\nTOKEN=\"dup\"\nTOKEN_FILE=/x\nKEEP=1\n"
	out := Update(in, map[string]string{"TOKEN": `a"b$c`, "THREAD_ID": "5", "PROXY": "socks5://h:1"}, []string{"TOKEN_FILE"})
	want := "# head\nTOKEN=\"a\\\"b\\$c\"\nTHREAD_ID=\"5\"\nKEEP=1\nPROXY=\"socks5://h:1\"\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	es, err := Parse(strings.NewReader(out))
	if err != nil || es[0].Value != `a"b$c` {
		t.Fatalf("round trip: %v %+v", err, es)
	}
	// The packaged template must parse.
	if _, err := Parse(strings.NewReader(DefaultFile)); err != nil {
		t.Fatalf("default.conf: %v", err)
	}
}

func TestWriteFileMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "config.conf")
	if err := WriteFile(p, "A=1\n"); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
}
