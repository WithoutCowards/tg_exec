//go:build unix

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type sent struct{ method, chat, text, silent, file string }

type api struct {
	mu      sync.Mutex
	got     []sent
	migrate bool
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	if !strings.HasPrefix(r.URL.Path, "/bot"+testToken+"/") {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
		return
	}
	var s sent
	s.method = method
	if method == "sendDocument" {
		r.ParseMultipartForm(50 << 20)
		f, _, _ := r.FormFile("document")
		b, _ := io.ReadAll(f)
		s.file = string(b)
		s.text = r.FormValue("caption")
	} else {
		r.ParseForm()
		s.text = r.Form.Get("text")
	}
	s.chat = r.FormValue("chat_id")
	s.silent = r.FormValue("disable_notification")
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.migrate && s.chat == "-1" {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"ok":false,"error_code":400,"description":"Bad Request: group chat was upgraded to a supergroup chat","parameters":{"migrate_to_chat_id":-100777}}`)
		return
	}
	a.got = append(a.got, s)
	fmt.Fprint(w, `{"ok":true,"result":{"message_id":1}}`)
}

func setup(t *testing.T, conf string) *api {
	t.Helper()
	systemConfig = "-"
	a := &api{}
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
	for _, k := range []string{"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TG_NOTE", "DEBUG", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(k, "")
	}
	p := filepath.Join(dir, "test.conf")
	body := "API_URL=" + srv.URL + "\nPROXY=none\nRETRIES=1\nBACKOFF=0\nLANG=ru\nTIMEZONE=UTC\n" + conf
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TG_EXEC_CONFIG", p)
	return a
}

func TestFailureReport(t *testing.T) {
	a := setup(t, "TOKEN=\""+testToken+"\"\nCHAT_ID=-100\nNOTE=db01\n")
	code := run([]string{"echo 'boom <&>'; exit 3"})
	if code != 3 {
		t.Fatalf("exit code %d", code)
	}
	if len(a.got) != 1 {
		t.Fatalf("messages: %+v", a.got)
	}
	m := a.got[0]
	for _, want := range []string{"❌", "код 3", "db01", "boom &lt;&amp;&gt;", "language-bash"} {
		if !strings.Contains(m.text, want) {
			t.Errorf("missing %q in %s", want, m.text)
		}
	}
	if m.chat != "-100" || m.silent != "" {
		t.Errorf("chat=%s silent=%s", m.chat, m.silent)
	}
}

func TestDirectArgsAndSilentSuccess(t *testing.T) {
	a := setup(t, "TOKEN=\""+testToken+"\"\nCHAT_ID=1\nSILENT_SUCCESS=1\n")
	code := run([]string{"--note", "x", "--", "printf", "%s", "a b; rm -rf /"})
	if code != 0 || len(a.got) != 1 {
		t.Fatalf("code=%d got=%+v", code, a.got)
	}
	if !strings.Contains(a.got[0].text, "a b; rm -rf /") || !strings.Contains(a.got[0].text, "printf %s &#39;a b; rm -rf /&#39;") &&
		!strings.Contains(a.got[0].text, "printf %s 'a b; rm -rf /'") {
		t.Errorf("args not kept: %s", a.got[0].text)
	}
	if a.got[0].silent != "true" {
		t.Error("success must be silent")
	}
}

func TestOnFailureSkipsSuccess(t *testing.T) {
	a := setup(t, "TOKEN=\""+testToken+"\"\nCHAT_ID=1\n")
	if code := run([]string{"--on-failure", "true"}); code != 0 || len(a.got) != 0 {
		t.Fatalf("code=%d sent=%d", code, len(a.got))
	}
	if code := run([]string{"--on-failure", "false"}); code != 1 || len(a.got) != 1 {
		t.Fatalf("code=%d sent=%d", code, len(a.got))
	}
}

func TestBrokenConfigStillRunsCommand(t *testing.T) {
	setup(t, "CHAT_ID=1\n") // no token
	marker := filepath.Join(t.TempDir(), "ran")
	if code := run([]string{"touch " + marker + "; exit 5"}); code != 5 {
		t.Fatalf("exit code %d", code)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("command must run even if notifications are misconfigured")
	}
	if code := run([]string{"--strict", "true"}); code != 70 {
		t.Fatalf("strict success without delivery must exit 70, got %d", code)
	}
}

func TestAttachLongOutput(t *testing.T) {
	a := setup(t, "TOKEN=\""+testToken+"\"\nCHAT_ID=1\n")
	code := run([]string{"seq 1 100000"})
	if code != 0 || len(a.got) != 2 {
		t.Fatalf("code=%d got=%d", code, len(a.got))
	}
	if a.got[1].method != "sendDocument" || !strings.HasPrefix(a.got[1].file, "1\n2\n3\n") || !strings.HasSuffix(a.got[1].file, "100000\n") {
		t.Fatalf("document: %s %d bytes", a.got[1].method, len(a.got[1].file))
	}
	if !strings.Contains(a.got[0].text, "100000</pre>") || !strings.Contains(a.got[0].text, "из 100\u202f000 строк") {
		t.Errorf("tail/total missing: %s", a.got[0].text[len(a.got[0].text)-200:])
	}
}

func TestMigrate(t *testing.T) {
	a := setup(t, "TOKEN=\""+testToken+"\"\nCHAT_ID=-1\n")
	a.migrate = true
	if code := run([]string{"true"}); code != 0 || len(a.got) != 1 || a.got[0].chat != "-100777" {
		t.Fatalf("code=%d got=%+v", code, a.got)
	}
}

func TestBadToken(t *testing.T) {
	setup(t, "TOKEN=\"999:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\"\nCHAT_ID=1\nSTRICT=1\n")
	if code := run([]string{"true"}); code != 70 {
		t.Fatalf("got %d", code)
	}
	if code := run([]string{"exit 4"}); code != 4 {
		t.Fatalf("job failure code must win over 70, got %d", code)
	}
}

func TestTokenCmd(t *testing.T) {
	a := setup(t, "TOKEN_CMD=\"printf '"+testToken+"\\n'\"\nCHAT_ID=1\n")
	if code := run([]string{"true"}); code != 0 || len(a.got) != 1 {
		t.Fatalf("code=%d got=%d", code, len(a.got))
	}
}

func TestBrokenConfigKeepsTimeoutAndStrict(t *testing.T) {
	setup(t, "TOKEN=\""+testToken+"\"\nCHAT_ID=1\nLANG=de\n")
	start := time.Now()
	if code := run([]string{"-t", "300ms", "--", "sleep", "5"}); code != 124 {
		t.Fatalf("timeout lost on config error: %d", code)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("too slow")
	}
	if code := run([]string{"--strict", "true"}); code != 70 {
		t.Fatalf("strict lost on config error: %d", code)
	}
}

func TestShellFlagWithDashDash(t *testing.T) {
	a := setup(t, "TOKEN=\""+testToken+"\"\nCHAT_ID=1\n")
	if code := run([]string{"-c", "--", "echo", "a", "|", "tr", "a", "b"}); code != 0 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(a.got[0].text, "<pre>b</pre>") {
		t.Fatalf("-c ignored with --: %s", a.got[0].text)
	}
	if code := run([]string{"-n", "--", "echo hi"}); code != 0 {
		t.Fatalf("note \"--\" must not switch to direct exec: %d", code)
	}
}

func TestTokenCmdOnlyWhenSending(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "called")
	a := setup(t, "TOKEN_CMD=\"touch "+marker+"; echo "+testToken+"\"\nCHAT_ID=1\nNOTIFY=failure\n")
	if code := run([]string{"true"}); code != 0 || len(a.got) != 0 {
		t.Fatalf("code=%d sent=%d", code, len(a.got))
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("TOKEN_CMD must not run when nothing is sent")
	}
	if code := run([]string{"false"}); code != 1 || len(a.got) != 1 {
		t.Fatalf("code=%d sent=%d", code, len(a.got))
	}
}
