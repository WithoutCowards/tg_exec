package message

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func baseReport() Report {
	st := time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC)
	return Report{
		Command: "pg_dump db | gzip > /backup/db.gz", Note: "db01", Host: "db01",
		Start: st, End: st.Add(2*time.Minute + 3*time.Second), Lang: "ru", Location: time.UTC,
		IncludeOutput: true,
	}
}

func TestBuildFitsLimit(t *testing.T) {
	for _, chunk := range []string{"Ошибка & <ошибка> — строка лога\n", "a&b<c>d\n", "😀😀😀 emoji line\n", "x"} {
		r := baseReport()
		r.ExitCode = 1
		r.Output = []byte(strings.Repeat(chunk, 5000))
		r.OutputPartial = true
		r.TotalLines = 123456
		r.Attached = true
		msg := r.Build()
		if n := VisibleLen(msg); n > MaxText {
			t.Fatalf("%q: visible length %d > %d", chunk, n, MaxText)
		}
		if !utf8.ValidString(msg) {
			t.Fatal("invalid UTF-8")
		}
		// No entity may be cut in half.
		body := msg[strings.Index(msg, "<pre>")+5:]
		for _, frag := range strings.Split(body, "&")[1:] {
			if !(strings.HasPrefix(frag, "amp;") || strings.HasPrefix(frag, "lt;") || strings.HasPrefix(frag, "gt;")) {
				t.Fatalf("broken entity near %q", frag[:min(10, len(frag))])
			}
		}
		if !strings.Contains(msg, "123 456") || !strings.Contains(msg, "📎") {
			t.Errorf("missing totals or attach note:\n%s", msg[:300])
		}
	}
}

func TestHeader(t *testing.T) {
	r := baseReport()
	if h := r.Header(); h != "✅ <b>Готово</b> · <b>db01</b>" {
		t.Errorf("ok header %q", h)
	}
	r.ExitCode = 2
	if h := r.Header(); !strings.Contains(h, "код 2") {
		t.Errorf("fail header %q", h)
	}
	r.TimedOut, r.Timeout = true, 30*time.Minute
	if h := r.Header(); !strings.Contains(h, "таймауту") || !strings.Contains(h, "30 мин") {
		t.Errorf("timeout header %q", h)
	}
	r = baseReport()
	r.Lang, r.Signal, r.Note = "en", "SIGTERM", "<x>"
	if h := r.Header(); !strings.Contains(h, "SIGTERM") || !strings.Contains(h, "&lt;x&gt;") {
		t.Errorf("signal header %q", h)
	}
}

func TestBuildSmall(t *testing.T) {
	r := baseReport()
	r.Output = []byte("\x1b[32mok\x1b[0m\r\n10%\r50%\r100%\ndone\n")
	msg := r.Build()
	for _, want := range []string{"<pre>ok\n100%\ndone</pre>", "2 мин 3 с", "2026-10-16 03:00:00 → 03:02:03 UTC", "language-bash"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "Хост") {
		t.Error("host line must be hidden when it equals the note")
	}
	r.Output = nil
	if !strings.Contains(r.Build(), "Вывода нет") {
		t.Error("empty output note missing")
	}
	r.IncludeOutput = false
	if strings.Contains(r.Build(), "Вывод") {
		t.Error("output must be omitted")
	}
}

func TestLongCommand(t *testing.T) {
	r := baseReport()
	r.Command = strings.Repeat("echo длинная команда; ", 500)
	msg := r.Build()
	if VisibleLen(msg) > MaxText || !strings.Contains(msg, "команда сокращена") {
		t.Errorf("long command not shortened: %d", VisibleLen(msg))
	}
}

func TestCleanOutputBrokenUTF8Start(t *testing.T) {
	b := []byte("привет\nмир")
	got := CleanOutput(b[1:]) // starts mid-rune, as a ring buffer may
	if !utf8.ValidString(got) || !strings.HasSuffix(got, "мир") {
		t.Errorf("got %q", got)
	}
}

func TestTailUTF16(t *testing.T) {
	s, cut := TailUTF16("line1\nline2\nline3", 11)
	if !cut || s != "line3" {
		t.Errorf("got %q %v", s, cut)
	}
	s, cut = TailUTF16("short", 100)
	if cut || s != "short" {
		t.Errorf("got %q %v", s, cut)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration][2]string{
		350 * time.Millisecond:                     {"350 мс", "350ms"},
		12 * time.Second:                           {"12 с", "12s"},
		2*time.Minute + 3*time.Second:              {"2 мин 3 с", "2m 3s"},
		time.Hour + 4*time.Minute + 59*time.Second: {"1 ч 5 мин", "1h 5m"},
		3 * time.Hour:                              {"3 ч", "3h"},
	}
	for d, want := range cases {
		if got := HumanDuration(d, "ru"); got != want[0] {
			t.Errorf("ru %v: %q", d, got)
		}
		if got := HumanDuration(d, "en"); got != want[1] {
			t.Errorf("en %v: %q", d, got)
		}
	}
}

func TestPlain(t *testing.T) {
	r := baseReport()
	r.Output = []byte("a < b && c")
	p := Plain(r.Build())
	if strings.Contains(p, "<b>") || !strings.Contains(p, "a < b && c") {
		t.Errorf("plain: %q", p)
	}
}

func TestLongNoteStillFits(t *testing.T) {
	r := baseReport()
	r.Note = strings.Repeat("очень длинная подпись ", 400)
	r.Host = "other"
	r.Output = []byte(strings.Repeat("x\n", 3000))
	msg, cut := r.Render()
	if VisibleLen(msg) > MaxText || !cut {
		t.Fatalf("len=%d cut=%v", VisibleLen(msg), cut)
	}
	if VisibleLen(r.Caption(45<<20)) > MaxCaption {
		t.Fatal("caption too long")
	}
}

func TestRenderCutFlag(t *testing.T) {
	r := baseReport()
	r.Output = []byte("short")
	if _, cut := r.Render(); cut {
		t.Fatal("short output reported as cut")
	}
	r.Command = strings.Repeat("x", 900)
	r.Output = []byte(strings.Repeat("строка\n", 500)) // fits by runes, not after a long command
	if _, cut := r.Render(); !cut {
		t.Fatal("cut not reported")
	}
}
