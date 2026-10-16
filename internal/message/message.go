// Package message renders the Telegram report for a finished command.
package message

import (
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Telegram limits, in UTF-16 code units of the visible (entity-parsed) text.
const (
	MaxText    = 4096
	MaxCaption = 1024
)

// Report is everything that goes into a message.
type Report struct {
	Command    string
	Note       string
	Host       string
	Start, End time.Time
	ExitCode   int
	Signal     string
	TimedOut   bool
	Timeout    time.Duration
	StartErr   string

	IncludeOutput bool
	Output        []byte // tail of combined output (raw)
	OutputPartial bool   // Output is only the tail of a longer stream
	TotalLines    int64
	TotalBytes    int64
	Attached      bool // full log goes as a file

	Lang     string
	Location *time.Location
}

// Success reports a clean run.
func (r Report) Success() bool {
	return r.ExitCode == 0 && r.StartErr == "" && !r.TimedOut && r.Signal == ""
}

type strs struct {
	ok, failed, timeout, signal, notStarted, code         string
	output, outputTail, noOutput, attached, host, caption string
	truncatedCmd, captionCut                              string
}

var i18n = map[string]strs{
	"ru": {
		ok: "Готово", failed: "Ошибка", timeout: "Прервано по таймауту", signal: "Остановлено сигналом",
		notStarted: "Не удалось запустить", code: "код",
		output: "Вывод", outputTail: "Вывод (последние %s из %s строк)", noOutput: "Вывода нет",
		attached: "Полный вывод — в файле ниже", host: "Хост", caption: "Полный вывод",
		truncatedCmd: "команда сокращена", captionCut: "из %s, обрезан до %s",
	},
	"en": {
		ok: "Done", failed: "Failed", timeout: "Timed out", signal: "Killed by signal",
		notStarted: "Could not start", code: "exit",
		output: "Output", outputTail: "Output (last %s of %s lines)", noOutput: "No output",
		attached: "Full output is in the file below", host: "Host", caption: "Full output",
		truncatedCmd: "command shortened", captionCut: "of %s, cut to %s",
	},
}

func (r Report) t() strs {
	if s, ok := i18n[r.Lang]; ok {
		return s
	}
	return i18n["en"]
}

// Esc escapes text for Telegram HTML.
func Esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

// VisibleLen is the length Telegram checks: UTF-16 units of the text without tags.
func VisibleLen(htmlText string) int {
	return utf16Len(html.UnescapeString(tagRe.ReplaceAllString(htmlText, "")))
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// Header is the status line (HTML).
func (r Report) Header() string {
	t := r.t()
	var status string
	switch {
	case r.StartErr != "":
		status = "🚫 <b>" + t.notStarted + "</b>"
	case r.TimedOut:
		status = fmt.Sprintf("⏰ <b>%s</b> (%s)", t.timeout, HumanDuration(r.Timeout, r.Lang))
	case r.Signal != "":
		status = fmt.Sprintf("⚠️ <b>%s</b> %s", t.signal, r.Signal)
	case r.ExitCode != 0:
		status = fmt.Sprintf("❌ <b>%s</b> · %s %d", t.failed, t.code, r.ExitCode)
	default:
		status = "✅ <b>" + t.ok + "</b>"
	}
	if r.Note != "" {
		status += " · <b>" + Esc(r.Note) + "</b>"
	}
	return status
}

// Build renders the message. It always fits Telegram's 4096 limit.
func (r Report) Build() string {
	msg, _ := r.Render()
	return msg
}

// Render is Build that also reports whether the output had to be cut.
func (r Report) Render() (string, bool) {
	r.Note = shorten(r.Note, 200)
	r.Host = shorten(r.Host, 200)
	t := r.t()
	loc := r.Location
	if loc == nil {
		loc = time.Local
	}

	cmd := r.Command
	cmdNote := ""
	if utf16Len(cmd) > 1000 {
		cmd = cutUTF16(cmd, 1000) + "…"
		cmdNote = " <i>(" + t.truncatedCmd + ")</i>"
	}

	var b strings.Builder
	b.WriteString(r.Header())
	b.WriteString("\n<pre><code class=\"language-bash\">" + Esc(cmd) + "</code></pre>" + cmdNote + "\n")

	start, end := r.Start.In(loc), r.End.In(loc)
	tf := "15:04:05"
	when := start.Format("2006-01-02 " + tf)
	if !sameDay(start, end) {
		tf = "2006-01-02 15:04:05"
	}
	fmt.Fprintf(&b, "🕒 %s → %s %s · %s", when, end.Format(tf), zone(end), HumanDuration(r.End.Sub(r.Start), r.Lang))
	if r.Host != "" && r.Host != r.Note {
		fmt.Fprintf(&b, "\n🖥 %s: <code>%s</code>", t.host, Esc(r.Host))
	}
	if r.StartErr != "" {
		b.WriteString("\n<pre>" + Esc(cutUTF16(r.StartErr, 500)) + "</pre>")
	}
	if !r.IncludeOutput {
		return b.String(), false
	}

	out := CleanOutput(r.Output)
	if strings.TrimSpace(out) == "" {
		if r.StartErr == "" {
			b.WriteString("\n💬 <i>" + t.noOutput + "</i>")
		}
		return b.String(), false
	}

	base := b.String()
	tail := "\n📎 <i>" + t.attached + "</i>"
	if !r.Attached {
		tail = ""
	}
	// Budget for output = limit - everything else - title - safety margin.
	budget := MaxText - VisibleLen(base) - VisibleLen(tail) - 80
	if budget < 200 {
		budget = 200
	}
	shown, cut := TailUTF16(out, budget)
	title := t.output
	if cut || r.OutputPartial {
		lines := int64(strings.Count(shown, "\n") + 1)
		total := r.TotalLines
		if total < lines {
			total = lines
		}
		title = fmt.Sprintf(t.outputTail, group(lines), group(total))
	}
	msg := base + "\n💬 " + title + ":\n<pre>" + Esc(shown) + "</pre>" + tail
	for VisibleLen(msg) > MaxText && len(shown) > 0 {
		shown, _ = TailUTF16(shown, utf16Len(shown)-200)
		cut = true
		msg = base + "\n💬 " + title + ":\n<pre>" + Esc(shown) + "</pre>" + tail
	}
	return msg, cut || r.OutputPartial
}

func shorten(s string, n int) string {
	if utf16Len(s) <= n {
		return s
	}
	return cutUTF16(s, n) + "…"
}

// Plain is a fallback rendering without markup.
func Plain(htmlText string) string {
	s := strings.ReplaceAll(htmlText, "<pre>", "\n")
	s = strings.ReplaceAll(s, "</pre>", "\n")
	return html.UnescapeString(tagRe.ReplaceAllString(s, ""))
}

// Caption for the attached log; limit > 0 means the file was cut to limit bytes.
func (r Report) Caption(limit int64) string {
	c := "📎 " + r.t().caption
	if r.Note != "" {
		c += " · " + Esc(shorten(r.Note, 200))
	}
	if limit > 0 {
		c += " (" + fmt.Sprintf(r.t().captionCut, HumanBytes(r.TotalBytes), HumanBytes(limit)) + ")"
	}
	if VisibleLen(c) > MaxCaption {
		c = "📎 " + r.t().caption
	}
	return c
}

var (
	ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]`)
	ctrlRe = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
)

// CleanOutput strips ANSI colours and control characters, collapses
// carriage-return progress lines to their final state and fixes UTF-8.
func CleanOutput(b []byte) string {
	// The ring buffer may start in the middle of a UTF-8 sequence.
	for len(b) > 0 && !utf8.RuneStart(b[0]) {
		b = b[1:]
	}
	s := strings.ToValidUTF8(string(b), "�")
	s = ansiRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if strings.Contains(s, "\r") {
		lines := strings.Split(s, "\n")
		for i, l := range lines {
			if j := strings.LastIndex(strings.TrimRight(l, "\r"), "\r"); j >= 0 {
				l = l[j+1:]
			}
			lines[i] = strings.TrimRight(l, "\r")
		}
		s = strings.Join(lines, "\n")
	}
	s = ctrlRe.ReplaceAllString(s, "")
	return strings.TrimRight(s, "\n ")
}

// TailUTF16 keeps the end of s within n UTF-16 units, starting at a line
// boundary when possible. cut reports whether anything was removed.
func TailUTF16(s string, n int) (string, bool) {
	if n <= 0 {
		return "", s != ""
	}
	if utf16Len(s) <= n {
		return s, false
	}
	units := 0
	i := len(s)
	for i > 0 {
		r, size := utf8.DecodeLastRuneInString(s[:i])
		u := utf16.RuneLen(r)
		if units+u > n {
			break
		}
		units += u
		i -= size
	}
	tail := s[i:]
	if j := strings.IndexByte(tail, '\n'); j >= 0 && j < len(tail)-1 {
		tail = tail[j+1:]
	}
	return tail, true
}

func cutUTF16(s string, n int) string {
	units := 0
	for i, r := range s {
		u := utf16.RuneLen(r)
		if units+u > n {
			return s[:i]
		}
		units += u
	}
	return s
}

func sameDay(a, b time.Time) bool {
	y1, m1, d1 := a.Date()
	y2, m2, d2 := b.Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}

func zone(t time.Time) string {
	name, off := t.Zone()
	if name != "" && !strings.HasPrefix(name, "+") && !strings.HasPrefix(name, "-") {
		return name
	}
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	if off%3600 == 0 {
		return fmt.Sprintf("UTC%s%d", sign, off/3600)
	}
	return fmt.Sprintf("UTC%s%d:%02d", sign, off/3600, off%3600/60)
}

// HumanDuration formats durations as "2 мин 3 с" / "2m 3s".
func HumanDuration(d time.Duration, lang string) string {
	ru := lang == "ru"
	if d < time.Second {
		ms := d.Milliseconds()
		if ru {
			return fmt.Sprintf("%d мс", ms)
		}
		return fmt.Sprintf("%dms", ms)
	}
	d = d.Round(time.Second)
	if d >= time.Hour {
		d = d.Round(time.Minute)
	}
	h, m, s := int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60
	var parts []string
	unit := func(v int, r, e string) {
		if ru {
			parts = append(parts, fmt.Sprintf("%d %s", v, r))
		} else {
			parts = append(parts, fmt.Sprintf("%d%s", v, e))
		}
	}
	if h > 0 {
		unit(h, "ч", "h")
		if m > 0 {
			unit(m, "мин", "m")
		}
		return strings.Join(parts, " ")
	}
	if m > 0 {
		unit(m, "мин", "m")
		if s > 0 {
			unit(s, "с", "s")
		}
		return strings.Join(parts, " ")
	}
	unit(s, "с", "s")
	return strings.Join(parts, " ")
}

// HumanBytes formats sizes (1.5 MB).
func HumanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func group(n int64) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}
