//go:build unix

package runner

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		code int
		sig  string
		to   bool
	}{
		{"ok", Spec{Args: []string{"true"}}, 0, "", false},
		{"exit 3", Spec{Shell: "/bin/sh", Command: "exit 3"}, 3, "", false},
		{"not found", Spec{Args: []string{"/no/such/binary"}}, 127, "", false},
		{"signal", Spec{Shell: "/bin/sh", Command: "kill -TERM $$"}, 128 + int(syscall.SIGTERM), "SIGTERM", false},
		{"timeout", Spec{Args: []string{"sleep", "5"}, Timeout: 200 * time.Millisecond}, 124, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			r := Run(c.spec)
			if r.ExitCode != c.code || r.Signal != c.sig || r.TimedOut != c.to {
				t.Fatalf("code=%d sig=%q timedOut=%v startErr=%v", r.ExitCode, r.Signal, r.TimedOut, r.StartErr)
			}
			if c.to && time.Since(start) > 3*time.Second {
				t.Fatal("timeout did not stop the command quickly")
			}
		})
	}
}

func TestArgsKeptIntact(t *testing.T) {
	var out bytes.Buffer
	r := Run(Spec{Args: []string{"printf", "%s|", "a b", "it's", "$HOME"}, Stdout: &out})
	if r.ExitCode != 0 || out.String() != "a b|it's|$HOME|" {
		t.Fatalf("got %q", out.String())
	}
	if string(r.Tail) != out.String() {
		t.Fatalf("tail %q", r.Tail)
	}
}

func TestTailAndSpool(t *testing.T) {
	var out bytes.Buffer
	r := Run(Spec{
		Shell: "/bin/sh", Command: "echo err >&2; sleep 0.1; i=0; while [ $i -lt 2000 ]; do echo line$i; i=$((i+1)); done",
		Stdout: &out, Stderr: &out, TailBytes: 100, SpoolLimit: 1 << 20,
	})
	defer os.Remove(r.SpoolPath)
	// stdout and stderr are separate pipes, so only per-stream order is guaranteed.
	if len(r.Tail) != 100 || !strings.HasSuffix(string(r.Tail), "line1998\nline1999\n") {
		t.Fatalf("tail %q", r.Tail)
	}
	if r.TotalLines != 2001 || r.TotalBytes != int64(out.Len()) {
		t.Fatalf("lines=%d bytes=%d out=%d", r.TotalLines, r.TotalBytes, out.Len())
	}
	b, err := os.ReadFile(r.SpoolPath)
	if err != nil || !bytes.Equal(b, out.Bytes()) {
		t.Fatalf("spool mismatch: %v", err)
	}
	st, _ := os.Stat(r.SpoolPath)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("spool mode %v", st.Mode())
	}
}

func TestSpoolLimit(t *testing.T) {
	r := Run(Spec{Shell: "/bin/sh", Command: "head -c 5000 /dev/zero", SpoolLimit: 1000})
	defer os.Remove(r.SpoolPath)
	st, _ := os.Stat(r.SpoolPath)
	if st.Size() != 1000 || !r.SpoolTruncated || r.TotalBytes != 5000 {
		t.Fatalf("size=%d trunc=%v total=%d", st.Size(), r.SpoolTruncated, r.TotalBytes)
	}
}

func TestNoSpoolWithoutOutput(t *testing.T) {
	r := Run(Spec{Args: []string{"true"}, SpoolLimit: 1000})
	if r.SpoolPath != "" {
		t.Fatal("empty spool must be removed")
	}
}

func TestRing(t *testing.T) {
	r := newRing(5)
	for _, s := range []string{"ab", "cd", "ef", "g"} {
		r.Write([]byte(s))
	}
	if got := string(r.Bytes()); got != "cdefg" {
		t.Fatalf("got %q", got)
	}
	r.Write([]byte("0123456789"))
	if got := string(r.Bytes()); got != "56789" {
		t.Fatalf("got %q", got)
	}
}

func TestShellQuote(t *testing.T) {
	got := ShellQuote([]string{"rsync", "-a", "/src dir/", "it's", "host:/x", ""})
	want := `rsync -a '/src dir/' 'it'\''s' host:/x ''`
	if got != want {
		t.Fatalf("got %s", got)
	}
}

func alive(pidfile string) bool {
	b, err := os.ReadFile(pidfile)
	if err != nil {
		return false
	}
	var pid int
	for _, c := range strings.TrimSpace(string(b)) {
		pid = pid*10 + int(c-'0')
	}
	if pid <= 0 || syscall.Kill(pid, 0) != nil {
		return false
	}
	// A killed orphan may linger as a zombie if init does not reap it.
	if st, err := os.ReadFile("/proc/" + strings.TrimSpace(string(b)) + "/stat"); err == nil {
		if f := strings.Fields(string(st)); len(f) > 2 && f[2] == "Z" {
			return false
		}
	}
	return true
}

func TestTimeoutKillsWholeGroup(t *testing.T) {
	pf := t.TempDir() + "/pid"
	start := time.Now()
	r := Run(Spec{Shell: "/bin/sh", Command: "sleep 30 & echo $! > " + pf + "; sleep 30 | cat", Timeout: 300 * time.Millisecond,
		Group: true, KillGrace: time.Second})
	if r.ExitCode != 124 || !r.TimedOut {
		t.Fatalf("code=%d timedOut=%v", r.ExitCode, r.TimedOut)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v", d)
	}
	time.Sleep(100 * time.Millisecond)
	if alive(pf) {
		t.Fatal("background child survived the timeout")
	}
}

func TestBackgroundChildIsNotATimeout(t *testing.T) {
	start := time.Now()
	r := Run(Spec{Shell: "/bin/sh", Command: "sleep 5 & echo started", Timeout: 2 * time.Second, Group: true,
		KillGrace: 500 * time.Millisecond})
	if r.ExitCode != 0 || r.TimedOut || string(r.Tail) != "started\n" {
		t.Fatalf("code=%d timedOut=%v tail=%q", r.ExitCode, r.TimedOut, r.Tail)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("waited %v for a background child", d)
	}
}

func TestForwardedTermReachesGroup(t *testing.T) {
	pf := t.TempDir() + "/pid"
	go func() {
		time.Sleep(300 * time.Millisecond)
		syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}()
	r := Run(Spec{Shell: "/bin/sh", Command: "sleep 30 & echo $! > " + pf + "; wait", Group: true, KillGrace: time.Second})
	if r.ExitCode == 0 {
		t.Fatalf("code=%d", r.ExitCode)
	}
	time.Sleep(100 * time.Millisecond)
	if alive(pf) {
		t.Fatal("SIGTERM was not forwarded to the background child")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, syscall.EPIPE }

func TestBrokenTerminalKeepsCapturing(t *testing.T) {
	r := Run(Spec{Shell: "/bin/sh", Command: "echo a; echo b; exit 3", Stdout: brokenWriter{}})
	if r.ExitCode != 3 || string(r.Tail) != "a\nb\n" {
		t.Fatalf("code=%d tail=%q", r.ExitCode, r.Tail)
	}
}
