//go:build unix

// Package runner executes the user's command, mirrors its output to the
// terminal and keeps the tail (and optionally a full spool file) for the report.
package runner

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Spec describes what to run.
type Spec struct {
	Args       []string // program and arguments (direct exec)
	Shell      string   // if set, run Shell -c Command
	Command    string   // command line for shell mode
	Timeout    time.Duration
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	TailBytes  int   // bytes of output kept in memory (default 64 KiB)
	SpoolLimit int64 // >0: also write output to a temp file up to this size
	KillGrace  time.Duration
	Group      bool // run in its own process group (use when stdin is not a terminal)
}

// Result is what happened.
type Result struct {
	Start, End time.Time
	ExitCode   int
	Signal     string // e.g. SIGTERM when killed by a signal
	TimedOut   bool
	StartErr   error

	Tail       []byte // last TailBytes of combined output
	TotalBytes int64
	TotalLines int64

	SpoolPath      string // full output (caller removes it)
	SpoolTruncated bool
}

// Failed reports a non-successful run.
func (r *Result) Failed() bool { return r.ExitCode != 0 || r.StartErr != nil || r.TimedOut }

// Run executes the command and blocks until it finishes.
func Run(s Spec) *Result {
	if s.TailBytes <= 0 {
		s.TailBytes = 64 << 10
	}
	if s.KillGrace <= 0 {
		s.KillGrace = 10 * time.Second
	}
	if s.Stdout == nil {
		s.Stdout = io.Discard
	}
	if s.Stderr == nil {
		s.Stderr = io.Discard
	}

	cp := &capture{tail: newRing(s.TailBytes)}
	if s.SpoolLimit > 0 {
		if f, err := os.CreateTemp("", "tg-exec-*.log"); err == nil {
			_ = f.Chmod(0o600)
			cp.spool, cp.spoolLimit = f, s.SpoolLimit
		}
	}

	var cmd *exec.Cmd
	if s.Shell != "" {
		cmd = exec.Command(s.Shell, "-c", s.Command)
	} else {
		cmd = exec.Command(s.Args[0], s.Args[1:]...)
	}
	cmd.Stdin = s.Stdin
	if s.Group {
		// Own process group: timeouts and forwarded signals reach pipelines
		// and background children too, not just the shell.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	// Our own pipes: Wait returns exactly when the process exits, even if a
	// background child still holds the output open.
	var mu sync.Mutex
	outR, outW, err1 := os.Pipe()
	errR, errW, err2 := os.Pipe()
	res := &Result{Start: time.Now()}
	if err := errors.Join(err1, err2); err != nil {
		res.End, res.StartErr, res.ExitCode = time.Now(), err, 1
		cp.finish(res)
		return res
	}
	cmd.Stdout, cmd.Stderr = outW, errW

	// SIGPIPE must be caught, or a closed reader of our stdout (| head,
	// restarted journald) kills tg-exec before it can report. A caught signal
	// is reset to default in the child, so the job behaves as usual.
	// SIGINT/SIGQUIT from a terminal reach the job directly (same process
	// group); without a terminal they are forwarded like SIGTERM/SIGHUP.
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		outW.Close()
		errW.Close()
		outR.Close()
		errR.Close()
		res.End = time.Now()
		res.StartErr = err
		res.ExitCode = startExitCode(err)
		cp.finish(res)
		return res
	}
	outW.Close()
	errW.Close()

	pid := cmd.Process.Pid
	kill := func(sig syscall.Signal) {
		if s.Group {
			_ = syscall.Kill(-pid, sig)
		} else {
			_ = cmd.Process.Signal(sig)
		}
	}

	var copies sync.WaitGroup
	for _, p := range []struct {
		r *os.File
		w io.Writer
	}{{outR, s.Stdout}, {errR, s.Stderr}} {
		copies.Add(1)
		go func(r *os.File, w io.Writer) {
			defer copies.Done()
			_, _ = io.Copy(&locked{mu: &mu, w: w, c: cp}, r)
		}(p.r, p.w)
	}

	var state sync.Mutex
	exited, timedOut := false, false
	var timer, killer *time.Timer
	if s.Timeout > 0 {
		timer = time.AfterFunc(s.Timeout, func() {
			state.Lock()
			defer state.Unlock()
			if exited {
				return
			}
			timedOut = true
			kill(syscall.SIGTERM)
			killer = time.AfterFunc(s.KillGrace, func() { kill(syscall.SIGKILL) })
		})
	}

	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigs:
				switch sig {
				case syscall.SIGTERM, syscall.SIGHUP:
					kill(sig.(syscall.Signal))
				case syscall.SIGINT, syscall.SIGQUIT:
					if s.Group {
						kill(sig.(syscall.Signal))
					}
				}
			case <-done:
				return
			}
		}
	}()

	err := cmd.Wait()
	state.Lock()
	exited = true
	res.TimedOut = timedOut
	if timer != nil {
		timer.Stop()
	}
	state.Unlock()
	close(done)

	// Give background children a moment to finish writing, then stop reading:
	// a daemon started without redirects must not hold up the report.
	drain := time.Second
	if res.TimedOut {
		drain = s.KillGrace
	}
	finished := make(chan struct{})
	go func() { copies.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(drain):
		if res.TimedOut {
			kill(syscall.SIGKILL)
		}
		outR.SetReadDeadline(time.Now())
		errR.SetReadDeadline(time.Now())
		<-finished
	}
	outR.Close()
	errR.Close()
	if res.TimedOut {
		kill(syscall.SIGKILL) // whatever ignored SIGTERM in the group
	}
	if killer != nil {
		killer.Stop()
	}
	res.End = time.Now()

	if ps := cmd.ProcessState; ps != nil {
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res.Signal = SignalName(ws.Signal())
			res.ExitCode = 128 + int(ws.Signal())
		} else {
			res.ExitCode = ps.ExitCode()
		}
	} else if err != nil {
		res.ExitCode = 1
	}
	if res.TimedOut {
		res.ExitCode, res.Signal = 124, "" // we sent the signal ourselves
	}
	if res.ExitCode == -1 {
		res.ExitCode = 1
	}
	cp.finish(res)
	return res
}

func startExitCode(err error) int {
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
		return 127
	}
	if errors.Is(err, fs.ErrPermission) {
		return 126
	}
	return 127
}

// SignalName maps common signals to their short names.
func SignalName(s syscall.Signal) string {
	names := map[syscall.Signal]string{
		syscall.SIGHUP: "SIGHUP", syscall.SIGINT: "SIGINT", syscall.SIGQUIT: "SIGQUIT",
		syscall.SIGILL: "SIGILL", syscall.SIGABRT: "SIGABRT", syscall.SIGBUS: "SIGBUS",
		syscall.SIGFPE: "SIGFPE", syscall.SIGKILL: "SIGKILL", syscall.SIGSEGV: "SIGSEGV",
		syscall.SIGPIPE: "SIGPIPE", syscall.SIGALRM: "SIGALRM", syscall.SIGTERM: "SIGTERM",
		syscall.SIGUSR1: "SIGUSR1", syscall.SIGUSR2: "SIGUSR2", syscall.SIGXCPU: "SIGXCPU",
	}
	if n, ok := names[s]; ok {
		return n
	}
	return "signal " + itoa(int(s))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ShellQuote renders args as a copy-pasteable shell command line.
func ShellQuote(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a != "" && strings.IndexFunc(a, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
				strings.ContainsRune("-_./:=@%+,", r))
		}) < 0 {
			out[i] = a
			continue
		}
		out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(out, " ")
}

type capture struct {
	tail       *ring
	total      int64
	lines      int64
	spool      *os.File
	spoolLimit int64
	spooled    int64
	spoolTrunc bool
}

func (c *capture) Write(p []byte) (int, error) {
	c.total += int64(len(p))
	for _, b := range p {
		if b == '\n' {
			c.lines++
		}
	}
	c.tail.Write(p)
	if c.spool != nil && !c.spoolTrunc {
		room := c.spoolLimit - c.spooled
		chunk := p
		if int64(len(chunk)) > room {
			chunk = chunk[:room]
			c.spoolTrunc = true
		}
		if n, err := c.spool.Write(chunk); err != nil {
			c.spoolTrunc = true
		} else {
			c.spooled += int64(n)
		}
	}
	return len(p), nil
}

func (c *capture) finish(r *Result) {
	r.Tail = c.tail.Bytes()
	r.TotalBytes = c.total
	r.TotalLines = c.lines
	if c.total > 0 && len(r.Tail) > 0 && r.Tail[len(r.Tail)-1] != '\n' {
		r.TotalLines++
	}
	if c.spool != nil {
		c.spool.Close()
		if c.total == 0 {
			os.Remove(c.spool.Name())
		} else {
			r.SpoolPath = c.spool.Name()
			r.SpoolTruncated = c.spoolTrunc
		}
	}
}

// locked mirrors output to the terminal and the capture under one lock, so
// stdout and stderr interleave in the report as they did on screen.
type locked struct {
	mu *sync.Mutex
	w  io.Writer
	c  *capture
}

func (l *locked) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w != nil {
		if _, err := l.w.Write(p); err != nil {
			l.w = nil // reader went away (EPIPE): keep capturing, stop mirroring
		}
	}
	return l.c.Write(p)
}

// ring keeps the last n bytes written.
type ring struct {
	buf  []byte
	n    int
	full bool
	pos  int
}

func newRing(n int) *ring { return &ring{buf: make([]byte, n), n: n} }

func (r *ring) Write(p []byte) {
	if len(p) >= r.n {
		copy(r.buf, p[len(p)-r.n:])
		r.pos, r.full = 0, true
		return
	}
	k := copy(r.buf[r.pos:], p)
	if k < len(p) {
		copy(r.buf, p[k:])
		r.full = true
	}
	r.pos = (r.pos + len(p)) % r.n
	if r.pos == 0 && len(p) > 0 {
		r.full = true
	}
}

func (r *ring) Bytes() []byte {
	if !r.full {
		return append([]byte(nil), r.buf[:r.pos]...)
	}
	out := make([]byte, 0, r.n)
	out = append(out, r.buf[r.pos:]...)
	return append(out, r.buf[:r.pos]...)
}
