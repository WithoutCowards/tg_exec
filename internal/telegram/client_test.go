package telegram

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const tok = "123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// fakeAPI is a minimal Bot API.
type fakeAPI struct {
	mu       sync.Mutex
	calls    []string
	texts    []string
	failures map[string][]string // method -> queued JSON error bodies
	docs     []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "bot"+tok {
		w.WriteHeader(404)
		fmt.Fprint(w, `{"ok":false,"error_code":404,"description":"Not Found"}`)
		return
	}
	method := parts[1]
	f.mu.Lock()
	f.calls = append(f.calls, method)
	if q := f.failures[method]; len(q) > 0 {
		f.failures[method] = q[1:]
		f.mu.Unlock()
		w.WriteHeader(400)
		fmt.Fprint(w, q[0])
		return
	}
	f.mu.Unlock()
	switch method {
	case "getMe":
		fmt.Fprint(w, `{"ok":true,"result":{"id":123456,"is_bot":true,"first_name":"T","username":"test_bot"}}`)
	case "sendMessage":
		_ = r.ParseForm()
		f.mu.Lock()
		f.texts = append(f.texts, r.Form.Get("parse_mode")+"|"+r.Form.Get("chat_id")+"|"+r.Form.Get("text"))
		f.mu.Unlock()
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":1}}`)
	case "sendDocument":
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			w.WriteHeader(400)
			return
		}
		file, hdr, _ := r.FormFile("document")
		b, _ := io.ReadAll(file)
		f.mu.Lock()
		f.docs = append(f.docs, hdr.Filename+"|"+r.FormValue("caption")+"|"+string(b))
		f.mu.Unlock()
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":2}}`)
	case "getUpdates":
		fmt.Fprint(w, `{"ok":true,"result":[
			{"update_id":1,"message":{"chat":{"id":42,"type":"private","first_name":"Ann"}}},
			{"update_id":2,"message":{"chat":{"id":-1001,"type":"supergroup","title":"Ops","is_forum":true},"message_thread_id":7,"is_topic_message":true}},
			{"update_id":3,"message":{"chat":{"id":42,"type":"private","first_name":"Ann"}}}]}`)
	default:
		w.WriteHeader(404)
		fmt.Fprint(w, `{"ok":false,"error_code":404,"description":"method not found"}`)
	}
}

func newTLSAPI(t *testing.T) (*fakeAPI, *httptest.Server, string) {
	f := &fakeAPI{failures: map[string][]string{}}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return f, srv, ca
}

func TestCAFileAndSend(t *testing.T) {
	f, srv, ca := newTLSAPI(t)
	// Without CA_FILE the self-signed endpoint must be rejected.
	c, _ := New(Options{Token: tok, APIURL: srv.URL, Proxy: "none", Retries: 1})
	if _, err := c.GetMe(context.Background()); err == nil || strings.Contains(err.Error(), tok) {
		t.Fatalf("expected TLS error without token in it, got %v", err)
	}
	c, err := New(Options{Token: tok, APIURL: srv.URL, Proxy: "none", CAFile: ca, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	me, err := c.GetMe(context.Background())
	if err != nil || me.Username != "test_bot" {
		t.Fatalf("getMe: %v %+v", err, me)
	}
	if err := c.SendHTML(context.Background(), Target{ChatID: "-100", ThreadID: 7}, "<b>hi</b>", "hi"); err != nil {
		t.Fatal(err)
	}
	if f.texts[0] != "HTML|-100|<b>hi</b>" {
		t.Fatalf("sent %q", f.texts[0])
	}
}

func TestParseErrorFallsBackToPlain(t *testing.T) {
	f, srv, ca := newTLSAPI(t)
	f.failures["sendMessage"] = []string{`{"ok":false,"error_code":400,"description":"Bad Request: can't parse entities: unclosed tag"}`}
	c, _ := New(Options{Token: tok, APIURL: srv.URL, Proxy: "none", CAFile: ca, Retries: 3})
	if err := c.SendHTML(context.Background(), Target{ChatID: "1"}, "<b>broken", "broken"); err != nil {
		t.Fatal(err)
	}
	if len(f.texts) != 1 || f.texts[0] != "|1|broken" {
		t.Fatalf("fallback not plain: %q", f.texts)
	}
}

func TestRetry429AndNoRetryOn400(t *testing.T) {
	f, srv, ca := newTLSAPI(t)
	f.failures["sendMessage"] = []string{`{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":1}}`}
	c, _ := New(Options{Token: tok, APIURL: srv.URL, Proxy: "none", CAFile: ca, Retries: 3, Backoff: 10 * time.Millisecond})
	start := time.Now()
	if err := c.SendHTML(context.Background(), Target{ChatID: "1"}, "x", "x"); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 900*time.Millisecond {
		t.Error("retry_after was not respected")
	}
	f.failures["sendMessage"] = []string{`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`}
	n := len(f.calls)
	err := c.SendHTML(context.Background(), Target{ChatID: "1"}, "x", "x")
	if err == nil || !strings.Contains(err.Error(), "chat not found") || len(f.calls)-n != 1 {
		t.Fatalf("400 must fail fast: %v, calls %d", err, len(f.calls)-n)
	}
}

func TestMigrateParsed(t *testing.T) {
	f, srv, ca := newTLSAPI(t)
	f.failures["sendMessage"] = []string{`{"ok":false,"error_code":400,"description":"Bad Request: group chat was upgraded to a supergroup chat","parameters":{"migrate_to_chat_id":-1009}}`}
	c, _ := New(Options{Token: tok, APIURL: srv.URL, Proxy: "none", CAFile: ca})
	err := c.SendHTML(context.Background(), Target{ChatID: "1"}, "x", "x")
	ae, ok := err.(*APIError)
	if !ok || ae.MigrateTo != -1009 {
		t.Fatalf("got %#v", err)
	}
}

func TestSendDocument(t *testing.T) {
	f, srv, ca := newTLSAPI(t)
	p := filepath.Join(t.TempDir(), "x.log")
	os.WriteFile(p, []byte("full log"), 0o600)
	c, _ := New(Options{Token: tok, APIURL: srv.URL, Proxy: "none", CAFile: ca})
	if err := c.SendDocument(context.Background(), Target{ChatID: "1"}, p, "run.log", "📎 cap"); err != nil {
		t.Fatal(err)
	}
	if f.docs[0] != "run.log|📎 cap|full log" {
		t.Fatalf("doc %q", f.docs[0])
	}
}

func TestRecentChats(t *testing.T) {
	_, srv, ca := newTLSAPI(t)
	c, _ := New(Options{Token: tok, APIURL: srv.URL, Proxy: "none", CAFile: ca})
	chats, err := c.RecentChats(context.Background())
	if err != nil || len(chats) != 2 || chats[1].ThreadID != 7 || chats[0].Chat.Name() != "Ann" {
		t.Fatalf("%v %+v", err, chats)
	}
}

// --- proxies ---------------------------------------------------------------

func pipe(a, b net.Conn) {
	go func() { io.Copy(a, b); a.Close() }()
	io.Copy(b, a)
	b.Close()
}

func TestHTTPConnectProxy(t *testing.T) {
	_, srv, ca := newTLSAPI(t)
	var used atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("Proxy-Authorization") == "" {
			w.Header().Set("Proxy-Authenticate", "Basic")
			w.WriteHeader(407)
			return
		}
		used.Add(1)
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		w.WriteHeader(200)
		conn, _, _ := w.(http.Hijacker).Hijack()
		pipe(conn, up)
	}))
	defer proxy.Close()
	purl := strings.Replace(proxy.URL, "http://", "http://u:secret@", 1)
	c, err := New(Options{Token: tok, APIURL: srv.URL, Proxy: purl, CAFile: ca, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetMe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if used.Load() == 0 {
		t.Fatal("proxy not used")
	}
	if RedactURL(purl) == purl || strings.Contains(RedactURL(purl), "secret") {
		t.Error("password not redacted")
	}
}

// socks5Server is a tiny RFC 1928 server (no auth / user+pass) for tests.
func socks5Server(t *testing.T, user, pass string) (addr string, used *atomic.Int32) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	used = &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				hdr := make([]byte, 2)
				io.ReadFull(r, hdr)
				methods := make([]byte, hdr[1])
				io.ReadFull(r, methods)
				if user != "" {
					c.Write([]byte{5, 2})
					b := make([]byte, 2)
					io.ReadFull(r, b)
					u := make([]byte, b[1])
					io.ReadFull(r, u)
					pl, _ := r.ReadByte()
					p := make([]byte, pl)
					io.ReadFull(r, p)
					if string(u) != user || string(p) != pass {
						c.Write([]byte{1, 1})
						return
					}
					c.Write([]byte{1, 0})
				} else {
					c.Write([]byte{5, 0})
				}
				req := make([]byte, 4)
				io.ReadFull(r, req)
				var host string
				switch req[3] {
				case 1:
					ip := make([]byte, 4)
					io.ReadFull(r, ip)
					host = net.IP(ip).String()
				case 3:
					l, _ := r.ReadByte()
					h := make([]byte, l)
					io.ReadFull(r, h)
					host = string(h)
				default:
					return
				}
				pb := make([]byte, 2)
				io.ReadFull(r, pb)
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				used.Add(1)
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				pipe(&bufConn{c, r}, up)
			}(conn)
		}
	}()
	return ln.Addr().String(), used
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestSOCKS5Proxy(t *testing.T) {
	_, srv, ca := newTLSAPI(t)
	for _, scheme := range []string{"socks5", "socks5h"} {
		addr, used := socks5Server(t, "u", "p@ss")
		c, err := New(Options{Token: tok, APIURL: srv.URL, Proxy: scheme + "://u:p%40ss@" + addr, CAFile: ca, Retries: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.GetMe(context.Background()); err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		if used.Load() == 0 {
			t.Fatalf("%s proxy not used", scheme)
		}
	}
}

func TestProxyValidation(t *testing.T) {
	for _, p := range []string{"ftp://x:1", "nonsense", "socks4://h:1"} {
		if _, _, err := ProxyFunc(p); err == nil {
			t.Errorf("%q must be rejected", p)
		}
	}
	for _, p := range []string{"", "none", "http://h:3128", "https://h:443", "socks5h://h:1080"} {
		if _, _, err := ProxyFunc(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
}
