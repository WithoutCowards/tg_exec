// Package telegram is a minimal Bot API client: proxy (HTTP/HTTPS/SOCKS5),
// custom API endpoint and CA, retries with backoff and 429 handling.
package telegram

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Options configures a Client.
type Options struct {
	Token   string
	APIURL  string // default https://api.telegram.org
	Proxy   string // "" = from environment (HTTPS_PROXY/ALL_PROXY/NO_PROXY), "none" = direct
	CAFile  string // extra PEM CA bundle (corporate proxy, self-hosted Bot API)
	Timeout time.Duration
	Retries int // total attempts
	Backoff time.Duration
	Debug   func(format string, args ...any)
	UA      string
}

// Client talks to the Bot API.
type Client struct {
	o    Options
	http *http.Client
	base string
}

// APIError is a non-OK Bot API response.
type APIError struct {
	Status      int
	Code        int
	Description string
	RetryAfter  int
	MigrateTo   int64
}

func (e *APIError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("telegram: %d %s", e.Code, e.Description)
	}
	return fmt.Sprintf("telegram: HTTP %d", e.Status)
}

// IsParseError reports a rejected HTML entity/markup.
func IsParseError(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == 400 && strings.Contains(strings.ToLower(ae.Description), "parse entities")
}

// ProxyFunc builds the proxy selector for the given setting.
func ProxyFunc(p string) (func(*http.Request) (*url.URL, error), string, error) {
	switch strings.ToLower(p) {
	case "":
		return envProxy, "from environment", nil
	case "none":
		return nil, "none (direct)", nil
	}
	u, err := url.Parse(p)
	if err != nil || u.Host == "" {
		return nil, "", fmt.Errorf("PROXY: cannot parse %q (expected scheme://host:port)", RedactURL(p))
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, "", fmt.Errorf("PROXY: unsupported scheme %q (http, https, socks5, socks5h)", u.Scheme)
	}
	return http.ProxyURL(u), RedactURL(p), nil
}

// envProxy is http.ProxyFromEnvironment plus ALL_PROXY / all_proxy as a
// fallback (curl semantics), which Go itself ignores.
func envProxy(req *http.Request) (*url.URL, error) {
	if firstEnv("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy") != "" {
		return http.ProxyFromEnvironment(req)
	}
	all := firstEnv("ALL_PROXY", "all_proxy")
	if all == "" || noProxy(req.URL.Hostname()) {
		return nil, nil
	}
	if !strings.Contains(all, "://") {
		all = "http://" + all
	}
	return url.Parse(all)
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// noProxy implements the common NO_PROXY rules: "*", exact hosts, domain suffixes.
func noProxy(host string) bool {
	host = strings.ToLower(host)
	for _, e := range strings.Split(firstEnv("NO_PROXY", "no_proxy"), ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if h, _, err := net.SplitHostPort(e); err == nil {
			e = h
		}
		switch {
		case e == "":
		case e == "*":
			return true
		case host == strings.TrimPrefix(e, "."):
			return true
		case strings.HasSuffix(host, "."+strings.TrimPrefix(e, ".")):
			return true
		}
	}
	return false
}

// RedactURL hides the password in a URL.
func RedactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		if i := strings.LastIndex(s, "@"); i >= 0 {
			return "xxxxx@" + s[i+1:] // unparsable but may carry credentials
		}
		return s
	}
	if u.User == nil {
		return s
	}
	if _, ok := u.User.Password(); ok {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
	}
	return u.String()
}

// New creates a client.
func New(o Options) (*Client, error) {
	if o.APIURL == "" {
		o.APIURL = "https://api.telegram.org"
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.Retries < 1 {
		o.Retries = 1
	}
	if o.Debug == nil {
		o.Debug = func(string, ...any) {}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	proxy, _, err := ProxyFunc(o.Proxy)
	if err != nil {
		return nil, err
	}
	tr.Proxy = proxy
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("CA_FILE: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA_FILE %s: no PEM certificates found", o.CAFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Client{
		o:    o,
		http: &http.Client{Transport: tr},
		base: strings.TrimRight(o.APIURL, "/") + "/bot" + o.Token + "/",
	}, nil
}

type apiResp struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter      int   `json:"retry_after"`
		MigrateToChatID int64 `json:"migrate_to_chat_id"`
	} `json:"parameters"`
}

// body produces a fresh request body for every attempt.
type body func() (io.Reader, string, error)

func formBody(v url.Values) body {
	enc := v.Encode()
	return func() (io.Reader, string, error) {
		return strings.NewReader(enc), "application/x-www-form-urlencoded", nil
	}
}

func (c *Client) redact(err error) error {
	if err == nil || c.o.Token == "" || !strings.Contains(err.Error(), c.o.Token) {
		return err // keep the type (APIError) when there is nothing to hide
	}
	return errors.New(strings.ReplaceAll(err.Error(), c.o.Token, "<token>"))
}

func (c *Client) call(ctx context.Context, method string, b body, out any) error {
	return c.callT(ctx, method, b, out, c.o.Timeout)
}

func (c *Client) callT(ctx context.Context, method string, b body, out any, timeout time.Duration) error {
	var last error
	wait := c.o.Backoff
	for attempt := 1; attempt <= c.o.Retries; attempt++ {
		retry, after, err := c.once(ctx, method, b, out, timeout)
		if err == nil {
			return nil
		}
		last = c.redact(err)
		if !retry || attempt == c.o.Retries {
			break
		}
		d := wait
		if after > 0 {
			d = after
		}
		if d > time.Minute {
			d = time.Minute
		}
		c.o.Debug("%s: attempt %d/%d failed: %v; retrying in %s", method, attempt, c.o.Retries, last, d)
		select {
		case <-ctx.Done():
			return last
		case <-time.After(d):
		}
		if wait *= 2; wait > 30*time.Second {
			wait = 30 * time.Second
		}
	}
	return last
}

// once performs a single request. retry tells whether another attempt may help.
func (c *Client) once(ctx context.Context, method string, b body, out any, timeout time.Duration) (retry bool, after time.Duration, err error) {
	rd, ctype, err := b()
	if err != nil {
		return false, 0, err
	}
	if cl, ok := rd.(io.Closer); ok {
		defer cl.Close()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+method, rd)
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("Content-Type", ctype)
	if c.o.UA != "" {
		req.Header.Set("User-Agent", c.o.UA)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return true, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return true, 0, err
	}
	var ar apiResp
	if jerr := json.Unmarshal(raw, &ar); jerr != nil {
		snippet := strings.TrimSpace(string(raw))
		if c.o.Token != "" {
			snippet = strings.ReplaceAll(snippet, c.o.Token, "<token>")
		}
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return resp.StatusCode >= 500 || resp.StatusCode == 429,
			0, fmt.Errorf("telegram: HTTP %d, not a Bot API response: %q", resp.StatusCode, snippet)
	}
	if !ar.OK {
		ae := &APIError{Status: resp.StatusCode, Code: ar.ErrorCode, Description: ar.Description,
			RetryAfter: ar.Parameters.RetryAfter, MigrateTo: ar.Parameters.MigrateToChatID}
		if ae.Code == 0 {
			ae.Code = resp.StatusCode
		}
		switch {
		case ae.Code == 429:
			return true, time.Duration(max(ae.RetryAfter, 1)) * time.Second, ae
		case ae.Code >= 500:
			return true, 0, ae
		}
		return false, 0, ae
	}
	if out != nil {
		if err := json.Unmarshal(ar.Result, out); err != nil {
			return false, 0, fmt.Errorf("telegram: decode %s result: %w", method, err)
		}
	}
	return false, 0, nil
}

// User is a Telegram user/bot.
type User struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

// GetMe checks the token.
func (c *Client) GetMe(ctx context.Context) (User, error) {
	var u User
	err := c.call(ctx, "getMe", formBody(url.Values{}), &u)
	return u, err
}

// Target is where messages go.
type Target struct {
	ChatID   string
	ThreadID int64
	Silent   bool
}

func (t Target) values() url.Values {
	v := url.Values{}
	v.Set("chat_id", t.ChatID)
	if t.ThreadID > 0 {
		v.Set("message_thread_id", strconv.FormatInt(t.ThreadID, 10))
	}
	if t.Silent {
		v.Set("disable_notification", "true")
	}
	return v
}

// SendHTML sends an HTML message. If Telegram rejects the markup, it is
// re-sent as plain text so the notification is never lost.
func (c *Client) SendHTML(ctx context.Context, t Target, html, plain string) error {
	v := t.values()
	v.Set("text", html)
	v.Set("parse_mode", "HTML")
	v.Set("link_preview_options", `{"is_disabled":true}`)
	err := c.call(ctx, "sendMessage", formBody(v), nil)
	if err != nil && IsParseError(err) && plain != "" {
		c.o.Debug("HTML rejected (%v), resending as plain text", err)
		v.Del("parse_mode")
		v.Set("text", plain)
		err = c.call(ctx, "sendMessage", formBody(v), nil)
	}
	return err
}

// SendDocument uploads a file with an HTML caption.
func (c *Client) SendDocument(ctx context.Context, t Target, path, filename, caption string) error {
	if filename == "" {
		filename = filepath.Base(path)
	}
	fields := t.values()
	fields.Set("caption", caption)
	fields.Set("parse_mode", "HTML")
	b := func() (io.Reader, string, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, "", err
		}
		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		go func() {
			defer f.Close()
			for k, vs := range fields {
				for _, v := range vs {
					if err := mw.WriteField(k, v); err != nil {
						pw.CloseWithError(err)
						return
					}
				}
			}
			fw, err := mw.CreateFormFile("document", filename)
			if err == nil {
				_, err = io.Copy(fw, f)
			}
			if err == nil {
				err = mw.Close()
			}
			pw.CloseWithError(err)
		}()
		return pr, mw.FormDataContentType(), nil
	}
	// Uploads get extra time: at least 256 KiB/s on top of the request timeout.
	timeout := c.o.Timeout
	if st, err := os.Stat(path); err == nil {
		timeout += time.Duration(st.Size()/(256<<10)+1) * time.Second
	}
	return c.callT(ctx, "sendDocument", b, nil, timeout)
}

// Chat is a chat seen in updates.
type Chat struct {
	ID       int64  `json:"id"`
	Type     string `json:"type"`
	Title    string `json:"title"`
	Username string `json:"username"`
	First    string `json:"first_name"`
	IsForum  bool   `json:"is_forum"`
}

// Name is a readable chat label.
func (ch Chat) Name() string {
	switch {
	case ch.Title != "":
		return ch.Title
	case ch.Username != "":
		return "@" + ch.Username
	default:
		return ch.First
	}
}

type message struct {
	Chat     Chat  `json:"chat"`
	ThreadID int64 `json:"message_thread_id"`
	IsTopic  bool  `json:"is_topic_message"`
}

// Update is the subset of an update used to discover chats.
type Update struct {
	ID           int64    `json:"update_id"`
	Message      *message `json:"message"`
	ChannelPost  *message `json:"channel_post"`
	MyChatMember *struct {
		Chat Chat `json:"chat"`
	} `json:"my_chat_member"`
}

// SeenChat is a chat plus a forum topic, if the message was in one.
type SeenChat struct {
	Chat     Chat
	ThreadID int64
}

// RecentChats returns chats from pending updates (newest last), without
// consuming them.
func (c *Client) RecentChats(ctx context.Context) ([]SeenChat, error) {
	var ups []Update
	v := url.Values{}
	v.Set("timeout", "0")
	v.Set("allowed_updates", `["message","channel_post","my_chat_member"]`)
	if err := c.call(ctx, "getUpdates", formBody(v), &ups); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []SeenChat
	add := func(ch Chat, thread int64) {
		key := fmt.Sprintf("%d/%d", ch.ID, thread)
		if ch.ID == 0 || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, SeenChat{ch, thread})
	}
	for _, u := range ups {
		switch {
		case u.Message != nil:
			th := int64(0)
			if u.Message.IsTopic {
				th = u.Message.ThreadID
			}
			add(u.Message.Chat, th)
		case u.ChannelPost != nil:
			add(u.ChannelPost.Chat, 0)
		case u.MyChatMember != nil:
			add(u.MyChatMember.Chat, 0)
		}
	}
	return out, nil
}
