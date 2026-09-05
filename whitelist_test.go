package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestWhitelistEmptyDeny(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), false)
	if err != nil {
		t.Fatal(err)
	}
	if wl.Allow(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("empty whitelist with emptyAllow=false must deny everything")
	}
}

func TestWhitelistEmptyAllow(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), true)
	if err != nil {
		t.Fatal(err)
	}
	if !wl.Allow(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("empty whitelist with emptyAllow=true must allow everything")
	}
}

func TestWhitelistMatching(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{"10.0.0.0/8", "8.8.8.8", "2001:db8::/32"} {
		if _, err := wl.Add(e, ""); err != nil {
			t.Fatalf("add %q: %v", e, err)
		}
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"11.1.2.3", false},
		{"8.8.8.8", true},
		{"8.8.4.4", false},
		{"2001:db8::1", true},
		{"2001:db9::1", false},
	}
	for _, c := range cases {
		if got := wl.Allow(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("Allow(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestWhitelistInvalidEntry(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wl.Add("not-an-ip", ""); err == nil {
		t.Fatal("expected error for invalid entry")
	}
}

func newTestProxy(t *testing.T, upstream string) (*Proxy, *AccessLog) {
	t.Helper()
	return newTestProxyWithPaths(t, upstream, nil)
}

func newTestProxyWithPaths(t *testing.T, upstream string, allowedPaths []string) (*Proxy, *AccessLog) {
	t.Helper()
	wl, err := NewWhitelist(newTestDB(t), false)
	if err != nil {
		t.Fatal(err)
	}
	al := NewAccessLog(newTestDB(t))
	p, err := NewProxy(upstream, allowedPaths, wl, al)
	if err != nil {
		t.Fatal(err)
	}
	return p, al
}

func TestProxyDeny(t *testing.T) {
	p, al := newTestProxy(t, "http://127.0.0.1:1")

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/v1/models", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	var body struct {
		Error struct {
			Type string `json:"type"`
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Type != "access_denied" || body.Error.Code != "forbidden" {
		t.Fatalf("unexpected error body: %+v", body.Error)
	}

	attempts, total, err := al.Query(1, 10, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(attempts) != 1 {
		t.Fatalf("expected 1 logged attempt, got %d", total)
	}
	if attempts[0].Allowed || attempts[0].ClientIP != "203.0.113.7" || attempts[0].Path != "/v1/models" {
		t.Fatalf("unexpected attempt record: %+v", attempts[0])
	}
}

func TestProxyAllowStreamsAndSetsHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-For"); got != "127.0.0.1" {
			t.Errorf("X-Forwarded-For = %q, want 127.0.0.1", got)
		}
		if got := r.Header.Get("X-Real-IP"); got != "127.0.0.1" {
			t.Errorf("X-Real-IP = %q, want 127.0.0.1", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`data: hello`))
	}))
	defer upstream.Close()

	p, _ := newTestProxy(t, upstream.URL)
	if _, err := p.wl.Add("127.0.0.1", "test"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/v1/chat/completions", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	// Client-supplied header must be overwritten with the real peer IP.
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream content-type = %q", rec.Header().Get("Content-Type"))
	}
}

func TestHealthzNotBlocked(t *testing.T) {
	p, _ := newTestProxy(t, "http://127.0.0.1:1")
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/healthz", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", rec.Code)
	}
}

func TestPathAllowlist(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p, al := newTestProxyWithPaths(t, upstream.URL, []string{"/v1"})
	if _, err := p.wl.Add("127.0.0.1", "test"); err != nil {
		t.Fatal(err)
	}

	// Allowed path is proxied.
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/v1/models", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed path status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	// Non-allowed path returns 404 and is logged as denied with reason "path".
	req = httptest.NewRequest(http.MethodGet, "http://proxy.local/", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("blocked path status = %d, want 404", rec.Code)
	}
	attempts, _, err := al.Query(1, 10, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(attempts))
	}
	if attempts[0].Allowed || attempts[0].Reason != "path" {
		t.Fatalf("expected denied with reason=path, got %+v", attempts[0])
	}
}

func TestPathAllowlistEmptyAllowsAll(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p, _ := newTestProxy(t, upstream.URL)
	if _, err := p.wl.Add("127.0.0.1", "test"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/anything", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
