package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

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
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if wl.Allow(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("empty whitelist must deny everything")
	}
}

func TestWhitelistMatching(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
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
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
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
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	al := NewAccessLog(10000)
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

	// Non-allowed path returns 403 (generic denial) and is logged as denied with reason "path".
	req = httptest.NewRequest(http.MethodGet, "http://proxy.local/", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blocked path status = %d, want 403", rec.Code)
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

func TestPathAllowed(t *testing.T) {
	allow := []string{"/v1", "/api/"}
	cases := []struct {
		path string
		want bool
	}{
		{"/v1", true},
		{"/v1/", true},
		{"/v1/models", true},
		{"/v1/models/chat", true},
		{"/v1evil", false},
		{"/v1evil/models", false},
		{"/v1/../admin", false},
		{"/v1/a/../../admin", false},
		{"/v1/../v1/models", true},
		{"/v1/./models", true},
		{"/v1//x", true},
		{"//v1/models", false},
		{"/api", true},
		{"/api/", true},
		{"/api/users", true},
		{"/api/../admin", false},
		{"/other", false},
	}
	for _, c := range cases {
		if got := pathAllowed(c.path, allow); got != c.want {
			t.Errorf("pathAllowed(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestPathAllowedEmptyAllowsAll(t *testing.T) {
	if !pathAllowed("/anything", nil) {
		t.Fatal("empty allow list must permit every path")
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

func TestAccessLogRingBufferEviction(t *testing.T) {
	al := NewAccessLog(3)
	for i := 0; i < 5; i++ {
		al.Record(Attempt{TS: "t", ClientIP: "10.0.0.1", Allowed: true, Method: "GET", Path: "/v1", Query: "", UserAgent: "", UpstreamStatus: 200, DurationMS: 1})
	}
	attempts, total, err := al.Query(1, 10, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(attempts) != 3 {
		t.Fatalf("expected 3 retained attempts, got total=%d len=%d", total, len(attempts))
	}
	if attempts[0].ID != 4 {
		t.Fatalf("newest attempt ID = %d, want 4", attempts[0].ID)
	}
	if attempts[2].ID != 2 {
		t.Fatalf("oldest retained attempt ID = %d, want 2", attempts[2].ID)
	}
}

func TestAccessLogPathFilter(t *testing.T) {
	al := NewAccessLog(10)
	for _, p := range []string{"/v1/models", "/v1/chat", "/healthz"} {
		al.Record(Attempt{TS: "t", ClientIP: "10.0.0.1", Allowed: false, Method: "GET", Path: p, Query: "", UserAgent: "", UpstreamStatus: 0, DurationMS: 1})
	}
	attempts, total, err := al.Query(1, 10, nil, "/v1")
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(attempts) != 2 {
		t.Fatalf("expected 2 /v1 attempts, got total=%d len=%d", total, len(attempts))
	}

	denied := false
	attempts, total, err = al.Query(1, 10, &denied, "")
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("expected 3 denied attempts, got %d", total)
	}

	allowed := true
	attempts, _, err = al.Query(1, 10, &allowed, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 0 {
		t.Fatalf("expected 0 allowed attempts, got %d", len(attempts))
	}
}

func TestAccessLogNotPersistedToSQLite(t *testing.T) {
	db := newTestDB(t)
	wl, err := NewWhitelist(db, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	al := NewAccessLog(100)
	p, err := NewProxy("http://127.0.0.1:1", nil, wl, al)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/v1/models", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='access_log'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("access_log table must not exist; found %d", count)
	}

	if _, err := wl.Add("203.0.113.7", "test"); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "http://proxy.local/v1/models", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("allowed attempt status = %d, want 502", rec.Code)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='access_log'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("allowed attempts must also not be persisted; access_log found %d", count)
	}
}

func TestWhitelistTimeWindow(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wl.AddScheduled("203.0.113.7", "work hours", nil, "09:00", "17:00"); err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr("203.0.113.7")
	if ok, reason := wl.checkAt(ip, time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)); !ok {
		t.Fatalf("12:00 should be allowed, got reason %q", reason)
	}
	if ok, reason := wl.checkAt(ip, time.Date(2026, 1, 5, 8, 59, 0, 0, time.UTC)); ok || reason != "time" {
		t.Fatalf("08:59 should be denied with reason time, got ok=%v reason=%q", ok, reason)
	}
	if ok, reason := wl.checkAt(ip, time.Date(2026, 1, 5, 17, 1, 0, 0, time.UTC)); ok || reason != "time" {
		t.Fatalf("17:01 should be denied with reason time, got ok=%v reason=%q", ok, reason)
	}
}

func TestWhitelistDayWindow(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	// 2026-01-05 is a Monday.
	if _, err := wl.AddScheduled("203.0.113.7", "weekdays", []int{1, 2, 3}, "", ""); err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr("203.0.113.7")
	if ok, _ := wl.checkAt(ip, time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)); !ok {
		t.Fatalf("Monday should be allowed")
	}
	if ok, reason := wl.checkAt(ip, time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)); ok || reason != "time" {
		t.Fatalf("Saturday should be denied with reason time, got ok=%v reason=%q", ok, reason)
	}
}

func TestWhitelistMixedRestrictedAndOpen(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wl.Add("203.0.113.0/24", "open subnet"); err != nil {
		t.Fatal(err)
	}
	if _, err := wl.AddScheduled("203.0.113.7", "restricted host", nil, "09:00", "17:00"); err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr("203.0.113.7")
	// The restricted entry is out of window, but the open subnet entry allows it.
	if ok, reason := wl.checkAt(ip, time.Date(2026, 1, 5, 20, 0, 0, 0, time.UTC)); !ok {
		t.Fatalf("open subnet should allow even outside the host window, got reason %q", reason)
	}
}

func TestWhitelistDaysRoundTrip(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wl.AddScheduled("203.0.113.7", "", []int{7, 1, 3, 1}, "", ""); err != nil {
		t.Fatal(err)
	}
	e := wl.List()[0]
	want := []int{1, 3, 7} // deduplicated and sorted ascending
	if len(e.Days) != len(want) {
		t.Fatalf("Days = %v, want %v", e.Days, want)
	}
	for i := range want {
		if e.Days[i] != want[i] {
			t.Fatalf("Days = %v, want %v", e.Days, want)
		}
	}
	// Reloaded from DB: still numbers.
	wl2, err := NewWhitelist(wl.db, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	e2 := wl2.List()[0]
	if len(e2.Days) != len(want) || e2.Days[0] != 1 || e2.Days[1] != 3 || e2.Days[2] != 7 {
		t.Fatalf("Days after reload = %v, want %v", e2.Days, want)
	}
}

func TestAdminAddWhitelistNumericDays(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	a := NewAdmin(wl, NewAccessLog(10), "u", "p", false)
	body := strings.NewReader(`{"entry":"203.0.113.10","comment":"c","days":[2,4],"start":"08:00","end":"18:00"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/whitelist", body)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var e WhitelistEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if len(e.Days) != 2 || e.Days[0] != 2 || e.Days[1] != 4 {
		t.Fatalf("Days = %v, want [2 4]", e.Days)
	}
	if e.StartTime != "08:00" || e.EndTime != "18:00" {
		t.Fatalf("window = %q-%q", e.StartTime, e.EndTime)
	}
}

func TestAdminAllowAttemptScheduled(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	al := NewAccessLog(100)
	al.Record(Attempt{TS: "t", ClientIP: "203.0.113.9", Allowed: false, Method: "GET", Path: "/v1"})
	a := NewAdmin(wl, al, "u", "p", false)

	body := strings.NewReader(`{"comment":"ok","days":[1,3],"start":"09:00","end":"17:00"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/attempts/0/allow", body)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var e WhitelistEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if len(e.Days) != 2 || e.Days[0] != 1 || e.Days[1] != 3 {
		t.Fatalf("Days = %v, want [1 3]", e.Days)
	}
	if e.StartTime != "09:00" || e.EndTime != "17:00" {
		t.Fatalf("window = %q-%q", e.StartTime, e.EndTime)
	}
	ip := netip.MustParseAddr("203.0.113.9")
	// days [1,3] = Mon,Wed; window 09:00-17:00. Monday 2026-01-05 12:00 is in window.
	if ok, reason := wl.checkAt(ip, time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)); !ok {
		t.Fatalf("IP should be allowed Monday noon, got reason %q", reason)
	}
	if ok, _ := wl.checkAt(ip, time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)); ok {
		t.Fatal("IP should be denied on Saturday (day not selected)")
	}
}

func TestAdminAllowAttemptEmptyBody(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	al := NewAccessLog(100)
	al.Record(Attempt{TS: "t", ClientIP: "203.0.113.11", Allowed: false, Method: "GET", Path: "/v1"})
	a := NewAdmin(wl, al, "u", "p", false)

	req := httptest.NewRequest(http.MethodPost, "/api/attempts/0/allow", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	e := wl.List()[0]
	if len(e.Days) != 0 || e.StartTime != "" || e.EndTime != "" {
		t.Fatalf("expected unrestricted allow, got %+v", e)
	}
	if e.Comment != "allowed from attempt #0" {
		t.Fatalf("comment = %q", e.Comment)
	}
	if !wl.Allow(netip.MustParseAddr("203.0.113.11")) {
		t.Fatal("IP should now be allowed")
	}
}

func TestAdminAllowAttemptInvalidDays(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	al := NewAccessLog(100)
	al.Record(Attempt{TS: "t", ClientIP: "203.0.113.12", Allowed: false, Method: "GET", Path: "/v1"})
	a := NewAdmin(wl, al, "u", "p", false)

	body := strings.NewReader(`{"days":[0]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/attempts/0/allow", body)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestWhitelistInvalidScheduledEntry(t *testing.T) {
	wl, err := NewWhitelist(newTestDB(t), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wl.AddScheduled("203.0.113.7", "", []int{0}, "", ""); err == nil {
		t.Fatal("expected error for invalid day 0")
	}
	if _, err := wl.AddScheduled("203.0.113.7", "", []int{8}, "", ""); err == nil {
		t.Fatal("expected error for invalid day 8")
	}
	if _, err := wl.AddScheduled("203.0.113.7", "", nil, "18:00", "09:00"); err == nil {
		t.Fatal("expected error for start >= end")
	}
	if _, err := wl.AddScheduled("203.0.113.7", "", nil, "09:00", ""); err == nil {
		t.Fatal("expected error for start without end")
	}
}
