package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS whitelist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry TEXT NOT NULL UNIQUE,
  comment TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  allowed INTEGER NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  query TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  upstream_status INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_log_ts ON access_log(ts);
CREATE INDEX IF NOT EXISTS idx_access_log_ip ON access_log(client_ip);
`

func openDB(path string) (*sql.DB, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func run() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	if dir := filepath.Dir(cfg.DBPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	db, err := openDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	wl, err := NewWhitelist(db)
	if err != nil {
		return err
	}
	al := NewAccessLog(db)

	proxy, err := NewProxy(cfg.Upstream, cfg.AllowedPaths, wl, al)
	if err != nil {
		return err
	}
	admin := NewAdmin(wl, al, cfg.AdminUser, cfg.AdminPassword, cfg.AdminAuth)

	servers := []*http.Server{
		{Addr: cfg.ProxyListen, Handler: proxy},
		{Addr: cfg.AdminListen, Handler: admin},
	}

	lns := make([]net.Listener, 0, len(servers))
	for _, s := range servers {
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			return err
		}
		lns = append(lns, ln)
	}

	if cfg.AcceptProxy {
		// Fail closed: connections without a valid PROXY header are rejected.
		lns[0] = &proxyproto.Listener{
			Listener: lns[0],
			Policy:   func(net.Addr) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil },
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, len(servers))
	for i, s := range servers {
		go func(i int, s *http.Server, ln net.Listener) {
			log.Printf("listening on %s (proxy=%v)", s.Addr, i == 0)
			if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}(i, s, lns[i])
	}

	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				al.Trim(cfg.LogRetentionDays)
			}
		}
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, s := range servers {
			_ = s.Shutdown(shutdownCtx)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("whitelist-proxy: %v", err)
	}
}
