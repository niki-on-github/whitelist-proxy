package main

import (
	"database/sql"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

type WhitelistEntry struct {
	ID        int64  `json:"id"`
	Entry     string `json:"entry"`
	Comment   string `json:"comment"`
	CreatedAt string `json:"created_at"`
}

type Whitelist struct {
	mu         sync.RWMutex
	db         *sql.DB
	prefixes   []netip.Prefix
	entries    []WhitelistEntry
	emptyAllow bool
}

func NewWhitelist(db *sql.DB, emptyAllow bool) (*Whitelist, error) {
	w := &Whitelist{db: db, emptyAllow: emptyAllow}
	if err := w.reload(); err != nil {
		return nil, err
	}
	return w, nil
}

func parseEntry(s string) (netip.Prefix, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid whitelist entry %q: must be an IP or CIDR", s)
	}
	return p.Masked(), nil
}

func (w *Whitelist) reload() error {
	rows, err := w.db.Query(`SELECT id, entry, comment, created_at FROM whitelist ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var entries []WhitelistEntry
	var prefixes []netip.Prefix
	for rows.Next() {
		var e WhitelistEntry
		if err := rows.Scan(&e.ID, &e.Entry, &e.Comment, &e.CreatedAt); err != nil {
			return err
		}
		p, err := parseEntry(e.Entry)
		if err != nil {
			continue
		}
		entries = append(entries, e)
		prefixes = append(prefixes, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	w.mu.Lock()
	w.entries = entries
	w.prefixes = prefixes
	w.mu.Unlock()
	return nil
}

func (w *Whitelist) Allow(ip netip.Addr) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.prefixes) == 0 {
		return w.emptyAllow
	}
	for _, p := range w.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (w *Whitelist) List() []WhitelistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]WhitelistEntry, len(w.entries))
	copy(out, w.entries)
	return out
}

func (w *Whitelist) Add(entry, comment string) (WhitelistEntry, error) {
	if _, err := parseEntry(entry); err != nil {
		return WhitelistEntry{}, err
	}
	res, err := w.db.Exec(`INSERT INTO whitelist (entry, comment, created_at) VALUES (?, ?, ?)`,
		entry, comment, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return WhitelistEntry{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return WhitelistEntry{}, err
	}
	if err := w.reload(); err != nil {
		return WhitelistEntry{}, err
	}
	for _, e := range w.entries {
		if e.ID == id {
			return e, nil
		}
	}
	return WhitelistEntry{}, fmt.Errorf("entry not found after insert")
}

func (w *Whitelist) Remove(id int64) error {
	if _, err := w.db.Exec(`DELETE FROM whitelist WHERE id = ?`, id); err != nil {
		return err
	}
	return w.reload()
}
