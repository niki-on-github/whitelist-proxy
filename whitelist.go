package main

import (
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var dayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

func dayToName(d time.Weekday) string { return dayNames[int(d)] }
func nameToDay(s string) (time.Weekday, bool) {
	for i, n := range dayNames {
		if n == strings.ToLower(strings.TrimSpace(s)) {
			return time.Weekday(i), true
		}
	}
	return 0, false
}

func mustNameToDay(s string) time.Weekday {
	wd, _ := nameToDay(s)
	return wd
}

type WhitelistEntry struct {
	ID        int64  `json:"id"`
	Entry     string `json:"entry"`
	Comment   string `json:"comment"`
	CreatedAt string `json:"created_at"`
	Days      []string `json:"days,omitempty"`
	StartTime string `json:"start_time,omitempty"`
	EndTime   string `json:"end_time,omitempty"`

	daysSet map[time.Weekday]bool
	startMin, endMin int
}

type Whitelist struct {
	mu       sync.RWMutex
	db       *sql.DB
	loc      *time.Location
	prefixes []netip.Prefix
	entries  []WhitelistEntry
}

func NewWhitelist(db *sql.DB, loc *time.Location) (*Whitelist, error) {
	w := &Whitelist{db: db, loc: loc}
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

// hasRestriction reports whether the entry carries any day or time window.
func (e *WhitelistEntry) hasRestriction() bool {
	return len(e.daysSet) > 0 || e.StartTime != "" || e.EndTime != ""
}

// allowsAt reports whether the entry permits access at the given time.
// Entries without a window always allow.
func (e *WhitelistEntry) allowsAt(t time.Time) bool {
	if len(e.daysSet) > 0 && !e.daysSet[t.Weekday()] {
		return false
	}
	if e.StartTime != "" {
		minutes := t.Hour()*60 + t.Minute()
		if minutes < e.startMin || minutes > e.endMin {
			return false
		}
	}
	return true
}

func (w *Whitelist) reload() error {
	rows, err := w.db.Query(`SELECT id, entry, comment, created_at, days, start_time, end_time FROM whitelist ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var entries []WhitelistEntry
	var prefixes []netip.Prefix
	for rows.Next() {
		var e WhitelistEntry
		var days, start, end sql.NullString
		if err := rows.Scan(&e.ID, &e.Entry, &e.Comment, &e.CreatedAt, &days, &start, &end); err != nil {
			return err
		}
		p, err := parseEntry(e.Entry)
		if err != nil {
			continue
		}
		e.Days = []string{}
		if days.Valid && strings.TrimSpace(days.String) != "" {
			e.daysSet = map[time.Weekday]bool{}
			for _, d := range strings.Split(days.String, ",") {
				if wd, ok := nameToDay(d); ok {
					e.daysSet[wd] = true
					e.Days = append(e.Days, dayToName(wd))
				}
			}
		}
		if start.Valid {
			e.StartTime = start.String
		}
		if end.Valid {
			e.EndTime = end.String
		}
		if e.StartTime != "" && e.EndTime != "" {
			if sm, em, ok := parseWindow(e.StartTime, e.EndTime); ok {
				e.startMin, e.endMin = sm, em
			} else {
				e.StartTime, e.EndTime = "", ""
			}
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

// Allow reports whether the IP is currently allowed (thin wrapper around Check).
func (w *Whitelist) Allow(ip netip.Addr) bool {
	allowed, _ := w.Check(ip)
	return allowed
}

// Check reports whether the IP is allowed right now and why not.
// reason: "" allowed, "ip" not on the whitelist, "time" outside its window.
func (w *Whitelist) Check(ip netip.Addr) (bool, string) {
	return w.checkAt(ip, time.Now().In(w.loc))
}

func (w *Whitelist) checkAt(ip netip.Addr, now time.Time) (bool, string) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	matched := false
	for i, p := range w.prefixes {
		if !p.Contains(ip) {
			continue
		}
		matched = true
		if !w.entries[i].hasRestriction() || w.entries[i].allowsAt(now) {
			return true, ""
		}
	}
	if !matched {
		return false, "ip"
	}
	return false, "time"
}

func (w *Whitelist) List() []WhitelistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]WhitelistEntry, len(w.entries))
	copy(out, w.entries)
	return out
}

func (w *Whitelist) Add(entry, comment string) (WhitelistEntry, error) {
	return w.AddScheduled(entry, comment, nil, "", "")
}

// AddScheduled adds a whitelist entry with an optional day list and time window.
func (w *Whitelist) AddScheduled(entry, comment string, days []string, start, end string) (WhitelistEntry, error) {
	if _, err := parseEntry(entry); err != nil {
		return WhitelistEntry{}, err
	}

	normalized := []string{}
	for _, d := range days {
		if _, ok := nameToDay(d); !ok {
			return WhitelistEntry{}, fmt.Errorf("invalid day %q", d)
		}
		normalized = append(normalized, dayToName(mustNameToDay(d)))
	}

	if (start != "" && end == "") || (start == "" && end != "") {
		return WhitelistEntry{}, fmt.Errorf("start and end times must be set together as HH:MM with start < end")
	}
	if start != "" {
		if _, _, ok := parseWindow(start, end); !ok {
			return WhitelistEntry{}, fmt.Errorf("start and end times must be HH:MM with start < end")
		}
	}

	daysStr := ""
	if len(normalized) > 0 {
		daysStr = strings.Join(normalized, ",")
	}
	var startStr, endStr sql.NullString
	if start != "" {
		startStr = sql.NullString{String: start, Valid: true}
	}
	if end != "" {
		endStr = sql.NullString{String: end, Valid: true}
	}

	res, err := w.db.Exec(`INSERT INTO whitelist (entry, comment, created_at, days, start_time, end_time) VALUES (?, ?, ?, ?, ?, ?)`,
		entry, comment, time.Now().UTC().Format(time.RFC3339), daysStr, startStr, endStr)
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

// parseWindow parses two HH:MM strings into minutes since midnight, requiring start < end.
func parseWindow(start, end string) (int, int, bool) {
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)
	if start == "" || end == "" {
		return 0, 0, false
	}
	sm, ok := parseHHMM(start)
	if !ok {
		return 0, 0, false
	}
	em, ok := parseHHMM(end)
	if !ok {
		return 0, 0, false
	}
	if sm >= em {
		return 0, 0, false
	}
	return sm, em, true
}

func parseHHMM(s string) (int, bool) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, false
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}