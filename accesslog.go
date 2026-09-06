package main

import (
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
)

var errAttemptNotFound = errors.New("attempt not found")

type Attempt struct {
	ID             int64  `json:"id"`
	TS             string `json:"ts"`
	ClientIP       string `json:"client_ip"`
	Allowed        bool   `json:"allowed"`
	Reason         string `json:"reason"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	Query          string `json:"query"`
	UserAgent      string `json:"user_agent"`
	UpstreamStatus int    `json:"upstream_status"`
	DurationMS     int64  `json:"duration_ms"`
}

// AccessLog keeps a bounded, in-memory circular buffer of recent access
// attempts. Nothing is persisted: the whitelist lives in SQLite, the access
// log lives only in RAM and is lost on restart.
type AccessLog struct {
	mu    sync.Mutex
	buf   []Attempt
	head  int // next write position
	count int // number of stored attempts
	seq   int64
}

func NewAccessLog(size int) *AccessLog {
	return &AccessLog{buf: make([]Attempt, size)}
}

func (l *AccessLog) Record(a Attempt) {
	l.mu.Lock()
	a.ID = l.seq
	l.seq++
	l.buf[l.head] = a
	l.head = (l.head + 1) % len(l.buf)
	if l.count < len(l.buf) {
		l.count++
	}
	l.mu.Unlock()

	if b, err := json.Marshal(a); err == nil {
		log.Printf("%s", b)
	}
}

// Query returns up to limit attempts matching the filters, newest first.
// Filters: allowed (nil = all) and path (empty = all, else substring match).
func (l *AccessLog) Query(page, limit int, allowed *bool, path string) ([]Attempt, int, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	var matches []Attempt
	for i := 0; i < l.count; i++ {
		a := l.buf[(l.head-1-i+len(l.buf))%len(l.buf)]
		if allowed != nil && a.Allowed != *allowed {
			continue
		}
		if path != "" && !strings.Contains(a.Path, path) {
			continue
		}
		matches = append(matches, a)
	}

	total := len(matches)
	start := (page - 1) * limit
	if start >= total {
		return []Attempt{}, total, nil
	}
	end := start + limit
	if end > total {
		end = total
	}
	return matches[start:end], total, nil
}

// IPForID returns the client IP for the attempt with the given ID, searching
// the ring buffer. Used to allow a denied IP in one click.
func (l *AccessLog) IPForID(id int64) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := 0; i < l.count; i++ {
		a := l.buf[(l.head-1-i+len(l.buf))%len(l.buf)]
		if a.ID == id {
			return a.ClientIP, nil
		}
	}
	return "", errAttemptNotFound
}