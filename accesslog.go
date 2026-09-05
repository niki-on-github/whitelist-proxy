package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"sync"
	"time"
)

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

type AccessLog struct {
	mu sync.Mutex
	db *sql.DB
}

func NewAccessLog(db *sql.DB) *AccessLog {
	return &AccessLog{db: db}
}

func (l *AccessLog) Record(a Attempt) {
	l.mu.Lock()
	defer l.mu.Unlock()

	allowed := 0
	if a.Allowed {
		allowed = 1
	}
	if _, err := l.db.Exec(`INSERT INTO access_log
		(ts, client_ip, allowed, reason, method, path, query, user_agent, upstream_status, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.TS, a.ClientIP, allowed, a.Reason, a.Method, a.Path, a.Query, a.UserAgent, a.UpstreamStatus, a.DurationMS); err != nil {
		log.Printf("accesslog: failed to record attempt: %v", err)
		return
	}

	if b, err := json.Marshal(a); err == nil {
		log.Printf("%s", b)
	}
}

func (l *AccessLog) Query(page, limit int, allowed *bool, ip string) ([]Attempt, int, error) {
	where := "WHERE 1=1"
	var args []any
	if allowed != nil {
		v := 0
		if *allowed {
			v = 1
		}
		where += " AND allowed = ?"
		args = append(args, v)
	}
	if ip != "" {
		where += " AND client_ip LIKE ?"
		args = append(args, "%"+ip+"%")
	}

	var total int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM access_log `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := (page - 1) * limit

	rows, err := l.db.Query(`SELECT id, ts, client_ip, allowed, reason, method, path, query, user_agent, upstream_status, duration_ms
		FROM access_log `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []Attempt
	for rows.Next() {
		var a Attempt
		var allowedInt int
		if err := rows.Scan(&a.ID, &a.TS, &a.ClientIP, &allowedInt, &a.Reason, &a.Method, &a.Path, &a.Query, &a.UserAgent, &a.UpstreamStatus, &a.DurationMS); err != nil {
			return nil, 0, err
		}
		a.Allowed = allowedInt == 1
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (l *AccessLog) IPForID(id int64) (string, error) {
	var ip string
	err := l.db.QueryRow(`SELECT client_ip FROM access_log WHERE id = ?`, id).Scan(&ip)
	return ip, err
}

func (l *AccessLog) Trim(retentionDays int) {
	if retentionDays <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().AddDate(0, 0, -retentionDays).UTC().Format(time.RFC3339)
	if _, err := l.db.Exec(`DELETE FROM access_log WHERE ts < ?`, cutoff); err != nil {
		log.Printf("accesslog: trim failed: %v", err)
	}
}
