package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

//go:embed webui/index.html
var webuiFS embed.FS

type Admin struct {
	wl    *Whitelist
	log   *AccessLog
	user  string
	pass  string
	index []byte
}

func NewAdmin(wl *Whitelist, al *AccessLog, user, pass string) *Admin {
	b, err := webuiFS.ReadFile("webui/index.html")
	if err != nil {
		panic(err)
	}
	return &Admin{wl: wl, log: al, user: user, pass: pass, index: b}
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="whitelist-proxy admin"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch {
	case r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(a.index)

	case r.URL.Path == "/api/whitelist" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, a.wl.List())

	case r.URL.Path == "/api/whitelist" && r.Method == http.MethodPost:
		a.addWhitelist(w, r)

	case strings.HasPrefix(r.URL.Path, "/api/whitelist/") && r.Method == http.MethodDelete:
		a.removeWhitelist(w, r)

	case r.URL.Path == "/api/attempts" && r.Method == http.MethodGet:
		a.listAttempts(w, r)

	case strings.HasPrefix(r.URL.Path, "/api/attempts/") && strings.HasSuffix(r.URL.Path, "/allow") && r.Method == http.MethodPost:
		a.allowAttempt(w, r)

	default:
		http.NotFound(w, r)
	}
}

func (a *Admin) authorized(r *http.Request) bool {
	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	uOK := subtle.ConstantTimeCompare([]byte(u), []byte(a.user)) == 1
	pOK := subtle.ConstantTimeCompare([]byte(p), []byte(a.pass)) == 1
	return uOK && pOK
}

func (a *Admin) addWhitelist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entry   string `json:"entry"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	req.Entry = strings.TrimSpace(req.Entry)
	if req.Entry == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "entry is required"})
		return
	}
	e, err := a.wl.Add(req.Entry, req.Comment)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, e)
}

func (a *Admin) removeWhitelist(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/whitelist/"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := a.wl.Remove(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) listAttempts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	var allowed *bool
	if v := q.Get("allowed"); v == "true" || v == "false" {
		b := v == "true"
		allowed = &b
	}
	attempts, total, err := a.log.Query(page, limit, allowed, q.Get("ip"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"attempts": attempts, "total": total})
}

func (a *Admin) allowAttempt(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/attempts/"), "/allow")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	ip, err := a.log.IPForID(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "attempt not found"})
		return
	}
	e, err := a.wl.Add(ip, fmt.Sprintf("allowed from attempt #%d", id))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, e)
}
