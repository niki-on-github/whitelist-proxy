package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func openAIError(message, typ, code string) map[string]any {
	return map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    typ,
			"param":   nil,
			"code":    code,
		},
	}
}

type Proxy struct {
	wl           *Whitelist
	log          *AccessLog
	upstream     *url.URL
	allowedPaths []string
	rp           *httputil.ReverseProxy
}

func NewProxy(upstream string, allowedPaths []string, wl *Whitelist, al *AccessLog) (*Proxy, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("UPSTREAM must be an http(s):// URL")
	}

	p := &Proxy{wl: wl, log: al, upstream: u, allowedPaths: allowedPaths}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = u.Host
			if ap, ok := parseAddrPort(pr.In.RemoteAddr); ok {
				ip := ap.Addr().String()
				// Overwrite any client-supplied headers; the real IP is known
				// from the PROXY protocol / socket peer only.
				pr.Out.Header.Set("X-Real-IP", ip)
				pr.Out.Header.Set("X-Forwarded-For", ip)
			}
			proto := "http"
			if pr.In.TLS != nil {
				proto = "https"
			}
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
			// Never trust a client-supplied Forwarded header: the real peer
			// is known only from the PROXY protocol / socket.
			pr.Out.Header.Del("Forwarded")
		},
		FlushInterval: 100 * time.Millisecond,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy: upstream error for %s %s: %v", r.RemoteAddr, r.URL.Path, err)
			writeJSON(w, http.StatusBadGateway, openAIError("upstream request failed", "upstream_error", "bad_gateway"))
		},
	}
	return p, nil
}

func parseAddrPort(s string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return ap, true
}

// pathAllowed reports whether the request path is within an allowed prefix.
// An empty allowedPaths list permits every path.
//
// The raw path must match at a segment boundary, and the cleaned path must
// still resolve inside the prefix. This stops crafted paths such as
// "/v1/../admin" or "/v1//x" from matching an "/v1" allow rule and, depending
// on upstream normalization, reaching endpoints outside the intended set.
func pathAllowed(p string, allowedPaths []string) bool {
	if len(allowedPaths) == 0 {
		return true
	}
	clean := path.Clean(p)
	for _, pref := range allowedPaths {
		base := strings.TrimSuffix(pref, "/")
		if base == "" {
			base = "/"
		}
		if base != "/" && p != base && !strings.HasPrefix(p, base+"/") {
			continue
		}
		if base == "/" || clean == base || strings.HasPrefix(clean, base+"/") {
			return true
		}
	}
	return false
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	ap, ok := parseAddrPort(r.RemoteAddr)
	if !ok {
		http.Error(w, "cannot determine client address", http.StatusBadRequest)
		return
	}
	ip := ap.Addr()

	start := time.Now()
	sw := &statusWriter{ResponseWriter: w}

	allowed, reason := p.wl.Check(ip)
	if allowed && !pathAllowed(r.URL.Path, p.allowedPaths) {
		allowed = false
		reason = "path"
	}

	if allowed {
		p.rp.ServeHTTP(sw, r)
	} else {
		// Generic denial: never reveal the whitelist, allowed paths, or the
		// client IP to the caller. Real details go to the container log only.
		// %q prevents an attacker-controlled path from injecting log lines.
		log.Printf("denied: ip=%s reason=%s method=%s path=%q status=403", ip, reason, r.Method, r.URL.Path)
		writeJSON(sw, http.StatusForbidden, openAIError(
			"access denied", "access_denied", "forbidden"))
	}

	p.log.Record(Attempt{
		TS:             time.Now().UTC().Format(time.RFC3339),
		ClientIP:       ip.String(),
		Allowed:        allowed,
		Reason:         reason,
		Method:         r.Method,
		Path:           r.URL.Path,
		Query:          r.URL.RawQuery,
		UserAgent:      r.UserAgent(),
		UpstreamStatus: sw.status,
		DurationMS:     time.Since(start).Milliseconds(),
	})
}
