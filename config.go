package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ProxyListen     string
	AdminListen     string
	Upstream        string
	AdminUser       string
	AdminPassword   string
	DBPath          string
	LogBufferSize   int
	AcceptProxy     bool
	AdminAuth       bool
	AllowedPaths    []string
	Location        *time.Location
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func requiredEnv(key string) (string, error) {
	if v := os.Getenv(key); v == "" {
		return "", fmt.Errorf("required environment variable %s is not set", key)
	} else {
		return v, nil
	}
}

func LoadConfig() (*Config, error) {
	upstream, err := requiredEnv("UPSTREAM")
	if err != nil {
		return nil, err
	}
	user, err := requiredEnv("ADMIN_USER")
	if err != nil {
		return nil, err
	}
	pass, err := requiredEnv("ADMIN_PASSWORD")
	if err != nil {
		return nil, err
	}

	bufSize := 10000
	if v := os.Getenv("LOG_BUFFER_SIZE"); v != "" {
		bufSize, err = strconv.Atoi(v)
		if err != nil || bufSize <= 0 {
			return nil, fmt.Errorf("LOG_BUFFER_SIZE must be a positive integer")
		}
	}

	acceptProxy := true
	if v := os.Getenv("ACCEPT_PROXY"); v != "" {
		acceptProxy, err = strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("ACCEPT_PROXY must be a boolean")
		}
	}

	adminAuth := true
	if v := os.Getenv("ADMIN_AUTH"); v != "" {
		adminAuth, err = strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("ADMIN_AUTH must be a boolean")
		}
	}

	allowedPaths := []string{}
	if v := os.Getenv("ALLOW_PATHS"); v != "" {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("ALLOW_PATHS entries must start with '/', got %q", p)
			}
			allowedPaths = append(allowedPaths, p)
		}
	}

	loc, err := time.LoadLocation(env("TIMEZONE", "UTC"))
	if err != nil {
		return nil, fmt.Errorf("TIMEZONE must be a valid IANA location: %v", err)
	}

	return &Config{
		ProxyListen:      env("PROXY_LISTEN", "0.0.0.0:8080"),
		AdminListen:      env("ADMIN_LISTEN", "0.0.0.0:8081"),
		Upstream:         upstream,
		AdminUser:        user,
		AdminPassword:    pass,
		DBPath:           env("DB_PATH", "data/whitelist-proxy.db"),
		LogBufferSize:    bufSize,
		AcceptProxy:      acceptProxy,
		AdminAuth:        adminAuth,
		AllowedPaths:     allowedPaths,
		Location:         loc,
	}, nil
}
