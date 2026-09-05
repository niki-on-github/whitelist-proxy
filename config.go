package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ProxyListen      string
	AdminListen      string
	Upstream         string
	AdminUser        string
	AdminPassword    string
	DBPath           string
	EmptyWhitelist   string
	LogRetentionDays int
	AcceptProxy      bool
	AllowedPaths     []string
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

	retention := 30
	if v := os.Getenv("LOG_RETENTION_DAYS"); v != "" {
		retention, err = strconv.Atoi(v)
		if err != nil || retention < 0 {
			return nil, fmt.Errorf("LOG_RETENTION_DAYS must be a non-negative integer")
		}
	}

	empty := env("EMPTY_WHITELIST", "deny")
	if empty != "deny" && empty != "allow" {
		return nil, fmt.Errorf("EMPTY_WHITELIST must be 'deny' or 'allow'")
	}

	acceptProxy := true
	if v := os.Getenv("ACCEPT_PROXY"); v != "" {
		acceptProxy, err = strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("ACCEPT_PROXY must be a boolean")
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

	return &Config{
		ProxyListen:      env("PROXY_LISTEN", "0.0.0.0:8080"),
		AdminListen:      env("ADMIN_LISTEN", "0.0.0.0:8081"),
		Upstream:         upstream,
		AdminUser:        user,
		AdminPassword:    pass,
		DBPath:           env("DB_PATH", "data/whitelist-proxy.db"),
		EmptyWhitelist:   empty,
		LogRetentionDays: retention,
		AcceptProxy:      acceptProxy,
		AllowedPaths:     allowedPaths,
	}, nil
}
