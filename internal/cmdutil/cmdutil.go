package cmdutil

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func EnvOrDefault(key, def string) string {
	if value, ok := lookupEnv(key); ok {
		return value
	}
	return def
}

func EnvDuration(key string, def time.Duration) time.Duration {
	value, ok := lookupEnv(key)
	if !ok {
		return def
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return def
	}
	return duration
}

func EnvBool(key string, def bool) bool {
	value, ok := lookupEnv(key)
	if !ok {
		return def
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return def
	}
	return parsed
}

func lookupEnv(key string) (string, bool) {
	for _, candidate := range envCandidates(key) {
		value := strings.TrimSpace(os.Getenv(candidate))
		if value != "" {
			return value, true
		}
	}
	return "", false
}

func envCandidates(key string) []string {
	candidates := []string{key}
	if strings.HasPrefix(key, "CM_") {
		base := strings.TrimPrefix(key, "CM_")
		lowerUnderscore := strings.ToLower(base)
		lowerHyphen := strings.ReplaceAll(lowerUnderscore, "_", "-")
		candidates = append(candidates, base, lowerUnderscore, lowerHyphen)
	}
	return uniqueStrings(candidates)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func ParseCommaList(raw string) []string {
	parts := strings.Split(raw, ",")
	list := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		list = append(list, value)
	}
	return list
}

func DefaultHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "node"
	}
	return hostname
}

func DefaultDataDir() string {
	return "./data"
}

func NormalizeListen(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return trimmed
	}
	if strings.HasPrefix(trimmed, ":") || strings.Contains(trimmed, ":") {
		return trimmed
	}
	return ":" + trimmed
}
