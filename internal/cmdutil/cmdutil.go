package cmdutil

import (
	"log"
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
		if strings.TrimSpace(value) != "" {
			// 空值（如 docker 中 CM_X=）视为未设置，静默回退。
			log.Printf("环境变量 %s=%q 解析失败（%v），使用默认值 %s", key, value, err, def)
		}
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
		if strings.TrimSpace(value) != "" {
			log.Printf("环境变量 %s=%q 不是合法布尔值，使用默认值 %v", key, value, def)
		}
		return def
	}
	return parsed
}

func lookupEnv(key string) (string, bool) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", false
	}
	return value, true
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
	if strings.Contains(trimmed, ":") {
		return trimmed
	}
	return ":" + trimmed
}
