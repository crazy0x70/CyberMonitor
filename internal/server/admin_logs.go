package server

import (
	"bufio"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	adminLogLevelDebug   = "debug"
	adminLogLevelInfo    = "info"
	adminLogLevelWarning = "warning"
	adminLogLevelError   = "error"
	adminLogLevelSilent  = "silent"
	adminLogLevelAll     = "all"
	maxAdminLogEntries   = 1000
	defaultAdminLogLimit = 300
	maxAdminLogLimit     = 1000
)

type adminLogEntry struct {
	ID        int64  `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Time      string `json:"time"`
	Level     string `json:"level"`
	Source    string `json:"source"`
	Message   string `json:"message"`
}

type adminLogBuffer struct {
	mu      sync.RWMutex
	nextID  int64
	entries []adminLogEntry
	max     int
}

type adminLogCaptureWriter struct {
	source string
}

var runtimeAdminLogs = &adminLogBuffer{max: maxAdminLogEntries}

func (w adminLogCaptureWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(string(p), "\n") {
		runtimeAdminLogs.AppendLine(w.source, line)
	}
	return len(p), nil
}

func (b *adminLogBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID = 0
	b.entries = nil
}

func (b *adminLogBuffer) AppendLine(source, raw string) {
	message, occurredAt, ok := normalizeAdminLogLine(raw)
	if !ok {
		return
	}
	b.append(adminLogEntry{
		Timestamp: occurredAt.Unix(),
		Time:      occurredAt.Format(time.RFC3339),
		Level:     inferAdminLogLevel(message),
		Source:    normalizeAdminLogSource(source),
		Message:   message,
	})
}

func (b *adminLogBuffer) SeedFile(path, source string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	lines := make([]string, 0, maxAdminLogEntries)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > maxAdminLogEntries {
			copy(lines, lines[len(lines)-maxAdminLogEntries:])
			lines = lines[:maxAdminLogEntries]
		}
	}
	for _, line := range lines {
		b.AppendLine(source, line)
	}
}

func (b *adminLogBuffer) Snapshot(level string, limit int) []adminLogEntry {
	level = normalizeAdminLogLevel(level)
	if level == adminLogLevelSilent {
		return []adminLogEntry{}
	}
	if limit <= 0 || limit > maxAdminLogLimit {
		limit = defaultAdminLogLimit
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	entries := make([]adminLogEntry, 0, len(b.entries))
	for _, entry := range b.entries {
		if level == adminLogLevelAll || entry.Level == level {
			entries = append(entries, entry)
		}
	}
	sort.SliceStable(entries, func(left, right int) bool {
		if entries[left].Timestamp == entries[right].Timestamp {
			return entries[left].ID < entries[right].ID
		}
		return entries[left].Timestamp < entries[right].Timestamp
	})
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	return entries
}

func (b *adminLogBuffer) append(entry adminLogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	entry.ID = b.nextID
	if b.max <= 0 {
		b.max = maxAdminLogEntries
	}
	b.entries = append(b.entries, entry)
	if len(b.entries) > b.max {
		copy(b.entries, b.entries[len(b.entries)-b.max:])
		b.entries = b.entries[:b.max]
	}
}

func handleAdminLogsRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	limit := defaultAdminLogLimit
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil {
			limit = parsed
		}
	}
	level := normalizeAdminLogLevel(r.URL.Query().Get("level"))
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": runtimeAdminLogs.Snapshot(level, limit),
		"levels":  []string{adminLogLevelAll, adminLogLevelInfo, adminLogLevelWarning, adminLogLevelError, adminLogLevelDebug, adminLogLevelSilent},
		"limit":   limit,
	})
}

func normalizeAdminLogLine(raw string) (string, time.Time, bool) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return "", time.Time{}, false
	}
	occurredAt := time.Now()
	if len(line) > len("2006/01/02 15:04:05 ") {
		if parsed, err := time.ParseInLocation("2006/01/02 15:04:05", line[:19], time.Local); err == nil {
			occurredAt = parsed
			line = strings.TrimSpace(line[20:])
		}
	}
	if line == "" {
		return "", time.Time{}, false
	}
	return line, occurredAt, true
}

func normalizeAdminLogSource(source string) string {
	switch strings.TrimSpace(source) {
	case "report":
		return "report"
	default:
		return "server"
	}
}

func normalizeAdminLogLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case adminLogLevelDebug:
		return adminLogLevelDebug
	case adminLogLevelInfo, "information":
		return adminLogLevelInfo
	case adminLogLevelWarning, "warn":
		return adminLogLevelWarning
	case adminLogLevelError, "err":
		return adminLogLevelError
	case adminLogLevelSilent:
		return adminLogLevelSilent
	default:
		return adminLogLevelAll
	}
}

func inferAdminLogLevel(message string) string {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "[debug]") || strings.Contains(message, "调试"):
		return adminLogLevelDebug
	case strings.Contains(lower, "fatal") ||
		strings.Contains(lower, "error") ||
		strings.Contains(message, "错误") ||
		strings.Contains(message, "失败") ||
		strings.Contains(message, "拒绝"):
		return adminLogLevelError
	case strings.Contains(lower, "warn") ||
		strings.Contains(message, "警告") ||
		strings.Contains(message, "不可用") ||
		strings.Contains(message, "回退") ||
		strings.Contains(message, "跳过"):
		return adminLogLevelWarning
	default:
		return adminLogLevelInfo
	}
}
