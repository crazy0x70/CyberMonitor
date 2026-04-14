package server

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"

	"github.com/gorilla/websocket"
)

func TestAgentIngestDoesNotWriteSuccessfulReportsToReportLog(t *testing.T) {
	dataDir := t.TempDir()
	reportPath := filepath.Join(dataDir, "report.log")
	reportLogger.SetOutput(&sizeLimitedWriter{path: reportPath, maxSize: maxLogSize})
	t.Cleanup(func() {
		reportLogger.SetOutput(io.Discard)
	})

	store := &Store{
		nodes:           make(map[string]NodeState),
		profiles:        make(map[string]*NodeProfile),
		settings:        initSettings(Config{AdminPath: "/cm-admin", AgentToken: "bootstrap-token"}),
		alerted:         make(map[string]alertState),
		offlineSessions: make(map[string]OfflineSessionState),
		testHistory:     make(map[string]map[string]*TestHistoryEntry),
		loginAttempts:   make(map[string]*loginAttempt),
	}
	api := newAgentAPI(store, &Hub{clients: make(map[*websocket.Conn]*hubClient)}, &Config{
		AgentToken: "bootstrap-token",
	})

	if err := api.ingest("127.0.0.1:12345", metrics.NodeStats{
		NodeID:    "node-a",
		NodeName:  "node-a",
		Hostname:  "node-a",
		OS:        "linux",
		Arch:      "amd64",
		Timestamp: time.Now().Unix(),
		CPU:       metrics.CPUInfo{},
		Memory:    metrics.MemInfo{},
		Disk:      []metrics.DiskPartition{},
		DiskIO:    metrics.DiskIO{},
		Network:   metrics.NetworkIO{},
	}, "bootstrap-token"); err != nil {
		t.Fatalf("ingest stats: %v", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read report log: %v", err)
	}
	if strings.TrimSpace(string(data)) != "" {
		t.Fatalf("expected successful ingest not to write report.log, got %q", string(data))
	}
}

func TestCollectAlertEventsWritesOfflineAndRecoveryLogWithoutExternalTargets(t *testing.T) {
	dataDir := t.TempDir()
	reportPath := filepath.Join(dataDir, "report.log")
	reportLogger.SetOutput(&sizeLimitedWriter{path: reportPath, maxSize: maxLogSize})
	t.Cleanup(func() {
		reportLogger.SetOutput(io.Discard)
	})

	now := time.Now().UTC().Truncate(time.Second)
	settings := initSettings(Config{AdminPath: "/cm-admin", AgentToken: "bootstrap-token"})
	settings.AlertOfflineSec = 60
	settings.AlertWebhook = ""
	settings.AlertTelegramToken = ""
	settings.AlertTelegramUserIDs = nil
	settings.SiteTitle = "Cyber Monitor"

	store := &Store{
		nodes: map[string]NodeState{
			"node-a": {
				Stats: metrics.NodeStats{
					NodeID:   "node-a",
					NodeName: "primary-node",
					OS:       "linux",
				},
				LastSeen:  now.Add(-2 * time.Minute),
				FirstSeen: now.Add(-time.Hour),
			},
		},
		profiles:        map[string]*NodeProfile{},
		settings:        settings,
		alerted:         make(map[string]alertState),
		offlineSessions: make(map[string]OfflineSessionState),
		testHistory:     make(map[string]map[string]*TestHistoryEntry),
		loginAttempts:   make(map[string]*loginAttempt),
	}

	targets, offlineEvents, recoveredEvents := store.CollectAlertEvents(now)
	if targets.FeishuWebhook != "" || targets.TelegramToken != "" {
		t.Fatalf("expected no external alert targets, got %+v", targets)
	}
	if len(offlineEvents) != 1 || len(recoveredEvents) != 0 {
		t.Fatalf("expected one offline event without recovery, got offline=%d recovery=%d", len(offlineEvents), len(recoveredEvents))
	}
	logReportEvents(targets.SiteTitle, offlineEvents, recoveredEvents)

	store.nodes["node-a"] = NodeState{
		Stats: metrics.NodeStats{
			NodeID:   "node-a",
			NodeName: "primary-node",
			OS:       "linux",
		},
		LastSeen:  now,
		FirstSeen: now.Add(-time.Hour),
	}

	targets, offlineEvents, recoveredEvents = store.CollectAlertEvents(now)
	if len(offlineEvents) != 0 || len(recoveredEvents) != 1 {
		t.Fatalf("expected one recovery event after node resumed, got offline=%d recovery=%d", len(offlineEvents), len(recoveredEvents))
	}
	logReportEvents(targets.SiteTitle, offlineEvents, recoveredEvents)

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report log: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "离线：primary-node") {
		t.Fatalf("expected offline event to be logged, got %q", content)
	}
	if !strings.Contains(content, "恢复：primary-node") {
		t.Fatalf("expected recovery event to be logged, got %q", content)
	}
	if !strings.Contains(content, "node=node-a") {
		t.Fatalf("expected node id to be kept in compact log, got %q", content)
	}
	if !strings.Contains(content, "最后=") {
		t.Fatalf("expected offline event to keep compact last-seen field, got %q", content)
	}
	if !strings.Contains(content, "恢复=") {
		t.Fatalf("expected recovery event to keep compact recovered-at field, got %q", content)
	}
	if !strings.Contains(content, "时长=") {
		t.Fatalf("expected duration field to stay in compact log, got %q", content)
	}
	if strings.Contains(content, "最后在线=") {
		t.Fatalf("expected verbose offline label to be removed, got %q", content)
	}
	if strings.Contains(content, "恢复上报=") {
		t.Fatalf("expected verbose recovery label to be removed, got %q", content)
	}
	if strings.Contains(content, "离线时长=") {
		t.Fatalf("expected verbose duration label to be removed, got %q", content)
	}
	if strings.Contains(content, "Agent 上报") {
		t.Fatalf("expected report log to avoid successful ingest entries, got %q", content)
	}
}
