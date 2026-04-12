package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

func TestPublicNodeHistoryRangeReturnsRequestedWindow(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})

	baseNow := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
	const (
		nodeID   = "node-a"
		host     = "1.1.1.1"
		testName = "daily-range"
	)

	timestamps := make([]int64, 0, 31)
	for daysAgo := 30; daysAgo >= 0; daysAgo-- {
		timestamps = append(timestamps, baseNow.Add(-time.Duration(daysAgo)*24*time.Hour).Unix())
	}
	seedPublicHistory(t, baseURL, "bootstrap-token", nodeID, host, testName, timestamps)

	client, _ := bootstrapPublicPageClient(t, baseURL)
	resp := getPublicNodeHistory(t, client, baseURL, fmt.Sprintf("/api/v1/public/nodes/%s/history?range=7d", nodeID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(raw))
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected history Cache-Control no-store, got %q", got)
	}

	var payload struct {
		NodeID   string                       `json:"node_id"`
		RangeKey string                       `json:"range_key"`
		From     int64                        `json:"from"`
		To       int64                        `json:"to"`
		Tests    map[string]*TestHistoryEntry `json:"tests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode history payload: %v", err)
	}

	if payload.NodeID != nodeID {
		t.Fatalf("expected node_id %q, got %q", nodeID, payload.NodeID)
	}
	if payload.RangeKey != "7d" {
		t.Fatalf("expected range key 7d, got %q", payload.RangeKey)
	}
	if got := payload.To - payload.From; got != int64(7*24*time.Hour/time.Second) {
		t.Fatalf("expected 7d window, got %d seconds", got)
	}

	seriesKey := buildTestHistoryKey(metrics.NetworkTestResult{Type: "icmp", Host: host, Name: testName})
	entry := payload.Tests[seriesKey]
	if entry == nil {
		t.Fatalf("expected series %q in payload", seriesKey)
	}
	if len(entry.Times) == 0 {
		t.Fatal("expected returned history points")
	}
	for _, ts := range entry.Times {
		if ts < payload.From || ts > payload.To {
			t.Fatalf("timestamp %d out of range [%d, %d]", ts, payload.From, payload.To)
		}
	}
	if containsTimestamp(entry.Times, baseNow.Add(-8*24*time.Hour).Unix()) {
		t.Fatalf("expected 8d-old point to be excluded from 7d window: %v", entry.Times)
	}
	if !containsTimestamp(entry.Times, baseNow.Add(-6*24*time.Hour).Unix()) {
		t.Fatalf("expected 6d-old point to remain in 7d window: %v", entry.Times)
	}
}

func TestPublicNodeHistoryOneYearDoesNotCollapseTo24Hours(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})

	baseNow := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second)
	const (
		nodeID   = "node-year"
		host     = "8.8.8.8"
		testName = "year-range"
	)

	extraOld := baseNow.Add(-(365*24*time.Hour + 12*time.Hour)).Unix()
	timestamps := make([]int64, 0, 367)
	timestamps = append(timestamps, extraOld)
	for daysAgo := 365; daysAgo >= 0; daysAgo-- {
		timestamps = append(timestamps, baseNow.Add(-time.Duration(daysAgo)*24*time.Hour).Unix())
	}
	seedPublicHistory(t, baseURL, "bootstrap-token", nodeID, host, testName, timestamps)

	client, _ := bootstrapPublicPageClient(t, baseURL)
	resp := getPublicNodeHistory(t, client, baseURL, fmt.Sprintf("/api/v1/public/nodes/%s/history?range=1y", nodeID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(raw))
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected history Cache-Control no-store, got %q", got)
	}

	var payload struct {
		NodeID   string                       `json:"node_id"`
		RangeKey string                       `json:"range_key"`
		From     int64                        `json:"from"`
		To       int64                        `json:"to"`
		Tests    map[string]*TestHistoryEntry `json:"tests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode history payload: %v", err)
	}

	if payload.RangeKey != "1y" {
		t.Fatalf("expected range key 1y, got %q", payload.RangeKey)
	}
	if got := payload.To - payload.From; got != int64(366*24*time.Hour/time.Second) {
		t.Fatalf("expected 366d window, got %d seconds", got)
	}

	seriesKey := buildTestHistoryKey(metrics.NetworkTestResult{Type: "icmp", Host: host, Name: testName})
	entry := payload.Tests[seriesKey]
	if entry == nil {
		t.Fatalf("expected series %q in payload", seriesKey)
	}
	if len(entry.Times) < 300 {
		t.Fatalf("expected 1y request to return long history, got %d points", len(entry.Times))
	}
	if !containsTimestamp(entry.Times, extraOld) {
		t.Fatalf("expected >365d point %d to remain in 366d window", extraOld)
	}
	if containsTimestamp(entry.Times, baseNow.Add(-2*24*time.Hour).Unix()) && len(entry.Times) <= 3 {
		t.Fatalf("expected 1y response not to collapse to recent 24h points only: %v", entry.Times)
	}
}

func TestPublicNodeHistoryRejectsInvalidRangeAndMissingNode(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:      reserveTCPAddr(t),
		AdminPath: "/cm-admin",
	})

	client, _ := bootstrapPublicPageClient(t, baseURL)
	invalidResp := getPublicNodeHistory(t, client, baseURL, "/api/v1/public/nodes/node-a/history?range=bogus")
	defer invalidResp.Body.Close()
	if invalidResp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(invalidResp.Body)
		t.Fatalf("expected invalid range 400, got %d: %s", invalidResp.StatusCode, string(raw))
	}

	missingResp := getPublicNodeHistory(t, client, baseURL, "/api/v1/public/nodes/missing-node/history?range=24h")
	defer missingResp.Body.Close()
	if missingResp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(missingResp.Body)
		t.Fatalf("expected missing node 404, got %d: %s", missingResp.StatusCode, string(raw))
	}
}

func TestPublicNodeHistoryDefaultsToOneHourWindow(t *testing.T) {
	baseURL, _ := startTestServer(t, Config{
		Addr:       reserveTCPAddr(t),
		AdminPath:  "/cm-admin",
		AgentToken: "bootstrap-token",
	})

	baseNow := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
	const (
		nodeID   = "node-default"
		host     = "9.9.9.9"
		testName = "default-range"
	)

	timestamps := []int64{
		baseNow.Add(-2 * time.Hour).Unix(),
		baseNow.Add(-30 * time.Minute).Unix(),
	}
	seedPublicHistory(t, baseURL, "bootstrap-token", nodeID, host, testName, timestamps)

	client, _ := bootstrapPublicPageClient(t, baseURL)
	resp := getPublicNodeHistory(t, client, baseURL, fmt.Sprintf("/api/v1/public/nodes/%s/history", nodeID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(raw))
	}

	var payload struct {
		NodeID   string                       `json:"node_id"`
		RangeKey string                       `json:"range_key"`
		From     int64                        `json:"from"`
		To       int64                        `json:"to"`
		Tests    map[string]*TestHistoryEntry `json:"tests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode history payload: %v", err)
	}

	if payload.RangeKey != "1h" {
		t.Fatalf("expected default range key 1h, got %q", payload.RangeKey)
	}
	if got := payload.To - payload.From; got != int64(time.Hour/time.Second) {
		t.Fatalf("expected 1h window, got %d seconds", got)
	}

	seriesKey := buildTestHistoryKey(metrics.NetworkTestResult{Type: "icmp", Host: host, Name: testName})
	entry := payload.Tests[seriesKey]
	if entry == nil {
		t.Fatalf("expected series %q in payload", seriesKey)
	}
	if containsTimestamp(entry.Times, timestamps[0]) {
		t.Fatalf("expected 2h-old point to be excluded from default 1h window: %v", entry.Times)
	}
	if !containsTimestamp(entry.Times, timestamps[1]) {
		t.Fatalf("expected 30m-old point to remain in default 1h window: %v", entry.Times)
	}
}

func seedPublicHistory(t *testing.T, baseURL, token, nodeID, host, testName string, timestamps []int64) {
	t.Helper()

	results := make([]metrics.NetworkTestResult, 0, len(timestamps))
	for idx, ts := range timestamps {
		latency := 10 + float64(idx)
		results = append(results, metrics.NetworkTestResult{
			Type:       "icmp",
			Host:       host,
			Name:       testName,
			CheckedAt:  ts,
			LatencyMs:  &latency,
			PacketLoss: 0,
			Status:     "online",
		})
	}

	payload := metrics.NodeStats{
		NodeID:       nodeID,
		NodeName:     nodeID,
		Hostname:     nodeID,
		OS:           "linux",
		Arch:         "amd64",
		Timestamp:    timestamps[len(timestamps)-1],
		CPU:          metrics.CPUInfo{UsagePercent: 1},
		Memory:       metrics.MemInfo{Total: 1, Used: 1, Free: 0, UsedPercent: 100},
		NetworkTests: results,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal ingest payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/ingest", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create ingest request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-AGENT-TOKEN", token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post ingest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected ingest 200, got %d: %s", resp.StatusCode, string(raw))
	}
}

func getPublicNodeHistory(t *testing.T, client *http.Client, baseURL, path string) *http.Response {
	t.Helper()

	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		t.Fatalf("create %s request: %v", path, err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	return resp
}

func containsTimestamp(values []int64, want int64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
