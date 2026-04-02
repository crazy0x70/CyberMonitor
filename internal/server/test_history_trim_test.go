package server

import (
	"testing"
	"time"
)

func TestTrimHistoryEntryRetainsMultiDayCoverage(t *testing.T) {
	t.Parallel()

	const intervalSec = int64(20)
	const totalHours = 72
	const totalSamples = totalHours * 60 * 60 / int(intervalSec)
	start := time.Unix(1_700_000_000, 0)

	entry := &TestHistoryEntry{
		Latency: make([]*float64, 0, totalSamples),
		Loss:    make([]*float64, 0, totalSamples),
		Times:   make([]int64, 0, totalSamples),
	}
	for i := 0; i < totalSamples; i++ {
		ts := start.Add(time.Duration(i) * time.Duration(intervalSec) * time.Second).Unix()
		entry.Times = append(entry.Times, ts)
		entry.Latency = append(entry.Latency, nil)
		entry.Loss = append(entry.Loss, nil)
		entry.LastAt = ts
	}

	if !trimHistoryEntry(entry, entry.LastAt) {
		t.Fatal("expected history trimming to activate for a multi-day series")
	}
	if len(entry.Times) == 0 {
		t.Fatal("expected history to keep retained samples")
	}
	coverage := entry.LastAt - entry.Times[0]
	if coverage < 48*60*60 {
		t.Fatalf("expected retained coverage to stay above 48h, got %s", time.Duration(coverage)*time.Second)
	}
	if len(entry.Times) != len(entry.Latency) || len(entry.Times) != len(entry.Loss) {
		t.Fatalf("history series lengths diverged: times=%d latency=%d loss=%d", len(entry.Times), len(entry.Latency), len(entry.Loss))
	}
}
