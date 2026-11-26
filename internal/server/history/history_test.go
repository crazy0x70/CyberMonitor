package history

import (
	"sync"
	"testing"
	"time"

	"cyber_monitor/internal/metrics"
)

func TestParseNetworkSeriesKeyAllowsPipeInName(t *testing.T) {
	parsed, err := ParseNetworkSeriesKey("tcp|1.1.1.1|443|us | cloudflare | edge")
	if err != nil {
		t.Fatalf("expected key with '|' in name to parse, got %v", err)
	}
	if parsed.Type != "tcp" || parsed.Host != "1.1.1.1" || parsed.Port != 443 || parsed.Name != "us | cloudflare | edge" {
		t.Fatalf("unexpected parsed identity: %+v", parsed)
	}
}

func TestResourceStoreDeleteAndClearConcurrency(t *testing.T) {
	store, err := OpenResourceStore(t.TempDir(), 7)
	if err != nil {
		t.Fatalf("OpenResourceStore failed: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			_ = store.Observe("node-a", metrics.NodeStats{
				CPU:    metrics.CPUInfo{UsagePercent: float64(i)},
				Memory: metrics.MemInfo{UsedPercent: 40},
			}, now.Add(time.Duration(i)*time.Second))
		}
	}()
	go func() {
		defer wg.Done()
		_ = store.DeleteNode("node-a")
		_ = store.Clear()
	}()
	wg.Wait()
}
