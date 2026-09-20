package history

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestMigrateLegacyNullEntryPreservesValidSeries(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenNetworkStore(filepath.Join(dir, "network"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	now := time.Unix(1700000060, 0).UTC()
	path := filepath.Join(dir, "legacy.json")
	// A null series is a valid JSON value; it must not prevent other series migrating.
	payload := []byte(`{"version":1,"nodes":{"node-a":{"icmp|empty.test|0|empty":null,"icmp|valid.test|0|valid":{"times":[1700000000],"latency":[12],"loss":[0]}}}}`)
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateLegacyJSONIfNeeded(path, store, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.LegacyFound {
		t.Fatal("legacy missing")
	}
	got, err := store.QueryRangeRaw(context.Background(), "node-a", time.Unix(1699999999, 0), now)
	if err != nil {
		t.Fatal(err)
	}
	entry := got["icmp|valid.test|0|valid"]
	if len(got) != 1 || entry == nil || len(entry.Times) != 1 || entry.Times[0] != 1700000000 || entry.Latency[0] == nil || *entry.Latency[0] != 12 {
		t.Fatalf("migrated data: %+v", got)
	}
	if _, err := MigrateLegacyJSONIfNeeded(path, store, now); err != nil {
		t.Fatal(err)
	}
	replayed, err := store.QueryRangeRaw(context.Background(), "node-a", time.Unix(1699999999, 0), now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, replayed) {
		t.Fatalf("migration replay changed data: before=%+v after=%+v", got, replayed)
	}

	backup, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != string(payload) {
		t.Fatal("backup changed")
	}
}
