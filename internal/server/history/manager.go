package history

import (
	"errors"
	"path/filepath"
	"strings"
	"time"

	"cyber_monitor/internal/metrics"
)

type Manager struct {
	network *NetworkStore
	offline *OfflineStore
}

func OpenManager(dataDir string) (*Manager, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("history data dir required")
	}
	network, err := OpenNetworkStore(defaultNetworkStoreDir(dataDir))
	if err != nil {
		return nil, err
	}
	offline, err := OpenOfflineStore(defaultOfflineStoreDir(dataDir))
	if err != nil {
		_ = network.Close()
		return nil, err
	}
	return &Manager{
		network: network,
		offline: offline,
	}, nil
}

func (m *Manager) Close() error {
	return m.joinStoreOps((*NetworkStore).Close, (*OfflineStore).Close)
}

func (m *Manager) joinStoreOps(
	runNetwork func(*NetworkStore) error,
	runOffline func(*OfflineStore) error,
) error {
	if m == nil {
		return nil
	}
	return errors.Join(
		runNetworkStoreOp(m.network, runNetwork),
		runOfflineStoreOp(m.offline, runOffline),
	)
}

func runNetworkStoreOp(store *NetworkStore, run func(*NetworkStore) error) error {
	if store == nil || run == nil {
		return nil
	}
	return run(store)
}

func runOfflineStoreOp(store *OfflineStore, run func(*OfflineStore) error) error {
	if store == nil || run == nil {
		return nil
	}
	return run(store)
}

func (m *Manager) AppendNetworkBatch(nodeID string, tests []metrics.NetworkTestResult, now time.Time) error {
	if m == nil || m.network == nil {
		return nil
	}
	return m.network.AppendBatch(nodeID, tests, now)
}

func (m *Manager) DeleteNode(nodeID string) error {
	return m.joinStoreOps(
		func(store *NetworkStore) error { return store.DeleteNode(nodeID) },
		func(store *OfflineStore) error { return store.DeleteNode(nodeID) },
	)
}

func (m *Manager) ClearNodes() error {
	return m.joinStoreOps((*NetworkStore).Clear, (*OfflineStore).Clear)
}

func (m *Manager) NetworkStore() *NetworkStore {
	if m == nil {
		return nil
	}
	return m.network
}

func (m *Manager) AppendOfflineEvent(nodeID string, recoveredAt time.Time, duration time.Duration) error {
	if m == nil || m.offline == nil {
		return nil
	}
	return m.offline.AppendEvent(nodeID, recoveredAt, duration)
}

func (m *Manager) HasOfflineEventForSession(nodeID string, startedAt time.Time) (bool, error) {
	if m == nil || m.offline == nil {
		return false, nil
	}
	return m.offline.HasEventForSession(nodeID, startedAt)
}

func (m *Manager) OfflineStore() *OfflineStore {
	if m == nil {
		return nil
	}
	return m.offline
}

func HistoryRootDir(dataDir string) string {
	return filepath.Join(dataDir, "history")
}
