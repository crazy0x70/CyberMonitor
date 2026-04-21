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
	return errors.Join(
		runStoreOp(m.networkStore(), runNetwork),
		runStoreOp(m.offlineStore(), runOffline),
	)
}

func runStoreOp[Store any](store *Store, run func(*Store) error) error {
	if store == nil || run == nil {
		return nil
	}
	return run(store)
}

func (m *Manager) AppendNetworkBatch(nodeID string, tests []metrics.NetworkTestResult, now time.Time) error {
	store := m.networkStore()
	if store == nil {
		return nil
	}
	return store.AppendBatch(nodeID, tests, now)
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
	return m.networkStore()
}

func (m *Manager) AppendOfflineEvent(nodeID string, recoveredAt time.Time, duration time.Duration) error {
	store := m.offlineStore()
	if store == nil {
		return nil
	}
	return store.AppendEvent(nodeID, recoveredAt, duration)
}

func (m *Manager) HasOfflineEventForSession(nodeID string, startedAt time.Time) (bool, error) {
	store := m.offlineStore()
	if store == nil {
		return false, nil
	}
	return store.HasEventForSession(nodeID, startedAt)
}

func (m *Manager) OfflineStore() *OfflineStore {
	return m.offlineStore()
}

func (m *Manager) networkStore() *NetworkStore {
	if m == nil {
		return nil
	}
	return m.network
}

func (m *Manager) offlineStore() *OfflineStore {
	if m == nil {
		return nil
	}
	return m.offline
}

func HistoryRootDir(dataDir string) string {
	return filepath.Join(dataDir, "history")
}
