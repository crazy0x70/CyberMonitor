package history

import (
	"errors"
	"path/filepath"
	"strings"
	"time"

	"cyber_monitor/internal/metrics"
)

type Manager struct {
	network  *NetworkStore
	offline  *OfflineStore
	resource *ResourceStore
}

func OpenManager(dataDir string, resourceRetentionDays int) (*Manager, error) {
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
	resource, err := OpenResourceStore(defaultResourceStoreDir(dataDir), resourceRetentionDays)
	if err != nil {
		_ = network.Close()
		_ = offline.Close()
		return nil, err
	}
	return &Manager{
		network:  network,
		offline:  offline,
		resource: resource,
	}, nil
}

func (m *Manager) Close() error {
	return errors.Join(
		runStoreOp(m.networkStore(), (*NetworkStore).Close),
		runStoreOp(m.offlineStore(), (*OfflineStore).Close),
		runStoreOp(m.resourceStore(), (*ResourceStore).Close),
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
	nodeID, err := NormalizeNodeID(nodeID)
	if err != nil || nodeID == "" {
		return err
	}
	return errors.Join(
		runStoreOp(m.networkStore(), func(store *NetworkStore) error { return store.DeleteNode(nodeID) }),
		runStoreOp(m.offlineStore(), func(store *OfflineStore) error { return store.DeleteNode(nodeID) }),
		runStoreOp(m.resourceStore(), func(store *ResourceStore) error { return store.DeleteNode(nodeID) }),
	)
}

func (m *Manager) HasNodeHistory(nodeID string) (bool, error) {
	var err error
	nodeID, err = NormalizeNodeID(nodeID)
	if err != nil || nodeID == "" {
		return false, err
	}
	for _, store := range []historyExistenceStore{m.networkStore(), m.offlineStore(), m.resourceStore()} {
		if store == nil {
			continue
		}
		if ok, err := hasStoreHistory(store, nodeID); ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}

type historyExistenceStore interface {
	HasNodeHistory(string) (bool, error)
}

func hasStoreHistory(store historyExistenceStore, nodeID string) (bool, error) {
	if store == nil {
		return false, nil
	}
	return store.HasNodeHistory(nodeID)
}

func (m *Manager) ClearNodes() error {
	return errors.Join(
		runStoreOp(m.networkStore(), (*NetworkStore).Clear),
		runStoreOp(m.offlineStore(), (*OfflineStore).Clear),
		runStoreOp(m.resourceStore(), (*ResourceStore).Clear),
	)
}

func (m *Manager) NetworkStore() *NetworkStore {
	return m.networkStore()
}

func (m *Manager) ResourceStore() *ResourceStore {
	return m.resourceStore()
}

// ObserveResource 计入一次资源采样（30 秒桶内求平均）。
func (m *Manager) ObserveResource(nodeID string, stats metrics.NodeStats, now time.Time) error {
	store := m.resourceStore()
	if store == nil {
		return nil
	}
	return store.Observe(nodeID, stats, now)
}

// FlushResourceHistory 落盘已结束的桶并清理过期样本，由服务端巡检每秒调用。
func (m *Manager) FlushResourceHistory(now time.Time) error {
	store := m.resourceStore()
	if store == nil {
		return nil
	}
	return store.FlushExpired(now)
}

// SetResourceRetentionDays 运行时修改资源历史保留天数。
func (m *Manager) SetResourceRetentionDays(days int) error {
	store := m.resourceStore()
	if store == nil {
		return nil
	}
	return store.SetRetentionDays(days)
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

func (m *Manager) resourceStore() *ResourceStore {
	if m == nil {
		return nil
	}
	return m.resource
}

func HistoryRootDir(dataDir string) string {
	return filepath.Join(dataDir, "history")
}
