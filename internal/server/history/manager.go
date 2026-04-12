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
	if m == nil {
		return nil
	}
	var networkErr error
	if m.network != nil {
		networkErr = m.network.Close()
	}
	var offlineErr error
	if m.offline != nil {
		offlineErr = m.offline.Close()
	}
	return errors.Join(networkErr, offlineErr)
}

func (m *Manager) AppendNetworkBatch(nodeID string, tests []metrics.NetworkTestResult, now time.Time) error {
	if m == nil || m.network == nil {
		return nil
	}
	return m.network.AppendBatch(nodeID, tests, now)
}

func (m *Manager) DeleteNode(nodeID string) error {
	if m == nil {
		return nil
	}
	var networkErr error
	if m.network != nil {
		networkErr = m.network.DeleteNode(nodeID)
	}
	var offlineErr error
	if m.offline != nil {
		offlineErr = m.offline.DeleteNode(nodeID)
	}
	return errors.Join(networkErr, offlineErr)
}

func (m *Manager) ClearNodes() error {
	if m == nil {
		return nil
	}
	var networkErr error
	if m.network != nil {
		networkErr = m.network.Clear()
	}
	var offlineErr error
	if m.offline != nil {
		offlineErr = m.offline.Clear()
	}
	return errors.Join(networkErr, offlineErr)
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
