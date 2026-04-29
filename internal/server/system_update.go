package server

import (
	"context"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/updater"
)

const systemUpdateRefreshWindow = 60 * time.Second

type SystemUpdateView struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version,omitempty"`
	Available      bool   `json:"available"`
	Updating       bool   `json:"updating"`
	Supported      bool   `json:"supported"`
	Mode           string `json:"mode"`
	Message        string `json:"message,omitempty"`
	HTMLURL        string `json:"html_url,omitempty"`
	PublishedAt    string `json:"published_at,omitempty"`
	LastCheckedAt  int64  `json:"last_checked_at,omitempty"`
	LastStartedAt  int64  `json:"last_started_at,omitempty"`
	LastFinishedAt int64  `json:"last_finished_at,omitempty"`
}

type AgentUpdateView struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version,omitempty"`
	Available      bool   `json:"available"`
	Supported      bool   `json:"supported"`
	Mode           string `json:"mode"`
	Message        string `json:"message,omitempty"`
	HTMLURL        string `json:"html_url,omitempty"`
	PublishedAt    string `json:"published_at,omitempty"`
}

type systemUpdateManager struct {
	mu             sync.Mutex
	client         *updater.Client
	lastInfo       updater.ReleaseInfo
	lastCheckedAt  time.Time
	lastStartedAt  time.Time
	lastFinishedAt time.Time
	updating       bool
	message        string
}

func newSystemUpdateManager(currentVersion string) *systemUpdateManager {
	return &systemUpdateManager{
		client: updater.NewClient(updater.DefaultRepo, updater.KindServer, currentVersion),
	}
}

func (m *systemUpdateManager) View(ctx context.Context, force bool) SystemUpdateView {
	m.mu.Lock()
	defer m.mu.Unlock()

	if force || m.lastCheckedAt.IsZero() || time.Since(m.lastCheckedAt) > systemUpdateRefreshWindow {
		m.refreshLocked(ctx)
	}

	return m.snapshotLocked()
}

func (m *systemUpdateManager) CheckLatest(ctx context.Context) (updater.ReleaseInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refreshLocked(ctx)
}

func (m *systemUpdateManager) Start(info updater.ReleaseInfo, apply func() error) error {
	m.mu.Lock()
	if m.updating {
		m.mu.Unlock()
		return context.Canceled
	}
	m.updating = true
	m.lastInfo = info
	m.lastStartedAt = time.Now()
	if updater.CanDockerManagedUpdate() {
		m.message = "正在拉取新镜像并准备重建服务端容器"
	} else {
		m.message = "正在下载并替换服务端二进制"
	}
	m.mu.Unlock()

	go func() {
		err := apply()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.lastFinishedAt = time.Now()
		if err != nil {
			m.updating = false
			m.message = err.Error()
			return
		}
		m.updating = false
		if updater.CanDockerManagedUpdate() {
			m.message = "Docker 更新任务已启动，服务端容器即将重建"
		} else {
			m.message = "更新包已写入，服务正在重启"
		}
	}()

	return nil
}

func (m *systemUpdateManager) snapshotLocked() SystemUpdateView {
	currentVersion := "dev"
	if current := strings.TrimSpace(m.client.CurrentVersion); current != "" {
		currentVersion = current
	}
	return SystemUpdateView{
		CurrentVersion: currentVersion,
		LatestVersion:  strings.TrimSpace(m.lastInfo.LatestVersion),
		Available:      m.lastInfo.HasUpdate,
		Updating:       m.updating,
		Supported:      updater.CanCurrentDeployUpdate(),
		Mode:           updater.DetectUpdateMode(),
		Message:        systemUpdateMessage(strings.TrimSpace(m.message)),
		HTMLURL:        strings.TrimSpace(m.lastInfo.HTMLURL),
		PublishedAt:    strings.TrimSpace(m.lastInfo.PublishedAt),
		LastCheckedAt:  m.lastCheckedAt.Unix(),
		LastStartedAt:  unixOrZero(m.lastStartedAt),
		LastFinishedAt: unixOrZero(m.lastFinishedAt),
	}
}

func (m *systemUpdateManager) refreshLocked(ctx context.Context) (updater.ReleaseInfo, error) {
	info, err := m.client.CheckLatest(ctx)
	m.lastCheckedAt = time.Now()
	if err != nil {
		m.message = err.Error()
		return updater.ReleaseInfo{}, err
	}
	m.lastInfo = info
	if !m.updating {
		m.message = ""
	}
	return info, nil
}

func unixOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}

func systemUpdateMessage(message string) string {
	if message != "" {
		return message
	}
	return updater.DefaultUnsupportedUpdateMessage()
}

func buildAgentUpdateView(stats metrics.NodeStats, info updater.ReleaseInfo, message string) AgentUpdateView {
	return AgentUpdateView{
		CurrentVersion: strings.TrimSpace(stats.AgentVersion),
		LatestVersion:  strings.TrimSpace(info.LatestVersion),
		Available:      info.HasUpdate,
		Supported:      resolveAgentUpdateSupported(stats),
		Mode:           resolveAgentUpdateMode(stats),
		Message:        strings.TrimSpace(message),
		HTMLURL:        strings.TrimSpace(info.HTMLURL),
		PublishedAt:    strings.TrimSpace(info.PublishedAt),
	}
}
