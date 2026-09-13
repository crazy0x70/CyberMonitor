package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/updater"
)

const systemUpdateRefreshWindow = 60 * time.Second

// systemUpdateCheckTimeout 是单轮 release check 的独立上限：领跑者与请求
// ctx 解耦后需要自己的超时兜底，不能依赖管理端请求超时。
const systemUpdateCheckTimeout = 15 * time.Second

var errSystemUpdateInProgress = errors.New("system update already in progress")

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

type agentReleaseChecker func(context.Context, metrics.NodeStats) (updater.ReleaseInfo, error)

type systemUpdateManager struct {
	mu             sync.Mutex
	client         *updater.Client
	lastInfo       updater.ReleaseInfo
	lastCheckError string
	lastAttemptAt  time.Time
	lastCheckedAt  time.Time
	lastStartedAt  time.Time
	lastFinishedAt time.Time
	starting       bool
	updating       bool
	refreshing     bool
	refreshDone    chan struct{}
	refreshResult  *systemUpdateRefreshResult
	message        string
}

type systemUpdateStartReservation struct {
	manager *systemUpdateManager
	active  bool
}

func newSystemUpdateManager(currentVersion string) *systemUpdateManager {
	return &systemUpdateManager{
		client: updater.NewClient(updater.DefaultRepo, updater.KindServer, currentVersion),
	}
}

func (m *systemUpdateManager) View(ctx context.Context, force bool) SystemUpdateView {
	if m.needsRefresh(force, time.Now()) {
		_, _ = m.refresh(ctx, force)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotLocked()
}

func (m *systemUpdateManager) CheckLatest(ctx context.Context) (updater.ReleaseInfo, error) {
	return m.refresh(ctx, true)
}

func (m *systemUpdateManager) ReserveStart() (*systemUpdateStartReservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updating || m.starting {
		return nil, errSystemUpdateInProgress
	}
	m.starting = true
	return &systemUpdateStartReservation{manager: m, active: true}, nil
}

func (r *systemUpdateStartReservation) Cancel() {
	if r == nil || !r.active {
		return
	}
	r.manager.mu.Lock()
	if r.active {
		r.manager.starting = false
		r.active = false
	}
	r.manager.mu.Unlock()
}

func (r *systemUpdateStartReservation) Start(info updater.ReleaseInfo, dockerManaged bool, apply func() error) error {
	if r == nil || !r.active {
		return errSystemUpdateInProgress
	}
	m := r.manager
	m.mu.Lock()
	if m.updating || !m.starting {
		r.active = false
		m.mu.Unlock()
		return errSystemUpdateInProgress
	}
	r.active = false
	m.starting = false
	m.startLocked(info, dockerManaged)
	m.mu.Unlock()
	m.runApply(dockerManaged, apply)
	return nil
}

func (m *systemUpdateManager) startLocked(info updater.ReleaseInfo, dockerManaged bool) {
	m.updating = true
	m.lastInfo = info
	m.lastStartedAt = time.Now()
	if dockerManaged {
		m.message = "正在拉取新镜像并准备重建服务端容器"
	} else {
		m.message = "正在下载并替换服务端二进制"
	}
}

func (m *systemUpdateManager) runApply(dockerManaged bool, apply func() error) {
	go func() {
		err := apply()
		m.mu.Lock()
		defer m.mu.Unlock()
		if err != nil {
			m.lastFinishedAt = time.Now()
			m.updating = false
			m.message = err.Error()
			return
		}
		if dockerManaged {
			m.lastFinishedAt = time.Now()
			m.updating = false
			m.message = "Docker 更新 helper 已启动，服务端容器重建由 Docker 接管"
			return
		}
		m.lastFinishedAt = time.Now()
		m.updating = false
		m.message = "更新包已写入，服务正在重启"
	}()
}

func (m *systemUpdateManager) snapshotLocked() SystemUpdateView {
	currentVersion := "dev"
	if current := strings.TrimSpace(m.client.CurrentVersion); current != "" {
		currentVersion = current
	}
	message := strings.TrimSpace(m.message)
	if message == "" && !m.updating {
		message = strings.TrimSpace(m.lastCheckError)
	}
	return SystemUpdateView{
		CurrentVersion: currentVersion,
		LatestVersion:  strings.TrimSpace(m.lastInfo.LatestVersion),
		Available:      m.lastInfo.HasUpdate,
		Updating:       m.updating,
		Supported:      updater.CanCurrentDeployUpdate(),
		Mode:           updater.DetectUpdateMode(),
		Message:        systemUpdateMessage(message),
		HTMLURL:        strings.TrimSpace(m.lastInfo.HTMLURL),
		PublishedAt:    strings.TrimSpace(m.lastInfo.PublishedAt),
		LastCheckedAt:  unixOrZero(m.lastCheckedAt),
		LastStartedAt:  unixOrZero(m.lastStartedAt),
		LastFinishedAt: unixOrZero(m.lastFinishedAt),
	}
}

func (m *systemUpdateManager) needsRefresh(force bool, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return force || m.lastAttemptAt.IsZero() || now.Sub(m.lastAttemptAt) > systemUpdateRefreshWindow
}

// systemUpdateRefreshResult 是单轮 refresh 的结果快照，专供等待该轮的
// 调用方读取，避免读到后续轮次重置后的共享状态。
type systemUpdateRefreshResult struct {
	info updater.ReleaseInfo
	err  error
}

func (m *systemUpdateManager) refresh(ctx context.Context, force bool) (updater.ReleaseInfo, error) {
	m.mu.Lock()
	if m.refreshing {
		// 等待者读取本轮 result 指针而非共享字段：若读 m.lastInfo/m.refreshErr，
		// 新一轮 refresh 启动时会把 refreshErr 清为 nil，旧一轮的失败被吞。
		result := m.refreshResult
		done := m.refreshDone
		m.mu.Unlock()
		select {
		case <-done:
			if result.err != nil {
				return updater.ReleaseInfo{}, result.err
			}
			return result.info, nil
		case <-ctx.Done():
			return updater.ReleaseInfo{}, ctx.Err()
		}
	}
	now := time.Now()
	if !force && !m.lastAttemptAt.IsZero() && now.Sub(m.lastAttemptAt) <= systemUpdateRefreshWindow {
		info := m.lastInfo
		errMessage := strings.TrimSpace(m.lastCheckError)
		m.mu.Unlock()
		if errMessage != "" {
			return updater.ReleaseInfo{}, errors.New(errMessage)
		}
		return info, nil
	}
	done := make(chan struct{})
	result := &systemUpdateRefreshResult{}
	m.refreshing = true
	m.refreshDone = done
	m.refreshResult = result
	m.mu.Unlock()

	// 领跑者与请求 ctx 解耦：领跑者客户端断开不得取消整轮刷新，
	// 否则所有等待者拿到 context.Canceled，活请求集体报错。
	checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), systemUpdateCheckTimeout)
	defer cancel()
	info, err := m.client.CheckLatest(checkCtx)
	checkedAt := time.Now()
	m.mu.Lock()
	defer func() {
		result.info = info
		result.err = err
		m.refreshing = false
		if m.refreshDone == done {
			m.refreshDone = nil
			m.refreshResult = nil
		}
		close(done)
		m.mu.Unlock()
	}()
	// 超时/取消同样是真实发生的上游尝试，必须记录 lastAttemptAt，
	// 否则节流窗口失效，慢上游期间每次请求都会重新发起刷新。
	m.lastAttemptAt = checkedAt
	if err != nil {
		m.lastCheckError = err.Error()
		if !m.updating {
			m.message = ""
		}
		return updater.ReleaseInfo{}, err
	}
	m.lastInfo = info
	m.lastCheckError = ""
	m.lastCheckedAt = checkedAt
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

func releaseUpdateAssetError(kind updater.Kind, dockerManaged bool, missingAssetMessage string, info updater.ReleaseInfo) string {
	if strings.TrimSpace(info.LatestVersion) == "" {
		return "Release 缺少目标版本"
	}
	if dockerManaged {
		return ""
	}
	if strings.TrimSpace(info.DownloadURL) == "" {
		return missingAssetMessage
	}
	if strings.TrimSpace(info.ChecksumURL) == "" {
		return "Release 缺少 SHA256SUMS 校验文件"
	}
	if err := updater.ValidateReleaseAssetURLs(kind, info.LatestVersion, info.DownloadURL, info.ChecksumURL); err != nil {
		return err.Error()
	}
	return ""
}

func agentUpdateReleaseAssetError(stats metrics.NodeStats, info updater.ReleaseInfo) string {
	return releaseUpdateAssetError(updater.KindAgent, resolveAgentUpdateMode(stats) == "docker-managed", "未找到当前节点平台对应的 Agent 安装包", info)
}

func systemUpdateReleaseAssetError(info updater.ReleaseInfo, dockerManaged bool) string {
	return releaseUpdateAssetError(updater.KindServer, dockerManaged, "未找到当前平台对应的服务端安装包", info)
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
