package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/agentrpc"
	"cyber_monitor/internal/cmdutil"
	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/netguard"
	"cyber_monitor/internal/server/history"
	"cyber_monitor/internal/updater"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxLogSize        = 10 * 1024 * 1024
	maxLogBackupCount = 3
	maxJSONBodySize   = 4 * 1024 * 1024
	// maxPublicRequestBodySize 是公开入口最外层（包在 h2c 之外）的请求体上限。
	// h2c 的 HTTP/1.1 upgrade 握手会在路由/鉴权之前把整个请求体 io.ReadAll 进内存
	// （x/net/http2/h2c 的 h2cUpgrade），必须用 http.MaxBytesHandler 约束这条无界入口。
	// 取值 ≥ maxJSONBodySize，并远大于 Agent HTTP 回退上报体积。
	maxPublicRequestBodySize        = 16 * 1024 * 1024
	wsMaxClientMessageBytes         = 4 * 1024
	maxHTTPHeaderBytes              = 1 << 20
	wsSendQueueSize                 = 8
	wsWriteWait                     = 10 * time.Second
	wsPongWait                      = 60 * time.Second
	wsPingPeriod                    = (wsPongWait * 9) / 10
	agentRateSweepInterval          = 5 * time.Minute
	agentUpdateLeaseDelivery        = 2 * time.Minute
	agentUpdateLeaseUpdating        = 10 * time.Minute
	agentUpdateLeaseRestart         = 5 * time.Minute
	agentUpdateStatePending         = "pending"
	agentUpdateStateUpdating        = "updating"
	agentUpdateStateRestarting      = "restarting"
	agentUpdateStateSucceeded       = "succeeded"
	agentUpdateStateFailed          = "failed"
	agentIngestWindow               = time.Second
	agentRegisterWindow             = time.Minute
	defaultAgentIngestLimit         = 2
	defaultAgentRegisterLimit       = 1
	defaultAgentRegisterGlobalLimit = 30
	// register-invalid:* 桶的限速：非法 bootstrap token 的猜测速率上限，与全局注册
	// 配额同量级（改动前非法请求消耗 register:* 时即受 30 次/分钟约束）。
	defaultAgentRegisterInvalidLimit = 30
	maxNetworkTestsPerNode           = 128
	// maxLoginUsernameLen 限制登录用户名的字节长度：用户名直接作为 loginAttempts 的键，
	// 无上限时被拒的登录可用接近 4MB 的请求体写出超长键，轮换用户名即可无限堆积。
	maxLoginUsernameLen = 256
	// maxLoginAttemptsEntries 是 loginAttempts 的硬上限，保证 map 大小有界。
	maxLoginAttemptsEntries = 4096
	// loginAttemptPruneInterval 是摊还清理间隔：每 N 次登录限流操作才做一次全表扫描，
	// 避免未认证流量在全局锁内触发随表大小线性上升的 O(n) 扫描。
	loginAttemptPruneInterval = 64
	// loginAttemptEvictBatch 是表达到上限时按最旧活跃时间淘汰的批大小。
	loginAttemptEvictBatch = 256
	// loginGlobalAttemptKey 是进程级登录尝试预算的固定键：不含任何攻击者可控字段，
	// 使任意用户名/IP 轮换下的 bcrypt 总次数在 defaultLoginFailWindow 窗口内有上界。
	loginGlobalAttemptKey = "login-global"
	// defaultLoginGlobalLimit 是全局登录尝试预算：取单 IP 阈值的 10 倍，宽松到不误伤
	// 正常运维，同时把全进程每窗口的 bcrypt 次数封顶（单 IP 键已被 IP 分桶约束）。
	defaultLoginGlobalLimit       = 10 * defaultLoginFailLimit
	nodeStaleGraceSeconds         = 12
	nodeStatusOnline              = "online"
	nodeStatusOffline             = "offline"
	nodeStatusWaitingRegistration = "waiting_registration"
	publicVariantBalanced         = "balanced"
	adminVariant                  = "admin"
	adminSessionCookieName        = "cm_admin_session"
	// publicWSGlobalLimit / publicWSPerIPLimit 是公开（未认证）WS 连接的进程级上限：
	// 全局与按真实客户端 IP 双重限制，避免未认证放大（每条连接一次全量快照 + 三条 goroutine）。
	publicWSGlobalLimit = 512
	publicWSPerIPLimit  = 8
	// startupOfflineGrace 是服务端启动后的离线判定宽限期：自身重启期间节点 LastSeen
	// 停留在旧值，若不设宽限期会在启动瞬间对全部节点产生离线告警风暴与离线历史污染。
	// 宽限期结束后恢复正常判定，始终不重连的节点仍会在宽限期后被告警。
	startupOfflineGrace = 60 * time.Second
	// alertDeliveryDrainTimeout 是关闭时等待告警投递 goroutine 的兜底上限：避免排空卡死。
	alertDeliveryDrainTimeout = 5 * time.Second
)

// loginGlobalAttemptLimit 是全局登录尝试预算的当前值。用变量而非常量，便于测试注入较小
// 阈值，避免用例为触发全局预算而支付大量 bcrypt 成本；生产值恒为 defaultLoginGlobalLimit。
var loginGlobalAttemptLimit = defaultLoginGlobalLimit

type sizeLimitedWriter struct {
	path    string
	maxSize int64
	mu      sync.Mutex
	file    *os.File
	size    int64
}

var reportLogger = log.New(io.Discard, "", log.LstdFlags)

// Write 保持常驻文件句柄，仅在轮转时重开；log.Logger 串行调用，这里仅防多 Logger 共享时竞争。
func (w *sizeLimitedWriter) Write(p []byte) (int, error) {
	if w == nil || w.path == "" || w.maxSize <= 0 {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		if err := w.openLocked(); err != nil {
			return len(p), err
		}
	}
	if w.size+int64(len(p)) > w.maxSize {
		if err := w.rotateLocked(); err != nil {
			return len(p), err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	if err != nil {
		return len(p), err
	}
	return len(p), nil
}

func (w *sizeLimitedWriter) openLocked() error {
	if dir := filepath.Dir(w.path); dir != "" {
		_ = os.MkdirAll(dir, 0755)
	}
	file, err := os.OpenFile(w.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	w.file = file
	w.size = info.Size()
	return nil
}

func (w *sizeLimitedWriter) rotateLocked() error {
	_ = w.file.Close()
	w.file = nil
	if err := rotateLogFile(w.path, maxLogBackupCount); err != nil {
		return err
	}
	if err := w.openLocked(); err != nil {
		return err
	}
	w.size = 0
	return nil
}

func rotateLogFile(path string, backups int) error {
	if path == "" || backups <= 0 {
		return nil
	}
	for idx := backups; idx >= 1; idx-- {
		src := path
		if idx > 1 {
			src = fmt.Sprintf("%s.%d", path, idx-1)
		}
		dst := fmt.Sprintf("%s.%d", path, idx)
		if _, err := os.Stat(src); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func setupLogger(dataDir string) {
	runtimeAdminLogs.Reset()
	serverOutput := io.Writer(os.Stdout)
	reportOutput := io.Writer(os.Stdout)
	serverCapture := adminLogCaptureWriter{source: "server"}
	reportCapture := adminLogCaptureWriter{source: "report"}
	if dataDir == "" {
		log.SetOutput(io.MultiWriter(serverOutput, serverCapture))
		reportLogger.SetOutput(io.MultiWriter(reportOutput, reportCapture))
		return
	}
	serverPath := filepath.Join(dataDir, "server.log")
	reportPath := filepath.Join(dataDir, "report.log")
	runtimeAdminLogs.SeedFile(serverPath, "server")
	runtimeAdminLogs.SeedFile(reportPath, "report")
	serverWriter := &sizeLimitedWriter{path: serverPath, maxSize: maxLogSize}
	reportWriter := &sizeLimitedWriter{path: reportPath, maxSize: maxLogSize}
	serverOutput = io.MultiWriter(os.Stdout, serverWriter, serverCapture)
	reportOutput = io.MultiWriter(reportWriter, reportCapture)
	log.SetOutput(serverOutput)
	reportLogger.SetOutput(reportOutput)
}

func wrapDataPathError(action, path string, err error) error {
	if err == nil {
		return nil
	}
	if os.IsPermission(err) || errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%s: %w（请检查 %s 的所有者与读写权限）", action, err, path)
	}
	return fmt.Errorf("%s: %w", action, err)
}

const (
	defaultAddr            = ":25012"
	defaultTestIntervalSec = 5
	defaultPersistInterval = 10 * time.Second
)

//go:embed web/public/* web/public/assets/* web/dist/admin/* web/dist/admin/assets/*
var webFS embed.FS

var webAssetRefPattern = regexp.MustCompile(`(?i)(?:src|href)="\.?/?assets/([^"]+)"`)

func verifyEmbeddedWebAssets() error {
	pages := []struct {
		page string
		dir  string
	}{
		{"web/public/index.html", "web/public/assets"},
		{"web/dist/admin/index.html", "web/dist/admin/assets"},
	}
	for _, item := range pages {
		data, err := webFS.ReadFile(item.page)
		if err != nil {
			return fmt.Errorf("读取内嵌页面 %s 失败: %w", item.page, err)
		}
		for _, ref := range webAssetRefPattern.FindAllStringSubmatch(string(data), -1) {
			if _, err := webFS.Open(filepath.Join(item.dir, ref[1])); err != nil {
				return fmt.Errorf("内嵌前端资源缺失: %s 引用的 assets/%s 不存在，dist 构建不完整（重新执行 npm run build:admin 后再编译）", item.page, ref[1])
			}
		}
	}
	return nil
}

var newAgentUpdateID = func() (string, error) {
	return randomToken(16)
}

type Config struct {
	Addr                string
	PublicAddr          string
	AdminUser           string
	AdminPass           string
	AdminPath           string
	JWTSecret           string
	AgentToken          string
	DataDir             string
	Version             string
	Commit              string
	TrustedProxyHeaders bool
}

type Store struct {
	mu                sync.RWMutex
	agentMutationMu   sync.RWMutex
	nodeMutationMu    sync.Mutex
	nodeMutationLocks map[string]*nodeMutationLock
	persistMu         sync.Mutex
	persistPending    bool // 持久化失败后置位（persistMu 内维护），成功后清除
	nodes             map[string]NodeState
	profiles          map[string]*NodeProfile
	settings          Settings
	buildVersion      string
	buildCommit       string
	dataPath          string
	lastPersist       time.Time
	persistInterval   time.Duration
	alerted           map[string]AlertedState
	offlineSessions   map[string]OfflineSessionState
	// alertStates（F4）按 nodeID|ruleID 记录告警规则评估状态机（offline 规则除外，
	// 继续使用 alerted）；ruleSamples 为同 key 的阈值类样本环（仅内存，重启重建）。
	alertStates        map[string]RuleAlertState
	ruleSamples        map[string][]ruleSample
	historyManager     *history.Manager
	pendingNodeDeletes map[string]struct{}
	pendingClearNodes  bool
	loginAttempts      map[string]*loginAttempt
	loginPruneOps      int
	configRefresh      map[string]struct{}
	agentIngestRate    map[string]agentRateWindow
	agentRegisterRate  map[string]agentRateWindow

	// startedAt 是服务端进程启动时间（仅内存，不落盘）：启动宽限期内抑制离线告警与
	// 离线会话/历史写入，避免自身停机被误判为节点离线。
	startedAt time.Time
	// alertDeliveryWG 跟踪 tick 循环派生的告警投递 goroutine：关闭时在释放
	// historyManager/数据目录锁之前做有界等待。
	alertDeliveryWG sync.WaitGroup
}

type nodeMutationLock struct {
	mu   sync.RWMutex
	refs int
}

type NodeState struct {
	Stats     metrics.NodeStats `json:"stats"`
	LastSeen  time.Time         `json:"last_seen"`
	FirstSeen time.Time         `json:"first_seen"`
}

type NodeProfile struct {
	ServerID       string   `json:"server_id,omitempty"`
	AgentAuthToken string   `json:"agent_auth_token,omitempty"`
	AlertEnabled   *bool    `json:"alert_enabled,omitempty"`
	Alias          string   `json:"alias,omitempty"`
	Group          string   `json:"group,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Groups         []string `json:"groups,omitempty"`

	GroupSeeded      bool   `json:"group_seeded,omitempty"`
	Region           string `json:"region,omitempty"`
	HideFromCR       bool   `json:"hide_from_cr,omitempty"`
	HideFromAll      bool   `json:"hide_from_all,omitempty"`
	HideFromDisplay  bool   `json:"hide_from_display,omitempty"`
	DiskType         string `json:"disk_type,omitempty"`
	NetSpeedMbps     int    `json:"net_speed_mbps,omitempty"`
	ExpireAt         int64  `json:"expire_at,omitempty"`
	AutoRenew        bool   `json:"auto_renew,omitempty"`
	RenewIntervalSec int64  `json:"renew_interval_sec,omitempty"`
	// 流量配额（F4 traffic_quota 前置）：配额与计算方式为配置，TrafficCounter 为
	// updateNodeStats 按增量累加的运行数据（均落盘）。
	TrafficLimitBytes        uint64                  `json:"traffic_limit_bytes,omitempty"`
	TrafficLimitType         string                  `json:"traffic_limit_type,omitempty"` // sum|max|up|down，默认 sum
	TrafficResetDay          int                     `json:"traffic_reset_day,omitempty"`  // 1–28，默认 1
	TrafficCounter           *TrafficCounter         `json:"traffic_counter,omitempty"`
	TestIntervalSec          int                     `json:"test_interval_sec"`
	TestSelections           []TestSelection         `json:"test_selections,omitempty"`
	AgentUpdate              *AgentUpdateInstruction `json:"agent_update,omitempty"`
	AgentUpdateState         string                  `json:"agent_update_state,omitempty"`
	AgentUpdateTargetVersion string                  `json:"agent_update_target_version,omitempty"`
	AgentUpdateMessage       string                  `json:"agent_update_message,omitempty"`
	AgentUpdateLeaseUntil    int64                   `json:"agent_update_lease_until,omitempty"`
	AgentUpdateReportedAt    int64                   `json:"agent_update_reported_at,omitempty"`
	UpdatedAt                int64                   `json:"updated_at,omitempty"`
}

type AgentUpdateInstruction struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	ChecksumURL string `json:"checksum_url,omitempty"`
	RequestedAt int64  `json:"requested_at,omitempty"`
}

type TestSelection struct {
	TestID      string `json:"test_id"`
	IntervalSec int    `json:"interval_sec,omitempty"`
}

type AgentConfig struct {
	Alias           string                      `json:"alias"`
	Group           string                      `json:"group"`
	AgentToken      string                      `json:"agent_token,omitempty"`
	TestIntervalSec int                         `json:"test_interval_sec"`
	Tests           []metrics.NetworkTestConfig `json:"tests"`
	Update          *AgentUpdateInstruction     `json:"update,omitempty"`
}

type NodeView struct {
	Stats             metrics.NodeStats `json:"stats"`
	LastSeen          int64             `json:"last_seen"`
	FirstSeen         int64             `json:"first_seen,omitempty"`
	Status            string            `json:"status"`
	ServerID          string            `json:"server_id,omitempty"`
	AlertEnabled      bool              `json:"alert_enabled"`
	Alias             string            `json:"alias,omitempty"`
	Group             string            `json:"group,omitempty"`
	Tags              []string          `json:"tags,omitempty"`
	Groups            []string          `json:"groups,omitempty"`
	Region            string            `json:"region,omitempty"`
	HiddenFromDisplay bool              `json:"hidden_from_display,omitempty"`
	HiddenFromCR      bool              `json:"hidden_from_cr,omitempty"`
	HiddenFromAll     bool              `json:"hidden_from_all,omitempty"`
	DiskType          string            `json:"disk_type,omitempty"`
	NetSpeedMbps      int               `json:"net_speed_mbps,omitempty"`
	ExpireAt          int64             `json:"expire_at,omitempty"`
	AutoRenew         bool              `json:"auto_renew,omitempty"`
	RenewIntervalSec  int64             `json:"renew_interval_sec,omitempty"`
	TrafficLimitBytes uint64            `json:"traffic_limit_bytes,omitempty"`
	TrafficLimitType  string            `json:"traffic_limit_type,omitempty"`
	TrafficResetDay   int               `json:"traffic_reset_day,omitempty"`
	// A-02：管理端专属的流量用量字段（红线 4：不得进入公开快照与公开 WS 载荷）。
	// 只在 AdminSnapshot 路径（snapshotLocked includeProfileOnly=true）填充；
	// nodeViewLocked 保持零值，omitempty 序列化时省略，公开快照与 node_delta 不含。
	TrafficUsedBytes  uint64 `json:"traffic_used_bytes,omitempty"`
	TrafficCycleStart int64  `json:"traffic_cycle_start,omitempty"`
	// O-01：管理端专属的范围下发探测目录项 ID（只读；手动选择优先，已被节点手动
	// 选择的目录项不列入）。红线 4：同样只在 AdminSnapshot 路径填充，公开快照与
	// node_delta 不含。
	ScopedTestIDs            []string        `json:"scoped_test_ids,omitempty"`
	TestIntervalSec          int             `json:"test_interval_sec,omitempty"`
	TestSelections           []TestSelection `json:"test_selections,omitempty"`
	AgentUpdateSupported     bool            `json:"agent_update_supported"`
	AgentUpdateMode          string          `json:"agent_update_mode,omitempty"`
	AgentUpdateState         string          `json:"agent_update_state,omitempty"`
	AgentUpdateTargetVersion string          `json:"agent_update_target_version,omitempty"`
	AgentUpdateMessage       string          `json:"agent_update_message,omitempty"`
}

// publicNodeView 生成公开受众的 NodeView 投影（红线 4：管理端专属字段不得进入
// 公开快照与公开 WS 载荷）。返回副本、不改原值；json tag 保持不变（管理端依赖
// 它们），没有 omitempty 的 bool 清零后序列化为 false 是可接受的。
func publicNodeView(view NodeView) NodeView {
	view.ServerID = ""
	view.AlertEnabled = false
	view.AgentUpdateSupported = false
	view.AgentUpdateMode = ""
	view.AgentUpdateState = ""
	view.AgentUpdateTargetVersion = ""
	view.AgentUpdateMessage = ""
	view.TrafficLimitBytes = 0
	view.TrafficLimitType = ""
	view.TrafficResetDay = 0
	view.Stats.PublicIPv4 = ""
	view.Stats.PublicIPv6 = ""
	view.Stats.DeployMode = ""
	view.Stats.AgentVersion = ""
	view.Stats.AgentUpdateDisabled = false
	view.Stats.AgentUpdateInsecure = false
	// docker_managed_update / agent_remote_update 同属管理端专属语义（公开页不使用，
	// 它们只用于管理端判断节点的升级方式与远程升级能力），一并清零。
	view.Stats.DockerManagedUpdate = false
	view.Stats.AgentRemoteUpdate = false
	return view
}

type PublicSettings struct {
	SiteTitle           string `json:"site_title,omitempty"`
	SiteIcon            string `json:"site_icon,omitempty"`
	SiteBackgroundImage string `json:"site_background_image,omitempty"`
	HomeTitle           string `json:"home_title,omitempty"`
	HomeSubtitle        string `json:"home_subtitle,omitempty"`
	Locale              string `json:"locale,omitempty"`
	RegionGroupEnabled  bool   `json:"region_group_enabled"`
}

type Snapshot struct {
	Type        string         `json:"type"`
	GeneratedAt int64          `json:"generated_at"`
	Nodes       []NodeView     `json:"nodes"`
	Groups      []string       `json:"groups,omitempty"`
	GroupTree   []GroupNode    `json:"group_tree,omitempty"`
	Settings    PublicSettings `json:"settings,omitempty"`
}

type PublicNodeHistoryResponse struct {
	NodeID   string                       `json:"node_id"`
	RangeKey string                       `json:"range_key"`
	From     int64                        `json:"from"`
	To       int64                        `json:"to"`
	Tests    map[string]*TestHistoryEntry `json:"tests"`
}

type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]*hubClient
}

type hubMessage struct {
	payload  []byte
	prepared *websocket.PreparedMessage
}

type hubClient struct {
	conn           *websocket.Conn
	variant        string
	adminTokenSalt string
	mu             sync.Mutex
	send           chan hubMessage
	done           chan struct{}
	once           sync.Once
}

type loginAttempt struct {
	failCount   int
	firstAt     time.Time
	lastAt      time.Time
	lockedUntil time.Time
}

type agentRateWindow struct {
	count int
	until time.Time
}

func (c *hubClient) writeMessage(msg hubMessage) error {
	if c == nil || c.conn == nil {
		return errors.New("websocket 连接不存在")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
	if msg.prepared != nil {
		return c.conn.WritePreparedMessage(msg.prepared)
	}
	return c.conn.WriteMessage(websocket.TextMessage, msg.payload)
}

func (c *hubClient) close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		close(c.done)
	})
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *hubClient) enqueue(payload []byte, prepared *websocket.PreparedMessage) bool {
	if c == nil {
		return false
	}
	msg := hubMessage{payload: payload, prepared: prepared}
	for {
		select {
		case <-c.done:
			return false
		case c.send <- msg:
			return true
		default:
		}
		select {
		case <-c.done:
			return false
		case <-c.send:
		default:
			continue
		}
	}
}

const shutdownGraceTimeout = 5 * time.Second

// 测试接缝（生产恒为 nil）：publicHandlerDecorator 允许测试在公开 handler 外层注入
// 阻塞逻辑；historyManagerCloseHook 允许测试观测 historyManager 关闭时序。二者仅用于
// 验证关闭排空顺序，不改变生产行为。
var (
	publicHandlerDecorator  func(http.Handler) http.Handler
	historyManagerCloseHook func()
)

func Run(ctx context.Context, cfg Config) error {
	if err := applyDefaults(&cfg); err != nil {
		return err
	}
	setupLogger(cfg.DataDir)

	if err := verifyEmbeddedWebAssets(); err != nil {
		return err
	}

	lockPath := filepath.Join(cfg.DataDir, "server.lock")
	lockFile, err := tryLockFile(lockPath)
	if err != nil {
		return wrapDataPathError("获取数据目录锁失败", lockPath, err)
	}
	defer lockFile.Close()

	dataPath := filepath.Join(cfg.DataDir, "state.json")
	persisted, loaded, err := loadPersistedData(dataPath)
	if err != nil {
		return wrapDataPathError("读取持久化数据失败", dataPath, err)
	}
	historyPath := filepath.Join(cfg.DataDir, testHistoryFileName)
	tokenGenerated := !loaded
	defaultSettings, err := initSettings(cfg)
	if err != nil {
		return err
	}
	settings := defaultSettings
	profiles := make(map[string]*NodeProfile)
	nodes := make(map[string]NodeState)
	offlineSessions := make(map[string]OfflineSessionState)
	alerted := make(map[string]AlertedState)
	alertStates := make(map[string]RuleAlertState)
	if loaded {
		settings, err = mergeSettings(persisted.Settings, defaultSettings)
		if err != nil {
			return err
		}
		profiles = persisted.Profiles
		if persisted.Nodes != nil {
			nodes = persisted.Nodes
		}
		if persisted.OfflineSessions != nil {
			offlineSessions = persisted.OfflineSessions
		}
		if persisted.Alerted != nil {
			alerted = persisted.Alerted
		}
		if persisted.AlertStates != nil {
			alertStates = persisted.AlertStates
		}
	}
	if err := ensureServerIDsForProfiles(profiles, nodes); err != nil {
		return err
	}
	if settings.AuthToken != "" {
		cfg.JWTSecret = settings.AuthToken
	}
	persistedSnapshot := PersistedData{
		Settings:              settings,
		Profiles:              profiles,
		Nodes:                 nodes,
		OfflineSessions:       offlineSessions,
		Alerted:               alerted,
		AlertStates:           alertStates,
		PendingHistoryClear:   persisted.PendingHistoryClear,
		PendingHistoryDeletes: slices.Clone(persisted.PendingHistoryDeletes),
	}
	if err := savePersistedData(dataPath, persistedSnapshot); err != nil {
		return wrapDataPathError("写入持久化数据失败", dataPath, err)
	}

	historyManager, err := history.OpenManager(cfg.DataDir, normalizeResourceHistoryDays(settings.ResourceHistoryDays))
	if err != nil {
		return wrapDataPathError("初始化历史存储失败", history.HistoryRootDir(cfg.DataDir), err)
	}
	defer func() {
		if historyManagerCloseHook != nil {
			historyManagerCloseHook()
		}
		if err := historyManager.Close(); err != nil {
			log.Printf("关闭历史存储失败: %v", err)
		}
	}()
	commit := strings.TrimSpace(cfg.Commit)
	if commit == "none" {
		commit = ""
	}
	if len(commit) > 7 {
		commit = commit[:7]
	}
	version := strings.TrimSpace(cfg.Version)
	if version == "" {
		version = "dev"
	}

	store := &Store{
		nodes:             nodes,
		profiles:          profiles,
		settings:          settings,
		buildVersion:      version,
		buildCommit:       commit,
		dataPath:          dataPath,
		persistInterval:   defaultPersistInterval,
		alerted:           alerted,
		offlineSessions:   offlineSessions,
		alertStates:       alertStates,
		ruleSamples:       make(map[string][]ruleSample),
		historyManager:    historyManager,
		loginAttempts:     make(map[string]*loginAttempt),
		configRefresh:     make(map[string]struct{}),
		agentIngestRate:   make(map[string]agentRateWindow),
		agentRegisterRate: make(map[string]agentRateWindow),
		startedAt:         time.Now(),
	}
	if _, err := recoverLegacyHistoryAndPendingCleanup(dataPath, historyPath, historyManager, persistedSnapshot); err != nil {
		return wrapDataPathError("恢复历史清理任务失败", dataPath, err)
	}
	hub := &Hub{clients: make(map[*websocket.Conn]*hubClient)}
	agentAPI := newAgentAPI(store, hub)
	systemUpdater := newSystemUpdateManager(version)
	splitMode := strings.TrimSpace(cfg.PublicAddr) != "" && cfg.PublicAddr != cfg.Addr
	trustedProxyHeaders := cfg.TrustedProxyHeaders

	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		return err
	}

	// F7 system/status：CPU 百分比后台采样器（随 runCtx 启动，见下）。
	statusMonitor := newSystemStatusMonitor()

	publicMux, adminMux, err := newRouteMuxes(routeDeps{
		cfg:                 cfg,
		store:               store,
		hub:                 hub,
		agentAPI:            agentAPI,
		systemUpdater:       systemUpdater,
		systemStatusMonitor: statusMonitor,
		splitMode:           splitMode,
		trustedProxyHeaders: trustedProxyHeaders,
		webRoot:             webRoot,
	})
	if err != nil {
		return err
	}

	grpcServer := newAgentRPCServer(agentAPI)
	publicHandler := stripForwardedPrefixPath(wrapPublicHandler(publicMux, grpcServer), trustedProxyHeaders)
	if publicHandlerDecorator != nil {
		publicHandler = publicHandlerDecorator(publicHandler)
	}
	publicServer := newHTTPServer(cfg.PublicAddr, withSecurityHeaders(publicHandler))

	adminServer := &http.Server{}
	if splitMode {
		adminServer = newHTTPServer(cfg.Addr, withSecurityHeaders(stripForwardedPrefixPath(adminMux, trustedProxyHeaders)))
	}

	tickDone := make(chan struct{})
	defer func() { <-tickDone }()
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	// F7 system/status：CPU 百分比每 5s 采样一次并缓存，请求只读缓存。
	statusMonitor.start(runCtx)
	go func() {
		defer close(tickDone)
		runTickLoop(runCtx, store, hub)
	}()

	startTelegramBot(ctx, store)

	// shutdownDone 在 HTTP Shutdown 完成排空（或 5s 宽限到期）后关闭：Run 必须等它关闭
	// 后才能返回，否则在途请求与告警投递 goroutine 会踩到随后释放的 TSDB 与锁文件。
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
		case <-runCtx.Done():
		}
		shutdownHTTPServer(publicServer)
		if splitMode {
			shutdownHTTPServer(adminServer)
		}
	}()

	log.Printf("管理后台路径已初始化")
	if splitMode {
		log.Printf("展示页监听: %s", cfg.PublicAddr)
		log.Printf("管理后台监听: %s", cfg.Addr)
	} else {
		log.Printf("监听: %s", cfg.Addr)
	}
	if !loaded {
		log.Printf("初始管理员账号: %s", settings.AdminUser)
		if settings.AdminPassPlain != "" {
			log.Printf("初始管理员密码: %s（自动生成，仅首次打印，请尽快登录修改）", settings.AdminPassPlain)
		} else {
			log.Printf("初始管理员密码: 已设置（不回显）")
		}
	}
	if tokenGenerated {
		log.Printf("初始 Agent Token 已生成")
	}
	if splitMode {
		adminListener, err := net.Listen("tcp", adminServer.Addr)
		if err != nil {
			return err
		}
		defer adminListener.Close()
		publicListener, err := net.Listen("tcp", publicServer.Addr)
		if err != nil {
			return err
		}
		defer publicListener.Close()

		serverErr := make(chan error, 2)
		go func() {
			if err := adminServer.Serve(adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErr <- err
				return
			}
			serverErr <- nil
		}()
		go func() {
			if err := publicServer.Serve(publicListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErr <- err
				return
			}
			serverErr <- nil
		}()

		for i := 0; i < 2; i++ {
			if err := <-serverErr; err != nil {
				awaitGracefulDrain(shutdownDone, runCancel, tickDone, &store.alertDeliveryWG)
				return err
			}
		}
		awaitGracefulDrain(shutdownDone, runCancel, tickDone, &store.alertDeliveryWG)
		// B-02：普通累加不再逐次落盘后，退出前做一次最终落盘（含至多 10s 节流窗口内的
		// 流量计数增量）。
		store.persistLogged()
		return nil
	}
	if err := publicServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		awaitGracefulDrain(shutdownDone, runCancel, tickDone, &store.alertDeliveryWG)
		return err
	}
	awaitGracefulDrain(shutdownDone, runCancel, tickDone, &store.alertDeliveryWG)
	// B-02：同上，退出前最终落盘。
	store.persistLogged()
	return nil
}

func shutdownHTTPServer(server *http.Server) {
	if server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGraceTimeout)
	defer cancel()
	_ = server.Shutdown(ctx)
}

// tickRunner 持有跨 tick 的派生状态（快照摘要、限速回收时间），使单次 tick 可被独立
// 调用与测试。
type tickRunner struct {
	lastBalancedDigest string
	lastAdminDigest    string
	lastRateSweep      time.Time
	// F4 评估节奏：expiry 每天本地 09:00（启动后立即一次）、traffic_quota 每分钟。
	lastExpiryScan  time.Time
	lastTrafficEval time.Time
}

func runTickLoop(ctx context.Context, store *Store, hub *Hub) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	runner := &tickRunner{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("tick 巡检 panic 已恢复: %v\n%s", rec, debug.Stack())
					}
				}()
				runner.runOnce(store, hub, time.Now())
			}()
		}
	}
}

func (t *tickRunner) runOnce(store *Store, hub *Hub, now time.Time) {
	if t.lastRateSweep.IsZero() || now.Sub(t.lastRateSweep) >= agentRateSweepInterval {
		store.sweepExpiredAgentRateWindows(now)
		t.lastRateSweep = now
	}
	// 资源历史：落盘已结束的 30 秒桶（节点离线/停报时也要靠这里收尾）并按节奏
	// 清理超过保留期的样本；与离线宽限期无关，必须放在它之前。
	store.FlushResourceHistory(now)
	store.ReconcileResourceHistoryRetention()
	if hub.HasVariant(adminVariant) {

		payload, err := json.Marshal(adminStoreSnapshot(store))
		if err != nil {
			log.Printf("序列化管理端节点快照失败: %v", err)
		} else if digest := snapshotPayloadDigest(payload); digest != t.lastAdminDigest {
			hub.BroadcastAdmin(payload, store.Credentials().TokenSalt)
			t.lastAdminDigest = digest
		}
	}
	if hub.HasVariant(publicVariantBalanced) {
		payload, err := json.Marshal(storeSnapshot(store))
		if err != nil {
			log.Printf("序列化节点快照失败: %v", err)
		} else if digest := snapshotPayloadDigest(payload); digest != t.lastBalancedDigest {
			hub.BroadcastVariant(payload, publicVariantBalanced)
			t.lastBalancedDigest = digest
		}
	}
	if store.reconcileProfiles(now) {
		store.persistLogged()
	}
	// 启动宽限期内不生成离线事件、不写离线会话/历史：服务端自身停机期间节点 LastSeen
	// 停留在旧值，若立即判定会形成离线告警风暴并污染 TSDB 离线历史。宽限期结束后恢复
	// 正常判定（始终不重连的节点仍会被告警），宽限期内可一并推迟恢复类事件。
	if !store.offlineGraceElapsed(now) {
		return
	}
	store.ReconcileOfflineTracker(now)
	targets, offlineEvents, recoveredEvents, skippedRecoveredEvents := store.CollectAlertEvents(now)
	logReportEvents(targets.SiteTitle, len(targets.Channels) > 0, offlineEvents, recoveredEvents, skippedRecoveredEvents)
	if len(offlineEvents) > 0 || len(recoveredEvents) > 0 {
		store.alertDeliveryWG.Add(1)
		go func() {
			defer store.alertDeliveryWG.Done()
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("告警投递 panic 已恢复: %v\n%s", rec, debug.Stack())
				}
			}()
			if len(targets.Channels) == 0 {
				// 无可用渠道：离线告警保持「待补发」（退避重试，补配渠道后补发）；恢复
				// 通知同样必须落成 RecoveryPending——CollectAlertEvents 产出恢复事件时
				// 已删除 alerted 状态，若这里只记录离线事件就返回，恢复通知会被永久
				// 丢弃：既不投递也不进补发队列，之后补配渠道也永远不会补发。
				store.RecordAlertDelivery(offlineEvents, nil, true)
				store.RecordAlertDelivery(recoveredEvents, nil, false)
				return
			}
			if len(offlineEvents) > 0 {
				results := dispatchChannelNotices(targets.Channels, targets.SiteTitle, offlineEvents, buildAlertMessage, "告警")
				if !allChannelNoticesOK(results) {
					store.RecordAlertDelivery(offlineEvents, results, true)
				}
			}
			if len(recoveredEvents) > 0 {
				results := dispatchChannelNotices(targets.Channels, targets.SiteTitle, recoveredEvents, buildRecoveryMessage, "恢复通知")
				if !allChannelNoticesOK(results) {
					store.RecordAlertDelivery(recoveredEvents, results, false)
				}
			}
		}()
	}

	// F4：CollectAlertEvents 之后评估告警规则（阈值类每 tick；expiry/traffic_quota
	// 按节奏），同一 tick 同一规则的多节点事件合并为一条消息投递。
	cadence := RuleEvalCadence{
		ExpiryScan:  t.expiryScanDue(now),
		TrafficScan: t.trafficEvalDue(now),
	}
	ruleBatches := store.CollectRuleEvents(now, cadence)
	if cadence.ExpiryScan {
		t.lastExpiryScan = now
	}
	if cadence.TrafficScan {
		t.lastTrafficEval = now
	}
	if len(ruleBatches) > 0 {
		logRuleNoticeEvents(ruleBatches)
		store.alertDeliveryWG.Add(1)
		go func(batches []RuleNoticeBatch) {
			defer store.alertDeliveryWG.Done()
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("规则告警投递 panic 已恢复: %v\n%s", rec, debug.Stack())
				}
			}()
			deliverRuleBatches(store, batches)
		}(ruleBatches)
	}
}

// offlineGraceElapsed 报告启动宽限期是否已过。startedAt 为零（测试/旧路径）视为已过，
// 保持原有判定语义不变。
func (s *Store) offlineGraceElapsed(now time.Time) bool {
	s.mu.RLock()
	startedAt := s.startedAt
	s.mu.RUnlock()
	if startedAt.IsZero() {
		return true
	}
	return now.Sub(startedAt) >= startupOfflineGrace
}

// awaitGracefulDrain 在 Run 返回前等待关闭排空：先停 tick 循环并触发 HTTP 排空，再等
// HTTP Shutdown 完成（或 5s 宽限到期），最后对告警投递 goroutine 做有界等待。返回后
// Run 的 defer 才会释放 historyManager、数据目录锁与 TSDB，避免在途请求/告警 goroutine
// 踩到已关闭的存储。
func awaitGracefulDrain(shutdownDone <-chan struct{}, runCancel context.CancelFunc, tickDone <-chan struct{}, alerts *sync.WaitGroup) {
	runCancel()
	<-shutdownDone
	<-tickDone
	waitGroupWithTimeout(alerts, alertDeliveryDrainTimeout)
}

// waitGroupWithTimeout 等待 wg 归零，超时返回 false（不阻塞关闭）。
func waitGroupWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	if wg == nil {
		return true
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           withGzip(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// WriteTimeout 是绝对写截止：公开历史查询预算 30s（publicHistoryQueryTimeout）、
		// AI/Telegram 外呼 18s、release 检查 8s，若低于最大预算，慢路径在写响应时会报
		// i/o timeout（客户端拿到空响应、服务端白等）。取 35s = 30s 查询预算 + 编码/写回余量。
		// 读侧无慢路径，ReadTimeout 维持 10s（slowloris 由 ReadHeaderTimeout=5s 覆盖）。
		WriteTimeout:   35 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: maxHTTPHeaderBytes,
	}
}

func withGzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			isAgentGRPCRequest(r) || !acceptsGzip(r) ||
			strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "websocket") ||
			r.Header.Get("Range") != "" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		gz := &gzipResponseWriter{ResponseWriter: w}
		defer gz.finish()
		next.ServeHTTP(gz, r)
	})
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		encoding := strings.TrimSpace(strings.ToLower(part))
		if idx := strings.IndexByte(encoding, ';'); idx >= 0 {
			encoding = strings.TrimSpace(encoding[:idx])
			if strings.Contains(encoding, "q=0") {
				continue
			}
		}
		if encoding == "gzip" {
			return true
		}
	}
	return false
}

const (
	gzipMinBodyBytes        = 1024
	gzipDecisionBufferBytes = 4096
)

var gzipWriterPool = sync.Pool{New: func() any { return gzip.NewWriter(nil) }}

type gzipResponseWriter struct {
	http.ResponseWriter
	decided bool
	on      bool
	status  int
	gz      *gzip.Writer
	buf     []byte
}

func (g *gzipResponseWriter) WriteHeader(status int) {
	if g.decided {
		return
	}
	g.status = status
	if g.Header().Get("Content-Length") != "" {
		g.decide()
	}
}

func (g *gzipResponseWriter) decide() {
	if g.decided {
		return
	}
	g.decided = true
	if g.status == 0 {
		g.status = http.StatusOK
	}
	header := g.Header()
	sizeKnownSmall := false
	if cl := header.Get("Content-Length"); cl != "" {
		n, err := strconv.Atoi(cl)
		sizeKnownSmall = err == nil && n < gzipMinBodyBytes
	} else if len(g.buf) > 0 {
		sizeKnownSmall = len(g.buf) < gzipMinBodyBytes
	}
	compressible := header.Get("Content-Encoding") == "" && !sizeKnownSmall &&
		gzipAllowedContentType(header.Get("Content-Type"))
	if !compressible {
		g.passthrough()
		return
	}
	g.gz = gzipWriterPool.Get().(*gzip.Writer)
	g.gz.Reset(g.ResponseWriter)
	header.Set("Content-Encoding", "gzip")
	header.Del("Content-Length")
	header.Del("Accept-Ranges")
	g.on = true
	g.ResponseWriter.WriteHeader(g.status)
	if len(g.buf) > 0 {
		g.gz.Write(g.buf)
		g.buf = nil
	}
}

func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	if g.on {
		return g.gz.Write(p)
	}
	if g.decided {
		return g.ResponseWriter.Write(p)
	}
	g.buf = append(g.buf, p...)
	if len(g.buf) >= gzipDecisionBufferBytes {
		g.decide()
	}
	return len(p), nil
}

func (g *gzipResponseWriter) finish() {
	if !g.on {
		g.decide()
	}
	if g.on {
		g.gz.Close()
		gzipWriterPool.Put(g.gz)
		g.gz = nil
		return
	}
	if len(g.buf) > 0 {
		g.passthrough()
	}
}

func (g *gzipResponseWriter) passthrough() {
	g.ResponseWriter.WriteHeader(g.status)
	if len(g.buf) > 0 {
		g.ResponseWriter.Write(g.buf)
		g.buf = nil
	}
}

func gzipAllowedContentType(contentType string) bool {
	base := contentType
	if idx := strings.IndexByte(base, ';'); idx >= 0 {
		base = base[:idx]
	}
	base = strings.ToLower(strings.TrimSpace(base))
	switch base {
	case "text/html", "text/css", "text/javascript",
		"application/javascript", "application/json", "image/svg+xml":
		return true
	}
	return false
}

func applyDefaults(cfg *Config) error {
	if cfg.Addr == "" {
		cfg.Addr = defaultAddr
	}
	if cfg.PublicAddr == "" {
		cfg.PublicAddr = cfg.Addr
	}
	if cfg.DataDir == "" {
		cfg.DataDir = cmdutil.DefaultDataDir()
	}
	if cfg.JWTSecret == "" && cfg.AgentToken == "" {
		token, err := generateBootstrapToken()
		if err != nil {
			return err
		}
		cfg.JWTSecret = token
		token, err = randomToken(32)
		if err != nil {
			return err
		}
		cfg.AgentToken = token
		return nil
	}
	if cfg.JWTSecret == "" {
		token, err := generateBootstrapToken()
		if err != nil {
			return err
		}
		cfg.JWTSecret = token
	}
	if cfg.AgentToken == "" {
		token, err := randomToken(32)
		if err != nil {
			return err
		}
		cfg.AgentToken = token
	}
	return nil
}

func isBcryptHash(value string) bool {
	return strings.HasPrefix(value, "$2a$") || strings.HasPrefix(value, "$2b$") || strings.HasPrefix(value, "$2y$")
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func verifyPassword(password, stored string) bool {
	if stored == "" || password == "" {
		return false
	}
	if isBcryptHash(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(password)) == 1
}

func generateBootstrapToken() (string, error) {
	return randomToken(48)
}

func (s *Store) updateNodeStats(stats metrics.NodeStats) (bool, *offlineRecoveryCandidate, error) {
	var persist bool
	var recoveryCandidate *offlineRecoveryCandidate
	var updateReconciled bool
	now := time.Now()

	s.mu.Lock()

	prev := s.nodes[stats.NodeID]

	var newServerID string
	if profile := s.profiles[stats.NodeID]; profile == nil || strings.TrimSpace(profile.ServerID) == "" {
		id, err := s.generateServerIDLocked()
		if err != nil {
			s.mu.Unlock()
			return false, nil, err
		}
		newServerID = id
	}
	firstSeen := prev.FirstSeen
	if firstSeen.IsZero() {
		firstSeen = now
	}
	acceptStats := shouldReplaceNodeStats(prev.Stats, stats)
	mergedStats := mergeNodeStatsStaticInfo(prev.Stats, stats)
	var storedStats metrics.NodeStats
	if acceptStats {
		storedStats = cloneNodeStats(mergedStats)
		if !mergedStats.NetworkTestsChanged && len(mergedStats.NetworkTests) == 0 && len(prev.Stats.NetworkTests) > 0 {
			storedStats.NetworkTests = cloneNetworkTestResults(prev.Stats.NetworkTests)
		}
	} else {
		storedStats = cloneNodeStats(prev.Stats)
	}
	s.nodes[stats.NodeID] = NodeState{
		Stats:     storedStats,
		LastSeen:  now,
		FirstSeen: firstSeen,
	}

	profile := s.ensureProfileLocked(stats.NodeID)
	if newServerID != "" {
		profile.ServerID = newServerID
		persist = true
	}
	if profile.TestIntervalSec == 0 {
		profile.TestIntervalSec = defaultTestIntervalSec
		persist = true
	}
	if profile.Alias == "" {
		if storedStats.NodeAlias != "" {
			profile.Alias = storedStats.NodeAlias
		} else if storedStats.NodeName != "" {
			profile.Alias = storedStats.NodeName
		} else if storedStats.Hostname != "" {
			profile.Alias = storedStats.Hostname
		}
		if profile.Alias != "" {
			persist = true
		}
	}
	if storedStats.NodeGroup != "" && !profile.GroupSeeded {

		groupNames, _, _ := groupSelectionSets(s.settings)
		if _, known := groupNames[normalizeGroupName(strings.TrimSpace(storedStats.NodeGroup))]; known {
			if profile.Group == "" {
				profile.Group = storedStats.NodeGroup
			}
			if len(profile.Groups) == 0 {
				profile.Groups = normalizeGroupSelections(selectionsFromGroupTags(storedStats.NodeGroup, nil))
				group, tags := primaryGroupTagsFromSelections(profile.Groups)
				if group != "" {
					profile.Group = group
				}
				profile.Tags = tags
			}

			profile.GroupSeeded = true
			persist = true
		}
	}
	if s.applyAutoRenewLocked(profile, now) {
		persist = true
	}
	// F4：按增量累加月度流量计数（agent 重启回绕时把新值当增量，到重置日清零）。
	// B-01：传原始上报 stats——mergeNodeStatsStaticInfo 会把首份静态上报之后的
	// 合并结果全部带上 StaticInfo=true，此前计数被守卫整体阻断（真实部署永不累计）。
	// B-02：只有周期重置立即落盘；普通累加交给 shouldPersistLocked 的 10s 周期落盘。
	if acceptStats {
		if _, cycleReset := s.applyTrafficCounterLocked(stats.NodeID, profile, stats, now); cycleReset {
			persist = true
		}
	}
	if reconcileAgentUpdateWithStatsLocked(profile, storedStats, now) {
		persist = true
		updateReconciled = true
	}
	if expireStaleAgentUpdateLocked(profile, now) {
		persist = true
		updateReconciled = true
	}
	profile.UpdatedAt = now.Unix()

	if session, ok := s.offlineSessions[stats.NodeID]; ok && session.StartedAt > 0 {
		recoveryCandidate = &offlineRecoveryCandidate{
			NodeID:      stats.NodeID,
			StartedAt:   session.StartedAt,
			RecoveredAt: now.UTC(),
		}
	}

	if s.shouldPersistLocked(now) {
		persist = true
	}
	s.mu.Unlock()

	if persist {
		s.persistLogged()
	}
	s.mu.RLock()
	historyManager := s.historyManager
	s.mu.RUnlock()
	if acceptStats && historyManager != nil && len(storedStats.NetworkTests) > 0 && mergedStats.NetworkTestsChanged {
		if err := historyManager.AppendNetworkBatch(mergedStats.NodeID, mergedStats.NetworkTests, now); err != nil {
			log.Printf("写入 network TSDB 失败: %v", err)
		}
	}
	// 资源历史：每秒上报在存储层按 30 秒桶求平均后再落盘，这里的调用只是累加。
	if acceptStats && historyManager != nil {
		if err := historyManager.ObserveResource(mergedStats.NodeID, mergedStats, now); err != nil {
			log.Printf("写入资源 TSDB 失败: %v", err)
		}
	}
	return updateReconciled, recoveryCandidate, nil
}

func shouldReplaceNodeStats(current, incoming metrics.NodeStats) bool {
	if strings.TrimSpace(current.NodeID) == "" {
		return true
	}
	if current.Timestamp <= 0 || incoming.Timestamp <= 0 {
		return true
	}
	return incoming.Timestamp >= current.Timestamp
}

func mergeNodeStatsStaticInfo(current, incoming metrics.NodeStats) metrics.NodeStats {
	if strings.TrimSpace(current.NodeID) == "" || incoming.StaticInfo {
		return incoming
	}
	incoming.OS = current.OS
	incoming.Arch = current.Arch
	incoming.StaticInfo = current.StaticInfo
	incoming.StaticUpdatedAt = current.StaticUpdatedAt
	incoming.CPU.Model = current.CPU.Model
	incoming.CPU.Cores = current.CPU.Cores
	incoming.DiskType = current.DiskType
	incoming.GPU = mergeGPUStaticInfo(current.GPU, incoming.GPU, incoming.GPUCollected)
	return incoming
}

func mergeGPUStaticInfo(current, incoming []metrics.GPUInfo, collected bool) []metrics.GPUInfo {
	if len(incoming) == 0 {
		if collected {
			return nil
		}
		return slices.Clone(current)
	}
	byID := make(map[string]metrics.GPUInfo, len(current))
	byIndex := make(map[int]metrics.GPUInfo, len(current))
	for _, gpu := range current {
		if id := strings.TrimSpace(gpu.ID); id != "" {
			byID[id] = gpu
		}
		byIndex[gpu.Index] = gpu
	}
	merged := make([]metrics.GPUInfo, len(incoming))
	for i, gpu := range incoming {
		if prev, ok := byID[strings.TrimSpace(gpu.ID)]; ok {
			gpu = mergeSingleGPUStaticInfo(prev, gpu)
		} else if prev, ok := byIndex[gpu.Index]; ok {
			gpu = mergeSingleGPUStaticInfo(prev, gpu)
		}
		merged[i] = gpu
	}
	return merged
}

func mergeSingleGPUStaticInfo(current, incoming metrics.GPUInfo) metrics.GPUInfo {
	if incoming.ID == "" {
		incoming.ID = current.ID
	}
	if incoming.Name == "" {
		incoming.Name = current.Name
	}
	if incoming.Vendor == "" {
		incoming.Vendor = current.Vendor
	}
	if incoming.DriverVersion == "" {
		incoming.DriverVersion = current.DriverVersion
	}
	return incoming
}

type AlertEvent struct {
	NodeID     string
	Display    string
	OS         string
	LastSeen   int64
	OfflineSec int64
	RetryCount int
	// Delivered 记录该事件已成功投递的渠道 ID（F5 泛化：只补发失败渠道）。
	Delivered map[string]bool
	// Retry 标记该事件来自失败补发（内部字段，不落盘、不对外）：日志只在事件
	// 首次产生时记录一次，退避补发不再重复记录成新事件。
	Retry bool
}

type AlertTargets struct {
	// Channels 为本次应投递的启用渠道（含深拷贝，锁外使用）。
	Channels  []NotifyChannel
	SiteTitle string
}

const offlineSessionDefaultThreshold = 5 * time.Minute

func (s *Store) offlineAlertThreshold() time.Duration {
	threshold := time.Duration(s.settings.AlertOfflineSec) * time.Second
	if threshold <= 0 {
		return offlineSessionDefaultThreshold
	}
	return threshold
}

type offlineRecoveryCandidate struct {
	NodeID      string
	StartedAt   int64
	RecoveredAt time.Time
}

func (s *Store) ReconcileOfflineTracker(now time.Time) {
	var (
		needsPersist       bool
		recoveryCandidates []offlineRecoveryCandidate
	)

	s.mu.Lock()
	if s.offlineSessions == nil {
		s.offlineSessions = make(map[string]OfflineSessionState)
	}

	threshold := s.offlineAlertThreshold()
	for nodeID, node := range s.nodes {
		offlineFor := now.Sub(node.LastSeen)
		session, hasSession := s.offlineSessions[nodeID]
		if offlineFor >= threshold {
			if !hasSession {
				s.offlineSessions[nodeID] = OfflineSessionState{StartedAt: node.LastSeen.Unix()}
				needsPersist = true
			}
			continue
		}
		if !hasSession {
			continue
		}
		if session.StartedAt <= 0 {
			delete(s.offlineSessions, nodeID)
			needsPersist = true
			continue
		}
		if session.StartedAt > now.Unix() {
			s.offlineSessions[nodeID] = OfflineSessionState{StartedAt: now.Unix()}
			needsPersist = true
			continue
		}
		recoveredAt := now.UTC()
		startedAt := time.Unix(session.StartedAt, 0).UTC()
		if !recoveredAt.After(startedAt) {
			continue
		}
		recoveryCandidates = append(recoveryCandidates, offlineRecoveryCandidate{
			NodeID:      nodeID,
			StartedAt:   session.StartedAt,
			RecoveredAt: recoveredAt,
		})
	}

	for nodeID := range s.offlineSessions {
		if _, ok := s.nodes[nodeID]; ok {
			continue
		}
		delete(s.offlineSessions, nodeID)
		needsPersist = true
	}

	s.mu.Unlock()

	if needsPersist {
		s.persistLogged()
	}
	for _, candidate := range recoveryCandidates {
		s.completeOfflineRecovery(candidate)
	}
}

func (s *Store) completeOfflineRecovery(candidate offlineRecoveryCandidate) {
	nodeID := strings.TrimSpace(candidate.NodeID)
	if nodeID == "" {
		return
	}
	candidate.NodeID = nodeID
	unlock := s.lockAgentNodeMutation(nodeID)
	defer unlock()
	s.completeOfflineRecoveryProtected(candidate)
}

func (s *Store) completeOfflineRecoveryProtected(candidate offlineRecoveryCandidate) {
	candidate.NodeID = strings.TrimSpace(candidate.NodeID)
	if candidate.StartedAt <= 0 {
		return
	}
	if candidate.NodeID == "" {
		return
	}
	recoveredAt := candidate.RecoveredAt.UTC()
	startedAt := time.Unix(candidate.StartedAt, 0).UTC()
	duration := recoveredAt.Sub(startedAt)
	if duration <= 0 {
		return
	}

	s.mu.RLock()
	manager := s.historyManager
	_, nodeExists := s.nodes[candidate.NodeID]
	session, hasSession := s.offlineSessions[candidate.NodeID]
	s.mu.RUnlock()
	if manager == nil {
		return
	}
	if !nodeExists || !hasSession || session.StartedAt != candidate.StartedAt {
		return
	}

	hasEvent, err := manager.HasOfflineEventForSession(candidate.NodeID, startedAt)
	if err != nil {
		log.Printf("检查 offline TSDB 去重失败 node=%s: %v", candidate.NodeID, err)
		return
	}
	if !hasEvent {
		if err := manager.AppendOfflineEvent(candidate.NodeID, recoveredAt, duration); err != nil {
			log.Printf("写入 offline TSDB 失败 node=%s: %v", candidate.NodeID, err)
			return
		}
	}

	var (
		shouldPersist bool
	)
	s.mu.Lock()
	session, ok := s.offlineSessions[candidate.NodeID]
	if ok && session.StartedAt == candidate.StartedAt {
		delete(s.offlineSessions, candidate.NodeID)
		shouldPersist = true
	}
	s.mu.Unlock()

	if shouldPersist {
		s.persistLogged()
	}
}

// CollectAlertEvents 收集本轮的离线事件与恢复事件。第四个返回值是「跳过恢复通知」
// 的恢复事件：离线告警一个渠道都没送达时节点恢复，不再单独发「已恢复」，只清状态
// 并记一行报告日志（该切片仅用于日志，不参与投递）。
func (s *Store) CollectAlertEvents(now time.Time) (AlertTargets, []AlertEvent, []AlertEvent, []AlertEvent) {
	s.mu.Lock()

	// B-03：内置 offline 规则接入离线引擎——停用、范围、渠道设置生效。
	rule := s.offlineAlertRuleLocked()
	targets := AlertTargets{
		Channels:  ruleChannelsFor(rule, enabledNotifyChannels(s.settings)),
		SiteTitle: normalizeSiteTitle(s.settings.SiteTitle),
	}
	alertDisabled := s.settings.AlertOfflineSec <= 0 || !rule.Enabled
	threshold := s.offlineAlertThreshold()
	offlineEvents := make([]AlertEvent, 0)
	recoveredEvents := make([]AlertEvent, 0)
	skippedRecoveredEvents := make([]AlertEvent, 0)
	needsPersist := false
	for nodeID, node := range s.nodes {
		state, wasAlerted := s.alerted[nodeID]
		profile := s.ensureProfileLocked(nodeID)
		if alertDisabled {
			if wasAlerted {
				delete(s.alerted, nodeID)
				needsPersist = true
			}
			continue
		}
		if !isAlertEnabled(profile) {
			if wasAlerted {
				delete(s.alerted, nodeID)
				needsPersist = true
			}
			continue
		}
		if !ruleScopeMatches(rule.Scope, nodeID, profile) {
			if wasAlerted {
				delete(s.alerted, nodeID)
				needsPersist = true
			}
			continue
		}
		offlineFor := now.Sub(node.LastSeen)
		if offlineFor < threshold {
			if wasAlerted {
				// 退避门槛只服务恢复通知自身的补发（RecoveryPending）：恢复通知投递
				// 失败后按 NextRetryAt 重试。离线告警阶段的补发退避（RecordAlertDelivery
				// offline=true 设置的 NextRetryAt）不能推迟恢复处理——否则恢复最多被
				// 推迟 5 分钟，期间离线告警可能仍未送达，用户只会收到「已恢复」。
				if state.RecoveryPending && !state.NextRetryAt.IsZero() && now.Before(state.NextRetryAt) &&
					state.NextRetryAt.Sub(now) <= maxAlertRetryBackoff {
					continue
				}
				stats := node.Stats
				display := resolveAlertDisplay(profile, stats, nodeID)
				offlineSec := int64(now.Sub(state.OfflineSince).Seconds())
				if state.OfflineSince.IsZero() {
					offlineSec = 0
				}
				// RecoveryPending 表示这条恢复通知是上一轮投递失败的补发；
				// 首次恢复（含离线告警尚在补发时恢复）不算补发。
				var delivered map[string]bool
				if state.RecoveryPending {
					delivered = cloneNotifyBoolMap(state.Delivered)
				}
				event := AlertEvent{
					NodeID:     nodeID,
					Display:    display,
					OS:         stats.OS,
					LastSeen:   node.LastSeen.Unix(),
					OfflineSec: offlineSec,
					RetryCount: state.RetryCount,
					Delivered:  delivered,
					Retry:      state.RecoveryPending,
				}
				// 「至少完成过一次离线告警投递尝试且全部失败」（RetryCount>0 且无任何
				// 已送达渠道）才跳过恢复：用户从未收到过这条告警，单独一条「已恢复」
				// 只会制造困惑。RetryCount 只在 RecordAlertDelivery 的失败/无渠道分支
				// 递增；投递仍在途（goroutine 未回执）或全部渠道一次送达（成功路径不记
				// 回执，RetryCount 仍为 0）时，离线告警已经发出或正在发送，必须产出恢复。
				if !state.RecoveryPending && state.RetryCount > 0 && len(state.Delivered) == 0 {
					skippedRecoveredEvents = append(skippedRecoveredEvents, event)
				} else {
					recoveredEvents = append(recoveredEvents, event)
				}
				delete(s.alerted, nodeID)
				needsPersist = true
			}
			continue
		}
		if wasAlerted {
			if state.NextRetryAt.IsZero() || (now.Before(state.NextRetryAt) && state.NextRetryAt.Sub(now) <= maxAlertRetryBackoff) {
				continue
			}
			// LastSeen 新于 OfflineSince 说明节点中间上过线，这是新一次离线事件（
			// 可能紧跟在一次未送达的恢复通知之后），不能当作失败补发而跳过日志。
			newIncident := state.OfflineSince.Before(node.LastSeen)
			if newIncident {
				// 新一次离线事件：回执与重试退避从头开始，不继承上一轮的送达记录和
				// 退避档位（否则首次失败从上一轮遗留的 5 分钟档起步）。
				state.OfflineSince = node.LastSeen
				state.Delivered = nil
				state.RetryCount = 0
				state.RecoveryPending = false
			}
			stats := node.Stats
			offlineSec := int64(now.Sub(state.OfflineSince).Seconds())
			if state.OfflineSince.IsZero() {
				offlineSec = 0
			}
			offlineEvents = append(offlineEvents, AlertEvent{
				NodeID:     nodeID,
				Display:    resolveAlertDisplay(profile, stats, nodeID),
				OS:         stats.OS,
				LastSeen:   node.LastSeen.Unix(),
				OfflineSec: offlineSec,
				Delivered:  cloneNotifyBoolMap(state.Delivered),
				Retry:      !newIncident,
			})
			state.NextRetryAt = time.Time{}
			s.alerted[nodeID] = state
			needsPersist = true
			continue
		}
		stats := node.Stats
		display := resolveAlertDisplay(profile, stats, nodeID)
		offlineEvents = append(offlineEvents, AlertEvent{
			NodeID:     nodeID,
			Display:    display,
			OS:         stats.OS,
			LastSeen:   node.LastSeen.Unix(),
			OfflineSec: int64(offlineFor.Seconds()),
		})
		s.alerted[nodeID] = AlertedState{OfflineSince: node.LastSeen}
		needsPersist = true
	}

	for nodeID := range s.alerted {
		if _, ok := s.nodes[nodeID]; !ok {
			delete(s.alerted, nodeID)
			needsPersist = true
		}
	}

	s.mu.Unlock()
	if needsPersist {
		s.persistLogged()
	}
	return targets, offlineEvents, recoveredEvents, skippedRecoveredEvents
}

const maxAlertRetryBackoff = 5 * time.Minute

func alertRetryBackoff(retryCount int) time.Duration {
	backoff := 2 * time.Second
	for i := 1; i < retryCount && backoff < maxAlertRetryBackoff; i++ {
		backoff *= 2
	}
	if backoff > maxAlertRetryBackoff {
		backoff = maxAlertRetryBackoff
	}
	return backoff
}

// owedAlertEvents 按 channelID 过滤尚未投递成功的事件（只补发失败渠道）。
func owedAlertEvents(events []AlertEvent, channelID string) []AlertEvent {
	owed := make([]AlertEvent, 0, len(events))
	for _, event := range events {
		if event.Delivered[channelID] {
			continue
		}
		owed = append(owed, event)
	}
	return owed
}

// RecordAlertDelivery 按 results（渠道 ID → 是否成功）记录投递进度；只有当本轮
// 涉及的渠道全部送达时才取消重试，失败渠道进入退避补发。
func (s *Store) RecordAlertDelivery(events []AlertEvent, results map[string]bool, offline bool) {
	needsPersist := false
	s.mu.Lock()
	now := time.Now()
	for _, event := range events {
		state, ok := s.alerted[event.NodeID]
		if offline {
			if !ok {
				continue
			}
			deliveredChanged := false
			for channelID, success := range results {
				if !success || state.Delivered[channelID] {
					continue
				}
				if state.Delivered == nil {
					state.Delivered = make(map[string]bool)
				}
				state.Delivered[channelID] = true
				deliveredChanged = true
			}
			// results 为空表示当前没有可用渠道：保持旧语义，安排退避重试，
			// 管理员补配渠道后仍能把未送达的告警补发出去。
			allDelivered := len(results) > 0
			for channelID := range results {
				if !state.Delivered[channelID] {
					allDelivered = false
					break
				}
			}
			if allDelivered {
				// 全部送达：没有待补发的离线告警，但 Delivered 要落盘——节点恢复时
				// 靠它区分「离线告警确实送达过」与「一个渠道都没送到」。重试档位一并
				// 归零，下次离线事件首次失败从最小退避起步。
				state.NextRetryAt = time.Time{}
				state.RetryCount = 0
				s.alerted[event.NodeID] = state
				needsPersist = needsPersist || deliveredChanged
				continue
			}
			state.RetryCount++
			state.NextRetryAt = now.Add(alertRetryBackoff(state.RetryCount))
			s.alerted[event.NodeID] = state
			needsPersist = true
			continue
		}
		delivered := cloneNotifyBoolMap(event.Delivered)
		if delivered == nil {
			delivered = make(map[string]bool)
		}
		for channelID, success := range results {
			if success {
				delivered[channelID] = true
			}
		}
		allDelivered := len(results) > 0
		for channelID := range results {
			if !delivered[channelID] {
				allDelivered = false
				break
			}
		}
		if allDelivered {
			continue
		}
		if !ok {
			if _, alive := s.nodes[event.NodeID]; !alive {
				continue
			}
			state = AlertedState{
				OfflineSince:    now.Add(-time.Duration(event.OfflineSec) * time.Second),
				RetryCount:      event.RetryCount + 1,
				Delivered:       delivered,
				RecoveryPending: true,
			}
		} else {
			if state.RecoveryPending {
				state.Delivered = delivered
			}
			state.RetryCount++
		}
		state.NextRetryAt = now.Add(alertRetryBackoff(state.RetryCount))
		s.alerted[event.NodeID] = state
		needsPersist = true
	}
	s.mu.Unlock()
	if needsPersist {
		s.persistLogged()
	}
}

func resolveAlertDisplay(profile *NodeProfile, stats metrics.NodeStats, nodeID string) string {
	display := strings.TrimSpace(profile.Alias)
	if display == "" {
		display = strings.TrimSpace(stats.NodeName)
	}
	if display == "" {
		display = nodeID
	}
	return display
}

// sendFeishuTest 维持旧测试推送语义（消息文案不变），内部改走 F5 的 feishu
// Notifier（SSRF 防护客户端 + 可选签名）。
func sendFeishuTest(webhook, siteTitle string) error {
	message := fmt.Sprintf("【%s】告警测试 %s", normalizeSiteTitle(siteTitle), time.Now().Format("2006-01-02 15:04:05"))
	notifier, err := newNotifier(NotifyChannel{
		ID:      legacyFeishuChannelID,
		Type:    notifyChannelTypeFeishu,
		Enabled: true,
		Secrets: map[string]string{"webhook": strings.TrimSpace(webhook)},
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), notifySendTimeout)
	defer cancel()
	return notifier.Send(ctx, NotifyMessage{Text: message})
}

func buildEventMessage(siteTitle, title, lead, footer string, events []AlertEvent) string {
	lines := []string{fmt.Sprintf("【%s】%s", normalizeSiteTitle(siteTitle), title), "", lead}
	for _, event := range events {
		label := formatAlertValue(event.Display, "未命名节点")
		detail := ""
		if event.OfflineSec > 0 {
			detail = fmt.Sprintf("（离线 %s）", formatAlertDuration(event.OfflineSec))
		}
		lines = append(lines, fmt.Sprintf("• %s%s", label, detail))
	}
	lines = append(lines, "", footer)
	return strings.Join(lines, "\n")
}

func buildAlertMessage(siteTitle string, events []AlertEvent) string {
	return buildEventMessage(siteTitle, "服务器离线告警", "离线节点：", "请及时检查服务器状态。", events)
}

func buildRecoveryMessage(siteTitle string, events []AlertEvent) string {
	return buildEventMessage(siteTitle, "服务器恢复在线", "已恢复节点：", "服务已恢复。", events)
}

// logReportEvents 输出离线/恢复报告日志。只有首次产生的事件记一行；失败的退避
// 补发（AlertEvent.Retry）不再重复记录，避免同一事件在日志页被记成多次掉线。
// hasChannels 为 false 时额外记一条「未发送」，同样只在首次产生时出现。
func logReportEvents(siteTitle string, hasChannels bool, offlineEvents, recoveredEvents, skippedRecoveredEvents []AlertEvent) {
	title := normalizeSiteTitle(siteTitle)
	freshOffline := 0
	for _, event := range offlineEvents {
		if event.Retry {
			continue
		}
		freshOffline++
		reportLogger.Printf("[%s] 离线：%s（node=%s，最后=%s，时长=%s）",
			title,
			formatAlertValue(event.Display, "未命名节点"),
			formatAlertValue(event.NodeID, "unknown"),
			formatReportEventTime(event.LastSeen),
			formatAlertDuration(event.OfflineSec),
		)
	}
	freshRecovered := 0
	for _, event := range recoveredEvents {
		if event.Retry {
			continue
		}
		freshRecovered++
		reportLogger.Printf("[%s] 恢复：%s（node=%s，恢复=%s，时长=%s）",
			title,
			formatAlertValue(event.Display, "未命名节点"),
			formatAlertValue(event.NodeID, "unknown"),
			formatReportEventTime(event.LastSeen),
			formatAlertDuration(event.OfflineSec),
		)
	}
	// 跳过恢复通知（离线告警一个渠道都没送达）：状态已清理，只在清理当轮记一行。
	for _, event := range skippedRecoveredEvents {
		reportLogger.Printf("[%s] 恢复：%s（node=%s，恢复=%s，时长=%s，离线告警未送达，跳过恢复通知）",
			title,
			formatAlertValue(event.Display, "未命名节点"),
			formatAlertValue(event.NodeID, "unknown"),
			formatReportEventTime(event.LastSeen),
			formatAlertDuration(event.OfflineSec),
		)
	}
	if !hasChannels && freshOffline+freshRecovered > 0 {
		// 分隔符用逗号而非中文分号：管理端日志页的 i18n 会把「；」当复合句分隔符重组。
		// 不提「已安排补发」：无渠道时只有离线事件会登记退避补发，恢复通知不会，
		// 这句话不能扩大到两者。
		reportLogger.Printf("[%s] 告警未发送：没有可用的通知渠道（离线 %d 个节点，恢复 %d 个节点）",
			title, freshOffline, freshRecovered)
	}
}

// formatReportEventTime 按服务器本地时区格式化（与 log 包的时间戳一致，避免日志行
// 与事件时间相差一个时区）。
func formatReportEventTime(unixSeconds int64) string {
	if unixSeconds <= 0 {
		return "unknown"
	}
	return time.Unix(unixSeconds, 0).Local().Format(time.DateTime)
}

func formatAlertDuration(seconds int64) string {
	if seconds < 0 {
		seconds = 0
	}
	if seconds < 60 {
		return fmt.Sprintf("%d秒", seconds)
	}
	minutes := seconds / 60
	if minutes < 60 {
		return fmt.Sprintf("%d分钟", minutes)
	}
	hours := minutes / 60
	if hours < 24 {
		return fmt.Sprintf("%d小时", hours)
	}
	days := hours / 24
	return fmt.Sprintf("%d天", days)
}

func formatAlertValue(value, fallback string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func boolPointer(value bool) *bool {
	return &value
}

func stringPointer(value string) *string {
	return &value
}

func intPointer(value int) *int {
	return &value
}

func int64Pointer(value int64) *int64 {
	return &value
}

func cloneNetworkTestResults(values []metrics.NetworkTestResult) []metrics.NetworkTestResult {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]metrics.NetworkTestResult, len(values))
	for i, value := range values {
		cloned[i] = value
		if value.LatencyMs != nil {
			latency := *value.LatencyMs
			cloned[i].LatencyMs = &latency
		}
	}
	return cloned
}

func cloneNodeStats(stats metrics.NodeStats) metrics.NodeStats {
	stats.Disk = slices.Clone(stats.Disk)
	stats.GPU = slices.Clone(stats.GPU)
	stats.NetworkTests = cloneNetworkTestResults(stats.NetworkTests)
	return stats
}

func cloneNodeState(value NodeState) NodeState {
	value.Stats = cloneNodeStats(value.Stats)
	return value
}

func cloneNodeStates(values map[string]NodeState) map[string]NodeState {
	if len(values) == 0 {
		return map[string]NodeState{}
	}
	cloned := make(map[string]NodeState, len(values))
	for id, value := range values {
		cloned[id] = cloneNodeState(value)
	}
	return cloned
}

func cloneGroupNodes(values []GroupNode) []GroupNode {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]GroupNode, len(values))
	for i, value := range values {
		cloned[i] = GroupNode{
			Name:     value.Name,
			Children: cloneGroupNodes(value.Children),
		}
	}
	return cloned
}

func cloneAISettings(settings AISettings) AISettings {
	settings.OpenAICompatibles = slices.Clone(settings.OpenAICompatibles)
	return settings
}

func cloneSettings(settings Settings) Settings {
	settings.AlertTelegramUserIDs = slices.Clone(settings.AlertTelegramUserIDs)
	settings.AdminAuth = cloneAdminAuthSettings(settings.AdminAuth)
	settings.AISettings = cloneAISettings(settings.AISettings)
	settings.Groups = slices.Clone(settings.Groups)
	settings.GroupTree = cloneGroupNodes(settings.GroupTree)
	settings.TestCatalog = slices.Clone(settings.TestCatalog)
	settings.NotifyChannels = cloneNotifyChannels(settings.NotifyChannels)
	return settings
}

func isAlertEnabled(profile *NodeProfile) bool {
	if profile == nil {
		return true
	}
	if profile.AlertEnabled == nil {
		return true
	}
	return *profile.AlertEnabled
}

func cloneAgentUpdateInstruction(value *AgentUpdateInstruction) *AgentUpdateInstruction {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func isAgentUpdateTerminalState(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case agentUpdateStateSucceeded, agentUpdateStateFailed:
		return true
	default:
		return false
	}
}

func normalizeAgentUpdateReportState(state string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case agentUpdateStateUpdating:
		return agentUpdateStateUpdating, true
	case agentUpdateStateRestarting:
		return agentUpdateStateRestarting, true
	case agentUpdateStateSucceeded:
		return agentUpdateStateSucceeded, true
	case agentUpdateStateFailed:
		return agentUpdateStateFailed, true
	default:
		return "", false
	}
}

func agentUpdateLeaseForState(state string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case agentUpdateStateUpdating:
		return agentUpdateLeaseUpdating
	case agentUpdateStateRestarting:
		return agentUpdateLeaseRestart
	default:
		return 0
	}
}

const agentUpdateDispatchTimeout = time.Hour

const agentUpdateProgressTimeout = 10 * time.Minute

func shouldDispatchAgentUpdate(profile *NodeProfile, now time.Time) bool {
	if profile == nil || profile.AgentUpdate == nil {
		return false
	}
	if isAgentUpdateTerminalState(profile.AgentUpdateState) {
		return false
	}
	return profile.AgentUpdateLeaseUntil <= now.Unix()
}

func expireStaleAgentUpdateLocked(profile *NodeProfile, now time.Time) bool {
	if profile == nil || profile.AgentUpdate == nil {
		return false
	}
	if isAgentUpdateTerminalState(profile.AgentUpdateState) {
		return false
	}
	requestedAt := profile.AgentUpdate.RequestedAt
	if requestedAt <= 0 || now.Unix()-requestedAt < int64(agentUpdateDispatchTimeout/time.Second) {
		return false
	}
	if profile.AgentUpdateReportedAt > 0 && now.Unix()-profile.AgentUpdateReportedAt < int64(agentUpdateProgressTimeout/time.Second) {
		return false
	}
	profile.AgentUpdate = nil
	profile.AgentUpdateState = agentUpdateStateFailed
	profile.AgentUpdateLeaseUntil = 0
	profile.AgentUpdateReportedAt = now.Unix()
	profile.AgentUpdateMessage = "更新任务超过 1 小时未完成，已自动收口"
	return true
}

func reconcileAgentUpdateWithStatsLocked(profile *NodeProfile, stats metrics.NodeStats, now time.Time) bool {
	if profile == nil || profile.AgentUpdate == nil {
		return false
	}
	currentVersion := strings.TrimSpace(stats.AgentVersion)
	targetVersion := strings.TrimSpace(profile.AgentUpdateTargetVersion)
	if targetVersion == "" {
		targetVersion = strings.TrimSpace(profile.AgentUpdate.Version)
	}
	if currentVersion == "" || targetVersion == "" {
		return false
	}
	if !updater.VersionsEqual(currentVersion, targetVersion) {
		return false
	}
	profile.AgentUpdate = nil
	profile.AgentUpdateState = agentUpdateStateSucceeded
	profile.AgentUpdateTargetVersion = targetVersion
	profile.AgentUpdateMessage = "节点已上报目标版本，服务端已自动完成更新任务收口"
	profile.AgentUpdateLeaseUntil = 0
	profile.AgentUpdateReportedAt = now.Unix()
	return true
}

func resolveAgentUpdateMode(stats metrics.NodeStats) string {
	deployMode := strings.ToLower(strings.TrimSpace(stats.DeployMode))
	if deployMode == string(updater.DeployModeDocker) {
		if stats.DockerManagedUpdate {
			return "docker-managed"
		}
		return string(updater.DeployModeDocker)
	}
	osLabel := strings.ToLower(strings.TrimSpace(stats.OS))
	if strings.Contains(osLabel, "windows") {
		return "windows"
	}
	return "binary"
}

func resolveAgentUpdateSupported(stats metrics.NodeStats) bool {
	return resolveAgentUpdateUnsupportedReason(stats) == ""
}

func resolveAgentUpdateUnsupportedReason(stats metrics.NodeStats) string {
	if stats.AgentUpdateDisabled {
		return "当前 Agent 已禁用远程更新"
	}
	if stats.AgentUpdateInsecure {
		return "远程更新要求 Agent 使用 HTTPS 控制面"
	}
	if !stats.AgentRemoteUpdate {
		return "当前 Agent 未上报远程更新能力"
	}
	switch resolveAgentUpdateMode(stats) {
	case "windows":
		return "当前节点平台暂不支持后台自更新"
	case "docker-managed":
		return ""
	case string(updater.DeployModeDocker):
		return "Docker 部署的 Agent 需同时设置 CM_ENABLE_DOCKER_UPDATE=1 并挂载 /var/run/docker.sock 才能启用后台一键更新；否则请拉取最新镜像并重建容器"
	default:
		return ""
	}
}

func resolveAgentUpdateView(profile *NodeProfile, stats metrics.NodeStats) (bool, string, string, string, string) {
	if profile == nil {
		supported := resolveAgentUpdateSupported(stats)
		message := ""
		if !supported {
			message = resolveAgentUpdateUnsupportedReason(stats)
		}
		return supported, resolveAgentUpdateMode(stats), "", "", message
	}
	supported := resolveAgentUpdateSupported(stats)
	if !supported {
		return supported, resolveAgentUpdateMode(stats), strings.TrimSpace(profile.AgentUpdateState), strings.TrimSpace(profile.AgentUpdateTargetVersion), resolveAgentUpdateUnsupportedReason(stats)
	}
	message := strings.TrimSpace(profile.AgentUpdateMessage)
	return supported, resolveAgentUpdateMode(stats), strings.TrimSpace(profile.AgentUpdateState), strings.TrimSpace(profile.AgentUpdateTargetVersion), message
}

func normalizeTelegramUserIDs(ids []int64) []int64 {
	seen := make(map[int64]struct{})
	normalized := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}
	return normalized
}

func normalizeSiteTitle(title string) string {
	value := strings.TrimSpace(title)
	if value == "" {
		return defaultSiteTitle
	}
	return value
}

func adminDocumentTitle(siteTitle string) string {
	return normalizeSiteTitle(siteTitle) + " 管理后台"
}

func parsePublicHistoryRange(raw string, now time.Time) (string, time.Time, time.Time, error) {
	rangeKey := strings.ToLower(strings.TrimSpace(raw))
	if rangeKey == "" {
		rangeKey = "1h"
	}
	if rangeKey == "1d" {
		rangeKey = "24h"
	}

	to := now.UTC()
	var duration time.Duration
	switch rangeKey {
	case "1h":
		duration = time.Hour
	case "24h":
		duration = 24 * time.Hour
	case "7d":
		duration = 7 * 24 * time.Hour
	default:
		return "", time.Time{}, time.Time{}, fmt.Errorf("invalid range")
	}

	return rangeKey, to.Add(-duration), to, nil
}

func storeSnapshot(s *Store) Snapshot {
	return buildStoreSnapshot(s, s.Snapshot())
}

func adminStoreSnapshot(s *Store) Snapshot {
	return buildStoreSnapshot(s, s.AdminSnapshot())
}

func buildStoreSnapshot(s *Store, nodes []NodeView) Snapshot {
	snapshot := Snapshot{
		Type:        "snapshot",
		GeneratedAt: time.Now().Unix(),
		Nodes:       nodes,
		Groups:      s.SettingsGroups(),
		GroupTree:   s.SettingsGroupTree(),
		Settings:    s.PublicSettings(),
	}
	return snapshot
}

func broadcastStoreSnapshot(hub *Hub, store *Store) {
	if hub == nil || store == nil {
		return
	}
	if !hub.HasVariant(publicVariantBalanced) && !hub.HasVariant(adminVariant) {
		return
	}
	if hub.HasVariant(publicVariantBalanced) {
		payload, err := json.Marshal(storeSnapshot(store))
		if err != nil {
			log.Printf("序列化节点快照失败: %v", err)
			return
		}
		hub.BroadcastVariant(payload, publicVariantBalanced)
	}
	if !hub.HasVariant(adminVariant) {
		return
	}
	payload, err := json.Marshal(adminStoreSnapshot(store))
	if err != nil {
		log.Printf("序列化管理端节点快照失败: %v", err)
		return
	}
	hub.BroadcastAdmin(payload, store.Credentials().TokenSalt)
}

func snapshotPayloadDigest(payload []byte) string {
	const prefix = `{"type":"snapshot","generated_at":`
	digest := fnv.New64a()
	if rest, ok := bytes.CutPrefix(payload, []byte(prefix)); ok {
		if comma := bytes.IndexByte(rest, ','); comma >= 0 {
			digest.Write([]byte(prefix))
			digest.Write(rest[comma:])
			return fmt.Sprintf("%x", digest.Sum(nil))
		}
	}
	digest.Write(payload)
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func normalizeHistoryEntry(entry *TestHistoryEntry) {
	if entry == nil {
		return
	}
	if entry.Times == nil {
		entry.Times = []int64{}
	}
	count := len(entry.Times)
	if entry.Latency == nil {
		entry.Latency = make([]*float64, 0, count)
	}
	if entry.Loss == nil {
		entry.Loss = make([]*float64, 0, count)
	}
	if count == 0 {
		entry.Latency = entry.Latency[:0]
		entry.Loss = entry.Loss[:0]
		return
	}
	if len(entry.Latency) > count {
		entry.Latency = entry.Latency[len(entry.Latency)-count:]
	}
	if len(entry.Loss) > count {
		entry.Loss = entry.Loss[len(entry.Loss)-count:]
	}
	for len(entry.Latency) < count {
		entry.Latency = append(entry.Latency, nil)
	}
	for len(entry.Loss) < count {
		entry.Loss = append(entry.Loss, nil)
	}
}

func convertNetworkHistoryToTestHistory(
	source map[string]*history.NetworkHistoryEntry,
) map[string]*TestHistoryEntry {
	result := make(map[string]*TestHistoryEntry, len(source))
	for key, entry := range source {
		if entry == nil {
			continue
		}
		result[key] = &TestHistoryEntry{
			Latency:        slices.Clone(entry.Latency),
			Loss:           slices.Clone(entry.Loss),
			Times:          slices.Clone(entry.Times),
			LastAt:         entry.LastAt,
			MinIntervalSec: entry.MinIntervalSec,
			AvgIntervalSec: entry.AvgIntervalSec,
		}
	}
	return result
}

func (s *Store) HasNode(nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if profile := s.profiles[nodeID]; profile != nil &&
		!s.nodePublicVisibleLocked(profile.HideFromDisplay, profile.HideFromCR, profile.HideFromAll,
			normalizeGroupSelections(profile.Groups)) {
		return false
	}
	_, exists := s.nodes[nodeID]
	return exists
}

func (s *Store) QueryPublicNodeHistory(ctx context.Context, nodeID string, from, to time.Time) (map[string]*TestHistoryEntry, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return map[string]*TestHistoryEntry{}, nil
	}
	if s == nil || s.historyManager == nil || s.historyManager.NetworkStore() == nil {
		return map[string]*TestHistoryEntry{}, nil
	}
	entries, err := s.historyManager.NetworkStore().QueryPublicRange(ctx, nodeID, from, to)
	if err != nil {
		return nil, err
	}
	return convertNetworkHistoryToTestHistory(entries), nil
}

// QueryAINodeResources 查询节点的 CPU / 内存 / 网络资源历史（供 AI 快照使用）。
func (s *Store) QueryAINodeResources(ctx context.Context, nodeID string, from, to time.Time) (*history.ResourceHistoryEntry, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return history.NewEmptyResourceHistoryEntry(), nil
	}
	if s == nil || s.historyManager == nil || s.historyManager.ResourceStore() == nil {
		return history.NewEmptyResourceHistoryEntry(), nil
	}
	return s.historyManager.ResourceStore().QueryPublicRange(ctx, nodeID, from, to)
}

// ReconcileResourceHistoryRetention 把设置中的资源历史保留天数应用到存储；已经
// 一致时无动作，由巡检每秒调用作兵底。最新设置在存储的串行锁内重读：调用方读到的
// 值可能在等锁期间就过期了，用旧值覆盖更新的配置会让内存值与磁盘保留期分叉。
func (s *Store) ReconcileResourceHistoryRetention() {
	s.mu.RLock()
	manager := s.historyManager
	s.mu.RUnlock()
	if manager == nil {
		return
	}
	store := manager.ResourceStore()
	if store == nil {
		return
	}
	latest := func() int {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return normalizeResourceHistoryDays(s.settings.ResourceHistoryDays)
	}
	if err := store.SyncRetention(latest); err != nil {
		log.Printf("应用资源历史保留设置失败: %v", err)
	}
}

// FlushResourceHistory 落盘已完成 30 秒桶并清理过期样本（巡检每秒调用）。
func (s *Store) FlushResourceHistory(now time.Time) {
	s.mu.RLock()
	manager := s.historyManager
	s.mu.RUnlock()
	if manager == nil {
		return
	}
	if err := manager.FlushResourceHistory(now); err != nil {
		log.Printf("落盘资源历史失败: %v", err)
	}
}

func (s *Store) Snapshot() []NodeView {
	s.mu.RLock()
	defer s.mu.RUnlock()

	groupNames, tagKeys, treeMode := groupSelectionSets(s.settings)
	all := s.snapshotLocked(false)
	visible := all[:0]
	for _, view := range all {
		if !nodePublicVisibleSetsLocked(groupNames, tagKeys, treeMode,
			view.HiddenFromDisplay, view.HiddenFromCR, view.HiddenFromAll, view.Groups) {
			continue
		}
		// 可见性过滤后统一做公开投影（红线 4）：storeSnapshot / 公开 REST 快照 /
		// 公开 WS 初始快照都走这里；AdminSnapshot 走 snapshotLocked(true)，不脱敏。
		visible = append(visible, publicNodeView(view))
	}
	return visible
}

func (s *Store) nodePublicVisibleLocked(hideDisplay, hideCR, hideAll bool, groups []string) bool {
	groupNames, tagKeys, treeMode := groupSelectionSets(s.settings)
	return nodePublicVisibleSetsLocked(groupNames, tagKeys, treeMode, hideDisplay, hideCR, hideAll, groups)
}

func nodePublicVisibleSetsLocked(groupNames, tagKeys map[string]struct{}, treeMode, hideDisplay, hideCR, hideAll bool, groups []string) bool {
	if hideDisplay {
		return false
	}
	if !hideCR || !hideAll {
		return true
	}
	return len(filterGroupSelections(groups, groupNames, tagKeys, treeMode)) > 0
}

func (s *Store) AdminSnapshot() []NodeView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked(true)
}

// applyAdminTrafficView 填充管理端专属的流量用量字段（A-02）：traffic_used_bytes
// 按当前计算方式（trafficUsedBytes），traffic_cycle_start 取 TrafficCounter 起点。
// 仅在 AdminSnapshot 路径调用；nodeViewLocked 不填这两个字段，公开快照与
// node_delta（公开 WS 载荷）序列化时因零值 + omitempty 而省略（红线 4）。
func applyAdminTrafficView(view *NodeView, profile *NodeProfile) {
	if profile == nil {
		return
	}
	view.TrafficUsedBytes = trafficUsedBytes(profile)
	if profile.TrafficCounter != nil {
		view.TrafficCycleStart = profile.TrafficCounter.CycleStart
	}
}

// applyAdminScopedTestsView 填充管理端专属的 scoped_test_ids（O-01）：范围下发
// 带来的探测目录项 ID（按目录顺序；手动选择优先，已被节点手动选择的目录项不
// 列入——此时该探测以手动选择形态呈现，间隔覆盖也以手动为准）。仅在
// AdminSnapshot 路径调用；nodeViewLocked 不填该字段，公开快照与 node_delta
// （公开 WS 载荷）序列化时因零值 + omitempty 而省略（红线 4）。
func (s *Store) applyAdminScopedTestsView(view *NodeView, nodeID string, profile *NodeProfile) {
	if profile == nil {
		return
	}
	manual := make(map[string]struct{}, len(profile.TestSelections))
	for _, sel := range profile.TestSelections {
		if sel.TestID != "" {
			manual[sel.TestID] = struct{}{}
		}
	}
	var scoped []string
	for _, item := range s.settings.TestCatalog {
		if item.Scope == nil {
			continue
		}
		if _, ok := manual[item.ID]; ok {
			continue
		}
		if !ruleScopeMatches(*item.Scope, nodeID, profile) {
			continue
		}
		scoped = append(scoped, item.ID)
	}
	view.ScopedTestIDs = scoped
}

func (s *Store) snapshotLocked(includeProfileOnly bool) []NodeView {
	views := make([]NodeView, 0, len(s.nodes))
	now := time.Now()
	seenNodes := make(map[string]struct{}, len(s.nodes))
	for _, node := range s.nodes {
		seenNodes[node.Stats.NodeID] = struct{}{}
		view, ok := s.nodeViewLocked(node.Stats.NodeID, now)
		if ok {
			if includeProfileOnly {
				applyAdminTrafficView(&view, s.profiles[node.Stats.NodeID])
				s.applyAdminScopedTestsView(&view, node.Stats.NodeID, s.profiles[node.Stats.NodeID])
			}
			views = append(views, view)
		}
	}
	if includeProfileOnly {
		for nodeID, profile := range s.profiles {
			if _, ok := seenNodes[nodeID]; ok {
				continue
			}
			if view, ok := profileOnlyNodeView(nodeID, profile); ok {
				applyAdminTrafficView(&view, profile)
				s.applyAdminScopedTestsView(&view, nodeID, profile)
				views = append(views, view)
			}
		}
	}
	// 分组名保持字节序（分组顺序由分组树单独表达，这里只保证同一分组内相邻）。
	sort.Slice(views, func(i, j int) bool { return nodeViewLess(views[i], views[j]) })
	return views
}

// nodeViewLess 是快照列表的排序谓词：先按分组名字节序，再按同组展示名的自然
// 顺序（de-vps-4 < de-vps-14、hk2 < hk10）。自然顺序相等（大小写不同、前导零
// 不同）时回退到原始字节序，最后用 NodeID 兜底，保证每次序列化顺序稳定。
func nodeViewLess(left, right NodeView) bool {
	if left.Group != right.Group {
		return left.Group < right.Group
	}
	if naturalLess(left.Alias, right.Alias) {
		return true
	}
	if naturalLess(right.Alias, left.Alias) {
		return false
	}
	if left.Alias != right.Alias {
		return left.Alias < right.Alias
	}
	return left.Stats.NodeID < right.Stats.NodeID
}

func (s *Store) reconcileProfiles(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, node := range s.nodes {
		s.ensureProfileLocked(node.Stats.NodeID)
	}
	for _, profile := range s.profiles {
		if s.applyAutoRenewLocked(profile, now) {
			changed = true
		}
	}
	return changed
}

func resolveNodeStatus(now time.Time, node NodeState) string {
	if now.IsZero() {
		now = time.Now()
	}
	if now.Sub(node.LastSeen) > nodeStaleGraceSeconds*time.Second {
		return nodeStatusOffline
	}
	return nodeStatusOnline
}

func profileOnlyNodeView(nodeID string, profile *NodeProfile) (NodeView, bool) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || profile == nil {
		return NodeView{}, false
	}
	alias := strings.TrimSpace(profile.Alias)
	nodeName := alias
	if nodeName == "" {
		nodeName = nodeID
	}
	stats := metrics.NodeStats{
		NodeID:    nodeID,
		NodeName:  nodeName,
		NodeAlias: alias,
		Hostname:  nodeID,
		Timestamp: profile.UpdatedAt,
	}
	group, tags := resolveProfileGroupTags(profile)
	stats.NodeGroup = group
	groups := normalizeGroupSelections(profile.Groups)
	return NodeView{
		Stats:                    stats,
		Status:                   nodeStatusWaitingRegistration,
		ServerID:                 profile.ServerID,
		AlertEnabled:             isAlertEnabled(profile),
		HiddenFromDisplay:        profile.HideFromDisplay,
		HiddenFromCR:             profile.HideFromCR,
		HiddenFromAll:            profile.HideFromAll,
		Alias:                    alias,
		Group:                    group,
		Tags:                     slices.Clone(tags),
		Groups:                   slices.Clone(groups),
		Region:                   profile.Region,
		DiskType:                 profile.DiskType,
		NetSpeedMbps:             profile.NetSpeedMbps,
		ExpireAt:                 profile.ExpireAt,
		AutoRenew:                profile.AutoRenew,
		RenewIntervalSec:         profile.RenewIntervalSec,
		TrafficLimitBytes:        profile.TrafficLimitBytes,
		TrafficLimitType:         profile.TrafficLimitType,
		TrafficResetDay:          profile.TrafficResetDay,
		TestIntervalSec:          profile.TestIntervalSec,
		TestSelections:           slices.Clone(profile.TestSelections),
		AgentUpdateSupported:     false,
		AgentUpdateState:         strings.TrimSpace(profile.AgentUpdateState),
		AgentUpdateTargetVersion: strings.TrimSpace(profile.AgentUpdateTargetVersion),
		AgentUpdateMessage:       strings.TrimSpace(profile.AgentUpdateMessage),
	}, true
}

func (s *Store) nodeViewLocked(nodeID string, now time.Time) (NodeView, bool) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return NodeView{}, false
	}
	node, ok := s.nodes[nodeID]
	if !ok {
		return NodeView{}, false
	}

	profile := s.profiles[nodeID]
	if profile == nil {
		profile = &NodeProfile{TestIntervalSec: defaultTestIntervalSec}
	}
	status := resolveNodeStatus(now, node)
	groups := normalizeGroupSelections(profile.Groups)
	group, tags := resolveProfileGroupTagsSelections(profile, groups)
	updateSupported, updateMode, updateState, updateTargetVersion, updateMessage := resolveAgentUpdateView(profile, node.Stats)

	stats := cloneNodeStats(node.Stats)

	stats.NodeGroup = group
	if status == nodeStatusOffline {
		stats.Network.TxBytesPerSec = 0
		stats.Network.RxBytesPerSec = 0
		stats.DiskIO.ReadBytesPerSec = 0
		stats.DiskIO.WriteBytesPerSec = 0
	}

	return NodeView{
		Stats:                    stats,
		LastSeen:                 node.LastSeen.Unix(),
		FirstSeen:                node.FirstSeen.Unix(),
		Status:                   status,
		ServerID:                 profile.ServerID,
		AlertEnabled:             isAlertEnabled(profile),
		HiddenFromDisplay:        profile.HideFromDisplay,
		HiddenFromCR:             profile.HideFromCR,
		HiddenFromAll:            profile.HideFromAll,
		Alias:                    profile.Alias,
		Group:                    group,
		Tags:                     slices.Clone(tags),
		Groups:                   slices.Clone(groups),
		Region:                   profile.Region,
		DiskType:                 profile.DiskType,
		NetSpeedMbps:             profile.NetSpeedMbps,
		ExpireAt:                 profile.ExpireAt,
		AutoRenew:                profile.AutoRenew,
		RenewIntervalSec:         profile.RenewIntervalSec,
		TrafficLimitBytes:        profile.TrafficLimitBytes,
		TrafficLimitType:         profile.TrafficLimitType,
		TrafficResetDay:          profile.TrafficResetDay,
		TestIntervalSec:          profile.TestIntervalSec,
		TestSelections:           slices.Clone(profile.TestSelections),
		AgentUpdateSupported:     updateSupported,
		AgentUpdateMode:          updateMode,
		AgentUpdateState:         updateState,
		AgentUpdateTargetVersion: updateTargetVersion,
		AgentUpdateMessage:       updateMessage,
	}, true
}

func resolveProfileGroupTags(profile *NodeProfile) (string, []string) {
	return resolveProfileGroupTagsSelections(profile, normalizeGroupSelections(profile.Groups))
}

func resolveProfileGroupTagsSelections(profile *NodeProfile, selections []string) (string, []string) {
	if len(selections) == 0 {
		selections = selectionsFromGroupTags(profile.Group, profile.Tags)
	}

	group, tags := primaryGroupTagsFromSelections(selections)
	return group, tags
}

func (s *Store) SettingsGroups() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.settings.GroupTree) > 0 {
		return flattenGroupTree(s.settings.GroupTree)
	}
	groups := make([]string, len(s.settings.Groups))
	copy(groups, s.settings.Groups)
	return groups
}

// SettingsGroupTree 返回分组树的深拷贝。树中只有分组 / 标签名称，属于可公开数据
// （F1：前台按树内顺序展示标签分区）。
func (s *Store) SettingsGroupTree() []GroupNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneGroupNodes(s.settings.GroupTree)
}

// BuildVersion / BuildCommit 返回构建时注入的版本信息（F7 system/status）。
// 两者在构造后不变，无需加锁。
func (s *Store) BuildVersion() string {
	if s == nil {
		return ""
	}
	return s.buildVersion
}

func (s *Store) BuildCommit() string {
	if s == nil {
		return ""
	}
	return s.buildCommit
}

// StartedAt 返回服务端进程启动时间（F7 system/status；测试中的裸 Store 为零值，
// 对应 started_at/uptime_sec 为 0）。
func (s *Store) StartedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.startedAt
}

// StateFilePath 返回 state.json 的完整路径（F7 system/status 统计数据目录占用）。
func (s *Store) StateFilePath() string {
	if s == nil {
		return ""
	}
	return s.dataPath
}

// AdminNodeIDs 返回全部已上报节点的 ID（含隐藏节点，不含仅建过 profile 的节点），
// 按字典序稳定输出（F7 probes/overview 遍历所有节点聚合探测历史）。
func (s *Store) AdminNodeIDs() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.nodes))
	for nodeID := range s.nodes {
		ids = append(ids, nodeID)
	}
	sort.Strings(ids)
	return ids
}

func (h *Hub) Add(conn *websocket.Conn, variant string, adminTokenSalt string, initialPayload []byte) (*hubClient, error) {
	client := &hubClient{
		conn:           conn,
		variant:        variant,
		adminTokenSalt: strings.TrimSpace(adminTokenSalt),
		send:           make(chan hubMessage, wsSendQueueSize),
		done:           make(chan struct{}),
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[conn] = client
	select {
	case client.send <- hubMessage{payload: initialPayload, prepared: nil}:
		return client, nil
	default:
		delete(h.clients, conn)
		return nil, errors.New("initial snapshot queue full")
	}
}

func (h *Hub) Remove(conn *websocket.Conn) {
	var client *hubClient
	h.mu.Lock()
	client = h.clients[conn]
	delete(h.clients, conn)
	h.mu.Unlock()
	if client != nil {
		_ = client.close()
		return
	}
	_ = conn.Close()
}

func (h *Hub) CloseAdminClients() {
	for _, client := range h.snapshotClients() {
		if client != nil && client.variant == adminVariant {
			h.removeClient(client)
		}
	}
}

func (h *Hub) broadcast(payload []byte, salt string, include func(client *hubClient, currentSalt string) bool) {
	clients := h.snapshotClients()
	if len(clients) == 0 {
		return
	}
	currentSalt := strings.TrimSpace(salt)
	prepared := h.prepareBroadcast(payload)
	for _, client := range clients {
		if client == nil || !include(client, currentSalt) {
			continue
		}
		if ok := client.enqueue(payload, prepared); !ok {
			h.removeClient(client)
		}
	}
}

func (h *Hub) adminClientAllowed(client *hubClient, currentSalt string) bool {
	if client.variant != adminVariant {
		return false
	}
	if client.adminTokenSalt != currentSalt {
		h.removeClient(client)
		return false
	}
	return true
}

func (h *Hub) BroadcastVariant(payload []byte, variant string) {
	h.broadcast(payload, "", func(client *hubClient, _ string) bool { return client.variant == variant })
}

func (h *Hub) BroadcastAdmin(payload []byte, tokenSalt string) {
	h.broadcast(payload, tokenSalt, h.adminClientAllowed)
}

func (h *Hub) prepareBroadcast(payload []byte) *websocket.PreparedMessage {
	prepared, err := websocket.NewPreparedMessage(websocket.TextMessage, payload)
	if err != nil {
		return nil
	}
	return prepared
}

func (h *Hub) HasVariant(variant string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, client := range h.clients {
		if client != nil && client.variant == variant {
			return true
		}
	}
	return false
}

// ClientCounts 返回当前 WS 连接数，按管理端 / 公开受众拆分（F7 system/status）。
func (h *Hub) ClientCounts() (admin int, public int) {
	if h == nil {
		return 0, 0
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, client := range h.clients {
		if client == nil {
			continue
		}
		switch client.variant {
		case adminVariant:
			admin++
		case publicVariantBalanced:
			public++
		}
	}
	return admin, public
}

func (h *Hub) snapshotClients() []*hubClient {
	h.mu.RLock()
	defer h.mu.RUnlock()
	clients := make([]*hubClient, 0, len(h.clients))
	for _, client := range h.clients {
		if client != nil {
			clients = append(clients, client)
		}
	}
	return clients
}

func (h *Hub) removeClient(client *hubClient) {
	if client == nil {
		return
	}
	h.mu.Lock()
	delete(h.clients, client.conn)
	h.mu.Unlock()
	_ = client.close()
}

func configureWSConn(conn *websocket.Conn) {
	if conn == nil {
		return
	}
	conn.SetReadLimit(wsMaxClientMessageBytes)
	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})
}

// publicWSQuota 是公开（未认证）WS 连接的进程级额度：全局上限 + 按真实客户端 IP 上限。
// 在 Upgrade 之前尝试占用（超限直接 503，不支付快照序列化成本），占用成功后若建连失败
// 立即释放；连接结束（client.done 关闭）时释放，释放函数幂等，保证每条连接只释放一次。
type publicWSQuota struct {
	mu          sync.Mutex
	perIP       map[string]int
	total       int
	perIPLimit  int
	globalLimit int
}

func newPublicWSQuota(perIPLimit, globalLimit int) *publicWSQuota {
	return &publicWSQuota{
		perIP:       make(map[string]int),
		perIPLimit:  perIPLimit,
		globalLimit: globalLimit,
	}
}

// acquire 尝试占用一个公开连接额度。成功返回幂等的释放函数；全局或按 IP 超限时返回
// (nil, false)。限额 <=0 表示该维度不限制。
func (q *publicWSQuota) acquire(clientIP string) (func(), bool) {
	if q == nil {
		return func() {}, true
	}
	ip := strings.TrimSpace(clientIP)
	if ip == "" {
		ip = "unknown"
	}
	q.mu.Lock()
	if q.globalLimit > 0 && q.total >= q.globalLimit {
		q.mu.Unlock()
		return nil, false
	}
	if q.perIPLimit > 0 && q.perIP[ip] >= q.perIPLimit {
		q.mu.Unlock()
		return nil, false
	}
	q.total++
	q.perIP[ip]++
	q.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			q.mu.Lock()
			if q.total > 0 {
				q.total--
			}
			if n := q.perIP[ip]; n > 1 {
				q.perIP[ip] = n - 1
			} else {
				delete(q.perIP, ip)
			}
			q.mu.Unlock()
		})
	}, true
}

func heartbeatLoop(client *hubClient, hub *Hub) {
	if client == nil {
		return
	}
	ticker := time.NewTicker(wsPingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-client.done:
			return
		case <-ticker.C:
		}
		if err := client.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(wsWriteWait)); err != nil {
			hub.removeClient(client)
			return
		}
	}
}

func writeLoop(client *hubClient, hub *Hub) {
	if client == nil {
		return
	}
	for {
		select {
		case <-client.done:
			return
		case msg := <-client.send:
			if err := client.writeMessage(msg); err != nil {
				hub.removeClient(client)
				return
			}
		}
	}
}

func readLoop(client *hubClient, hub *Hub) {
	if client == nil {
		return
	}
	defer hub.removeClient(client)
	conn := client.conn
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func isSameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func stripForwardedPrefixPath(next http.Handler, trustedProxyHeaders bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := forwardedPrefix(r, trustedProxyHeaders)
		if prefix == "" || r == nil || r.URL == nil {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		strippedPath := ""
		switch {
		case path == prefix:
			strippedPath = "/"
		case strings.HasPrefix(path, prefix+"/"):
			strippedPath = strings.TrimPrefix(path, prefix)
		default:
			next.ServeHTTP(w, r)
			return
		}
		req := r.Clone(r.Context())
		urlCopy := *r.URL
		urlCopy.Path = strippedPath
		urlCopy.RawPath = ""
		req.URL = &urlCopy
		next.ServeHTTP(w, req)
	})
}

func forwardedPrefix(r *http.Request, trustedProxyHeaders bool) string {
	if r == nil {
		return ""
	}
	raw := trustedForwardedHeader(r, trustedProxyHeaders, "X-Forwarded-Prefix")
	if raw == "" {
		return ""
	}
	if comma := strings.Index(raw, ","); comma >= 0 {
		raw = strings.TrimSpace(raw[:comma])
	}
	if invalidForwardedPrefix(raw) {
		return ""
	}
	decoded, ok := decodeForwardedPrefix(raw)
	if !ok {
		return ""
	}
	decoded = strings.TrimSpace(decoded)
	if invalidForwardedPrefix(decoded) {
		return ""
	}
	if !strings.HasPrefix(decoded, "/") {
		decoded = "/" + decoded
	}
	parts := strings.Split(decoded, "/")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		if part == "." || part == ".." {
			return ""
		}
		clean = append(clean, part)
	}
	if len(clean) == 0 {
		return ""
	}
	return "/" + strings.Join(clean, "/")
}

func trustedForwardedHeader(r *http.Request, trustedProxyHeaders bool, name string) string {
	if !trustedProxyHeaders || r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(name))
}

func decodeForwardedPrefix(raw string) (string, bool) {
	decoded := raw
	for i := 0; i < 4; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return "", false
		}
		if next == decoded {
			return next, true
		}
		decoded = next
		if invalidForwardedPrefix(decoded) {
			return "", false
		}
	}
	return "", false
}

func forwardedPrefixedPath(r *http.Request, path string, trustedProxyHeaders bool) string {
	prefix := forwardedPrefix(r, trustedProxyHeaders)
	if prefix == "" {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return prefix + path
}

func invalidForwardedPrefix(value string) bool {
	if value == "" || value == "/" || strings.Contains(value, "://") || strings.Contains(value, ":") || strings.ContainsAny(value, "?#\\") {
		return true
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src 'self' ws: wss: https://challenges.cloudflare.com")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

type NodeProfileUpdate struct {
	Alias            *string   `json:"alias"`
	Group            *string   `json:"group"`
	Tags             *[]string `json:"tags"`
	Groups           *[]string `json:"groups"`
	Region           *string   `json:"region"`
	DiskType         *string   `json:"disk_type"`
	NetSpeedMbps     *int      `json:"net_speed_mbps"`
	ExpireAt         *int64    `json:"expire_at"`
	AutoRenew        *bool     `json:"auto_renew"`
	HideFromDisplay  *bool     `json:"hide_from_display"`
	HideFromCR       *bool     `json:"hide_from_cr"`
	HideFromAll      *bool     `json:"hide_from_all"`
	RenewIntervalSec *int64    `json:"renew_interval_sec"`
	// 流量配额（F4）：三字段与节点抽屉「流量配额」分组卡片一一对应。
	TrafficLimitBytes *uint64          `json:"traffic_limit_bytes"`
	TrafficLimitType  *string          `json:"traffic_limit_type"`
	TrafficResetDay   *int             `json:"traffic_reset_day"`
	TestIntervalSec   *int             `json:"test_interval_sec"`
	TestSelections    *[]TestSelection `json:"test_selections"`
	AlertEnabled      *bool            `json:"alert_enabled"`
}

func (s *Store) AdminPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings.AdminPath
}

func (s *Store) Credentials() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

func (s *Store) RotateAdminTokenSalt() error {
	tokenSalt, err := randomToken(16)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.settings.TokenSalt = tokenSalt
	s.mu.Unlock()
	// 落盘失败不做回滚：mu 已释放，事后回滚会用旧盐覆盖并发提交的新状态；
	// 内存新盐已让现有会话立即失效，磁盘恢复后由后台 persistLogged 防抖固化，
	// 事后回滚反而制造部分回滚与并发覆盖。
	if err := s.persist(); err != nil {
		return fmt.Errorf("设置已生效但持久化失败，重启后可能回退；请检查磁盘后重试保存: %w", err)
	}
	return nil
}

var dummyAdminBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMye.IjPeGqBQVLf1F5zq1CzU9xUvOzX8fO"

func verifyAdminPasswordDummy(password string) {
	_ = verifyPassword(password, dummyAdminBcryptHash)
}

func (s *Store) VerifyAdminPassword(password string) bool {
	s.mu.RLock()
	stored := s.settings.AdminPass
	s.mu.RUnlock()
	if stored == "" {
		return false
	}
	if !verifyPassword(password, stored) {
		return false
	}
	if !isBcryptHash(stored) {
		s.upgradeAdminPasswordHash(password, stored)
	}
	return true
}

func (s *Store) loginPolicy() (int, time.Duration, time.Duration) {
	s.mu.RLock()
	limit := s.settings.LoginFailLimit
	windowSec := s.settings.LoginFailWindowSec
	lockSec := s.settings.LoginLockSec
	s.mu.RUnlock()
	if limit == 0 {
		limit = defaultLoginFailLimit
	}
	if limit < 0 {
		return 0, 0, 0
	}
	if windowSec <= 0 {
		windowSec = defaultLoginFailWindow
	}
	if lockSec <= 0 {
		lockSec = defaultLoginLockSec
	}
	return limit, time.Duration(windowSec) * time.Second, time.Duration(lockSec) * time.Second
}

// loginAttemptKey 只按真实客户端 IP 分桶：用户名由攻击者控制，若参与键，轮换用户名即可
// 获得全新额度并反复触发 dummy bcrypt；反代部署下若用 r.RemoteAddr 作为 host，则所有
// 客户端共享同一个「用户名|代理IP」桶，知道管理员用户名者可 5 次错误密码锁死管理员。
func loginAttemptKey(clientIP string) string {
	ip := strings.TrimSpace(clientIP)
	if ip == "" {
		ip = "unknown"
	}
	return "ip|" + ip
}

// clientIPFromRequest 解析真实客户端 IP。trustedProxyHeaders 为 true 时取
// X-Forwarded-For 最右一个非空条目（可信代理追加的那一跳）；否则只用 RemoteAddr 的
// host。XFF 条目必须能通过 net.ParseIP 校验，否则回退 RemoteAddr。默认（false）绝不
// 读取 XFF——这是防伪造绕过的关键。
func clientIPFromRequest(r *http.Request, trustedProxyHeaders bool) string {
	if r == nil {
		return "unknown"
	}
	if trustedProxyHeaders {
		if ip := forwardedForClientIP(r.Header.Values("X-Forwarded-For")); ip != "" {
			return ip
		}
	}
	host := strings.TrimSpace(clientIPFromRemoteAddr(r.RemoteAddr))
	if host == "" {
		return "unknown"
	}
	return host
}

// forwardedForClientIP 返回 X-Forwarded-For 最右一个非空且合法（net.ParseIP）的条目；
// 无合法条目时返回空串，调用方回退 RemoteAddr。多行头按出现顺序拼接后取最右。
func forwardedForClientIP(values []string) string {
	last := ""
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if candidate := strings.TrimSpace(part); candidate != "" {
				last = candidate
			}
		}
	}
	if last == "" || net.ParseIP(last) == nil {
		return ""
	}
	return last
}

func (s *Store) allowLoginAttempt(key string, now time.Time) (bool, time.Duration) {
	limit, window, lock := s.loginPolicy()
	if limit <= 0 {
		return true, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt := s.loginAttempts[key]
	if attempt == nil {
		s.maybePruneLoginAttemptsLocked(now, window, lock)
		return true, 0
	}
	if !attempt.lockedUntil.IsZero() && now.Before(attempt.lockedUntil) {
		return false, attempt.lockedUntil.Sub(now)
	}
	if window > 0 && !attempt.firstAt.IsZero() && now.Sub(attempt.firstAt) > window {
		delete(s.loginAttempts, key)
		s.maybePruneLoginAttemptsLocked(now, window, lock)
		return true, 0
	}
	s.maybePruneLoginAttemptsLocked(now, window, lock)
	return true, 0
}

func (s *Store) recordLoginFailure(key string, now time.Time) (bool, time.Duration) {
	limit, window, lock := s.loginPolicy()
	if limit <= 0 {
		return false, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loginAttempts == nil {
		s.loginAttempts = make(map[string]*loginAttempt)
	}
	attempt := s.loginAttempts[key]
	if attempt == nil {
		s.ensureLoginAttemptCapacityLocked(now, window, lock)
		attempt = &loginAttempt{firstAt: now}
		s.loginAttempts[key] = attempt
	}
	if !attempt.lockedUntil.IsZero() && now.Before(attempt.lockedUntil) {
		return true, attempt.lockedUntil.Sub(now)
	}
	if window > 0 && !attempt.firstAt.IsZero() && now.Sub(attempt.firstAt) > window {
		attempt.failCount = 0
		attempt.firstAt = now
	}
	if attempt.firstAt.IsZero() {
		attempt.firstAt = now
	}
	attempt.failCount++
	attempt.lastAt = now
	if attempt.failCount >= limit {
		attempt.lockedUntil = now.Add(lock)
		s.maybePruneLoginAttemptsLocked(now, window, lock)
		return true, lock
	}
	s.maybePruneLoginAttemptsLocked(now, window, lock)
	return false, 0
}

func (s *Store) clearLoginAttempts(key string) {
	s.mu.Lock()
	delete(s.loginAttempts, key)
	s.mu.Unlock()
}

// allowLoginGlobalAttempt 施加进程级登录尝试预算：键固定为 loginGlobalAttemptKey（不含
// 攻击者可控字段），使换用户名/换 IP 都无法突破全进程每窗口的 bcrypt 次数上界。超限时
// 返回 false 与建议的 Retry-After。窗口复用 agent 限速窗口，由 runTickLoop 定期回收。
func (s *Store) allowLoginGlobalAttempt(now time.Time) (bool, time.Duration) {
	window := time.Duration(defaultLoginFailWindow) * time.Second
	if !s.allowAgentRate(loginGlobalAttemptKey, window, loginGlobalAttemptLimit, now, false) {
		return false, window
	}
	return true, 0
}

// maybePruneLoginAttemptsLocked 以摊还方式清理过期条目：每 loginAttemptPruneInterval
// 次调用才做一次全表扫描，避免未认证流量在全局锁内持续触发 O(n) 扫描。
// 过期语义仍由 allow/record 内的 window/lock 判定保证，清理只影响内存回收时机。
func (s *Store) maybePruneLoginAttemptsLocked(now time.Time, window, lock time.Duration) {
	s.loginPruneOps++
	if s.loginPruneOps < loginAttemptPruneInterval {
		return
	}
	s.loginPruneOps = 0
	s.pruneLoginAttemptsLocked(now, window, lock)
}

// ensureLoginAttemptCapacityLocked 保证写入新键前表不会超过硬上限：先做一次过期清理，
// 仍满则按最旧活跃时间淘汰一批。仅在插入新键时调用（此时必然需要腾空间），
// 固定键（管理员）因此始终能写入，不会被上限拒之门外。
func (s *Store) ensureLoginAttemptCapacityLocked(now time.Time, window, lock time.Duration) {
	if len(s.loginAttempts) < maxLoginAttemptsEntries {
		return
	}
	s.pruneLoginAttemptsLocked(now, window, lock)
	if len(s.loginAttempts) < maxLoginAttemptsEntries {
		return
	}
	s.evictOldestLoginAttemptsLocked(loginAttemptEvictBatch)
}

// evictOldestLoginAttemptsLocked 按最近活跃时间（lastAt/lockedUntil 的较大者）淘汰最旧的
// batch 条记录，保证 map 大小有界。仅在表已达硬上限时调用。
func (s *Store) evictOldestLoginAttemptsLocked(batch int) {
	if batch <= 0 || len(s.loginAttempts) == 0 {
		return
	}
	type attemptAge struct {
		key string
		at  time.Time
	}
	ages := make([]attemptAge, 0, len(s.loginAttempts))
	for key, attempt := range s.loginAttempts {
		var at time.Time
		if attempt != nil {
			at = attempt.lastAt
			if at.IsZero() {
				at = attempt.firstAt
			}
			if !attempt.lockedUntil.IsZero() && attempt.lockedUntil.After(at) {
				at = attempt.lockedUntil
			}
		}
		ages = append(ages, attemptAge{key: key, at: at})
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].at.Before(ages[j].at) })
	if batch > len(ages) {
		batch = len(ages)
	}
	for i := 0; i < batch; i++ {
		delete(s.loginAttempts, ages[i].key)
	}
}

func (s *Store) pruneLoginAttemptsLocked(now time.Time, window, lock time.Duration) {
	if len(s.loginAttempts) == 0 {
		return
	}
	retain := window + lock
	if retain <= 0 {
		retain = 30 * time.Minute
	}
	cutoff := now.Add(-retain)
	for key, attempt := range s.loginAttempts {
		if attempt == nil {
			delete(s.loginAttempts, key)
			continue
		}
		last := attempt.lastAt
		if last.IsZero() {
			last = attempt.firstAt
		}
		if !attempt.lockedUntil.IsZero() && attempt.lockedUntil.After(last) {
			last = attempt.lockedUntil
		}
		if last.Before(cutoff) {
			delete(s.loginAttempts, key)
		}
	}
}

func (s *Store) allowAgentRate(key string, window time.Duration, limit int, now time.Time, useIngestMap bool) bool {
	key = strings.TrimSpace(key)
	if key == "" || window <= 0 || limit <= 0 {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowAgentRateLocked(key, window, limit, now, useIngestMap)
}

func (s *Store) allowAgentRateLocked(key string, window time.Duration, limit int, now time.Time, useIngestMap bool) bool {
	rates := s.agentRegisterRate
	if useIngestMap {
		rates = s.agentIngestRate
	}
	if rates == nil {
		rates = make(map[string]agentRateWindow)
		if useIngestMap {
			s.agentIngestRate = rates
		} else {
			s.agentRegisterRate = rates
		}
	}
	state, exists := rates[key]
	if exists && !state.until.IsZero() && !now.Before(state.until) {
		delete(rates, key)
		exists = false
	}
	if !exists {
		rates[key] = agentRateWindow{count: 1, until: now.Add(window)}
		return true
	}
	if state.count >= limit {
		return false
	}
	state.count++
	rates[key] = state
	return true
}

func (s *Store) sweepExpiredAgentRateWindows(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rates := range []map[string]agentRateWindow{s.agentIngestRate, s.agentRegisterRate} {
		for rateKey, windowState := range rates {
			if !windowState.until.IsZero() && !now.Before(windowState.until) {
				delete(rates, rateKey)
			}
		}
	}
}

func (s *Store) upgradeAdminPasswordHash(password, stored string) {
	hash, err := hashPassword(password)
	if err != nil {
		return
	}
	s.mu.Lock()
	if s.settings.AdminPass != stored {
		s.mu.Unlock()
		return
	}
	s.settings.AdminPass = hash
	s.mu.Unlock()
	s.persistLogged()
}

func redactAISettingsForView(settings AISettings) AISettings {
	settings = cloneAISettings(settings)
	settings.OpenAI.APIKeySet = strings.TrimSpace(settings.OpenAI.APIKey) != ""
	settings.OpenAI.APIKey = ""
	for i := range settings.OpenAICompatibles {
		settings.OpenAICompatibles[i].APIKeySet = strings.TrimSpace(settings.OpenAICompatibles[i].APIKey) != ""
		settings.OpenAICompatibles[i].APIKey = ""
	}
	return settings
}

func (s *Store) PublicSettings() PublicSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return PublicSettings{
		SiteTitle:           s.settings.SiteTitle,
		SiteIcon:            safeSiteIconURL(s.settings.SiteIcon),
		SiteBackgroundImage: safeSiteBackgroundImageURL(s.settings.SiteBackgroundImage),
		HomeTitle:           s.settings.HomeTitle,
		HomeSubtitle:        s.settings.HomeSubtitle,
		Locale:              normalizeLocale(s.settings.Locale),
		RegionGroupEnabled:  !s.settings.RegionGroupDisabled,
	}
}

// ResourceHistoryDays 返回生效中的资源历史保留天数。
func (s *Store) ResourceHistoryDays() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return normalizeResourceHistoryDays(s.settings.ResourceHistoryDays)
}

func (s *Store) settingsViewLocked() SettingsView {
	loginFailLimit := s.settings.LoginFailLimit
	if loginFailLimit < 0 {
		loginFailLimit = 0
	}
	return SettingsView{
		AdminPath:             s.settings.AdminPath,
		AdminUser:             s.settings.AdminUser,
		TurnstileSiteKey:      strings.TrimSpace(s.settings.TurnstileSiteKey),
		TurnstileSecretKey:    "",
		AgentEndpoint:         strings.TrimSpace(s.settings.AgentEndpoint),
		AgentToken:            strings.TrimSpace(s.settings.AgentToken),
		AgentTokenSet:         strings.TrimSpace(s.settings.AgentToken) != "",
		AlertWebhook:          "",
		AlertWebhookSet:       strings.TrimSpace(s.settings.AlertWebhook) != "",
		AlertTelegramToken:    "",
		AlertTelegramTokenSet: strings.TrimSpace(s.settings.AlertTelegramToken) != "",
		SiteTitle:             s.settings.SiteTitle,
		SiteIcon:              safeSiteIconURL(s.settings.SiteIcon),
		SiteBackgroundImage:   safeSiteBackgroundImageURL(s.settings.SiteBackgroundImage),
		HomeTitle:             s.settings.HomeTitle,
		HomeSubtitle:          s.settings.HomeSubtitle,
		Locale:                normalizeLocale(s.settings.Locale),
		RegionGroupEnabled:    boolPointer(!s.settings.RegionGroupDisabled),
		ResourceHistoryDays:   normalizeResourceHistoryDays(s.settings.ResourceHistoryDays),
		AlertOfflineSec:       s.settings.AlertOfflineSec,
		AlertTelegramUserIDs:  slices.Clone(s.settings.AlertTelegramUserIDs),
		NotifyChannels:        notifyChannelsForView(s.settings.NotifyChannels),
		LoginFailLimit:        loginFailLimit,
		LoginFailWindowSec:    s.settings.LoginFailWindowSec,
		LoginLockSec:          s.settings.LoginLockSec,
		AdminAuth:             redactAdminAuthSettings(normalizeAdminAuthSettings(s.settings.AdminAuth)),
		AISettings:            redactAISettingsForView(s.settings.AISettings),
		Version:               s.buildVersion,
		Commit:                s.buildCommit,
		Groups:                slices.Clone(s.settings.Groups),
		GroupTree:             cloneGroupNodes(s.settings.GroupTree),
		TestCatalog:           slices.Clone(s.settings.TestCatalog),
		AlertRules:            cloneAlertRules(s.settings.AlertRules),
		AlertRuleStatus:       s.alertRuleStatusLocked(),
	}
}

// alertRuleStatusLocked 聚合每条规则当前处于 FIRING 的节点数（含 0，
// 供前端「正常 / 告警中 N 台」徽标直接取用）。
func (s *Store) alertRuleStatusLocked() map[string]AlertRuleStatusView {
	status := make(map[string]AlertRuleStatusView, len(s.settings.AlertRules))
	for _, rule := range s.settings.AlertRules {
		status[rule.ID] = AlertRuleStatusView{}
	}
	// B-03：内置 offline 规则由离线引擎（s.alerted）驱动，firing = 处于离线告警
	// 状态的节点数；RecoveryPending 条目处于恢复通知补发阶段，不计入。
	if _, hasOffline := status[offlineAlertRuleID]; hasOffline {
		entry := status[offlineAlertRuleID]
		for _, state := range s.alerted {
			if !state.RecoveryPending {
				entry.Firing++
			}
		}
		status[offlineAlertRuleID] = entry
	}
	for key, state := range s.alertStates {
		if state.State != ruleStateFiring {
			continue
		}
		_, ruleID, ok := parseRuleStateKey(key)
		if !ok {
			continue
		}
		entry, exists := status[ruleID]
		if !exists {
			entry = AlertRuleStatusView{}
			status[ruleID] = entry
		}
		entry.Firing++
		status[ruleID] = entry
	}
	return status
}

func (s *Store) SettingsView() SettingsView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settingsViewLocked()
}

func (s *Store) ExportConfig() ConfigTransferData {
	s.mu.RLock()
	view := redactSettingsViewForExport(s.settingsViewLocked())
	profiles := configTransferProfilesFromNodeProfiles(s.profiles)
	s.mu.RUnlock()
	return ConfigTransferData{
		Version:    configExportVersion,
		ExportedAt: time.Now().Unix(),
		Settings:   view,
		Profiles:   profiles,
	}
}

func redactSettingsViewForExport(view SettingsView) SettingsView {
	view.TurnstileSiteKey = ""
	view.TurnstileSecretKey = ""
	view.AgentToken = ""
	// 推断的对接地址不属用户配置，导出只带用户实际填写的值。
	view.AgentEndpointSuggestion = ""
	view.AlertWebhook = ""
	view.AlertTelegramToken = ""
	view.AlertTelegramUserIDs = nil
	// F5：导出时清空渠道 Secrets（视图本已置空，此处兜底）与 Config 中的
	// chat_ids / to（收件人列表视同敏感信息）。
	view.NotifyChannels = redactNotifyChannelsForExport(view.NotifyChannels)
	view.AdminAuth = redactAdminAuthSettings(view.AdminAuth)
	view.AISettings = redactAISettingsForExport(view.AISettings)
	view.Commit = ""
	view.AgentTokenSet = false
	view.AlertWebhookSet = false
	view.AlertTelegramTokenSet = false
	view.AISettings.OpenAI.APIKeySet = false
	for i := range view.AISettings.OpenAICompatibles {
		view.AISettings.OpenAICompatibles[i].APIKeySet = false
	}
	return view
}

func redactAISettingsForExport(settings AISettings) AISettings {
	settings = cloneAISettings(settings)
	settings.OpenAI.APIKey = ""
	for i := range settings.OpenAICompatibles {
		settings.OpenAICompatibles[i].APIKey = ""
	}
	return settings
}

func refreshAdminSessionCookie(w http.ResponseWriter, r *http.Request, secret string, store *Store, trustedProxyHeaders bool) error {
	if w == nil || store == nil {
		return nil
	}
	creds := store.Credentials()
	if strings.TrimSpace(secret) == "" || strings.TrimSpace(creds.AdminUser) == "" || strings.TrimSpace(creds.TokenSalt) == "" {
		return nil
	}
	token, exp, err := generateToken(secret, creds.AdminUser, creds.TokenSalt)
	if err != nil {
		return err
	}
	setAdminSessionCookie(w, r, token, exp, trustedProxyHeaders)
	return nil
}

func setAdminSessionCookie(w http.ResponseWriter, r *http.Request, token string, exp int64, trustedProxyHeaders bool) {
	if w == nil {
		return
	}
	cookie := &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if exp > 0 {
		cookie.Expires = time.Unix(exp, 0)
	}
	if requestIsSecure(r, trustedProxyHeaders) {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

func clearAdminSessionCookie(w http.ResponseWriter, r *http.Request, trustedProxyHeaders bool) {
	if w == nil {
		return
	}
	cookie := &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		SameSite: http.SameSiteLaxMode,
	}
	if requestIsSecure(r, trustedProxyHeaders) {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

func requestIsSecure(r *http.Request, trustedProxyHeaders bool) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(trustedForwardedHeader(r, trustedProxyHeaders, "X-Forwarded-Proto"), "https")
}

// suggestAgentEndpoint 推断 Agent 对接地址，仅用于展示与生成安装命令：不写回
// agent_endpoint、不导出。推断值必须能通过 validateAgentEndpoint，构造不出合法
// 值就返回空串。
func suggestAgentEndpoint(r *http.Request, splitMode bool, publicAddr string, trustedProxyHeaders bool) string {
	scheme := "http"
	if requestIsSecure(r, trustedProxyHeaders) {
		scheme = "https"
	}
	host := requestExternalHost(r, trustedProxyHeaders)
	if splitMode {
		host = splitModeAgentHost(r, publicAddr, host)
	}
	if host == "" {
		return ""
	}
	candidate := scheme + "://" + host
	if err := validateAgentEndpoint(candidate); err != nil {
		return ""
	}
	return candidate
}

// splitModeAgentHost 用 publicAddr 的明确主机名与端口拼出分端口模式的 Agent 接入
// host：通配地址（空 / 0.0.0.0 / :: / *）退回请求 hostname；publicAddr 解析不出
// 端口时沿用整个请求 host（含其端口）。
func splitModeAgentHost(r *http.Request, publicAddr, requestHost string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(publicAddr))
	if err != nil || strings.TrimSpace(port) == "" {
		return requestHost
	}
	host = strings.TrimSpace(host)
	if host == "" || isWildcardListenHost(host) {
		host = requestHostname(requestHost)
	}
	if host == "" || !validExternalHost(host) {
		return ""
	}
	return net.JoinHostPort(host, port)
}

func isWildcardListenHost(host string) bool {
	switch strings.Trim(host, "[]") {
	case "", "*", "0.0.0.0", "::":
		return true
	}
	return false
}

// requestExternalHost 返回请求的外部 host（含端口）。仅当显式开启
// -trust-proxy-headers 时才采信 X-Forwarded-Host（逗号列表取第一个非空项）。
func requestExternalHost(r *http.Request, trustedProxyHeaders bool) string {
	if r == nil {
		return ""
	}
	if raw := trustedForwardedHeader(r, trustedProxyHeaders, "X-Forwarded-Host"); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !validExternalHost(part) {
				return ""
			}
			return part
		}
	}
	host := strings.TrimSpace(r.Host)
	if host == "" || !validExternalHost(host) {
		return ""
	}
	return host
}

// requestHostname 从已校验的请求 host 里取 hostname（去掉端口与 IPv6 方括号）。
func requestHostname(host string) string {
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}

// validExternalHost 严格校验来自请求头 / r.Host 的 host：拒绝空白、控制字符、
// 引号、反斜杠、路径、userinfo 等。
func validExternalHost(raw string) bool {
	value := strings.TrimSpace(raw)
	if value == "" || value != raw {
		return false
	}
	for _, ch := range value {
		if ch <= ' ' || ch == 0x7f {
			return false
		}
	}
	if strings.ContainsAny(value, "\"'`\\/<>@,;") {
		return false
	}
	// 裸 IPv6 字面量：url.Parse("http://"+value) 会把它当成 host:port 而报错，
	// 这里先用 net.ParseIP 单独放行（拼接时由 net.JoinHostPort 补方括号）。
	if net.ParseIP(value) != nil {
		return true
	}
	parsed, err := url.Parse("http://" + value)
	if err != nil {
		return false
	}
	return parsed.Host == value && parsed.Hostname() != "" && parsed.User == nil && parsed.Path == ""
}

func settingsViewToUpdate(view SettingsView) SettingsUpdate {
	adminPath := strings.TrimSpace(view.AdminPath)
	adminUser := strings.TrimSpace(view.AdminUser)
	agentToken := strings.TrimSpace(view.AgentToken)
	agentEndpoint := strings.TrimSpace(view.AgentEndpoint)
	siteTitle := strings.TrimSpace(view.SiteTitle)
	siteIcon := strings.TrimSpace(view.SiteIcon)
	siteBackgroundImage := strings.TrimSpace(view.SiteBackgroundImage)
	homeTitle := strings.TrimSpace(view.HomeTitle)
	homeSubtitle := strings.TrimSpace(view.HomeSubtitle)
	locale := strings.TrimSpace(view.Locale)
	alertWebhook := strings.TrimSpace(view.AlertWebhook)
	alertTelegramToken := strings.TrimSpace(view.AlertTelegramToken)
	alertTelegramUserIDs := slices.Clone(view.AlertTelegramUserIDs)
	adminAuth := cloneAdminAuthSettings(view.AdminAuth)
	aiSettings := cloneAISettings(view.AISettings)
	groups := slices.Clone(view.Groups)
	groupTree := cloneGroupNodes(view.GroupTree)
	testCatalog := slices.Clone(view.TestCatalog)
	notifyChannels := notifyChannelsFromViewForUpdate(view.NotifyChannels)
	alertRules := cloneAlertRules(view.AlertRules)

	update := SettingsUpdate{
		AdminPath:            stringPointer(adminPath),
		AdminUser:            stringPointer(adminUser),
		TurnstileSiteKey:     stringPointer(strings.TrimSpace(view.TurnstileSiteKey)),
		AgentEndpoint:        stringPointer(agentEndpoint),
		SiteTitle:            stringPointer(siteTitle),
		SiteIcon:             stringPointer(siteIcon),
		SiteBackgroundImage:  stringPointer(siteBackgroundImage),
		HomeTitle:            stringPointer(homeTitle),
		HomeSubtitle:         stringPointer(homeSubtitle),
		Locale:               stringPointer(locale),
		RegionGroupEnabled:   view.RegionGroupEnabled,
		AlertWebhook:         stringPointer(alertWebhook),
		AlertOfflineSec:      int64Pointer(view.AlertOfflineSec),
		AlertTelegramToken:   stringPointer(alertTelegramToken),
		AlertTelegramUserIDs: &alertTelegramUserIDs,
		LoginFailLimit:       intPointer(view.LoginFailLimit),
		LoginFailWindowSec:   int64Pointer(view.LoginFailWindowSec),
		LoginLockSec:         int64Pointer(view.LoginLockSec),
		AdminAuth:            &adminAuth,
		AISettings:           &aiSettings,
		Groups:               &groups,
		GroupTree:            &groupTree,
		TestCatalog:          &testCatalog,
		ResourceHistoryDays:  intPointer(normalizeResourceHistoryDays(view.ResourceHistoryDays)),
	}
	if agentToken != "" {
		update.AgentToken = stringPointer(agentToken)
	}
	if secret := strings.TrimSpace(view.TurnstileSecretKey); secret != "" {
		update.TurnstileSecretKey = stringPointer(secret)
	}
	// F5：只有导出文件确实携带渠道列表时才把 notify_channels 视为权威表示；
	// F5 之前的导出文件没有该字段，此时保持 nil，让旧字段 → 渠道方向的同步
	//（UpdateSettings 内）按旧字段重建迁移渠道，webhook/token 不丢。
	if len(notifyChannels) > 0 {
		update.NotifyChannels = &notifyChannels
	}
	// F4：导出文件确实携带规则列表时才视为权威表示（离线规则不可删除，导入后
	// normalizeAlertRules 会保证其存在；F4 之前的导出文件没有该字段，保持 nil）。
	if len(alertRules) > 0 {
		update.AlertRules = &alertRules
	}
	return update
}

// notifyChannelsFromViewForUpdate 把视图形态的渠道转成更新载荷（丢弃视图专属的
// SecretsSet 标记；Secrets 在视图中本已置空，由 UpdateSettings 按 ID 合并保留）。
func notifyChannelsFromViewForUpdate(channels []NotifyChannel) []NotifyChannel {
	if len(channels) == 0 {
		return nil
	}
	update := cloneNotifyChannels(channels)
	for i := range update {
		update[i].SecretsSet = nil
	}
	return update
}

func (s *Store) AlertWebhook() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.settings.AlertWebhook)
}

func (s *Store) TelegramSettings() (string, []int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.settings.AlertTelegramToken), slices.Clone(s.settings.AlertTelegramUserIDs)
}

// NotifyChannelByID 返回指定 ID 渠道的深拷贝（不存在时返回 nil）。
func (s *Store) NotifyChannelByID(id string) *NotifyChannel {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, channel := range s.settings.NotifyChannels {
		if channel.ID != id {
			continue
		}
		found := cloneNotifyChannel(channel)
		return &found
	}
	return nil
}

// RecordChannelTest 写入指定渠道的测试推送结果（LastTest）。
func (s *Store) RecordChannelTest(id string, result ChannelTestResult) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	s.mu.Lock()
	updated := false
	for i := range s.settings.NotifyChannels {
		if s.settings.NotifyChannels[i].ID != id {
			continue
		}
		s.settings.NotifyChannels[i].LastTest = &result
		updated = true
		break
	}
	s.mu.Unlock()
	if updated {
		s.persistLogged()
	}
}

func (s *Store) SiteTitle() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return normalizeSiteTitle(s.settings.SiteTitle)
}

func (s *Store) UpdateSettings(update SettingsUpdate) (SettingsView, error) {
	var (
		storedAdminPass  string
		newAdminPassHash string
		adminPassChanged bool
	)
	if update.AdminPass != nil {
		pass := strings.TrimSpace(*update.AdminPass)
		if pass == "" {
			return SettingsView{}, errors.New("admin_pass invalid")
		}
		update.AdminPass = &pass
		s.mu.RLock()
		storedAdminPass = s.settings.AdminPass
		s.mu.RUnlock()
		if verifyPassword(pass, storedAdminPass) {
			if !isBcryptHash(storedAdminPass) {
				hash, err := hashPassword(pass)
				if err != nil {
					return SettingsView{}, errors.New("admin_pass hash failed")
				}
				newAdminPassHash = hash
			}
		} else {
			hash, err := hashPassword(pass)
			if err != nil {
				return SettingsView{}, errors.New("admin_pass hash failed")
			}
			newAdminPassHash = hash
			adminPassChanged = true
		}
	}

	var view SettingsView
	s.mu.Lock()
	originalSettings := cloneSettings(s.settings)
	fail := func(err error) (SettingsView, error) {
		s.settings = originalSettings
		s.mu.Unlock()
		return SettingsView{}, err
	}
	if update.AdminPath != nil {
		normalized, err := normalizeAdminPath(*update.AdminPath)
		if err != nil {
			return fail(err)
		}
		s.settings.AdminPath = normalized
	}
	if update.AdminUser != nil {
		user := strings.TrimSpace(*update.AdminUser)
		if user == "" {
			return fail(errors.New("admin_user invalid"))
		}
		if user != s.settings.AdminUser {
			s.settings.AdminUser = user
			tokenSalt, err := randomToken(adminTokenLength)
			if err != nil {
				return fail(err)
			}
			s.settings.TokenSalt = tokenSalt
		}
	}
	if update.AdminPass != nil {
		if s.settings.AdminPass != storedAdminPass {
			return fail(errors.New("admin_pass changed concurrently, please retry"))
		}
		if newAdminPassHash != "" {
			s.settings.AdminPass = newAdminPassHash
		}
		if adminPassChanged {
			tokenSalt, err := randomToken(adminTokenLength)
			if err != nil {
				return fail(err)
			}
			s.settings.TokenSalt = tokenSalt
		}
		s.settings.AdminPassPlain = ""
	}
	if update.AgentToken != nil {
		token := strings.TrimSpace(*update.AgentToken)
		if token == "" {
			return fail(errors.New("agent_token invalid"))
		}
		s.settings.AgentToken = token
	}
	if update.AgentEndpoint != nil {
		value := strings.TrimSpace(*update.AgentEndpoint)
		if err := validateAgentEndpoint(value); err != nil {
			return fail(err)
		}
		s.settings.AgentEndpoint = value
	}
	if update.TurnstileSiteKey != nil {
		siteKey := strings.TrimSpace(*update.TurnstileSiteKey)
		if siteKey != "" &&
			siteKey != strings.TrimSpace(s.settings.TurnstileSiteKey) &&
			update.TurnstileSecretKey == nil &&
			strings.TrimSpace(s.settings.TurnstileSecretKey) != "" {
			return fail(errors.New("更换 turnstile_site_key 时必须同时填写新的 turnstile_secret_key"))
		}
		s.settings.TurnstileSiteKey = siteKey
		if siteKey == "" {
			s.settings.TurnstileSecretKey = ""
		}
	}
	if update.TurnstileSecretKey != nil {
		s.settings.TurnstileSecretKey = strings.TrimSpace(*update.TurnstileSecretKey)
	}
	if (s.settings.TurnstileSiteKey == "") != (s.settings.TurnstileSecretKey == "") {
		return fail(errors.New("turnstile 站点 Key 与 Secret Key 需要同时配置"))
	}
	if update.SiteTitle != nil {
		s.settings.SiteTitle = strings.TrimSpace(*update.SiteTitle)
		if s.settings.SiteTitle == "" {
			s.settings.SiteTitle = defaultSiteTitle
		}
	}
	if update.SiteIcon != nil {
		siteIcon, err := normalizeSiteIconURL(*update.SiteIcon)
		if err != nil {
			return fail(err)
		}
		s.settings.SiteIcon = siteIcon
	}
	if update.SiteBackgroundImage != nil {
		siteBackgroundImage, err := normalizeSiteBackgroundImageURL(*update.SiteBackgroundImage)
		if err != nil {
			return fail(err)
		}
		s.settings.SiteBackgroundImage = siteBackgroundImage
	}
	if update.HomeTitle != nil {
		s.settings.HomeTitle = strings.TrimSpace(*update.HomeTitle)
		if s.settings.HomeTitle == "" {
			s.settings.HomeTitle = defaultHomeTitle
		}
	}
	if update.HomeSubtitle != nil {
		s.settings.HomeSubtitle = strings.TrimSpace(*update.HomeSubtitle)
		if s.settings.HomeSubtitle == "" {
			s.settings.HomeSubtitle = defaultHomeSub
		}
	}
	if update.Locale != nil {
		s.settings.Locale = normalizeLocale(*update.Locale)
	}
	if update.RegionGroupEnabled != nil {
		s.settings.RegionGroupDisabled = !*update.RegionGroupEnabled
	}
	if update.AlertWebhook != nil {
		value := strings.TrimSpace(*update.AlertWebhook)
		if value != "" {
			if err := validateWebhookURL(value); err != nil {
				return fail(err)
			}
		}
		s.settings.AlertWebhook = value
	}
	if update.AlertOfflineSec != nil {
		offlineSec := *update.AlertOfflineSec
		if offlineSec <= 0 {
			offlineSec = defaultAlertOfflineSec
		}
		if offlineSec > maxDurationSettingSec {
			return fail(fmt.Errorf("alert_offline_sec 超过上限 %d 秒", maxDurationSettingSec))
		}
		s.settings.AlertOfflineSec = offlineSec
	}
	// F4：内置 offline 规则的 duration_sec 始终镜像 AlertOfflineSec；本次请求未携带
	// 规则列表时单独同步，携带时由 normalizeAlertRules 一并处理（且不可删除该规则）。
	if update.AlertOfflineSec != nil && update.AlertRules == nil {
		s.settings.AlertRules = syncOfflineAlertRuleDuration(s.settings.AlertRules, s.settings.AlertOfflineSec)
	}
	if update.AlertRules != nil {
		rules, err := normalizeAlertRules(*update.AlertRules, s.settings.AlertOfflineSec)
		if err != nil {
			return fail(err)
		}
		s.settings.AlertRules = rules
	}
	if update.AlertTelegramToken != nil {
		value := strings.TrimSpace(*update.AlertTelegramToken)
		if value != "" {
			if err := validateTelegramToken(value); err != nil {
				return fail(err)
			}
		}
		s.settings.AlertTelegramToken = value
	}
	if update.AlertTelegramUserIDs != nil {
		s.settings.AlertTelegramUserIDs = normalizeTelegramUserIDs(*update.AlertTelegramUserIDs)
	}
	if (s.settings.AlertTelegramToken != "" || len(s.settings.AlertTelegramUserIDs) > 0) &&
		(s.settings.AlertTelegramToken == "" || len(s.settings.AlertTelegramUserIDs) == 0) {
		return fail(errors.New("telegram token 与 telegram 用户 ID 需要同时配置"))
	}
	// F5：旧告警字段 ↔ 通知渠道双向同步。旧字段 → 渠道方向仅在本次请求没有
	// 携带 notify_channels 时执行（携带渠道列表时该列表是权威表示，避免互相覆盖）。
	if update.NotifyChannels == nil {
		if update.AlertWebhook != nil {
			upsertLegacyFeishuChannel(&s.settings, s.settings.AlertWebhook)
		}
		if update.AlertTelegramToken != nil || update.AlertTelegramUserIDs != nil {
			upsertLegacyTelegramChannel(&s.settings, s.settings.AlertTelegramToken, s.settings.AlertTelegramUserIDs)
		}
	}
	// 渠道方向：按 ID 合并（空 secret 保留旧值），规范化后写入；已记录的 LastTest
	// 不随设置保存改动，仅测试推送接口写入。
	if update.NotifyChannels != nil {
		merged := mergeNotifyChannelSecrets(*update.NotifyChannels, s.settings.NotifyChannels)
		merged = preserveChannelLastTest(merged, s.settings.NotifyChannels)
		normalized, err := normalizeNotifyChannels(merged)
		if err != nil {
			return fail(err)
		}
		s.settings.NotifyChannels = normalized
	}
	// 规则引用的渠道必须存在：删除/替换渠道后规则会静默失去投递目标，等于改写
	// 规则语义。只在本次请求涉及任一告警表示时校验（用本次请求生效后的渠道列表），
	// 旧 state.json 可能已带失效引用，不能让无关设置保存失败。
	if update.AlertRules != nil || update.NotifyChannels != nil ||
		update.AlertWebhook != nil || update.AlertTelegramToken != nil ||
		update.AlertTelegramUserIDs != nil {
		if err := validateAlertRuleChannelRefs(s.settings.AlertRules, s.settings.NotifyChannels); err != nil {
			return fail(err)
		}
	}
	// 渠道 → 旧字段：本次请求涉及任一告警表示时回填。Telegram Bot 轮询
	// （TelegramSettings）与旧测试推送回退由此读到第一个启用渠道的取值。
	if update.NotifyChannels != nil || update.AlertWebhook != nil ||
		update.AlertTelegramToken != nil || update.AlertTelegramUserIDs != nil {
		syncLegacyAlertFieldsFromChannels(&s.settings)
	}
	if update.LoginFailLimit != nil {
		limit := *update.LoginFailLimit
		if limit < -1 {
			return fail(errors.New("login_fail_limit invalid"))
		}
		if limit == 0 {
			s.settings.LoginFailLimit = -1
		} else {
			s.settings.LoginFailLimit = limit
		}
	}
	if update.LoginFailWindowSec != nil {
		windowSec := *update.LoginFailWindowSec
		if windowSec < 0 {
			return fail(errors.New("login_fail_window_sec invalid"))
		}
		if windowSec == 0 {
			windowSec = defaultLoginFailWindow
		}
		if windowSec > maxDurationSettingSec {
			return fail(fmt.Errorf("login_fail_window_sec 超过上限 %d 秒", maxDurationSettingSec))
		}
		s.settings.LoginFailWindowSec = windowSec
	}
	if update.LoginLockSec != nil {
		lockSec := *update.LoginLockSec
		if lockSec < 0 {
			return fail(errors.New("login_lock_sec invalid"))
		}
		if lockSec == 0 {
			lockSec = defaultLoginLockSec
		}
		if lockSec > maxDurationSettingSec {
			return fail(fmt.Errorf("login_lock_sec 超过上限 %d 秒", maxDurationSettingSec))
		}
		s.settings.LoginLockSec = lockSec
	}
	if update.AdminAuth != nil {
		normalized := normalizeAdminAuthSettings(*update.AdminAuth)
		normalized = preserveAdminAuthSecrets(normalized, s.settings.AdminAuth)
		if err := validateAdminAuthSettings(normalized); err != nil {
			return fail(err)
		}
		if !adminAuthSettingsEqual(s.settings.AdminAuth, normalized) {
			s.settings.AdminAuth = normalized
			tokenSalt, err := randomToken(adminTokenLength)
			if err != nil {
				return fail(err)
			}
			s.settings.TokenSalt = tokenSalt
		}
	}
	if update.AISettings != nil {
		merged := mergeRedactedAISettings(*update.AISettings, s.settings.AISettings)
		normalized, err := normalizeAISettings(merged)
		if err != nil {
			return fail(err)
		}
		if err := validateAISettings(normalized); err != nil {
			return fail(err)
		}
		s.settings.AISettings = normalized
	}
	// F1：group_moves 必须在写入新树之前执行——先把节点归属从 From 迁到 To，
	// 新树落地后再由 pruneProfileGroupSelectionsLocked 清掉映射到无效目标的条目。
	if update.GroupMoves != nil {
		s.applyProfileGroupMovesLocked(*update.GroupMoves)
	}
	if update.Groups != nil {
		s.settings.Groups = normalizeGroups(*update.Groups)
		if len(s.settings.GroupTree) == 0 {
			s.settings.GroupTree = buildGroupTree(s.settings.Groups)
		}
	}
	if update.GroupTree != nil {
		s.settings.GroupTree = normalizeGroupTree(*update.GroupTree)
		s.settings.Groups = flattenGroupTree(s.settings.GroupTree)
	}
	if update.TestCatalog != nil {
		previousCatalog := slices.Clone(s.settings.TestCatalog)
		catalog, err := normalizeTestCatalog(*update.TestCatalog)
		if err != nil {
			return fail(err)
		}
		s.settings.TestCatalog = catalog
		s.markAgentConfigRefreshForCatalogChangeLocked(previousCatalog, catalog)
		// O-01：任一目录项的 Scope 变化 → 对所有节点标记 agent 配置刷新（范围
		// 会影响没有手动选择的节点，含新接入节点）。
		s.markAgentConfigRefreshForScopeChangeLocked(previousCatalog, catalog)
		s.pruneProfileTestSelectionsLocked()
	}
	if update.Groups != nil || update.GroupTree != nil || update.GroupMoves != nil {
		s.pruneProfileGroupSelectionsLocked()
	}
	if update.ResourceHistoryDays != nil {
		days := *update.ResourceHistoryDays
		if !history.ValidResourceRetentionDays(days) {
			return fail(errors.New("resource_history_days invalid"))
		}
		s.settings.ResourceHistoryDays = days
	}
	// 规则变更后旧样本环语义失效（阈值/操作符可能已改），整体重建。位置必须在
	// 所有校验通过之后：fail() 只回滚 s.settings，样本环一旦提前清空无法回滚，
	// 会让「保存失败、规则实际未变」的全部节点重新预热、漏报一整个窗口。
	if update.AlertRules != nil {
		s.clearRuleSamplesLocked()
	}
	view = s.settingsViewLocked()
	s.mu.Unlock()

	// 落盘失败不做回滚（originalSettings 仅用于锁定期间的校验失败恢复）：mu 已释放，
	// 事后回滚会用旧设置覆盖并发成功提交的新状态，且 pruneProfile*Locked 已改的
	// profiles 无法一并还原，部分回滚只会撕裂状态。内存设置保持已生效，后台
	// persistLogged 防抖会在磁盘恢复后固化；调用方凭 errors.Is(err, errPersistFailed)
	// 区分 500（已生效未落盘）与 400（校验失败），因此这里返回已应用的 view。
	if err := s.persist(); err != nil {
		return view, err
	}
	// 保留天数改动无需重启：立即应用到资源历史存储（巡检也会兜底重填）。
	s.ReconcileResourceHistoryRetention()
	return view, nil
}

func (s *Store) ImportConfig(payload ConfigTransferData) (SettingsView, error) {
	if payload.Version <= 0 {
		return SettingsView{}, errors.New("导入文件版本无效")
	}

	s.agentMutationMu.Lock()
	defer s.agentMutationMu.Unlock()

	s.mu.RLock()
	staged := &Store{
		nodes:    cloneNodeStates(s.nodes),
		profiles: cloneProfiles(s.profiles),
		settings: cloneSettings(s.settings),
	}
	s.mu.RUnlock()

	settings := payload.Settings
	update := settingsViewToUpdate(settings)
	update.AdminUser = nil
	update.AdminPass = nil
	if strings.TrimSpace(settings.TurnstileSecretKey) == "" {
		update.TurnstileSiteKey = nil
		update.TurnstileSecretKey = nil
	}
	if secret := strings.TrimSpace(settings.TurnstileSecretKey); secret != "" {
		update.TurnstileSecretKey = stringPointer(secret)
	}
	preserveRedactedSensitiveSettings(&update, settings, staged.settings)
	if _, err := staged.UpdateSettings(update); err != nil {
		return SettingsView{}, err
	}
	staged.mu.Lock()
	normalizedProfiles, err := staged.normalizeProfilesForImportLocked(configTransferProfilesToNodeProfiles(payload.Profiles))
	staged.mu.Unlock()
	if err != nil {
		return SettingsView{}, err
	}
	preserveRedactedProfileRuntimeForImport(normalizedProfiles, staged.profiles)

	s.mu.Lock()
	now := time.Now()
	previousAgentConfigs := s.agentConfigProjectionsLocked(now)
	s.settings = staged.settings
	// 导入的规则可能与旧规则同 ID 但阈值/持续窗口不同，旧样本的 violated 语义
	// 已失效；与 UpdateSettings 保存规则一致，提交后清空正式 Store 的样本环，
	// 让窗口重新预热，避免用旧样本直接判定告警/恢复。
	s.clearRuleSamplesLocked()
	s.profiles = normalizedProfiles
	s.reconcileAgentConfigRefreshLocked(previousAgentConfigs, now)
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		return SettingsView{}, err
	}
	s.ReconcileResourceHistoryRetention()

	return s.SettingsView(), nil
}

func preserveRedactedProfileRuntimeForImport(profiles map[string]*NodeProfile, existing map[string]*NodeProfile) {
	for nodeID, profile := range profiles {
		if profile == nil {
			continue
		}
		existingProfile := existing[nodeID]
		if existingProfile == nil {
			redactProfileRuntimeForTransfer(profile)
			continue
		}
		profile.AgentAuthToken = strings.TrimSpace(existingProfile.AgentAuthToken)
		profile.AgentUpdate = cloneAgentUpdateInstruction(existingProfile.AgentUpdate)
		profile.AgentUpdateState = strings.TrimSpace(existingProfile.AgentUpdateState)
		profile.AgentUpdateTargetVersion = strings.TrimSpace(existingProfile.AgentUpdateTargetVersion)
		profile.AgentUpdateMessage = strings.TrimSpace(existingProfile.AgentUpdateMessage)
		profile.AgentUpdateLeaseUntil = existingProfile.AgentUpdateLeaseUntil
		profile.AgentUpdateReportedAt = existingProfile.AgentUpdateReportedAt
	}
}

func preserveRedactedSensitiveSettings(update *SettingsUpdate, imported SettingsView, existing Settings) {
	if update == nil {
		return
	}
	if strings.TrimSpace(imported.AgentToken) == "" {
		update.AgentToken = nil
	}
	if strings.TrimSpace(imported.AlertWebhook) == "" {
		update.AlertWebhook = nil
	}
	if strings.TrimSpace(imported.AlertTelegramToken) == "" {
		update.AlertTelegramToken = nil
		update.AlertTelegramUserIDs = nil
	}
	// F5：导出文件中的渠道 Secrets 与 chat_ids / to 均已脱敏为空；为空时按 ID
	// 沿用现有配置，避免导入清掉收件人与密钥。
	if update.NotifyChannels != nil {
		preserved := preserveRedactedNotifyChannels(*update.NotifyChannels, existing.NotifyChannels)
		update.NotifyChannels = &preserved
	}
	if update.AdminAuth != nil {
		merged := preserveAdminAuthSecrets(*update.AdminAuth, existing.AdminAuth)
		update.AdminAuth = &merged
	}
	if update.AISettings != nil {
		merged := mergeRedactedAISettings(*update.AISettings, existing.AISettings)
		update.AISettings = &merged
	}
}

func mergeRedactedAISettings(imported, existing AISettings) AISettings {
	imported = cloneAISettings(imported)
	existing = cloneAISettings(existing)
	imported.OpenAI.APIKey = preserveRedactedString(imported.OpenAI.APIKey, existing.OpenAI.APIKey)

	existingCompatibles := make(map[string]AIProviderProfile, len(existing.OpenAICompatibles))
	for _, item := range existing.OpenAICompatibles {
		id := strings.TrimSpace(item.ID)
		if id != "" {
			existingCompatibles[id] = item
		}
	}
	for i := range imported.OpenAICompatibles {
		id := strings.TrimSpace(imported.OpenAICompatibles[i].ID)
		if existingItem, ok := existingCompatibles[id]; ok {
			imported.OpenAICompatibles[i].APIKey = preserveRedactedString(imported.OpenAICompatibles[i].APIKey, existingItem.APIKey)
		}
	}
	return imported
}

func preserveRedactedString(imported, existing string) string {
	if strings.TrimSpace(imported) == "" {
		return strings.TrimSpace(existing)
	}
	return imported
}

func normalizePersistedProfiles(settings Settings, nodes map[string]NodeState, profiles map[string]*NodeProfile) (map[string]*NodeProfile, error) {
	store := &Store{
		settings: cloneSettings(settings),
		nodes:    nodes,
	}
	return store.normalizeProfilesForImportLocked(profiles)
}

func (s *Store) normalizeProfilesForImportLocked(profiles map[string]*NodeProfile) (map[string]*NodeProfile, error) {
	if profiles == nil {
		return map[string]*NodeProfile{}, nil
	}

	now := time.Now().Unix()
	groupNames, tagKeys, treeMode := groupSelectionSets(s.settings)
	normalized := make(map[string]*NodeProfile, len(profiles))
	for rawNodeID, rawProfile := range profiles {
		nodeID, err := history.NormalizeNodeID(rawNodeID)
		if err != nil {
			return nil, fmt.Errorf("profiles 节点 ID invalid node id: %w", err)
		}
		if nodeID == "" {
			return nil, errors.New("profiles 节点 ID 不能为空")
		}
		if _, exists := normalized[nodeID]; exists {
			return nil, fmt.Errorf("profiles 节点 ID 重复: %s", nodeID)
		}

		profile := &NodeProfile{}
		if rawProfile != nil {
			*profile = *rawProfile
		}

		profile.HideFromDisplay = false
		profile.Alias = strings.TrimSpace(profile.Alias)
		profile.Group = strings.TrimSpace(profile.Group)
		profile.Tags = normalizeGroups(profile.Tags)
		profile.Groups = normalizeGroupSelections(profile.Groups)
		if len(profile.Groups) == 0 && (profile.Group != "" || len(profile.Tags) > 0) {
			profile.Groups = selectionsFromGroupTags(profile.Group, profile.Tags)
		}
		profile.Groups = filterGroupSelections(profile.Groups, groupNames, tagKeys, treeMode)
		if len(profile.Groups) > 0 {
			group, tags := primaryGroupTagsFromSelections(profile.Groups)
			profile.Group = group
			profile.Tags = tags
		} else {
			profile.Group = ""
			profile.Tags = nil
		}
		profile.Region = strings.ToUpper(strings.TrimSpace(profile.Region))
		profile.DiskType = strings.TrimSpace(profile.DiskType)
		if profile.NetSpeedMbps < 0 {
			profile.NetSpeedMbps = 0
		}
		if profile.ExpireAt < 0 {
			profile.ExpireAt = 0
		}
		if profile.RenewIntervalSec < 0 {
			profile.RenewIntervalSec = 0
		}
		if profile.TestIntervalSec <= 0 {
			profile.TestIntervalSec = defaultTestIntervalSec
		}
		profile.TestSelections = s.normalizeSelectionsLocked(slices.Clone(profile.TestSelections))
		if profile.AlertEnabled == nil {
			profile.AlertEnabled = boolPointer(true)
		} else {
			value := *profile.AlertEnabled
			profile.AlertEnabled = &value
		}
		if profile.UpdatedAt <= 0 {
			profile.UpdatedAt = now
		}
		normalized[nodeID] = profile
	}
	if err := ensureServerIDsForProfiles(normalized, s.nodes); err != nil {
		return nil, err
	}
	return normalized, nil
}

func (s *Store) ensureProfileLocked(nodeID string) *NodeProfile {
	profile := s.profiles[nodeID]
	if profile == nil {
		profile = &NodeProfile{TestIntervalSec: defaultTestIntervalSec}
		s.profiles[nodeID] = profile
	}
	if profile.AlertEnabled == nil {
		profile.AlertEnabled = boolPointer(true)
	}
	if len(profile.Groups) == 0 {
		if profile.Group != "" || len(profile.Tags) > 0 {
			profile.Groups = selectionsFromGroupTags(profile.Group, profile.Tags)
		}
	}
	if len(profile.Groups) > 0 && profile.Group == "" && len(profile.Tags) == 0 {
		legacy := normalizeGroups(profile.Groups)
		if len(legacy) > 0 {
			profile.Groups = selectionsFromGroupTags(legacy[0], legacy[1:])
		}
	}
	if len(profile.Groups) > 0 {
		profile.Groups = normalizeGroupSelections(profile.Groups)
		group, tags := primaryGroupTagsFromSelections(profile.Groups)
		if group != "" {
			profile.Group = group
		}
		profile.Tags = tags
	}
	return profile
}

func (s *Store) registerAgentAuthToken(nodeID, bootstrapToken string, now time.Time) (string, *agentAPIError) {
	changed := false
	nodeID = strings.TrimSpace(nodeID)
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	expectedBootstrapToken := strings.TrimSpace(s.settings.AgentToken)
	// 先校验 bootstrap token，再消费全局配额：isBootstrapAgentToken 是
	// subtle.ConstantTimeCompare 的常数时间比较，无 I/O、无锁外开销，不构成新的
	// 放大面。反过来（先扣配额）会让未认证的 /api/v1/agent/register 用非法 token
	// 在 30 次/分钟内刷满 register:* 全局配额，使合法新节点持续拿到 429 卡在
	// waiting_registration。
	if expectedBootstrapToken != "" && !isBootstrapAgentToken(expectedBootstrapToken, bootstrapToken) {
		// 但非法 token 也不能完全免于限流：运维可能通过 settings 配置较短的
		// AgentToken，若不节流，未认证方可对公网注册接口无限制地暴破。这里用
		// 独立的全局失败计数 register-invalid:* 约束猜测速率——它只被非法 token
		// 消耗，不影响 register:*，所以合法新节点仍不会被刷 429。bootstrap token
		// 是服务端唯一的，按 nodeID 分桶会被攻击者轮换 nodeID 绕过，因此必须
		// 全局计数（HTTP 与 gRPC 两条注册路径在此汇聚）。
		allowed := s.allowAgentRateLocked("register-invalid:*", agentRegisterWindow, defaultAgentRegisterInvalidLimit, now, false)
		s.mu.Unlock()
		if !allowed {
			return "", agentRateLimitError()
		}
		return "", invalidBootstrapTokenError()
	}
	// 开放注册模式（未配置 AgentToken）token 门禁对所有人放行，此时全局配额是唯一
	// 的准入前限流，必须继续消费；合法 token 之后的全部流程（含已存在节点的 token
	// 补发分支与签发分支）同样由这里拦截。
	if !s.allowAgentRateLocked("register:*", agentRegisterWindow, defaultAgentRegisterGlobalLimit, now, false) {
		s.mu.Unlock()
		return "", agentRateLimitError()
	}
	if profile := s.profiles[nodeID]; profile != nil {
		token := strings.TrimSpace(profile.AgentAuthToken)
		if token != "" && !s.isAgentAuthTokenDuplicateLocked(nodeID, token) {
			s.mu.Unlock()
			// 上次签发可能已落盘失败（token 留在内存、persistPending 置位）：重试
			// 命中本分支时必须补一次落盘，否则直接返回成功会让磁盘永远缺这个
			// token，重启后该 Agent 凭据失效；仍失败则继续 503 让 Agent 稍后再试。
			if s.hasPersistPending() {
				if err := s.persist(); err != nil {
					return "", agentServiceUnavailable("persist failed, retry later")
				}
			}
			return token, nil
		}
	}
	if !s.allowAgentRateLocked("register:"+nodeID, agentRegisterWindow, defaultAgentRegisterLimit, now, false) {
		s.mu.Unlock()
		return "", agentRateLimitError()
	}
	previousProfile, hadProfile := s.profiles[nodeID]
	var previousProfileSnapshot NodeProfile
	if previousProfile != nil {
		previousProfileSnapshot = cloneNodeProfileValue(previousProfile)
	}
	rollbackProfile := func() {
		if !hadProfile {
			delete(s.profiles, nodeID)
			return
		}
		if previousProfile == nil {
			s.profiles[nodeID] = nil
			return
		}
		restoredProfile := previousProfileSnapshot
		s.profiles[nodeID] = &restoredProfile
	}
	profile := s.ensureProfileLocked(nodeID)
	if strings.TrimSpace(profile.AgentAuthToken) == "" || s.isAgentAuthTokenDuplicateLocked(nodeID, profile.AgentAuthToken) {
		token, err := s.generateAgentAuthTokenLocked()
		if err != nil {
			log.Printf("生成 Agent 凭据失败: %v", err)
			rollbackProfile()
			s.mu.Unlock()
			return "", agentServiceUnavailable("生成节点凭据失败")
		}
		profile.AgentAuthToken = token
		profile.UpdatedAt = time.Now().Unix()
		changed = true
	}
	token := strings.TrimSpace(profile.AgentAuthToken)
	s.mu.Unlock()
	if changed {
		if err := s.persist(); err != nil {
			return "", &agentAPIError{statusCode: http.StatusServiceUnavailable, message: "persist failed, retry later"}
		}
	}
	return token, nil
}

func (s *Store) validateAgentAuthToken(nodeID, token string) bool {
	nodeID = strings.TrimSpace(nodeID)
	token = strings.TrimSpace(token)
	if nodeID == "" || token == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	profile := s.profiles[nodeID]
	if profile == nil {
		return false
	}
	expected := strings.TrimSpace(profile.AgentAuthToken)
	// Token 唯一性由写路径保证（registerAgentAuthToken 签发前查重，配置导入不携带
	// token），读路径不做全表重复扫描——每次 ingest 都扫全 profiles 会把上报周期变成 O(n²)。
	return expected != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}

func isBootstrapAgentToken(expected, token string) bool {
	expected = strings.TrimSpace(expected)
	token = strings.TrimSpace(token)
	if expected == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}

func (s *Store) generateAgentAuthTokenLocked() (string, error) {
	for {
		token, err := randomToken(40)
		if err != nil {
			return "", err
		}
		if !s.isAgentAuthTokenUsedLocked(token) {
			return token, nil
		}
	}
}

func (s *Store) isAgentAuthTokenUsedLocked(token string) bool {
	if token == "" {
		return true
	}
	for _, profile := range s.profiles {
		if profile != nil && strings.TrimSpace(profile.AgentAuthToken) == token {
			return true
		}
	}
	return false
}

func (s *Store) isAgentAuthTokenDuplicateLocked(nodeID, token string) bool {
	if strings.TrimSpace(token) == "" {
		return false
	}
	for key, profile := range s.profiles {
		if key == nodeID || profile == nil {
			continue
		}
		if strings.TrimSpace(profile.AgentAuthToken) == strings.TrimSpace(token) {
			return true
		}
	}
	return false
}

func (s *Store) generateServerIDLocked() (string, error) {
	for {
		id, err := randomToken(10)
		if err != nil {
			return "", err
		}
		if !s.isServerIDUsedLocked(id) {
			return id, nil
		}
	}
}

func (s *Store) isServerIDUsedLocked(id string) bool {
	if id == "" {
		return true
	}
	for _, profile := range s.profiles {
		if profile != nil && strings.TrimSpace(profile.ServerID) == id {
			return true
		}
	}
	return false
}

func ensureServerIDsForProfiles(profiles map[string]*NodeProfile, nodes map[string]NodeState) error {
	if profiles == nil {
		return nil
	}
	for nodeID := range nodes {
		if profiles[nodeID] == nil {
			profiles[nodeID] = &NodeProfile{TestIntervalSec: defaultTestIntervalSec}
		}
	}
	used := make(map[string]struct{})
	for nodeID, profile := range profiles {
		if profile == nil {
			profile = &NodeProfile{TestIntervalSec: defaultTestIntervalSec}
			profiles[nodeID] = profile
		}
		if profile.AlertEnabled == nil {
			profile.AlertEnabled = boolPointer(true)
		}
		id := strings.TrimSpace(profile.ServerID)
		if _, exists := used[id]; id == "" || exists {
			generatedID, err := randomToken(10)
			if err != nil {
				return err
			}
			id = generatedID
			for _, exists := used[id]; exists; _, exists = used[id] {
				generatedID, err := randomToken(10)
				if err != nil {
					return err
				}
				id = generatedID
			}
			profile.ServerID = id
		}
		used[id] = struct{}{}
	}
	return nil
}

func (s *Store) UpdateProfile(nodeID string, update NodeProfileUpdate) (NodeProfile, bool, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return NodeProfile{}, false, nil
	}
	unlock := s.lockAgentNodeRead(nodeID)
	defer unlock()

	s.mu.Lock()
	if _, nodeExists := s.nodes[nodeID]; !nodeExists {
		if _, profileExists := s.profiles[nodeID]; !profileExists {
			s.mu.Unlock()
			return NodeProfile{}, false, nil
		}
	}

	profile := s.ensureProfileLocked(nodeID)
	configChanged := false
	if update.Alias != nil {
		profile.Alias = cleanAdminProfileText(*update.Alias, 120)
		configChanged = true
	}
	if update.Group != nil {
		profile.Group = cleanAdminProfileText(*update.Group, 120)
		configChanged = true
	}
	if update.Tags != nil {
		profile.Tags = normalizeGroups(*update.Tags)
		configChanged = true
	}
	if update.Groups != nil {
		profile.Groups = normalizeGroupSelections(*update.Groups)
		group, tags := primaryGroupTagsFromSelections(profile.Groups)
		profile.Group = group
		profile.Tags = tags
		configChanged = true
	}
	if update.Groups == nil && (update.Group != nil || update.Tags != nil) {
		profile.Groups = selectionsFromGroupTags(profile.Group, profile.Tags)
	} else if update.Groups == nil && len(profile.Groups) > 0 {
		profile.Groups = normalizeGroupSelections(profile.Groups)
	}
	if update.Group != nil || update.Tags != nil || update.Groups != nil {

		profile.GroupSeeded = true
	}
	if update.Region != nil {
		profile.Region, _ = normalizeRegionCode(*update.Region)
	}
	if update.DiskType != nil {
		profile.DiskType = strings.TrimSpace(*update.DiskType)
	}
	if update.NetSpeedMbps != nil {
		value := *update.NetSpeedMbps
		if value < 0 {
			value = 0
		}
		profile.NetSpeedMbps = value
	}
	if update.HideFromCR != nil || update.HideFromAll != nil {
		if update.HideFromCR != nil {
			profile.HideFromCR = *update.HideFromCR
		}
		if update.HideFromAll != nil {
			profile.HideFromAll = *update.HideFromAll
		}

		profile.HideFromDisplay = update.HideFromDisplay != nil && *update.HideFromDisplay
	} else if update.HideFromDisplay != nil {
		profile.HideFromCR = *update.HideFromDisplay
		profile.HideFromAll = *update.HideFromDisplay
		profile.HideFromDisplay = *update.HideFromDisplay
	}
	if update.AutoRenew != nil {
		profile.AutoRenew = *update.AutoRenew
		if profile.AutoRenew && profile.ExpireAt > 0 && profile.RenewIntervalSec <= 0 {
			renew := profile.ExpireAt - time.Now().Unix()
			if renew > 0 {
				profile.RenewIntervalSec = renew
			}
		}
	}
	if update.ExpireAt != nil {
		expireAt := *update.ExpireAt
		if expireAt < 0 {
			expireAt = 0
		}
		profile.ExpireAt = expireAt
		if profile.AutoRenew && expireAt > 0 {
			if update.RenewIntervalSec != nil && *update.RenewIntervalSec > 0 {
				profile.RenewIntervalSec = *update.RenewIntervalSec
			} else {
				renew := expireAt - time.Now().Unix()
				if renew > 0 {
					profile.RenewIntervalSec = renew
				}
			}
		}
	}
	if update.RenewIntervalSec != nil && *update.RenewIntervalSec > 0 {
		profile.RenewIntervalSec = *update.RenewIntervalSec
	}
	// F4：流量配额配置（校验在 handler 完成：limit_type ∈ sum|max|up|down，
	// reset_day ∈ 1–28 或 0 表示清空恢复默认）。
	if update.TrafficLimitBytes != nil {
		profile.TrafficLimitBytes = *update.TrafficLimitBytes
	}
	if update.TrafficLimitType != nil {
		limitType := strings.TrimSpace(*update.TrafficLimitType)
		if limitType == "" {
			profile.TrafficLimitType = ""
		} else {
			profile.TrafficLimitType = normalizeTrafficLimitType(limitType)
		}
	}
	if update.TrafficResetDay != nil {
		resetDay := *update.TrafficResetDay
		if resetDay == 0 {
			profile.TrafficResetDay = 0
		} else {
			profile.TrafficResetDay = normalizeTrafficResetDay(resetDay)
		}
	}
	if update.TestIntervalSec != nil && *update.TestIntervalSec > 0 {
		profile.TestIntervalSec = *update.TestIntervalSec
		configChanged = true
	}
	if update.TestSelections != nil {
		profile.TestSelections = s.normalizeSelectionsLocked(*update.TestSelections)
		configChanged = true
	}
	if update.AlertEnabled != nil {
		value := *update.AlertEnabled
		profile.AlertEnabled = &value
	}
	if configChanged {
		s.markAgentConfigRefreshLocked(nodeID)
	}
	profile.UpdatedAt = time.Now().Unix()
	result := cloneNodeProfileValue(profile)
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		return result, true, err
	}
	return result, true, nil
}

func (s *Store) UpdateAlertEnabledByServerID(serverID string, enabled bool) (string, string, bool, error) {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return "", "", false, nil
	}
	var nodeID string
	var display string
	s.mu.RLock()
	for id, profile := range s.profiles {
		if profile == nil {
			continue
		}
		if strings.TrimSpace(profile.ServerID) != serverID {
			continue
		}
		nodeID = id
		break
	}
	s.mu.RUnlock()
	if nodeID == "" {
		return "", "", false, nil
	}

	unlock := s.lockAgentNodeRead(nodeID)
	defer unlock()

	s.mu.Lock()
	profile := s.profiles[nodeID]
	if profile == nil || strings.TrimSpace(profile.ServerID) != serverID {
		s.mu.Unlock()
		return "", "", false, nil
	}
	profile = s.ensureProfileLocked(nodeID)
	value := enabled
	profile.AlertEnabled = &value
	if !enabled {
		delete(s.alerted, nodeID)
	}
	if node, ok := s.nodes[nodeID]; ok {
		display = resolveAlertDisplay(profile, node.Stats, nodeID)
	} else {
		display = resolveAlertDisplay(profile, metrics.NodeStats{}, nodeID)
	}
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		return nodeID, display, true, err
	}
	return nodeID, display, true, nil
}

func (s *Store) lockAgentNodeRead(nodeID string) func() {
	s.agentMutationMu.RLock()
	nodeID = strings.TrimSpace(nodeID)
	lock := s.acquireNodeMutationLock(nodeID)
	lock.mu.RLock()
	return func() {
		lock.mu.RUnlock()
		s.releaseNodeMutationLock(nodeID, lock)
		s.agentMutationMu.RUnlock()
	}
}

func (s *Store) lockAgentNodeMutation(nodeID string) func() {
	s.agentMutationMu.RLock()
	nodeID = strings.TrimSpace(nodeID)
	lock := s.acquireNodeMutationLock(nodeID)
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		s.releaseNodeMutationLock(nodeID, lock)
		s.agentMutationMu.RUnlock()
	}
}

func (s *Store) acquireNodeMutationLock(nodeID string) *nodeMutationLock {
	s.nodeMutationMu.Lock()
	defer s.nodeMutationMu.Unlock()
	if s.nodeMutationLocks == nil {
		s.nodeMutationLocks = make(map[string]*nodeMutationLock)
	}
	lock := s.nodeMutationLocks[nodeID]
	if lock == nil {
		lock = &nodeMutationLock{}
		s.nodeMutationLocks[nodeID] = lock
	}
	lock.refs++
	return lock
}

func (s *Store) releaseNodeMutationLock(nodeID string, lock *nodeMutationLock) {
	s.nodeMutationMu.Lock()
	defer s.nodeMutationMu.Unlock()
	if s.nodeMutationLocks[nodeID] != lock {
		return
	}
	lock.refs--
	if lock.refs <= 0 {
		delete(s.nodeMutationLocks, nodeID)
	}
}

func (s *Store) DeleteNode(nodeID string) (bool, error) {
	var err error
	nodeID, err = history.NormalizeNodeID(nodeID)
	if err != nil {
		return false, err
	}
	if nodeID == "" {
		return false, nil
	}
	unlock := s.lockAgentNodeMutation(nodeID)
	defer unlock()

	s.mu.RLock()
	_, nodeExists := s.nodes[nodeID]
	_, profileExists := s.profiles[nodeID]
	_, hadPendingDelete := s.pendingNodeDeletes[nodeID]
	historyManager := s.historyManager
	s.mu.RUnlock()
	hasBusinessState := nodeExists || profileExists
	shouldPersist := s.dataPath != ""
	if !nodeExists && !profileExists {
		if historyManager == nil {
			if hadPendingDelete {
				if shouldPersist {
					s.rollbackNodeDeleteIntent(nodeID)
				} else {
					s.mu.Lock()
					s.unmarkPendingNodeDeleteLocked(nodeID)
					s.mu.Unlock()
				}
				return true, nil
			}
			return false, nil
		}
		hasHistory, err := historyManager.HasNodeHistory(nodeID)
		if err != nil {
			log.Printf("查询节点 TSDB 历史失败 node=%s: %v", nodeID, err)
			return true, err
		}
		if !hasHistory {
			if hadPendingDelete {
				if shouldPersist {
					s.rollbackNodeDeleteIntent(nodeID)
				} else {
					s.mu.Lock()
					s.unmarkPendingNodeDeleteLocked(nodeID)
					s.mu.Unlock()
				}
				return true, nil
			}
			return false, nil
		}
	}

	if shouldPersist {
		if err := s.persistNodeDeleteIntent(nodeID); err != nil {
			return true, err
		}
	}

	var historyCleanupErr error
	if historyManager != nil {
		if err := historyManager.DeleteNode(nodeID); err != nil {
			log.Printf("删除节点 TSDB 历史失败 node=%s: %v", nodeID, err)
			if shouldPersist && !hasBusinessState && !hadPendingDelete {
				s.rollbackNodeDeleteIntent(nodeID)
			}
			if !hasBusinessState {
				return true, err
			}
			historyCleanupErr = err
		}
	}

	s.mu.Lock()
	s.deleteNodeMemoryLocked(nodeID)
	if historyCleanupErr == nil {
		s.unmarkPendingNodeDeleteLocked(nodeID)
	}
	s.mu.Unlock()
	if shouldPersist {
		if err := s.persist(); err != nil {
			return false, err
		}
	}
	if historyCleanupErr != nil {
		return true, newNodeDeleteHistoryCleanupError(historyCleanupErr)
	}
	return true, nil
}

type historyCleanupError struct {
	op  string
	err error
}

func newNodeDeleteHistoryCleanupError(err error) *historyCleanupError {
	return &historyCleanupError{op: "删除节点成功", err: err}
}

func newClearNodesHistoryCleanupError(err error) *historyCleanupError {
	return &historyCleanupError{op: "清空节点成功", err: err}
}

func (e *historyCleanupError) Error() string {
	return e.op + "，" + e.HistoryError()
}

func (e *historyCleanupError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (e *historyCleanupError) HistoryError() string {
	if e == nil || e.err == nil {
		return "历史数据清理失败"
	}
	return fmt.Sprintf("历史数据清理失败: %v", e.err)
}

func (s *Store) ClearNodes() error {
	s.agentMutationMu.Lock()
	defer s.agentMutationMu.Unlock()

	s.mu.RLock()
	historyManager := s.historyManager
	s.mu.RUnlock()

	shouldPersist := s.dataPath != ""
	if shouldPersist {
		if err := s.persistClearNodesIntent(); err != nil {
			return err
		}
	}

	var historyCleanupErr error
	if historyManager != nil {
		if err := historyManager.ClearNodes(); err != nil {
			log.Printf("清空节点 TSDB 历史失败: %v", err)
			historyCleanupErr = err
		}
	}

	s.mu.Lock()
	s.clearNodesMemoryLocked()
	if historyCleanupErr == nil {
		s.pendingClearNodes = false
	}
	s.pendingNodeDeletes = nil
	s.mu.Unlock()
	if shouldPersist {
		if err := s.persist(); err != nil {
			return err
		}
	}
	if historyCleanupErr != nil {
		return newClearNodesHistoryCleanupError(historyCleanupErr)
	}
	return nil
}

func replayPendingHistoryCleanupWithIntentMode(dataPath string, historyManager *history.Manager, payload PersistedData, clearIntent bool) (PersistedData, error) {
	if !payload.PendingHistoryClear && len(payload.PendingHistoryDeletes) == 0 {
		return payload, nil
	}
	if historyManager == nil {
		return payload, errors.New("history manager required for pending cleanup")
	}
	if payload.PendingHistoryClear {
		if err := historyManager.ClearNodes(); err != nil {
			return payload, err
		}
	} else {
		for _, nodeID := range payload.PendingHistoryDeletes {
			if err := historyManager.DeleteNode(nodeID); err != nil {
				return payload, err
			}
		}
	}
	if clearIntent {
		payload.PendingHistoryClear = false
		payload.PendingHistoryDeletes = nil
		if dataPath != "" {
			if err := savePersistedData(dataPath, payload); err != nil {
				return payload, err
			}
		}
	}
	return payload, nil
}

func recoverLegacyHistoryAndPendingCleanup(
	dataPath string,
	historyPath string,
	historyManager *history.Manager,
	payload PersistedData,
) (PersistedData, error) {
	legacyMigrationComplete := true
	if migration, err := history.MigrateLegacyJSONIfNeeded(historyPath, historyManager.NetworkStore(), time.Now()); err != nil {
		legacyMigrationComplete = false
		log.Printf("%v", wrapDataPathError("迁移探测历史失败", historyPath, err))
	} else if migration.LegacyFound {
		legacyMigrationComplete = false
		if migration.SourcePath == historyPath {
			if err := os.Remove(historyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Printf("%v", wrapDataPathError("清理 legacy 探测历史失败", historyPath, err))
			}
		}
		if err := history.MarkLegacyMigrationComplete(historyPath, time.Now()); err != nil {
			log.Printf("%v", wrapDataPathError("写入 legacy 迁移标记失败", migration.MarkerPath, err))
		} else {
			legacyMigrationComplete = true
			log.Printf("已将 legacy 探测历史迁移到 TSDB：%s", migration.SourcePath)
		}
	}
	replayed, err := replayPendingHistoryCleanupWithIntentMode(dataPath, historyManager, payload, legacyMigrationComplete)
	if err != nil {
		return payload, err
	}
	return replayed, nil
}

func (s *Store) persistNodeDeleteIntent(nodeID string) error {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	s.mu.Lock()
	s.markPendingNodeDeleteLocked(nodeID)
	snapshot := s.snapshotPersistedLocked()
	s.mu.Unlock()
	if err := s.writePersistedSnapshotLocked(snapshot); err != nil {
		s.mu.Lock()
		s.unmarkPendingNodeDeleteLocked(nodeID)
		s.mu.Unlock()
		log.Printf("%v", err)
		return err
	}
	return nil
}

func (s *Store) rollbackNodeDeleteIntent(nodeID string) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	s.mu.Lock()
	s.unmarkPendingNodeDeleteLocked(nodeID)
	snapshot := s.snapshotPersistedLocked()
	s.mu.Unlock()
	if persistErr := s.writePersistedSnapshotLocked(snapshot); persistErr != nil {
		log.Printf("%v", persistErr)
	}
}

func (s *Store) persistClearNodesIntent() error {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	s.mu.Lock()
	s.pendingClearNodes = true
	snapshot := s.snapshotPersistedLocked()
	s.mu.Unlock()
	if err := s.writePersistedSnapshotLocked(snapshot); err != nil {
		s.mu.Lock()
		s.pendingClearNodes = false
		s.mu.Unlock()
		log.Printf("%v", err)
		return err
	}
	return nil
}

func (s *Store) markPendingNodeDeleteLocked(nodeID string) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	if s.pendingNodeDeletes == nil {
		s.pendingNodeDeletes = make(map[string]struct{})
	}
	s.pendingNodeDeletes[nodeID] = struct{}{}
}

func (s *Store) unmarkPendingNodeDeleteLocked(nodeID string) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || s.pendingNodeDeletes == nil {
		return
	}
	delete(s.pendingNodeDeletes, nodeID)
	if len(s.pendingNodeDeletes) == 0 {
		s.pendingNodeDeletes = nil
	}
}

func (s *Store) deleteNodeMemoryLocked(nodeID string) {
	delete(s.nodes, nodeID)
	delete(s.profiles, nodeID)
	delete(s.alerted, nodeID)
	delete(s.offlineSessions, nodeID)
	delete(s.configRefresh, nodeID)
}

func (s *Store) clearNodesMemoryLocked() {
	s.nodes = make(map[string]NodeState)
	s.profiles = make(map[string]*NodeProfile)
	s.alerted = make(map[string]AlertedState)
	s.offlineSessions = make(map[string]OfflineSessionState)
	s.configRefresh = make(map[string]struct{})
}

type AgentUpdateReport struct {
	State   string `json:"state"`
	ID      string `json:"update_id,omitempty"`
	Version string `json:"version,omitempty"`
	Message string `json:"message,omitempty"`
}

type agentUpdateQueueStatus string

const (
	agentUpdateQueueNotFound agentUpdateQueueStatus = "not_found"
	agentUpdateQueueActive   agentUpdateQueueStatus = "active"
	agentUpdateQueueQueued   agentUpdateQueueStatus = "queued"
)

func (s *Store) QueueAgentUpdate(nodeID string, instruction AgentUpdateInstruction) (NodeProfile, agentUpdateQueueStatus, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return NodeProfile{}, agentUpdateQueueNotFound, nil
	}
	unlock := s.lockAgentNodeRead(nodeID)
	defer unlock()

	s.mu.Lock()
	if _, nodeExists := s.nodes[nodeID]; !nodeExists {
		if _, profileExists := s.profiles[nodeID]; !profileExists {
			s.mu.Unlock()
			return NodeProfile{}, agentUpdateQueueNotFound, nil
		}
	}

	profile := s.ensureProfileLocked(nodeID)
	if profile.AgentUpdate != nil && !isAgentUpdateTerminalState(profile.AgentUpdateState) {
		result := cloneNodeProfileValue(profile)
		s.mu.Unlock()
		return result, agentUpdateQueueActive, nil
	}
	instruction.Version = strings.TrimSpace(instruction.Version)
	instruction.DownloadURL = strings.TrimSpace(instruction.DownloadURL)
	instruction.ChecksumURL = strings.TrimSpace(instruction.ChecksumURL)
	instruction.ID = strings.TrimSpace(instruction.ID)
	if instruction.ID == "" {
		updateID, err := newAgentUpdateID()
		if err != nil {
			s.mu.Unlock()
			return NodeProfile{}, "", fmt.Errorf("生成 Agent 更新任务 ID 失败: %w", err)
		}
		instruction.ID = updateID
	}
	instruction.RequestedAt = time.Now().Unix()
	applyQueuedAgentUpdate(profile, instruction)
	s.markAgentConfigRefreshLocked(nodeID)
	result := cloneNodeProfileValue(profile)
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		return result, agentUpdateQueueQueued, err
	}
	return result, agentUpdateQueueQueued, nil
}

func (s *Store) applyAgentUpdateReportNodeLocked(nodeID string, report AgentUpdateReport) (NodeProfile, bool, error) {
	s.mu.Lock()
	if _, nodeExists := s.nodes[nodeID]; !nodeExists {
		if _, profileExists := s.profiles[nodeID]; !profileExists {
			s.mu.Unlock()
			return NodeProfile{}, false, nil
		}
	}
	// 进入即快照：终态报告会清空 AgentUpdate，若落盘失败直接返回 503，Agent 重试时
	// 已无 pending instruction 会被判冲突，永远无法收敛；落盘失败时在锁内恢复快照，
	// 让重试能重新匹配（同节点上报经 nodeMutationLock 串行，无并发覆盖风险）。
	previousProfile, hadProfile := s.profiles[nodeID]
	var previousSnapshot NodeProfile
	if previousProfile != nil {
		previousSnapshot = cloneNodeProfileValue(previousProfile)
	}
	profile := s.ensureProfileLocked(nodeID)
	reportedAt := time.Now().Unix()
	state, validState := normalizeAgentUpdateReportState(report.State)
	if !validState {
		result := cloneNodeProfileValue(profile)
		s.mu.Unlock()
		return result, false, nil
	}
	if !agentUpdateReportMatchesPendingInstruction(profile, report) {
		result := cloneNodeProfileValue(profile)
		s.mu.Unlock()
		return result, false, nil
	}
	if !agentUpdateReportAllowedForCurrentState(profile.AgentUpdateState, state) {
		result := cloneNodeProfileValue(profile)
		s.mu.Unlock()
		return result, false, nil
	}
	applyAgentUpdateReport(profile, report, state, reportedAt)
	result := cloneNodeProfileValue(profile)
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		s.mu.Lock()
		if hadProfile {
			restored := previousSnapshot
			s.profiles[nodeID] = &restored
		} else {
			delete(s.profiles, nodeID)
		}
		s.mu.Unlock()
		return result, true, err
	}
	return result, true, nil
}

func applyQueuedAgentUpdate(profile *NodeProfile, instruction AgentUpdateInstruction) {
	if profile == nil {
		return
	}
	profile.AgentUpdate = cloneAgentUpdateInstruction(&instruction)
	profile.AgentUpdateState = agentUpdateStatePending
	profile.AgentUpdateTargetVersion = instruction.Version
	profile.AgentUpdateMessage = "已下发更新任务，等待 Agent 执行"
	profile.AgentUpdateLeaseUntil = 0
	profile.AgentUpdateReportedAt = instruction.RequestedAt
	profile.UpdatedAt = instruction.RequestedAt
}

func applyAgentUpdateReport(profile *NodeProfile, report AgentUpdateReport, state string, reportedAt int64) {
	if profile == nil {
		return
	}
	profile.AgentUpdateState = state
	if version := strings.TrimSpace(report.Version); version != "" {
		profile.AgentUpdateTargetVersion = version
	}
	profile.AgentUpdateMessage = strings.TrimSpace(report.Message)
	profile.AgentUpdateReportedAt = reportedAt
	if lease := agentUpdateLeaseForState(state); lease > 0 {
		profile.AgentUpdateLeaseUntil = reportedAt + int64(lease/time.Second)
	} else {
		profile.AgentUpdateLeaseUntil = 0
	}
	if isAgentUpdateTerminalState(state) {
		profile.AgentUpdate = nil
		profile.AgentUpdateLeaseUntil = 0
	}
	profile.UpdatedAt = reportedAt
}

func agentUpdateReportMatchesPendingInstruction(profile *NodeProfile, report AgentUpdateReport) bool {
	if profile == nil || profile.AgentUpdate == nil {
		return false
	}
	targetVersion := strings.TrimSpace(profile.AgentUpdateTargetVersion)
	if targetVersion == "" {
		targetVersion = strings.TrimSpace(profile.AgentUpdate.Version)
	}
	reportVersion := strings.TrimSpace(report.Version)
	reportID := strings.TrimSpace(report.ID)
	if targetVersion == "" || reportVersion == "" || reportID == "" {
		return false
	}
	if reportID != strings.TrimSpace(profile.AgentUpdate.ID) {
		return false
	}
	return updater.VersionsEqual(reportVersion, targetVersion)
}

func agentUpdateReportAllowedForCurrentState(current, next string) bool {
	next = strings.ToLower(strings.TrimSpace(next))
	if isAgentUpdateTerminalState(next) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(current)) {
	case "", agentUpdateStatePending:
		return next == agentUpdateStateUpdating
	case agentUpdateStateUpdating:
		return next == agentUpdateStateUpdating || next == agentUpdateStateRestarting
	case agentUpdateStateRestarting:
		return next == agentUpdateStateRestarting
	default:
		return false
	}
}

func (s *Store) HasPendingAgentConfigRefresh(nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.configRefresh[nodeID]
	return ok
}

func (s *Store) markAgentConfigRefreshLocked(nodeID string) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	if s.configRefresh == nil {
		s.configRefresh = make(map[string]struct{})
	}
	s.configRefresh[nodeID] = struct{}{}
}

func (s *Store) DeliverAgentConfig(nodeID string, remoteUpdateCapable bool) (AgentConfig, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	config := s.buildAgentConfigLocked(nodeID, remoteUpdateCapable)
	return config, s.markAgentConfigDeliveredLocked(nodeID, config)
}

func (s *Store) markAgentConfigDeliveredLocked(nodeID string, config AgentConfig) bool {
	leaseUpdated := false
	if config.Update != nil {
		if profile := s.profiles[nodeID]; profile != nil {
			profile.AgentUpdateLeaseUntil = time.Now().Add(agentUpdateLeaseDelivery).Unix()
			leaseUpdated = true
		}
	}
	delete(s.configRefresh, nodeID)
	return leaseUpdated
}

func (s *Store) buildAgentConfigLocked(nodeID string, remoteUpdateCapable bool) AgentConfig {
	return s.buildAgentConfigAtLocked(nodeID, time.Now(), remoteUpdateCapable)
}

func (s *Store) buildAgentConfigAtLocked(nodeID string, now time.Time, remoteUpdateCapable bool) AgentConfig {
	profile := s.profiles[nodeID]
	if profile == nil {
		return AgentConfig{
			TestIntervalSec: defaultTestIntervalSec,
		}
	}
	tests := s.resolveTestsLocked(nodeID, profile)
	group, _ := primaryGroupTagsFromSelections(profile.Groups)
	if group == "" {
		group = strings.TrimSpace(profile.Group)
	}
	var update *AgentUpdateInstruction
	node, nodeExists := s.nodes[nodeID]
	if remoteUpdateCapable && nodeExists && resolveAgentUpdateSupported(node.Stats) && shouldDispatchAgentUpdate(profile, now) {
		update = cloneAgentUpdateInstruction(profile.AgentUpdate)
	}
	return AgentConfig{
		Alias:           profile.Alias,
		Group:           group,
		AgentToken:      strings.TrimSpace(profile.AgentAuthToken),
		TestIntervalSec: profile.TestIntervalSec,
		Tests:           slices.Clone(tests),
		Update:          update,
	}
}

func (s *Store) agentConfigProjectionsLocked(now time.Time) map[string]AgentConfig {
	if len(s.profiles) == 0 {
		return map[string]AgentConfig{}
	}
	configs := make(map[string]AgentConfig, len(s.profiles))
	for nodeID, profile := range s.profiles {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" || profile == nil {
			continue
		}
		configs[nodeID] = s.buildAgentConfigAtLocked(nodeID, now, false)
	}
	return configs
}

func (s *Store) reconcileAgentConfigRefreshLocked(previous map[string]AgentConfig, now time.Time) {
	for nodeID, previousConfig := range previous {
		if _, ok := s.profiles[nodeID]; !ok {
			delete(s.configRefresh, nodeID)
			continue
		}
		if !agentConfigsEqual(previousConfig, s.buildAgentConfigAtLocked(nodeID, now, false)) {
			s.markAgentConfigRefreshLocked(nodeID)
		}
	}

	defaultConfig := AgentConfig{
		TestIntervalSec: defaultTestIntervalSec,
		Tests:           []metrics.NetworkTestConfig{},
	}
	for nodeID, profile := range s.profiles {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" || profile == nil {
			delete(s.configRefresh, nodeID)
			continue
		}
		if _, ok := previous[nodeID]; ok {
			continue
		}
		if !agentConfigsEqual(defaultConfig, s.buildAgentConfigAtLocked(nodeID, now, false)) {
			s.markAgentConfigRefreshLocked(nodeID)
		}
	}
	for nodeID := range s.configRefresh {
		if profile := s.profiles[nodeID]; profile == nil {
			delete(s.configRefresh, nodeID)
		}
	}
}

func agentConfigsEqual(a, b AgentConfig) bool {
	return a.Alias == b.Alias &&
		a.Group == b.Group &&
		a.AgentToken == b.AgentToken &&
		a.TestIntervalSec == b.TestIntervalSec &&
		slices.Equal(a.Tests, b.Tests) &&
		agentUpdateInstructionsEqual(a.Update, b.Update)
}

func agentUpdateInstructionsEqual(a, b *AgentUpdateInstruction) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (s *Store) snapshotPersistedLocked() PersistedData {
	snapshot := PersistedData{
		Settings:        cloneSettings(s.settings),
		Profiles:        cloneProfiles(s.profiles),
		Nodes:           cloneNodeStates(s.nodes),
		OfflineSessions: cloneOfflineSessions(s.offlineSessions),
		Alerted:         cloneAlertedStates(s.alerted),
		AlertStates:     cloneAlertStates(s.alertStates),
	}
	applyPendingPersistIntentsToSnapshot(&snapshot, s.pendingClearNodes, s.pendingNodeDeletes)
	return snapshot
}

func applyPendingPersistIntentsToSnapshot(snapshot *PersistedData, pendingClearNodes bool, pendingNodeDeletes map[string]struct{}) {
	if snapshot == nil {
		return
	}
	if pendingClearNodes {
		snapshot.Profiles = map[string]*NodeProfile{}
		snapshot.Nodes = map[string]NodeState{}
		snapshot.OfflineSessions = map[string]OfflineSessionState{}
		snapshot.Alerted = map[string]AlertedState{}
		snapshot.AlertStates = map[string]RuleAlertState{}
		snapshot.PendingHistoryClear = true
		snapshot.PendingHistoryDeletes = nil
		return
	}
	pendingDeletes := make([]string, 0, len(pendingNodeDeletes))
	for nodeID := range pendingNodeDeletes {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" {
			continue
		}
		delete(snapshot.Profiles, nodeID)
		delete(snapshot.Nodes, nodeID)
		delete(snapshot.OfflineSessions, nodeID)
		delete(snapshot.Alerted, nodeID)
		deleteRuleAlertStatesForNode(snapshot.AlertStates, nodeID)
		pendingDeletes = append(pendingDeletes, nodeID)
	}
	if len(pendingDeletes) > 0 {
		sort.Strings(pendingDeletes)
		snapshot.PendingHistoryDeletes = pendingDeletes
	}
}

func (s *Store) persist() error {
	if s.dataPath == "" {
		return nil
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.mu.RLock()
	data := s.snapshotPersistedLocked()
	s.mu.RUnlock()
	return s.writePersistedSnapshotLocked(data)
}

// errPersistFailed 标记「内存已应用、落盘失败」：路由层据此返回 500（而非把落盘
// 错误当校验错误返回 400）。在 writePersistedSnapshotLocked 单点包装，所有
// persist 失败返回路径自动携带。
var errPersistFailed = errors.New("persist failed")

// hasPersistPending 供「凭内存状态直接返回成功」的路径判断是否需要补落盘。
func (s *Store) hasPersistPending() bool {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	return s.persistPending
}

func (s *Store) persistLogged() {
	if err := s.persist(); err != nil {
		log.Printf("%v", err)
	}
}

func (s *Store) writePersistedSnapshotLocked(data PersistedData) error {
	if err := savePersistedData(s.dataPath, data); err != nil {
		// persistPending 在 persistMu 内维护（本函数所有调用方均持有 persistMu）。
		s.persistPending = true
		return fmt.Errorf("%w: %v", errPersistFailed, wrapDataPathError("持久化失败", s.dataPath, err))
	}
	s.persistPending = false
	s.mu.Lock()
	s.lastPersist = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *Store) shouldPersistLocked(now time.Time) bool {
	if s.persistInterval <= 0 {
		return false
	}
	if s.lastPersist.IsZero() {
		return true
	}
	return now.Sub(s.lastPersist) >= s.persistInterval
}

func (s *Store) applyAutoRenewLocked(profile *NodeProfile, now time.Time) bool {
	if profile == nil || !profile.AutoRenew {
		return false
	}
	if profile.ExpireAt <= 0 || profile.RenewIntervalSec <= 0 {
		return false
	}
	if now.Unix() < profile.ExpireAt {
		return false
	}
	profile.ExpireAt = now.Unix() + profile.RenewIntervalSec
	return true
}

// resolveTestIntervalLocked 计算 (type, item, selection, profile) 的探测间隔。
// F2：icmp 优先级 selection > item > 0（0 = 持续，跟随 agent tick），不回落到
// profile.TestIntervalSec 或 defaultTestIntervalSec；tcp 回落链为
// selection > item > profile > 默认。
func resolveTestIntervalLocked(item TestCatalogItem, selInterval int, profile *NodeProfile) int {
	if strings.ToLower(item.Type) == "tcp" {
		if selInterval > 0 {
			return selInterval
		}
		if item.IntervalSec > 0 {
			return item.IntervalSec
		}
		if profile.TestIntervalSec > 0 {
			return profile.TestIntervalSec
		}
		return defaultTestIntervalSec
	}
	if selInterval > 0 {
		return selInterval
	}
	if item.IntervalSec > 0 {
		return item.IntervalSec
	}
	return 0
}

// resolveTestsLocked 解析节点最终生效的探测集合（O-01：手动选择 ∪ 范围命中的
// 目录项）。同一目录项既被手动选择又被范围命中时只出现一次，间隔用手动选择上的；
// 顺序：先手动选择（原顺序），再范围命中项（按目录顺序）。范围匹配复用
// ruleScopeMatches（含 D-05：exclude 两种模式都生效）。
func (s *Store) resolveTestsLocked(nodeID string, profile *NodeProfile) []metrics.NetworkTestConfig {
	catalog := make(map[string]TestCatalogItem, len(s.settings.TestCatalog))
	for _, item := range s.settings.TestCatalog {
		catalog[item.ID] = item
	}
	results := make([]metrics.NetworkTestConfig, 0, len(profile.TestSelections))
	resolved := make(map[string]struct{}, len(profile.TestSelections))
	for _, sel := range profile.TestSelections {
		if sel.TestID == "" {
			continue
		}
		item, ok := catalog[sel.TestID]
		if !ok {
			continue
		}
		results = append(results, metrics.NetworkTestConfig{
			Name:        item.Name,
			Type:        item.Type,
			Host:        item.Host,
			Port:        item.Port,
			IntervalSec: resolveTestIntervalLocked(item, sel.IntervalSec, profile),
		})
		resolved[sel.TestID] = struct{}{}
		if len(results) >= maxNetworkTestsPerNode {
			return results
		}
	}
	// O-01：范围命中且未被手动选择的目录项追加（无手动间隔，按 item / 类型回退）。
	for _, item := range s.settings.TestCatalog {
		if item.Scope == nil {
			continue
		}
		if _, done := resolved[item.ID]; done {
			continue
		}
		if !ruleScopeMatches(*item.Scope, nodeID, profile) {
			continue
		}
		results = append(results, metrics.NetworkTestConfig{
			Name:        item.Name,
			Type:        item.Type,
			Host:        item.Host,
			Port:        item.Port,
			IntervalSec: resolveTestIntervalLocked(item, 0, profile),
		})
		if len(results) >= maxNetworkTestsPerNode {
			break
		}
	}
	if len(results) == 0 {
		return nil
	}
	return results
}

func (s *Store) normalizeSelectionsLocked(selections []TestSelection) []TestSelection {
	return normalizeTestSelections(s.settings.TestCatalog, selections)
}

func normalizeTestSelections(catalog []TestCatalogItem, selections []TestSelection) []TestSelection {
	if len(selections) == 0 {
		return nil
	}
	valid := make(map[string]TestCatalogItem, len(catalog))
	for _, item := range catalog {
		if item.ID == "" {
			continue
		}
		valid[item.ID] = item
	}
	seen := make(map[string]struct{})
	result := make([]TestSelection, 0, len(selections))
	for _, sel := range selections {
		id := strings.TrimSpace(sel.TestID)
		if id == "" {
			continue
		}
		_, ok := valid[id]
		if !ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		// F2：icmp 不再强制清零，interval 原样保留（负数钳到 0）。
		interval := sel.IntervalSec
		if interval < 0 {
			interval = 0
		}
		result = append(result, TestSelection{
			TestID:      id,
			IntervalSec: interval,
		})
		if len(result) >= maxNetworkTestsPerNode {
			break
		}
	}
	return result
}

func catalogItemsByID(items []TestCatalogItem) map[string]TestCatalogItem {
	result := make(map[string]TestCatalogItem, len(items))
	for _, item := range items {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		item.ID = id
		result[id] = item
	}
	return result
}

// alertScopesValueEqual 按（规范化后的）值比较两个 AlertScope。Scope 为指针字段，
// 直接 == 只比指针地址——保存路径每次 normalize 都会构造新指针，内容相同的
// scope 会被误判为变化。
func alertScopesValueEqual(a, b *AlertScope) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Mode == b.Mode &&
		slices.Equal(a.Nodes, b.Nodes) &&
		slices.Equal(a.Groups, b.Groups) &&
		slices.Equal(a.Exclude, b.Exclude)
}

// testCatalogItemsEqual 按（规范化后的）值比较两个目录项（含 Scope）。
func testCatalogItemsEqual(a, b TestCatalogItem) bool {
	return a.ID == b.ID &&
		a.Name == b.Name &&
		a.Type == b.Type &&
		a.Host == b.Host &&
		a.Port == b.Port &&
		a.IntervalSec == b.IntervalSec &&
		alertScopesValueEqual(a.Scope, b.Scope)
}

// testCatalogScopeChanged 判断前后目录中任一目录项的 Scope 是否变化（新增带
// scope 的项 / 删除带 scope 的项 / scope 内容变化均算）。
func testCatalogScopeChanged(previous, next []TestCatalogItem) bool {
	previousByID := catalogItemsByID(previous)
	nextByID := catalogItemsByID(next)
	for id, item := range nextByID {
		previousItem, hadPrevious := previousByID[id]
		if !hadPrevious {
			if item.Scope != nil {
				return true
			}
			continue
		}
		if !alertScopesValueEqual(previousItem.Scope, item.Scope) {
			return true
		}
	}
	for id, item := range previousByID {
		if _, hasNext := nextByID[id]; !hasNext && item.Scope != nil {
			return true
		}
	}
	return false
}

// markAgentConfigRefreshForScopeChangeLocked 在任一目录项 Scope 变化时对所有
// 节点标记 agent 配置刷新（O-01）：范围变化会影响「无手动选择的节点」（旧函数
// 只覆盖有手动选择的节点），因此对所有节点标记。
func (s *Store) markAgentConfigRefreshForScopeChangeLocked(previous, next []TestCatalogItem) {
	if !testCatalogScopeChanged(previous, next) {
		return
	}
	for nodeID := range s.profiles {
		s.markAgentConfigRefreshLocked(nodeID)
	}
}

func (s *Store) markAgentConfigRefreshForCatalogChangeLocked(previous, next []TestCatalogItem) {
	if len(s.profiles) == 0 {
		return
	}
	previousByID := catalogItemsByID(previous)
	nextByID := catalogItemsByID(next)
	for nodeID, profile := range s.profiles {
		if profile == nil || len(profile.TestSelections) == 0 {
			continue
		}
		for _, selection := range profile.TestSelections {
			id := strings.TrimSpace(selection.TestID)
			if id == "" {
				continue
			}
			previousItem, hadPrevious := previousByID[id]
			nextItem, hasNext := nextByID[id]
			// O-01：比较改为按值（testCatalogItemsEqual）——Scope 是指针字段，
			// 旧的 struct != 会把内容相同的规范化 scope 误判为变化。
			if !hasNext || !hadPrevious || !testCatalogItemsEqual(previousItem, nextItem) {
				s.markAgentConfigRefreshLocked(nodeID)
				break
			}
		}
	}
}

func (s *Store) pruneProfileTestSelectionsLocked() {
	for _, profile := range s.profiles {
		if profile == nil || len(profile.TestSelections) == 0 {
			continue
		}
		profile.TestSelections = s.normalizeSelectionsLocked(profile.TestSelections)
	}
}

func (s *Store) pruneProfileGroupSelectionsLocked() {
	groupNames, tagKeys, treeMode := groupSelectionSets(s.settings)
	for _, profile := range s.profiles {
		if profile == nil || len(profile.Groups) == 0 {
			continue
		}
		kept := filterGroupSelections(profile.Groups, groupNames, tagKeys, treeMode)
		if len(kept) != len(profile.Groups) {
			profile.Groups = kept
			group, tags := primaryGroupTagsFromSelections(profile.Groups)
			profile.Group = group
			profile.Tags = tags
		}
	}
}

// groupMoveRule 是分组级迁移规则（From 为分组名）：命中的 selection 整体替换
// 分组前缀，保留原有标签；selection 本身无标签时落到 To 的标签（若有）。
type groupMoveRule struct {
	fromGroup string
	toGroup   string
	toTag     string
}

// applyProfileGroupMovesLocked 按 F1 的 group_moves 把节点归属从 From 迁移到 To：
//   - From 为分组（"A"）：该分组下所有归属整体替换前缀（"A"→"B"、"A:t"→"B:t"）；
//   - From 为标签（"A:t"）：仅精确匹配该条归属，替换为 To。
//
// 映射产生的重复条目会被去掉；映射到新树中不存在的目标由随后的
// pruneProfileGroupSelectionsLocked 清理。分组会随 AgentConfig 下发，受影响
// 节点需标记 agent 配置刷新。须在写入新分组树之前调用。
func (s *Store) applyProfileGroupMovesLocked(moves []GroupMove) {
	if len(moves) == 0 {
		return
	}
	groupRules := make([]groupMoveRule, 0, len(moves))
	tagRules := make(map[string]string, len(moves))
	for _, move := range moves {
		fromGroup, fromTag := parseGroupSelection(move.From)
		toGroup, toTag := parseGroupSelection(move.To)
		if fromGroup == "" || toGroup == "" || (fromGroup == toGroup && fromTag == toTag) {
			continue
		}
		if fromTag == "" {
			groupRules = append(groupRules, groupMoveRule{fromGroup: fromGroup, toGroup: toGroup, toTag: toTag})
			continue
		}
		tagRules[fromGroup+"\x00"+fromTag] = canonicalGroupSelection(toGroup, toTag)
	}
	if len(groupRules) == 0 && len(tagRules) == 0 {
		return
	}
	for nodeID, profile := range s.profiles {
		if profile == nil || len(profile.Groups) == 0 {
			continue
		}
		mapped := make([]string, 0, len(profile.Groups))
		seen := make(map[string]struct{}, len(profile.Groups))
		changed := false
		for _, selection := range profile.Groups {
			next := selection
			group, tag := parseGroupSelection(selection)
			if group != "" {
				if tag != "" {
					if target, ok := tagRules[group+"\x00"+tag]; ok {
						next = target
					}
				}
				if next == selection {
					for _, rule := range groupRules {
						if group != rule.fromGroup {
							continue
						}
						nextTag := tag
						if nextTag == "" {
							nextTag = rule.toTag
						}
						next = canonicalGroupSelection(rule.toGroup, nextTag)
						break
					}
				}
			}
			if _, dup := seen[next]; dup {
				changed = true
				continue
			}
			seen[next] = struct{}{}
			if next != selection {
				changed = true
			}
			mapped = append(mapped, next)
		}
		if !changed {
			continue
		}
		profile.Groups = mapped
		group, tags := primaryGroupTagsFromSelections(profile.Groups)
		profile.Group = group
		profile.Tags = tags
		s.markAgentConfigRefreshLocked(nodeID)
	}
}

func generateToken(secret, subject, tokenSalt string) (string, int64, error) {
	exp := time.Now().Add(12 * time.Hour)
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		ID:        tokenSalt,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(exp),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	str, err := token.SignedString([]byte(secret))
	return str, exp.Unix(), err
}

func requireAdminJWT(store *Store, secret string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := validateAdminJWT(store, secret, r); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if requestUsesCookieAdminAuth(r) && isStateChangingMethod(r.Method) && !isSameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin admin request rejected"})
			return
		}
		next(w, r)
	}
}

func requestUsesCookieAdminAuth(r *http.Request) bool {
	if r == nil || extractExplicitToken(r) != "" {
		return false
	}
	cookie, err := r.Cookie(adminSessionCookieName)
	return err == nil && strings.TrimSpace(cookie.Value) != ""
}

func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

func validateAdminJWT(store *Store, secret string, r *http.Request) error {
	token := extractToken(r)
	if token == "" {
		return errors.New("token required")
	}
	claims := &jwt.RegisteredClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return err
	}
	if parsed == nil || !parsed.Valid {
		return errors.New("token invalid")
	}
	creds := store.Credentials()
	if creds.AdminUser != "" && claims.Subject != creds.AdminUser {
		return errors.New("token subject mismatch")
	}
	if creds.TokenSalt != "" && claims.ID != creds.TokenSalt {
		return errors.New("token revoked")
	}
	return nil
}

func extractExplicitToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return parts[1]
		}
	}
	return ""
}

func extractToken(r *http.Request) string {
	if token := extractExplicitToken(r); token != "" {
		return token
	}
	if r != nil {
		if cookie, err := r.Cookie(adminSessionCookieName); err == nil {
			return strings.TrimSpace(cookie.Value)
		}
	}
	return ""
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("extra json content")
	}
	return nil
}

// validateWebhookURL 是默认的 webhook/端点静态校验：拒绝私网/环回目标。
func validateWebhookURL(raw string) error {
	return validateWebhookURLPolicy(raw, false)
}

// validateWebhookURLAllowPrivate 供通知渠道显式开启“允许内网地址”后使用：
// 只跳过私网/环回目标判定，其余校验（非空、协议、userinfo、歧义 IPv4 字面量、
// 百分号 zone）与 validateWebhookURL 完全一致。
func validateWebhookURLAllowPrivate(raw string) error {
	return validateWebhookURLPolicy(raw, true)
}

func validateWebhookURLPolicy(raw string, allowPrivate bool) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("webhook 不能为空")
	}
	if err := validateHTTPCallbackURLPolicy(raw, allowPrivate); err != nil {
		if errors.Is(err, errCallbackURLScheme) {
			return errors.New("webhook 协议无效")
		}
		var privateTarget *privateTargetError
		if errors.As(err, &privateTarget) {
			return privateTarget
		}
		return errors.New("webhook 无效")
	}
	return nil
}

func validateAgentEndpoint(raw string) error {
	if err := validateHTTPBaseURL(raw); err != nil {
		if errors.Is(err, errHTTPBaseURLScheme) {
			return errors.New("agent endpoint 需为 http 或 https")
		}
		return errors.New("agent endpoint 无效")
	}
	return nil
}

func normalizeSiteIconURL(raw string) (string, error) {
	return normalizePublicImageURL(raw, "site_icon")
}

func normalizeSiteBackgroundImageURL(raw string) (string, error) {
	return normalizePublicImageURL(raw, "site_background_image")
}

func normalizePublicImageURL(raw, field string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if strings.Contains(value, "\\") || strings.Contains(value, "\x00") || strings.ContainsAny(value, "\r\n\t") {
		return "", fmt.Errorf("%s 无效", field)
	}
	if strings.HasPrefix(value, "//") {
		return "", fmt.Errorf("%s 不能使用协议相对 URL", field)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("%s 无效", field)
	}
	if parsed.Scheme != "" {
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return "", fmt.Errorf("%s 需为 http/https 或相对路径", field)
		}
		if parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
			return "", fmt.Errorf("%s 无效", field)
		}
		if strings.Contains(parsed.Hostname(), "%") || isAmbiguousIPv4LiteralHost(parsed.Hostname()) {
			return "", fmt.Errorf("%s 无效", field)
		}
		if siteIconPathHasTraversal(parsed.EscapedPath()) {
			return "", fmt.Errorf("%s 不能包含路径穿越", field)
		}
		return value, nil
	}
	if parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("%s 无效", field)
	}
	if siteIconPathHasTraversal(parsed.EscapedPath()) {
		return "", fmt.Errorf("%s 不能包含路径穿越", field)
	}
	return value, nil
}

func safeSiteIconURL(raw string) string {
	value, err := normalizeSiteIconURL(raw)
	if err != nil {
		return ""
	}
	return value
}

func safeSiteBackgroundImageURL(raw string) string {
	value, err := normalizeSiteBackgroundImageURL(raw)
	if err != nil {
		return ""
	}
	return value
}

func normalizeLocale(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "en", "en-us", "en_us":
		return "en-US"
	default:
		return defaultLocale
	}
}

func siteIconPathHasTraversal(pathValue string) bool {
	pathValue = strings.TrimSpace(pathValue)
	if pathValue == "" {
		return false
	}
	for _, segment := range strings.Split(pathValue, "/") {
		if segment == "" {
			continue
		}
		decoded := segment
		for i := 0; i < 3; i++ {
			next, err := url.PathUnescape(decoded)
			if err != nil || next == decoded {
				break
			}
			decoded = next
		}
		if decoded == ".." {
			return true
		}
	}
	return false
}

func validateReleaseTargetVersion(info updater.ReleaseInfo) error {
	targetVersion := strings.TrimSpace(info.LatestVersion)
	if targetVersion == "" {
		return errors.New("缺少更新目标版本")
	}
	if !updater.ValidReleaseVersion(targetVersion) {
		return fmt.Errorf("更新目标版本无效: %s", targetVersion)
	}
	return nil
}

var errHTTPBaseURLScheme = errors.New("http base url scheme invalid")

func validateHTTPBaseURL(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" {
		return errors.New("http base url invalid")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errHTTPBaseURLScheme
	}
	if strings.Contains(parsed.Hostname(), "%") {
		return errors.New("http base url invalid")
	}
	if isAmbiguousIPv4LiteralHost(parsed.Hostname()) {
		return errors.New("http base url invalid")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("http base url invalid")
	}
	return nil
}

var errCallbackURLScheme = errors.New("callback url scheme invalid")

// privateTargetError 标记“目标解析或字面量是私网/环回/保留地址”这一类确定性拒绝：
// 携带被拒的 host 与 IP，供通知层拼出带指引的中文文案（errors.As 可识别）。
// Host 非空而 IP 为 nil 表示 host 本身命中（如 localhost）；两者都不为空表示 host
// 解析出的地址命中。
type privateTargetError struct {
	Host string
	IP   net.IP
}

func (e *privateTargetError) Error() string {
	if e == nil {
		return "callback private target rejected"
	}
	if e.IP != nil {
		if e.Host != "" && e.Host != e.IP.String() {
			return fmt.Sprintf("callback private ip rejected: %s (%s)", e.Host, e.IP.String())
		}
		return fmt.Sprintf("callback private ip rejected: %s", e.IP.String())
	}
	return fmt.Sprintf("callback private host rejected: %s", e.Host)
}

// target 返回用于提示文案的目标描述（优先 IP，附带主机名）。
func (e *privateTargetError) target() string {
	if e == nil {
		return "未知地址"
	}
	if e.IP != nil {
		if e.Host != "" && e.Host != e.IP.String() {
			return fmt.Sprintf("%s（%s）", e.Host, e.IP.String())
		}
		return e.IP.String()
	}
	return e.Host
}

type callbackResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type callbackDialContext func(context.Context, string, string) (net.Conn, error)

var (
	defaultCallbackResolver callbackResolver = net.DefaultResolver
	defaultCallbackDialer                    = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
)

var sharedWebhookClient = sync.OnceValue(func() *http.Client {
	return &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			DialContext:           restrictedCallbackDialContext(defaultCallbackResolver, defaultCallbackDialer),
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 6 * time.Second,
			ExpectContinueTimeout: time.Second,
			IdleConnTimeout:       60 * time.Second,
		},
		CheckRedirect: webhookRedirectPolicy,
	}
})

// sharedWebhookClientAllowPrivate 是通知渠道显式开启“允许内网地址”后的出站客户端：
// 超时、传输参数与 sharedWebhookClient 一致（不设 Proxy），也不再做地址判定，
// 让 fake-ip 代理（198.18.0.0/15）与内网自建服务可达。重定向语义不变（最多 10
// 跳、删 Referer、每跳重新校验），只是校验改用 allow-private 版本。
var sharedWebhookClientAllowPrivate = sync.OnceValue(func() *http.Client {
	return &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			DialContext:           defaultCallbackDialer,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 6 * time.Second,
			ExpectContinueTimeout: time.Second,
			IdleConnTimeout:       60 * time.Second,
		},
		CheckRedirect: webhookRedirectPolicyAllowPrivate,
	}
})

func webhookRedirectPolicy(req *http.Request, via []*http.Request) error {
	return webhookRedirectPolicyUsing(req, via, validateWebhookURL)
}

func webhookRedirectPolicyAllowPrivate(req *http.Request, via []*http.Request) error {
	return webhookRedirectPolicyUsing(req, via, validateWebhookURLAllowPrivate)
}

func webhookRedirectPolicyUsing(req *http.Request, via []*http.Request, validate func(string) error) error {
	if len(via) >= 10 {
		return errors.New("webhook redirect limit exceeded")
	}
	req.Header.Del("Referer")
	return validate(req.URL.String())
}

func noRedirectHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func restrictedCallbackDialContext(resolver callbackResolver, dialContext callbackDialContext) callbackDialContext {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return nil, errors.New("callback address invalid")
		}
		ips, err := validateResolvedCallbackHost(ctx, resolver, host)
		if err != nil {
			return nil, err
		}
		var firstErr error
		for _, ip := range ips {
			target := net.JoinHostPort(ip.IP.String(), port)
			conn, err := dialContext(ctx, network, target)
			if err == nil {
				return conn, nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, errors.New("callback host has no resolved ip")
	}
}

func validateResolvedCallbackHost(ctx context.Context, resolver callbackResolver, host string) ([]net.IPAddr, error) {
	host = canonicalCallbackHost(host)
	if host == "" || strings.Contains(host, "%") || isAmbiguousIPv4LiteralHost(host) {
		return nil, errors.New("callback host invalid")
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("callback host resolve failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("callback host has no resolved ip")
	}
	for _, ip := range ips {
		if ip.IP == nil {
			return nil, errors.New("callback host resolved empty ip")
		}
		if isPrivateCallbackIP(ip.IP) {
			return nil, &privateTargetError{Host: host, IP: ip.IP}
		}
	}
	return ips, nil
}

// validateHTTPCallbackURL 是默认的 callback URL 静态校验：拒绝私网/环回目标。
func validateHTTPCallbackURL(raw string) error {
	return validateHTTPCallbackURLPolicy(raw, false)
}

// validateHTTPCallbackURLPolicy 按 allowPrivate 决定是否放行字面量私网 IP 与
// localhost；其余校验（空/非法 host、非 http(s)、userinfo、百分号 zone、歧义 IPv4
// 字面量）在两种模式下都保留。
func validateHTTPCallbackURLPolicy(raw string, allowPrivate bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return errors.New("callback url invalid")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errCallbackURLScheme
	}
	if parsed.User != nil {
		return errors.New("callback url invalid")
	}
	host := canonicalCallbackHost(parsed.Hostname())
	if host == "" {
		return errors.New("callback host invalid")
	}
	// 结构性非法 host（百分号 zone、歧义 IPv4 字面量）先判，避免被下面的
	// localhost 放行分支绕过。
	if strings.Contains(host, "%") {
		return errors.New("callback host invalid")
	}
	if isAmbiguousIPv4LiteralHost(host) {
		return errors.New("callback host invalid")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		if allowPrivate {
			return nil
		}
		return &privateTargetError{Host: host}
	}
	if ip := net.ParseIP(host); ip != nil && isPrivateCallbackIP(ip) {
		if allowPrivate {
			return nil
		}
		return &privateTargetError{Host: host, IP: ip}
	}
	return nil
}

func canonicalCallbackHost(raw string) string {
	return strings.TrimRight(strings.Trim(strings.ToLower(raw), "[]"), ".")
}

func isPrivateCallbackIP(ip net.IP) bool {
	return !netguard.IsAllowedPublicIP(ip)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		log.Printf("序列化 JSON 响应失败: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("{\"error\":\"encode failed\"}\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func handleAdminUpdateNodeProfileRequest(w http.ResponseWriter, r *http.Request, store *Store, hub *Hub, nodeID string) {
	var update NodeProfileUpdate
	if err := decodeJSON(w, r, &update); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if update.Region != nil && strings.TrimSpace(*update.Region) != "" {
		if _, ok := normalizeRegionCode(*update.Region); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "region 必须是两位地区代码（如 SG/JP/HK）"})
			return
		}
	}
	// F4：流量配额字段校验（计算方式与每月重置日）。
	if update.TrafficLimitType != nil {
		switch strings.TrimSpace(*update.TrafficLimitType) {
		case "", "sum", "max", "up", "down":
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "traffic_limit_type 仅支持 sum、max、up、down"})
			return
		}
	}
	if update.TrafficResetDay != nil {
		day := *update.TrafficResetDay
		if day != 0 && (day < 1 || day > 28) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "traffic_reset_day 需在 1 - 28 之间"})
			return
		}
	}
	if _, ok, err := store.UpdateProfile(nodeID, update); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "保存失败，落盘异常，请检查磁盘后重试"})
		return
	} else if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	broadcastStoreSnapshot(hub, store)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func adminNodeIDFromPath(w http.ResponseWriter, rawPath string) (string, bool) {
	nodeID, err := url.PathUnescape(rawPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node id"})
		return "", false
	}
	nodeID, err = history.NormalizeNodeID(nodeID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node id"})
		return "", false
	}
	if nodeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node id required"})
		return "", false
	}
	return nodeID, true
}

func releaseCheckContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 8*time.Second)
}

// handleReleaseUpdateGate 是 POST 更新处理器（服务端自更新 / Agent 更新）共用的
// release 闸门：校验目标版本，并在「已是最新」时写短路响应。返回 true 表示
// 请求已写完响应，调用方应直接 return。检查外呼和资产校验两步在两个处理器
// 中语义不同（checkRelease/CheckLatest、agent/system 资产规则），保留在各自调用点。
func handleReleaseUpdateGate(w http.ResponseWriter, info updater.ReleaseInfo) bool {
	if err := validateReleaseTargetVersion(info); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return true
	}
	if !info.HasUpdate && updater.VersionCurrentOrNewer(info.CurrentVersion, info.LatestVersion) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":         "up_to_date",
			"target_version": info.LatestVersion,
		})
		return true
	}
	return false
}

const agentReleaseCacheTTL = time.Minute

type agentReleaseCacheEntry struct {
	info      updater.ReleaseInfo
	err       error
	expiresAt time.Time
}

var agentReleaseCache = struct {
	sync.Mutex
	entries map[string]agentReleaseCacheEntry
}{entries: map[string]agentReleaseCacheEntry{}}

// agentReleaseCacheKey 把节点平台计入缓存键：ReleaseInfo 里已按平台挑好 AssetName/
// DownloadURL，只按 version 做键会让第一个节点的平台污染其他平台节点的选包结果。
func agentReleaseCacheKey(version, goos, goarch string) string {
	return version + "\x00" + goos + "\x00" + goarch
}

// resolveAgentPlatform 从节点上报的 stats 推导一键升级的选包目标平台。判断方式与
// resolveAgentUpdateMode 保持一致（按 stats.OS 标签子串识别平台，normalizeOSLabel
// 会把 darwin 归一成 "macOS …"）。stats 缺失（OS 为空）时返回空串，由 updater 回退到
// 服务端自身平台——即老 Agent 未上报 OS/Arch 时的既有行为，不劣化。
//
// 发布矩阵只有 linux/darwin/windows/freebsd 四种平台（build-release.yml），因此除
// windows/darwin/freebsd 外的标签只可能是 Linux 发行版名，linux 必须作为兜底：Linux
// Agent 上报的 stats.OS 取自 gopsutil host.Platform（发行版名，如 "ubuntu 22.04"、
// "debian 12"、"alpine 3.19"），并不含 "linux" 子串；若把兜底改成空串，Linux 节点会
// 退化成"按服务端平台选包"，非 Linux 服务端管理 Linux Agent 时会选错包。反过来，
// freebsd 必须显式匹配：FreeBSD 的 Platform 是 kern.ostype（"freebsd …"），不显式
// 匹配就会落进 linux 兜底，导致 FreeBSD 节点被下发 linux 包。
func resolveAgentPlatform(stats metrics.NodeStats) (string, string) {
	osLabel := strings.ToLower(strings.TrimSpace(stats.OS))
	var goos string
	switch {
	case osLabel == "":
		goos = ""
	case strings.Contains(osLabel, "windows"):
		goos = "windows"
	case strings.Contains(osLabel, "macos"), strings.Contains(osLabel, "darwin"), strings.Contains(osLabel, "os x"):
		goos = "darwin"
	case strings.Contains(osLabel, "freebsd"):
		goos = "freebsd"
	default:
		goos = "linux"
	}
	// arch 直接透传 stats.Arch（normalizeArch 已归一成 amd64/arm64/arm/386，
	// arm→armv7 由 updater.AssetNameFor 处理）；为空则让 updater 回退。
	return goos, strings.TrimSpace(stats.Arch)
}

func defaultAgentReleaseChecker(ctx context.Context, stats metrics.NodeStats) (updater.ReleaseInfo, error) {
	version := strings.TrimSpace(stats.AgentVersion)
	goos, goarch := resolveAgentPlatform(stats)
	cacheKey := agentReleaseCacheKey(version, goos, goarch)
	now := time.Now()

	agentReleaseCache.Lock()
	if entry, ok := agentReleaseCache.entries[cacheKey]; ok && now.Before(entry.expiresAt) {
		agentReleaseCache.Unlock()
		return entry.info, entry.err
	}
	if len(agentReleaseCache.entries) > 32 {
		for key, entry := range agentReleaseCache.entries {
			if now.After(entry.expiresAt) {
				delete(agentReleaseCache.entries, key)
			}
		}
		if len(agentReleaseCache.entries) > 32 {
			agentReleaseCache.entries = map[string]agentReleaseCacheEntry{}
		}
	}
	agentReleaseCache.Unlock()

	client := updater.NewClient(updater.DefaultRepo, updater.KindAgent, version)
	client.GOOS = goos
	client.GOARCH = goarch
	info, err := client.CheckLatest(ctx)

	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		agentReleaseCache.Lock()
		agentReleaseCache.entries[cacheKey] = agentReleaseCacheEntry{info: info, err: err, expiresAt: now.Add(agentReleaseCacheTTL)}
		agentReleaseCache.Unlock()
	}
	return info, err
}

func adminAgentUpdateHandler(store *Store, hub *Hub, checkRelease agentReleaseChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		rawNodeID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/admin/nodes/"), "/agent/update")
		nodeID, ok := adminNodeIDFromPath(w, rawNodeID)
		if !ok {
			return
		}
		store.mu.RLock()
		node, exists := store.nodes[nodeID]
		store.mu.RUnlock()
		if !exists {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
			return
		}

		if r.Method == http.MethodGet {
			handleAdminGetAgentUpdate(w, r, node.Stats, checkRelease)
			return
		}
		handleAdminPostAgentUpdate(w, r, store, hub, nodeID, node.Stats, checkRelease)
	}
}

func handleAdminGetAgentUpdate(w http.ResponseWriter, r *http.Request, stats metrics.NodeStats, checkRelease agentReleaseChecker) {
	if !resolveAgentUpdateSupported(stats) {
		writeJSON(w, http.StatusOK, buildAgentUpdateView(stats, updater.ReleaseInfo{}, resolveAgentUpdateUnsupportedReason(stats)))
		return
	}
	if strings.TrimSpace(stats.AgentVersion) == "" {
		writeJSON(w, http.StatusOK, buildAgentUpdateView(stats, updater.ReleaseInfo{}, "当前节点还没有上报 Agent 版本"))
		return
	}
	checkCtx, cancelCheck := releaseCheckContext(r)
	releaseInfo, err := checkRelease(checkCtx, stats)
	cancelCheck()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, buildAgentUpdateView(stats, releaseInfo, ""))
}

func handleAdminPostAgentUpdate(
	w http.ResponseWriter,
	r *http.Request,
	store *Store,
	hub *Hub,
	nodeID string,
	stats metrics.NodeStats,
	checkRelease agentReleaseChecker,
) {
	if !resolveAgentUpdateSupported(stats) {
		message := resolveAgentUpdateUnsupportedReason(stats)
		if strings.TrimSpace(message) == "" {
			message = "当前节点平台暂不支持后台自更新"
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": message})
		return
	}
	if strings.TrimSpace(stats.AgentVersion) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "当前节点还没有上报 Agent 版本"})
		return
	}
	checkCtx, cancelCheck := releaseCheckContext(r)
	releaseInfo, err := checkRelease(checkCtx, stats)
	cancelCheck()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if handleReleaseUpdateGate(w, releaseInfo) {
		return
	}
	if message := agentUpdateReleaseAssetError(stats, releaseInfo); message != "" {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": message})
		return
	}
	queuedProfile, queueStatus, queueErr := store.QueueAgentUpdate(nodeID, AgentUpdateInstruction{
		Version:     releaseInfo.LatestVersion,
		DownloadURL: releaseInfo.DownloadURL,
		ChecksumURL: releaseInfo.ChecksumURL,
	})
	if queueErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": queueErr.Error()})
		return
	}
	if queueStatus == agentUpdateQueueNotFound {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	if queueStatus == agentUpdateQueueQueued {
		broadcastStoreSnapshot(hub, store)
	}
	status := "in_progress"
	targetVersion := releaseInfo.LatestVersion
	if queueStatus == agentUpdateQueueQueued {
		status = "queued"
	} else if pending := strings.TrimSpace(queuedProfile.AgentUpdateTargetVersion); pending != "" {
		targetVersion = pending
	}
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":         status,
		"target_version": targetVersion,
	})
}

func handleAdminClearNodesRequest(w http.ResponseWriter, r *http.Request, store *Store, hub *Hub) {
	if err := store.ClearNodes(); err != nil {
		var partialHistoryErr *historyCleanupError
		if errors.As(err, &partialHistoryErr) {
			broadcastStoreSnapshot(hub, store)
			writeJSON(w, http.StatusOK, map[string]string{
				"status":        "cleared",
				"history_error": partialHistoryErr.HistoryError(),
			})
			return
		}
		writeNodesHistoryError(w, "clear_failed", "清空节点", err)
		return
	}
	broadcastStoreSnapshot(hub, store)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func handleAdminDeleteNodeRequest(w http.ResponseWriter, r *http.Request, store *Store, hub *Hub, nodeID string) {
	deleted, err := store.DeleteNode(nodeID)
	if err != nil {
		var partialHistoryErr *historyCleanupError
		if errors.As(err, &partialHistoryErr) {
			broadcastStoreSnapshot(hub, store)
			writeJSON(w, http.StatusOK, map[string]string{
				"status":        "deleted",
				"history_error": partialHistoryErr.HistoryError(),
			})
			return
		}
		if errors.Is(err, history.ErrInvalidNodeID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node id"})
			return
		}
		writeNodesHistoryError(w, "delete_failed", "删除节点", err)
		return
	}
	if !deleted {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	broadcastStoreSnapshot(hub, store)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func agentConfigHTTPHandler(agentAPI *agentAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		nodeID := r.URL.Query().Get("node_id")
		token := r.Header.Get("X-AGENT-TOKEN")
		config, err := agentAPI.config(nodeID, token, agentRemoteUpdateCapableHeader(r.Header.Get(agentrpc.AgentCapabilitiesHeader)))
		if err != nil {
			writeJSON(w, err.statusCode, map[string]string{"error": err.message})
			return
		}
		writeJSON(w, http.StatusOK, config)
	}
}

func agentUpdateReportHTTPHandler(agentAPI *agentAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			NodeID   string `json:"node_id"`
			UpdateID string `json:"update_id"`
			State    string `json:"state"`
			Version  string `json:"version,omitempty"`
			Message  string `json:"message,omitempty"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if err := agentAPI.reportUpdate(req.NodeID, r.Header.Get("X-AGENT-TOKEN"), AgentUpdateReport{
			State:   req.State,
			ID:      req.UpdateID,
			Version: req.Version,
			Message: req.Message,
		}); err != nil {
			writeJSON(w, err.statusCode, map[string]string{"error": err.message})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

var regionAliases = map[string]string{
	"新加坡": "SG", "japan": "JP", "日本": "JP",
	"香港": "HK", "中国香港": "HK", "hong kong": "HK", "hongkong": "HK",
	"台湾": "TW", "中国台湾": "TW", "taiwan": "TW",
	"美国": "US", "united states": "US", "usa": "US",
	"英国": "UK", "united kingdom": "UK", "uk": "UK",
	"加拿大": "CA", "canada": "CA",
	"德国": "DE", "germany": "DE",
	"法国": "FR", "france": "FR",
	"荷兰": "NL", "netherlands": "NL",
	"中国": "CN", "中国大陆": "CN", "china": "CN",
	"韩国": "KR", "korea": "KR",
	"澳门": "MO", "macau": "MO", "macao": "MO",
	"澳大利亚": "AU", "australia": "AU",
	"俄罗斯": "RU", "russia": "RU",
	"singapore": "SG",
}

func normalizeRegionCode(value string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(value))
	if key == "" {
		return "", false
	}
	if code, ok := regionAliases[key]; ok {
		return code, true
	}
	upper := strings.ToUpper(key)
	if len(upper) == 2 && upper[0] >= 'A' && upper[0] <= 'Z' && upper[1] >= 'A' && upper[1] <= 'Z' {
		return upper, true
	}
	return "", false
}

func cleanAdminProfileText(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if maxLen <= 0 || len([]rune(value)) <= maxLen {
		return value
	}
	return string([]rune(value)[:maxLen])
}

func writeNodesHistoryError(w http.ResponseWriter, bodyStatus, action string, err error) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{
		"status": bodyStatus,
		"error":  fmt.Sprintf("%s失败，历史数据清理失败: %v", action, err),
	})
}

func withNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func isPublicReadMethod(r *http.Request) bool {
	return r != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead)
}

func applyPublicCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Add("Vary", "Origin")
}

func withPublicCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			applyPublicCORSHeaders(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		applyPublicCORSHeaders(w)
		next(w, r)
	}
}

func buildAdminBootPayload(store *Store, r *http.Request, trustedProxyHeaders bool) (string, error) {
	settings := store.PublicSettings()
	adminSettings := struct {
		SiteTitle           string `json:"site_title,omitempty"`
		SiteIcon            string `json:"site_icon,omitempty"`
		SiteBackgroundImage string `json:"site_background_image,omitempty"`
		HomeTitle           string `json:"home_title,omitempty"`
		HomeSubtitle        string `json:"home_subtitle,omitempty"`
		Locale              string `json:"locale,omitempty"`
		Version             string `json:"version,omitempty"`
		Commit              string `json:"commit,omitempty"`
	}{
		SiteTitle:           settings.SiteTitle,
		SiteIcon:            settings.SiteIcon,
		SiteBackgroundImage: settings.SiteBackgroundImage,
		HomeTitle:           settings.HomeTitle,
		HomeSubtitle:        settings.HomeSubtitle,
		Locale:              settings.Locale,
		Version:             store.buildVersion,
		Commit:              store.buildCommit,
	}
	payload := struct {
		Settings interface{} `json:"settings"`
		BasePath string      `json:"base_path,omitempty"`
	}{
		Settings: adminSettings,
		BasePath: forwardedPrefix(r, trustedProxyHeaders),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func writeLoginRateLimit(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(math.Ceil(retryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
	writeJSON(w, http.StatusTooManyRequests, map[string]string{
		"error": fmt.Sprintf("尝试次数过多，请在 %d 秒后重试", seconds),
	})
}
