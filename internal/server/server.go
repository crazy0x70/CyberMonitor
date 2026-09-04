package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"html"
	"io"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	maxLogSize                      = 10 * 1024 * 1024
	maxLogBackupCount               = 3
	maxTestHistoryPoints            = 5000
	testHistoryHotSeconds           = 60 * 60
	testHistoryMaxAgeSeconds        = 60 * 60 * 24 * 365
	maxJSONBodySize                 = 4 * 1024 * 1024
	maxHTTPHeaderBytes              = 1 << 20
	wsSendQueueSize                 = 8
	wsWriteWait                     = 10 * time.Second
	wsPongWait                      = 60 * time.Second
	wsPingPeriod                    = (wsPongWait * 9) / 10
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
	maxNetworkTestsPerNode          = 128
	nodeStaleGraceSeconds           = 12
	nodeStatusOnline                = "online"
	nodeStatusOffline               = "offline"
	nodeStatusWaitingRegistration   = "waiting_registration"
	publicVariantBalanced           = "balanced"
	adminVariant                    = "admin"
	adminSessionCookieName          = "cm_admin_session"
)

type sizeLimitedWriter struct {
	path    string
	maxSize int64
	mu      sync.Mutex
}

var reportLogger = log.New(io.Discard, "", log.LstdFlags)

func (w *sizeLimitedWriter) Write(p []byte) (int, error) {
	if w == nil || w.path == "" || w.maxSize <= 0 {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	dir := filepath.Dir(w.path)
	if dir != "" {
		_ = os.MkdirAll(dir, 0755)
	}

	file, err := os.OpenFile(w.path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return len(p), err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()

	info, err := file.Stat()
	if err != nil {
		return len(p), err
	}

	if info.Size()+int64(len(p)) > w.maxSize {
		if err := file.Close(); err != nil {
			return len(p), err
		}
		file = nil
		if err := rotateLogFile(w.path, maxLogBackupCount); err != nil {
			return len(p), err
		}
		file, err = os.OpenFile(w.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return len(p), err
		}
	} else {
		if _, err := file.Seek(0, io.SeekEnd); err != nil {
			return len(p), err
		}
	}

	_, err = file.Write(p)
	if err != nil {
		return len(p), err
	}
	return len(p), nil
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
	mu                 sync.RWMutex
	agentMutationMu    sync.RWMutex
	nodeMutationMu     sync.Mutex
	nodeMutationLocks  map[string]*nodeMutationLock
	persistMu          sync.Mutex
	nodes              map[string]NodeState
	profiles           map[string]*NodeProfile
	settings           Settings
	buildVersion       string
	buildCommit        string
	dataPath           string
	lastPersist        time.Time
	persistInterval    time.Duration
	alerted            map[string]alertState
	offlineSessions    map[string]OfflineSessionState
	testHistory        map[string]map[string]*TestHistoryEntry
	historyManager     *history.Manager
	pendingNodeDeletes map[string]struct{}
	pendingClearNodes  bool
	loginAttempts      map[string]*loginAttempt
	configRefresh      map[string]struct{}
	agentIngestRate    map[string]agentRateWindow
	agentRegisterRate  map[string]agentRateWindow
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
	ServerID                 string                  `json:"server_id,omitempty"`
	AgentAuthToken           string                  `json:"agent_auth_token,omitempty"`
	AlertEnabled             *bool                   `json:"alert_enabled,omitempty"`
	Alias                    string                  `json:"alias,omitempty"`
	Group                    string                  `json:"group,omitempty"`
	Tags                     []string                `json:"tags,omitempty"`
	Groups                   []string                `json:"groups,omitempty"`
	Region                   string                  `json:"region,omitempty"`
	DiskType                 string                  `json:"disk_type,omitempty"`
	NetSpeedMbps             int                     `json:"net_speed_mbps,omitempty"`
	ExpireAt                 int64                   `json:"expire_at,omitempty"`
	AutoRenew                bool                    `json:"auto_renew,omitempty"`
	RenewIntervalSec         int64                   `json:"renew_interval_sec,omitempty"`
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
	Stats                    metrics.NodeStats `json:"stats"`
	LastSeen                 int64             `json:"last_seen"`
	FirstSeen                int64             `json:"first_seen,omitempty"`
	Status                   string            `json:"status"`
	ServerID                 string            `json:"server_id,omitempty"`
	AlertEnabled             bool              `json:"alert_enabled"`
	Alias                    string            `json:"alias,omitempty"`
	Group                    string            `json:"group,omitempty"`
	Tags                     []string          `json:"tags,omitempty"`
	Groups                   []string          `json:"groups,omitempty"`
	Region                   string            `json:"region,omitempty"`
	DiskType                 string            `json:"disk_type,omitempty"`
	NetSpeedMbps             int               `json:"net_speed_mbps,omitempty"`
	ExpireAt                 int64             `json:"expire_at,omitempty"`
	AutoRenew                bool              `json:"auto_renew,omitempty"`
	RenewIntervalSec         int64             `json:"renew_interval_sec,omitempty"`
	TestIntervalSec          int               `json:"test_interval_sec,omitempty"`
	TestSelections           []TestSelection   `json:"test_selections,omitempty"`
	AgentUpdateSupported     bool              `json:"agent_update_supported"`
	AgentUpdateMode          string            `json:"agent_update_mode,omitempty"`
	AgentUpdateState         string            `json:"agent_update_state,omitempty"`
	AgentUpdateTargetVersion string            `json:"agent_update_target_version,omitempty"`
	AgentUpdateMessage       string            `json:"agent_update_message,omitempty"`
}

type PublicSettings struct {
	SiteTitle           string `json:"site_title,omitempty"`
	SiteIcon            string `json:"site_icon,omitempty"`
	SiteBackgroundImage string `json:"site_background_image,omitempty"`
	HomeTitle           string `json:"home_title,omitempty"`
	HomeSubtitle        string `json:"home_subtitle,omitempty"`
	Locale              string `json:"locale,omitempty"`
}

type Snapshot struct {
	Type        string                                  `json:"type"`
	GeneratedAt int64                                   `json:"generated_at"`
	Nodes       []NodeView                              `json:"nodes"`
	Groups      []string                                `json:"groups,omitempty"`
	Settings    PublicSettings                          `json:"settings,omitempty"`
	TestHistory map[string]map[string]*TestHistoryEntry `json:"test_history,omitempty"`
}

type PublicNodeHistoryResponse struct {
	NodeID   string                       `json:"node_id"`
	RangeKey string                       `json:"range_key"`
	From     int64                        `json:"from"`
	To       int64                        `json:"to"`
	Tests    map[string]*TestHistoryEntry `json:"tests"`
}

type NodeDelta struct {
	Type        string   `json:"type"`
	GeneratedAt int64    `json:"generated_at"`
	Node        NodeView `json:"node"`
}

type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]*hubClient
}

type hubMessage struct {
	messageType int
	payload     []byte
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

func (c *hubClient) writeMessage(messageType int, payload []byte) error {
	if c == nil || c.conn == nil {
		return errors.New("websocket 连接不存在")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
	return c.conn.WriteMessage(messageType, payload)
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
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Close()
}

func (c *hubClient) enqueue(messageType int, payload []byte) bool {
	if c == nil {
		return false
	}
	msg := hubMessage{messageType: messageType, payload: payload}
	if messageType == websocket.TextMessage {
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
				return false
			}
		}
	}
	select {
	case <-c.done:
		return false
	case c.send <- msg:
		return true
	default:
		return false
	}
}

func Run(ctx context.Context, cfg Config) error {
	if err := applyDefaults(&cfg); err != nil {
		return err
	}
	setupLogger(cfg.DataDir)

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
	testHistory := make(map[string]map[string]*TestHistoryEntry)
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
		PendingHistoryClear:   persisted.PendingHistoryClear,
		PendingHistoryDeletes: slices.Clone(persisted.PendingHistoryDeletes),
	}
	if err := savePersistedData(dataPath, persistedSnapshot); err != nil {
		return wrapDataPathError("写入持久化数据失败", dataPath, err)
	}

	historyManager, err := history.OpenManager(cfg.DataDir)
	if err != nil {
		return wrapDataPathError("初始化历史存储失败", history.HistoryRootDir(cfg.DataDir), err)
	}
	defer func() {
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
		alerted:           make(map[string]alertState),
		offlineSessions:   offlineSessions,
		testHistory:       testHistory,
		historyManager:    historyManager,
		loginAttempts:     make(map[string]*loginAttempt),
		configRefresh:     make(map[string]struct{}),
		agentIngestRate:   make(map[string]agentRateWindow),
		agentRegisterRate: make(map[string]agentRateWindow),
	}
	if _, err := recoverLegacyHistoryAndPendingCleanup(dataPath, historyPath, historyManager, store, persistedSnapshot); err != nil {
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

	publicMux := http.NewServeMux()
	adminMux := publicMux
	if splitMode {
		adminMux = http.NewServeMux()
	}

	adminMux.HandleFunc("/api/v1/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Username       string `json:"username"`
			Password       string `json:"password"`
			TurnstileToken string `json:"turnstile_token"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		now := time.Now()
		creds := store.Credentials()
		if !normalizeAdminAuthSettings(creds.AdminAuth).PasswordLoginEnabled {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "password login disabled"})
			return
		}
		attemptKey := loginAttemptKey(req.Username, r.RemoteAddr)
		if allowed, retryAfter := store.allowLoginAttempt(attemptKey, now); !allowed {
			writeLoginRateLimit(w, retryAfter)
			return
		}
		turnstileSettings := store.Credentials()
		if turnstileConfigured(turnstileSettings.TurnstileSiteKey, turnstileSettings.TurnstileSecretKey) {
			if err := verifyTurnstileToken(r.Context(), turnstileSettings.TurnstileSecretKey, req.TurnstileToken, clientIPFromRemoteAddr(r.RemoteAddr)); err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
				return
			}
		}
		if req.Username != creds.AdminUser || !store.VerifyAdminPassword(req.Password) {
			if locked, retryAfter := store.recordLoginFailure(attemptKey, now); locked {
				writeLoginRateLimit(w, retryAfter)
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		store.clearLoginAttempts(attemptKey)
		exp, err := issueAdminSession(w, r, cfg.JWTSecret, store, trustedProxyHeaders)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
			return
		}
		log.Printf("管理员登录: %s (%s)", req.Username, r.RemoteAddr)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"expires_at": exp,
		})
	})

	adminMux.HandleFunc("/api/v1/login/oauth/start", handleAdminOAuthStart(store, cfg.JWTSecret, trustedProxyHeaders))
	adminMux.HandleFunc("/api/v1/login/oauth/callback", handleAdminOAuthCallback(store, cfg.JWTSecret, trustedProxyHeaders))

	adminMux.HandleFunc("/api/v1/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if extractToken(r) != "" && isSameOrigin(r) {
			if err := validateAdminJWT(store, cfg.JWTSecret, r); err == nil {
				if err := store.RotateAdminTokenSalt(); err != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session revoke failed"})
					return
				}
				hub.CloseAdminClients()
			}
		}
		clearAdminSessionCookie(w, r, trustedProxyHeaders)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	adminMux.HandleFunc("/api/v1/login/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		view := store.SettingsView()
		settings := store.Credentials()
		enabled := turnstileConfigured(settings.TurnstileSiteKey, settings.TurnstileSecretKey)
		payload := map[string]interface{}{
			"turnstile_enabled": enabled,
		}
		for key, value := range buildAdminLoginConfig(store) {
			payload[key] = value
		}
		if enabled {
			payload["turnstile_site_key"] = strings.TrimSpace(view.TurnstileSiteKey)
		}
		writeJSON(w, http.StatusOK, payload)
	})

	healthHandler := withPublicCORS(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	publicMux.HandleFunc("/api/v1/health", healthHandler)
	if splitMode {
		adminMux.HandleFunc("/api/v1/health", healthHandler)
	}

	publicSnapshotHandler := withPublicCORS(func(w http.ResponseWriter, r *http.Request) {
		if !isPublicReadMethod(r) {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		snapshot := storeSnapshot(store, false)
		writeJSON(w, http.StatusOK, snapshot)
	})
	publicMux.HandleFunc("/api/v1/public/snapshot", publicSnapshotHandler)
	if splitMode {
		adminMux.HandleFunc("/api/v1/public/snapshot", publicSnapshotHandler)
	}

	publicMux.HandleFunc("/api/v1/public/nodes/", withPublicCORS(func(w http.ResponseWriter, r *http.Request) {
		if !isPublicReadMethod(r) {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")

		path := strings.TrimPrefix(r.URL.Path, "/api/v1/public/nodes/")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) != 2 || parts[1] != "history" {
			http.NotFound(w, r)
			return
		}
		nodeID, err := url.PathUnescape(parts[0])
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node id"})
			return
		}
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node id required"})
			return
		}

		rangeKey, from, to, err := parsePublicHistoryRange(r.URL.Query().Get("range"), time.Now())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if !store.HasNode(nodeID) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
			return
		}

		tests, err := store.QueryPublicNodeHistory(nodeID, from, to)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query public node history failed"})
			return
		}

		writeJSON(w, http.StatusOK, PublicNodeHistoryResponse{
			NodeID:   nodeID,
			RangeKey: rangeKey,
			From:     from.Unix(),
			To:       to.Unix(),
			Tests:    tests,
		})
	}))

	publicMux.HandleFunc("/api/v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}

		var payload metrics.NodeStats
		if err := decodeJSON(w, r, &payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		refreshConfig, err := agentAPI.ingest(r.RemoteAddr, payload, r.Header.Get("X-AGENT-TOKEN"))
		if err != nil {
			writeJSON(w, err.statusCode, map[string]string{"error": err.message})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":         "ok",
			"refresh_config": refreshConfig,
		})
	})

	agentUpdateAdminHandler := adminAgentUpdateHandler(store, hub, defaultAgentReleaseChecker)
	adminMux.HandleFunc("/api/v1/admin/nodes", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			snapshot := adminStoreSnapshot(store, parseBoolQuery(r, "history"))
			writeJSON(w, http.StatusOK, snapshot)
		case http.MethodDelete:
			handleAdminClearNodesRequest(w, r, store, hub)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}))

	adminMux.HandleFunc("/api/v1/admin/nodes/", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/nodes/")
		if strings.HasSuffix(path, "/agent/update") {
			agentUpdateAdminHandler(w, r)
			return
		}
		nodeID, ok := adminNodeIDFromPath(w, path)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodPut, http.MethodPatch:
			handleAdminUpdateNodeProfileRequest(w, r, store, hub, nodeID)
		case http.MethodDelete:
			handleAdminDeleteNodeRequest(w, r, store, hub, nodeID)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}))

	adminMux.HandleFunc("/api/v1/admin/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		authenticated := validateAdminJWT(store, cfg.JWTSecret, r) == nil
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": authenticated})
	})

	adminMux.HandleFunc("/api/v1/admin/logs", requireAdminJWT(store, cfg.JWTSecret, handleAdminLogsRequest))

	adminMux.HandleFunc("/api/v1/admin/settings", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			view := store.SettingsView()
			if splitMode && strings.TrimSpace(view.AgentEndpoint) == "" {
				view.AgentEndpoint = cfg.PublicAddr
			}
			writeJSON(w, http.StatusOK, view)
		case http.MethodPatch, http.MethodPut:
			var update SettingsUpdate
			if err := decodeJSON(w, r, &update); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			view, err := store.UpdateSettings(update)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if splitMode && strings.TrimSpace(view.AgentEndpoint) == "" {
				view.AgentEndpoint = cfg.PublicAddr
			}
			if err := refreshAdminSessionCookie(w, r, cfg.JWTSecret, store, trustedProxyHeaders); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session refresh failed"})
				return
			}
			broadcastStoreSnapshot(hub, store, false)
			writeJSON(w, http.StatusOK, view)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}))

	adminMux.HandleFunc("/api/v1/admin/system/update", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, systemUpdater.View(r.Context(), false))
		case http.MethodPost:
			if !updater.CanCurrentDeployUpdate() {
				message := updater.DefaultUnsupportedUpdateMessage()
				if strings.TrimSpace(message) == "" {
					message = "当前平台暂不支持服务端自更新"
				}
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": message})
				return
			}
			reservation, err := systemUpdater.ReserveStart()
			if err != nil {
				if errors.Is(err, errSystemUpdateInProgress) {
					writeJSON(w, http.StatusConflict, map[string]string{"error": "当前已有服务端更新任务正在执行"})
					return
				}
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			releaseInfo, err := systemUpdater.CheckLatest(r.Context())
			if err != nil {
				reservation.Cancel()
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if err := validateReleaseTargetVersion(releaseInfo); err != nil {
				reservation.Cancel()
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !releaseInfo.HasUpdate && updater.VersionCurrentOrNewer(releaseInfo.CurrentVersion, releaseInfo.LatestVersion) {
				reservation.Cancel()
				writeJSON(w, http.StatusOK, map[string]string{
					"status":         "up_to_date",
					"target_version": releaseInfo.LatestVersion,
				})
				return
			}
			dockerManaged := updater.CanDockerManagedUpdate()
			if message := systemUpdateReleaseAssetError(releaseInfo, dockerManaged); message != "" {
				reservation.Cancel()
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": message})
				return
			}
			err = reservation.Start(releaseInfo, dockerManaged, func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				if dockerManaged {
					dockerUpdater, err := updater.NewDockerManagedUpdaterContext(ctx)
					if err != nil {
						return err
					}
					targetImage, err := updater.ResolveDockerTargetImage(dockerUpdater.CurrentImage(), releaseInfo.LatestVersion)
					if err != nil {
						return fmt.Errorf("解析 Docker 目标镜像失败: %w", err)
					}
					return dockerUpdater.LaunchSelfContainerUpdate(ctx, targetImage, "")
				}
				if err := systemUpdater.client.ApplyReleaseAsset(ctx, releaseInfo.LatestVersion, releaseInfo.DownloadURL, releaseInfo.ChecksumURL); err != nil {
					return err
				}
				time.Sleep(700 * time.Millisecond)
				return updater.RestartSelf()
			})
			if err != nil {
				if errors.Is(err, errSystemUpdateInProgress) {
					writeJSON(w, http.StatusConflict, map[string]string{"error": "当前已有服务端更新任务正在执行"})
					return
				}
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]string{
				"status":         "started",
				"target_version": releaseInfo.LatestVersion,
			})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}))

	adminMux.HandleFunc("/api/v1/admin/config/export", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		payload := store.ExportConfig()
		if splitMode && strings.TrimSpace(payload.Settings.AgentEndpoint) == "" {
			payload.Settings.AgentEndpoint = cfg.PublicAddr
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "export failed"})
			return
		}
		filename := fmt.Sprintf("cybermonitor-config-%s.json", time.Now().Format("20060102-150405"))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))

	adminMux.HandleFunc("/api/v1/admin/config/import", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var payload ConfigTransferData
		if err := decodeJSON(w, r, &payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		view, err := store.ImportConfig(payload)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if splitMode && strings.TrimSpace(view.AgentEndpoint) == "" {
			view.AgentEndpoint = cfg.PublicAddr
		}
		if err := refreshAdminSessionCookie(w, r, cfg.JWTSecret, store, trustedProxyHeaders); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session refresh failed"})
			return
		}
		broadcastStoreSnapshot(hub, store, false)
		writeJSON(w, http.StatusOK, map[string]any{
			"settings": view,
		})
	}))

	adminMux.HandleFunc("/api/v1/admin/alerts/test", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Webhook         string  `json:"webhook"`
			TelegramToken   string  `json:"telegram_token"`
			TelegramUserIDs []int64 `json:"telegram_user_ids"`
			TelegramUserID  int64   `json:"telegram_user_id"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		webhook := strings.TrimSpace(req.Webhook)
		telegramToken := strings.TrimSpace(req.TelegramToken)
		telegramUserIDs := normalizeTelegramUserIDs(req.TelegramUserIDs)
		if len(telegramUserIDs) == 0 && req.TelegramUserID > 0 {
			telegramUserIDs = []int64{req.TelegramUserID}
		}
		if webhook == "" {
			webhook = store.AlertWebhook()
		}
		if telegramToken == "" || len(telegramUserIDs) == 0 {
			cfgToken, cfgUserIDs := store.TelegramSettings()
			if telegramToken == "" {
				telegramToken = cfgToken
			}
			if len(telegramUserIDs) == 0 {
				telegramUserIDs = cfgUserIDs
			}
		}
		if webhook == "" && (telegramToken == "" || len(telegramUserIDs) == 0) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请先配置飞书或 Telegram 告警"})
			return
		}
		siteTitle := store.SiteTitle()
		var errs []string
		if webhook != "" {
			if err := sendFeishuTest(webhook, siteTitle); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if telegramToken != "" && len(telegramUserIDs) > 0 {
			errs = append(errs, sendTelegramTest(telegramToken, telegramUserIDs, siteTitle)...)
		}
		if len(errs) > 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": strings.Join(errs, "; ")})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	adminMux.HandleFunc("/api/v1/admin/ai/test", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Provider string            `json:"provider"`
			Config   *AIProviderConfig `json:"config"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if strings.TrimSpace(req.Provider) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider required"})
			return
		}
		settings, err := store.AISettings()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		selection, err := resolveAIProviderConfigWithOverride(settings, req.Provider, req.Config)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
		defer cancel()
		if err := testAIProvider(ctx, selection.Provider, selection.Config); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	adminMux.HandleFunc("/api/v1/admin/ai/models", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Provider string            `json:"provider"`
			Config   *AIProviderConfig `json:"config"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if strings.TrimSpace(req.Provider) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider required"})
			return
		}
		settings, err := store.AISettings()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		selection, err := resolveAIProviderConfigWithOverride(settings, req.Provider, req.Config)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
		defer cancel()
		models, err := listAIModels(ctx, selection.Provider, selection.Config)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"models": models})
	}))

	publicMux.HandleFunc("/api/v1/agent/config", agentConfigHTTPHandler(agentAPI))

	publicMux.HandleFunc("/api/v1/agent/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
		agentToken, err := agentAPI.register(nodeID, r.Header.Get("X-AGENT-TOKEN"))
		if err != nil {
			writeJSON(w, err.statusCode, map[string]string{"error": err.message})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"node_id":     nodeID,
			"agent_token": agentToken,
		})
	})

	publicMux.HandleFunc("/api/v1/agent/update/report", agentUpdateReportHTTPHandler(agentAPI))

	type wsAuthMode int
	const (
		wsAuthPublic wsAuthMode = iota
		wsAuthRequired
		wsAuthMixed
	)

	wsHandler := func(mode wsAuthMode) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			audience := "public"
			adminTokenSalt := ""
			switch mode {
			case wsAuthRequired:
				if extractToken(r) == "" {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
				if !isSameOrigin(r) {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
				if err := validateAdminJWT(store, cfg.JWTSecret, r); err != nil {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
				audience = "admin"
				adminTokenSalt = store.Credentials().TokenSalt
			case wsAuthPublic:
			case wsAuthMixed:
				if extractToken(r) == "" {
					break
				}
				if !isSameOrigin(r) {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
				if err := validateAdminJWT(store, cfg.JWTSecret, r); err != nil {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
				audience = "admin"
				adminTokenSalt = store.Credentials().TokenSalt
			}
			upgrader := websocket.Upgrader{
				CheckOrigin: func(request *http.Request) bool {
					// admin 连接保持严格的同源校验（连 token 都要求
					// same-origin）。public 数据按设计免认证公开，允许
					// 任意 Origin 连接——静态托管（Cloudflare Pages 等）
					// 跨源访问公开看板必须如此。
					if audience == "admin" {
						return isSameOrigin(request)
					}
					return true
				},
			}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			configureWSConn(conn)
			variant := publicVariantBalanced
			snapshot := storeSnapshot(store, false)
			if audience == "admin" {
				variant = adminVariant
				snapshot = adminStoreSnapshot(store, false)
			}
			client := hub.Add(conn, variant, adminTokenSalt)

			// 首次连接立即推送快照
			payload, _ := json.Marshal(snapshot)
			if client != nil {
				if ok := client.enqueue(websocket.TextMessage, payload); !ok {
					hub.Remove(conn)
					return
				}
			}

			go heartbeatLoop(client, hub)
			go writeLoop(client, hub)
			go readLoop(client, hub)
		}
	}

	if splitMode {
		publicMux.HandleFunc("/ws", wsHandler(wsAuthPublic))
		adminMux.HandleFunc("/ws", wsHandler(wsAuthRequired))
	} else {
		publicMux.HandleFunc("/ws", wsHandler(wsAuthMixed))
	}

	assetsRoot, err := fs.Sub(webRoot, "public/assets")
	if err != nil {
		return err
	}
	assetsHandler := withNoStore(http.StripPrefix("/assets/", http.FileServer(http.FS(assetsRoot))))

	adminDistRoot, err := fs.Sub(webRoot, "dist/admin")
	if err != nil {
		return err
	}
	adminDistFileServer := http.FileServer(http.FS(adminDistRoot))
	publicMux.Handle("/assets/", assetsHandler)
	if splitMode {
		adminMux.Handle("/assets/", assetsHandler)
	}

	if !splitMode {
		publicMux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/dashboard" {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)
		})
	}

	writePublicIndexHTML := func(w http.ResponseWriter, r *http.Request) {
		data, err := webFS.ReadFile("web/public/index.html")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "index not found"})
			return
		}
		htmlText := string(data)
		if prefix := forwardedPrefix(r, trustedProxyHeaders); prefix != "" {
			baseTag := `<base href="` + html.EscapeString(prefix+"/") + `" />`
			if strings.Contains(htmlText, "<head>") {
				htmlText = strings.Replace(htmlText, "<head>", "<head>"+baseTag, 1)
			} else {
				htmlText = baseTag + htmlText
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(htmlText))
	}

	writeAdminAppHTML := func(w http.ResponseWriter, r *http.Request) {
		data, err := webFS.ReadFile("web/dist/admin/index.html")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "admin app not found"})
			return
		}
		htmlText := string(data)
		htmlText = strings.Replace(htmlText, "<title>CyberMonitor 管理后台</title>", "<title>"+html.EscapeString(adminDocumentTitle(store.SiteTitle()))+"</title>", 1)
		bootPayload, err := buildAdminBootPayload(store, r, trustedProxyHeaders)
		if err == nil {
			bootMeta := `<meta name="cm-admin-boot" content="` + bootPayload + `" />`
			if strings.Contains(htmlText, "</head>") {
				htmlText = strings.Replace(htmlText, "</head>", bootMeta+"</head>", 1)
			} else {
				htmlText = bootMeta + htmlText
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(htmlText))
	}

	serveAdminDistAt := func(w http.ResponseWriter, r *http.Request, prefix string) {
		trimmedPath := strings.TrimPrefix(r.URL.Path, prefix)
		if trimmedPath == r.URL.Path {
			http.NotFound(w, r)
			return
		}
		next := r.Clone(r.Context())
		next.URL.Path = "/" + strings.TrimPrefix(trimmedPath, "/")
		if r.URL.RawPath != "" {
			trimmedRawPath := strings.TrimPrefix(r.URL.RawPath, prefix)
			next.URL.RawPath = "/" + strings.TrimPrefix(trimmedRawPath, "/")
		}
		withNoStore(adminDistFileServer).ServeHTTP(w, next)
	}

	handleAdminRequest := func(w http.ResponseWriter, r *http.Request) bool {
		adminPath := store.AdminPath()
		adminPrefix := adminPath + "/"

		switch r.URL.Path {
		case adminPath:
			http.Redirect(w, r, forwardedPrefixedPath(r, adminPrefix, trustedProxyHeaders), http.StatusFound)
			return true
		case adminPrefix:
			writeAdminAppHTML(w, r)
			return true
		}

		if strings.HasPrefix(r.URL.Path, adminPrefix) {
			serveAdminDistAt(w, r, adminPrefix)
			return true
		}

		return false
	}

	if splitMode {
		adminMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if handleAdminRequest(w, r) {
				return
			}
			http.NotFound(w, r)
		})

		publicMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/", "/dashboard":
				writePublicIndexHTML(w, r)
				return
			default:
				http.NotFound(w, r)
			}
		})
	} else {
		publicMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if handleAdminRequest(w, r) {
				return
			}
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writePublicIndexHTML(w, r)
		})
	}

	grpcServer := newAgentRPCServer(agentAPI)
	publicHandler := stripForwardedPrefixPath(wrapPublicHandler(publicMux, grpcServer), trustedProxyHeaders)
	publicServer := newHTTPServer(cfg.PublicAddr, withSecurityHeaders(publicHandler))

	adminServer := &http.Server{}
	if splitMode {
		adminServer = newHTTPServer(cfg.Addr, withSecurityHeaders(stripForwardedPrefixPath(adminMux, trustedProxyHeaders)))
	}

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		lastBalancedDigest := ""
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				hasBalanced := hub.HasVariant(publicVariantBalanced)
				if hasBalanced {
					snapshot := storeSnapshot(store, false)
					digest := digestPublicSnapshot(snapshot)
					if digest != lastBalancedDigest {
						payload, err := json.Marshal(snapshot)
						if err != nil {
							log.Printf("序列化节点快照失败: %v", err)
						} else {
							hub.BroadcastVariant(payload, publicVariantBalanced)
							lastBalancedDigest = digest
						}
					}
				}
				store.ReconcileOfflineTracker(now)
				targets, offlineEvents, recoveredEvents := store.CollectAlertEvents(now)
				logReportEvents(targets.SiteTitle, offlineEvents, recoveredEvents)
				if len(offlineEvents) > 0 {
					go sendFeishuAlert(targets.FeishuWebhook, targets.SiteTitle, offlineEvents)
					go sendTelegramAlert(targets.TelegramToken, targets.TelegramUserIDs, targets.SiteTitle, offlineEvents)
				}
				if len(recoveredEvents) > 0 {
					go sendFeishuRecovery(targets.FeishuWebhook, targets.SiteTitle, recoveredEvents)
					go sendTelegramRecovery(targets.TelegramToken, targets.TelegramUserIDs, targets.SiteTitle, recoveredEvents)
				}
			}
		}
	}()

	startTelegramBot(ctx, store)

	go func() {
		<-ctx.Done()
		_ = publicServer.Shutdown(context.Background())
		if splitMode {
			_ = adminServer.Shutdown(context.Background())
		}
	}()

	log.Printf("管理后台路径已初始化")
	if splitMode {
		log.Printf("展示页监听: %s", cfg.PublicAddr)
		log.Printf("管理后台监听: %s", cfg.Addr)
	}
	if !loaded {
		log.Printf("初始管理员账号: %s", settings.AdminUser)
		if settings.AdminPassPlain != "" {
			log.Printf("初始管理员密码已生成，请从持久化配置或重置命令获取")
		} else {
			log.Printf("初始管理员密码: 已设置")
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
				_ = adminServer.Shutdown(context.Background())
				_ = publicServer.Shutdown(context.Background())
				return err
			}
		}
		return nil
	}
	if err := publicServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    maxHTTPHeaderBytes,
	}
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
	secret, err := randomToken(32)
	if err != nil {
		return "", err
	}
	claims := jwt.RegisteredClaims{
		Subject:  "bootstrap",
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		fallback, tokenErr := randomToken(48)
		if tokenErr != nil {
			return "", tokenErr
		}
		return fallback, nil
	}
	return signed, nil
}

// updateNodeStats requires the caller to hold lockAgentNodeRead(stats.NodeID).
func (s *Store) updateNodeStats(stats metrics.NodeStats) (bool, *offlineRecoveryCandidate, error) {
	var persist bool
	var recoveryCandidate *offlineRecoveryCandidate
	var updateReconciled bool
	now := time.Now()

	s.mu.Lock()

	prev, hadNode := s.nodes[stats.NodeID]
	previousProfile, hadProfile := s.profiles[stats.NodeID]
	var previousProfileSnapshot NodeProfile
	if previousProfile != nil {
		previousProfileSnapshot = cloneNodeProfileValue(previousProfile)
	}
	rollbackNodeProfile := func() {
		if hadNode {
			s.nodes[stats.NodeID] = prev
		} else {
			delete(s.nodes, stats.NodeID)
		}
		if !hadProfile {
			delete(s.profiles, stats.NodeID)
			return
		}
		if previousProfile == nil {
			s.profiles[stats.NodeID] = nil
			return
		}
		restoredProfile := previousProfileSnapshot
		s.profiles[stats.NodeID] = &restoredProfile
	}
	firstSeen := prev.FirstSeen
	if firstSeen.IsZero() {
		firstSeen = now
	}
	acceptStats := shouldReplaceNodeStats(prev.Stats, stats)
	mergedStats := mergeNodeStatsStaticInfo(prev.Stats, stats)
	storedStats := cloneNodeStats(mergedStats)
	if !acceptStats {
		storedStats = cloneNodeStats(prev.Stats)
	} else if !mergedStats.NetworkTestsChanged && len(mergedStats.NetworkTests) == 0 && len(prev.Stats.NetworkTests) > 0 {
		storedStats.NetworkTests = cloneNetworkTestResults(prev.Stats.NetworkTests)
	}
	s.nodes[stats.NodeID] = NodeState{
		Stats:     storedStats,
		LastSeen:  now,
		FirstSeen: firstSeen,
	}

	profile := s.ensureProfileLocked(stats.NodeID)
	serverIDChanged, err := s.ensureServerIDLocked(stats.NodeID, profile)
	if err != nil {
		rollbackNodeProfile()
		s.mu.Unlock()
		return false, nil, err
	}
	if serverIDChanged {
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
	if storedStats.NodeGroup != "" {
		if profile.Group == "" {
			profile.Group = storedStats.NodeGroup
			persist = true
		}
		if len(profile.Groups) == 0 {
			profile.Groups = normalizeGroupSelections(selectionsFromGroupTags(storedStats.NodeGroup, nil))
			group, tags := primaryGroupTagsFromSelections(profile.Groups)
			if group != "" {
				profile.Group = group
			}
			profile.Tags = tags
			persist = true
		}
	}
	if s.applyAutoRenewLocked(profile, now) {
		persist = true
	}
	if reconcileAgentUpdateWithStatsLocked(profile, storedStats, now) {
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
		persist = true
	}

	if acceptStats {
		s.updateTestHistoryLocked(mergedStats, now)
	}
	if s.shouldPersistLocked(now) {
		persist = true
	}
	s.mu.Unlock()

	if persist {
		s.persist()
	}
	s.mu.RLock()
	historyManager := s.historyManager
	s.mu.RUnlock()
	if acceptStats && historyManager != nil && len(storedStats.NetworkTests) > 0 && mergedStats.NetworkTestsChanged {
		if err := historyManager.AppendNetworkBatch(mergedStats.NodeID, mergedStats.NetworkTests, now); err != nil {
			log.Printf("写入 network TSDB 失败: %v", err)
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
		return cloneGPUInfos(current)
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

func (s *Store) updateTestHistoryLocked(stats metrics.NodeStats, now time.Time) bool {
	if len(stats.NetworkTests) == 0 {
		return false
	}
	nodeID := strings.TrimSpace(stats.NodeID)
	if nodeID == "" {
		return false
	}
	if s.testHistory == nil {
		s.testHistory = make(map[string]map[string]*TestHistoryEntry)
	}
	nodeHistory := s.testHistory[nodeID]
	if nodeHistory == nil {
		nodeHistory = make(map[string]*TestHistoryEntry)
		s.testHistory[nodeID] = nodeHistory
	}
	nowSec := now.Unix()
	changed := false
	for _, test := range stats.NetworkTests {
		key := buildTestHistoryKey(test)
		if key == "" {
			continue
		}
		entry := nodeHistory[key]
		if entry == nil {
			entry = &TestHistoryEntry{}
			nodeHistory[key] = entry
		}
		normalizeHistoryEntry(entry)
		checkedAt := test.CheckedAt
		if checkedAt <= 0 {
			checkedAt = nowSec
		}
		if entry.LastAt == 0 && len(entry.Times) > 0 {
			entry.LastAt = entry.Times[len(entry.Times)-1]
		}
		if checkedAt <= entry.LastAt {
			continue
		}
		if entry.LastAt > 0 {
			interval := checkedAt - entry.LastAt
			if interval > 0 {
				if entry.MinIntervalSec == 0 || interval < entry.MinIntervalSec {
					entry.MinIntervalSec = interval
				}
				if entry.AvgIntervalSec == 0 {
					entry.AvgIntervalSec = float64(interval)
				} else {
					entry.AvgIntervalSec = entry.AvgIntervalSec*0.9 + float64(interval)*0.1
				}
			}
		}
		entry.Latency = append(entry.Latency, history.CloneFloatPtr(test.LatencyMs))
		entry.Loss = append(entry.Loss, history.NormalizeFloat(test.PacketLoss))
		entry.Times = append(entry.Times, checkedAt)
		entry.LastAt = checkedAt
		trimHistoryEntry(entry, nowSec)
		changed = true
	}
	return changed
}

func buildTestHistoryKey(test metrics.NetworkTestResult) string {
	kind := strings.ToLower(strings.TrimSpace(test.Type))
	if kind == "" {
		kind = "icmp"
	}
	host := strings.ToLower(strings.TrimSpace(test.Host))
	name := strings.ToLower(strings.TrimSpace(test.Name))
	if host == "" && name == "" {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(kind) + len(host) + len(name) + 16)
	builder.WriteString(kind)
	builder.WriteByte('|')
	builder.WriteString(host)
	builder.WriteByte('|')
	builder.WriteString(strconv.Itoa(test.Port))
	builder.WriteByte('|')
	builder.WriteString(name)
	return builder.String()
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

func trimHistoryEntry(entry *TestHistoryEntry, nowSec int64) bool {
	if entry == nil {
		return false
	}
	normalizeHistoryEntry(entry)
	if len(entry.Times) == 0 {
		entry.LastAt = 0
		return false
	}
	if nowSec <= 0 {
		nowSec = entry.LastAt
	}
	if nowSec <= 0 {
		nowSec = entry.Times[len(entry.Times)-1]
	}

	changed := false
	cutoff := nowSec - testHistoryMaxAgeSeconds
	if cutoff > 0 {
		idx := sort.Search(len(entry.Times), func(i int) bool {
			return entry.Times[i] >= cutoff
		})
		if idx > 0 {
			entry.Times = entry.Times[idx:]
			entry.Latency = entry.Latency[idx:]
			entry.Loss = entry.Loss[idx:]
			changed = true
		}
	}
	if len(entry.Times) == 0 {
		entry.Latency = entry.Latency[:0]
		entry.Loss = entry.Loss[:0]
		entry.LastAt = 0
		return changed
	}

	total := len(entry.Times)
	if total <= maxTestHistoryPoints {
		if entry.LastAt == 0 {
			entry.LastAt = entry.Times[len(entry.Times)-1]
		}
		return changed
	}

	hotCutoff := nowSec - testHistoryHotSeconds
	hotIndex := sort.Search(total, func(i int) bool {
		return entry.Times[i] >= hotCutoff
	})
	hotCount := total - hotIndex
	if hotCount >= maxTestHistoryPoints {
		start := total - maxTestHistoryPoints
		entry.Times = entry.Times[start:]
		entry.Latency = entry.Latency[start:]
		entry.Loss = entry.Loss[start:]
		entry.LastAt = entry.Times[len(entry.Times)-1]
		return true
	}

	remaining := maxTestHistoryPoints - hotCount
	olderCount := hotIndex
	step := int(math.Ceil(float64(olderCount) / float64(remaining)))
	if step < 1 {
		step = 1
	}
	newLen := 0
	if olderCount > 0 {
		newLen = (olderCount-1)/step + 1
	}
	newTimes := make([]int64, 0, newLen+hotCount)
	newLatency := make([]*float64, 0, newLen+hotCount)
	newLoss := make([]*float64, 0, newLen+hotCount)
	for i := 0; i < olderCount; i += step {
		newTimes = append(newTimes, entry.Times[i])
		newLatency = append(newLatency, entry.Latency[i])
		newLoss = append(newLoss, entry.Loss[i])
	}
	if olderCount > 0 {
		last := olderCount - 1
		if len(newTimes) == 0 || newTimes[len(newTimes)-1] != entry.Times[last] {
			newTimes = append(newTimes, entry.Times[last])
			newLatency = append(newLatency, entry.Latency[last])
			newLoss = append(newLoss, entry.Loss[last])
		}
	}
	newTimes = append(newTimes, entry.Times[hotIndex:]...)
	newLatency = append(newLatency, entry.Latency[hotIndex:]...)
	newLoss = append(newLoss, entry.Loss[hotIndex:]...)
	entry.Times = newTimes
	entry.Latency = newLatency
	entry.Loss = newLoss
	entry.LastAt = entry.Times[len(entry.Times)-1]
	return true
}

type AlertEvent struct {
	NodeID     string
	Display    string
	OS         string
	LastSeen   int64
	OfflineSec int64
}

type AlertTargets struct {
	FeishuWebhook   string
	TelegramToken   string
	TelegramUserIDs []int64
	SiteTitle       string
}

type alertState struct {
	OfflineSince time.Time
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

	threshold := time.Duration(s.settings.AlertOfflineSec) * time.Second
	if threshold > 0 {
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
			recoveredAt := node.LastSeen.UTC()
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
		s.persist()
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

// completeOfflineRecoveryProtected requires the caller to hold a node mutation
// gate that blocks DeleteNode/ClearNodes for candidate.NodeID.
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
		s.persist()
	}
}

func (s *Store) CollectAlertEvents(now time.Time) (AlertTargets, []AlertEvent, []AlertEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	targets := AlertTargets{
		FeishuWebhook:   strings.TrimSpace(s.settings.AlertWebhook),
		TelegramToken:   strings.TrimSpace(s.settings.AlertTelegramToken),
		TelegramUserIDs: normalizeTelegramUserIDs(slices.Clone(s.settings.AlertTelegramUserIDs)),
		SiteTitle:       normalizeSiteTitle(s.settings.SiteTitle),
	}
	if targets.TelegramToken == "" || len(targets.TelegramUserIDs) == 0 {
		targets.TelegramToken = ""
		targets.TelegramUserIDs = nil
	}
	if s.settings.AlertOfflineSec <= 0 {
		return AlertTargets{}, nil, nil
	}
	threshold := time.Duration(s.settings.AlertOfflineSec) * time.Second
	offlineEvents := make([]AlertEvent, 0)
	recoveredEvents := make([]AlertEvent, 0)
	for nodeID, node := range s.nodes {
		state, wasAlerted := s.alerted[nodeID]
		profile := s.ensureProfileLocked(nodeID)
		if !isAlertEnabled(profile) {
			delete(s.alerted, nodeID)
			continue
		}
		offlineFor := now.Sub(node.LastSeen)
		if offlineFor < threshold {
			if wasAlerted {
				stats := node.Stats
				display := resolveAlertDisplay(profile, stats, nodeID)
				offlineSec := int64(now.Sub(state.OfflineSince).Seconds())
				if state.OfflineSince.IsZero() {
					offlineSec = 0
				}
				recoveredEvents = append(recoveredEvents, AlertEvent{
					NodeID:     nodeID,
					Display:    display,
					OS:         stats.OS,
					LastSeen:   node.LastSeen.Unix(),
					OfflineSec: offlineSec,
				})
				delete(s.alerted, nodeID)
			}
			continue
		}
		if wasAlerted {
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
		s.alerted[nodeID] = alertState{OfflineSince: node.LastSeen}
	}

	for nodeID := range s.alerted {
		if _, ok := s.nodes[nodeID]; !ok {
			delete(s.alerted, nodeID)
		}
	}

	return targets, offlineEvents, recoveredEvents
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

func sendFeishuAlert(webhook, siteTitle string, events []AlertEvent) {
	if webhook == "" || len(events) == 0 {
		return
	}
	if err := sendFeishuText(webhook, buildAlertMessage(siteTitle, events)); err != nil {
		log.Printf("告警发送失败: %v", err)
	}
}

func sendFeishuRecovery(webhook, siteTitle string, events []AlertEvent) {
	if webhook == "" || len(events) == 0 {
		return
	}
	if err := sendFeishuText(webhook, buildRecoveryMessage(siteTitle, events)); err != nil {
		log.Printf("恢复通知发送失败: %v", err)
	}
}

func sendFeishuTest(webhook, siteTitle string) error {
	message := fmt.Sprintf("【%s】告警测试 %s", normalizeSiteTitle(siteTitle), time.Now().Format("2006-01-02 15:04:05"))
	return sendFeishuText(webhook, message)
}

func sendFeishuText(webhook, text string) error {
	webhook = strings.TrimSpace(webhook)
	if webhook == "" || strings.TrimSpace(text) == "" {
		return errors.New("webhook 或消息为空")
	}
	if err := validateWebhookURL(webhook); err != nil {
		return err
	}
	payload := map[string]any{
		"msg_type": "text",
		"content": map[string]string{
			"text": text,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("告警消息编码失败: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("告警请求创建失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := newWebhookHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("告警发送失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := readResponseBodyLimited(resp.Body)
		return fmt.Errorf("webhook 响应错误: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func buildAlertMessage(siteTitle string, events []AlertEvent) string {
	lines := []string{fmt.Sprintf("【%s】服务器离线告警", normalizeSiteTitle(siteTitle)), "", "离线节点："}
	for _, event := range events {
		label := formatAlertValue(event.Display, "未命名节点")
		detail := ""
		if event.OfflineSec > 0 {
			detail = fmt.Sprintf("（离线 %s）", formatAlertDuration(event.OfflineSec))
		}
		lines = append(lines, fmt.Sprintf("• %s%s", label, detail))
	}
	lines = append(lines, "", "请及时检查服务器状态。")
	return strings.Join(lines, "\n")
}

func buildRecoveryMessage(siteTitle string, events []AlertEvent) string {
	lines := []string{fmt.Sprintf("【%s】服务器恢复在线", normalizeSiteTitle(siteTitle)), "", "已恢复节点："}
	for _, event := range events {
		label := formatAlertValue(event.Display, "未命名节点")
		detail := fmt.Sprintf("（离线 %s）", formatAlertDuration(event.OfflineSec))
		lines = append(lines, fmt.Sprintf("• %s%s", label, detail))
	}
	lines = append(lines, "", "服务已恢复。")
	return strings.Join(lines, "\n")
}

func logReportEvents(siteTitle string, offlineEvents, recoveredEvents []AlertEvent) {
	title := normalizeSiteTitle(siteTitle)
	for _, event := range offlineEvents {
		reportLogger.Printf("[%s] 离线：%s（node=%s，最后=%s，时长=%s）",
			title,
			formatAlertValue(event.Display, "未命名节点"),
			formatAlertValue(event.NodeID, "unknown"),
			formatReportEventTime(event.LastSeen),
			formatAlertDuration(event.OfflineSec),
		)
	}
	for _, event := range recoveredEvents {
		reportLogger.Printf("[%s] 恢复：%s（node=%s，恢复=%s，时长=%s）",
			title,
			formatAlertValue(event.Display, "未命名节点"),
			formatAlertValue(event.NodeID, "unknown"),
			formatReportEventTime(event.LastSeen),
			formatAlertDuration(event.OfflineSec),
		)
	}
}

func formatReportEventTime(unixSeconds int64) string {
	if unixSeconds <= 0 {
		return "unknown"
	}
	return time.Unix(unixSeconds, 0).UTC().Format(time.DateTime)
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
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
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

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func cloneInt64Slice(values []int64) []int64 {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]int64, len(values))
	copy(cloned, values)
	return cloned
}

func cloneDiskPartitions(values []metrics.DiskPartition) []metrics.DiskPartition {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]metrics.DiskPartition, len(values))
	copy(cloned, values)
	return cloned
}

func cloneGPUInfos(values []metrics.GPUInfo) []metrics.GPUInfo {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]metrics.GPUInfo, len(values))
	copy(cloned, values)
	return cloned
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
	stats.Disk = cloneDiskPartitions(stats.Disk)
	stats.GPU = cloneGPUInfos(stats.GPU)
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

func cloneNetworkTestConfigs(values []metrics.NetworkTestConfig) []metrics.NetworkTestConfig {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]metrics.NetworkTestConfig, len(values))
	copy(cloned, values)
	return cloned
}

func cloneTestSelections(values []TestSelection) []TestSelection {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]TestSelection, len(values))
	copy(cloned, values)
	return cloned
}

func cloneTestCatalogItems(values []TestCatalogItem) []TestCatalogItem {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]TestCatalogItem, len(values))
	copy(cloned, values)
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

func cloneAICompatibles(values []AIProviderProfile) []AIProviderProfile {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]AIProviderProfile, len(values))
	copy(cloned, values)
	return cloned
}

func cloneAISettings(settings AISettings) AISettings {
	settings.OpenAICompatibles = cloneAICompatibles(settings.OpenAICompatibles)
	return settings
}

func cloneSettings(settings Settings) Settings {
	settings.AlertTelegramUserIDs = cloneInt64Slice(settings.AlertTelegramUserIDs)
	settings.AdminAuth = cloneAdminAuthSettings(settings.AdminAuth)
	settings.AISettings = cloneAISettings(settings.AISettings)
	settings.Groups = cloneStringSlice(settings.Groups)
	settings.GroupTree = cloneGroupNodes(settings.GroupTree)
	settings.TestCatalog = cloneTestCatalogItems(settings.TestCatalog)
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

func shouldDispatchAgentUpdate(profile *NodeProfile, now time.Time) bool {
	if profile == nil || profile.AgentUpdate == nil {
		return false
	}
	if isAgentUpdateTerminalState(profile.AgentUpdateState) {
		return false
	}
	return profile.AgentUpdateLeaseUntil <= now.Unix()
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
	if osLabel == "" {
		return "binary"
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
		return "Docker 部署的 Agent 需要挂载 /var/run/docker.sock 才能启用后台一键更新"
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

func firstTelegramUserID(ids []int64) int64 {
	normalized := normalizeTelegramUserIDs(ids)
	if len(normalized) == 0 {
		return 0
	}
	return normalized[0]
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
	case "30d":
		duration = 30 * 24 * time.Hour
	case "1y":
		duration = 366 * 24 * time.Hour
	default:
		return "", time.Time{}, time.Time{}, fmt.Errorf("invalid range")
	}

	return rangeKey, to.Add(-duration), to, nil
}

func storeSnapshot(s *Store, withHistory bool) Snapshot {
	return buildStoreSnapshot(s, s.Snapshot(), withHistory)
}

func adminStoreSnapshot(s *Store, withHistory bool) Snapshot {
	return buildStoreSnapshot(s, s.AdminSnapshot(), withHistory)
}

func buildStoreSnapshot(s *Store, nodes []NodeView, withHistory bool) Snapshot {
	snapshot := Snapshot{
		Type:        "snapshot",
		GeneratedAt: time.Now().Unix(),
		Nodes:       nodes,
		Groups:      s.SettingsGroups(),
		Settings:    s.PublicSettings(),
	}
	if withHistory {
		snapshot.TestHistory = s.snapshotTestHistory()
	}
	return snapshot
}

func broadcastStoreSnapshot(hub *Hub, store *Store, withHistory bool) {
	if hub == nil || store == nil {
		return
	}
	if !hub.HasVariant(publicVariantBalanced) && !hub.HasVariant(adminVariant) {
		return
	}
	if hub.HasVariant(publicVariantBalanced) {
		payload, err := json.Marshal(storeSnapshot(store, withHistory))
		if err != nil {
			log.Printf("序列化节点快照失败: %v", err)
			return
		}
		hub.BroadcastVariant(payload, publicVariantBalanced)
	}
	if !hub.HasVariant(adminVariant) {
		return
	}
	payload, err := json.Marshal(adminStoreSnapshot(store, withHistory))
	if err != nil {
		log.Printf("序列化管理端节点快照失败: %v", err)
		return
	}
	hub.BroadcastAdmin(payload, store.Credentials().TokenSalt)
}

func digestPublicSnapshot(snapshot Snapshot) string {
	hash := fnv.New64a()
	encoder := json.NewEncoder(hash)
	_ = encoder.Encode(struct {
		Type     string         `json:"type"`
		Nodes    []NodeView     `json:"nodes"`
		Groups   []string       `json:"groups,omitempty"`
		Settings PublicSettings `json:"settings,omitempty"`
	}{
		Type:     snapshot.Type,
		Nodes:    snapshot.Nodes,
		Groups:   snapshot.Groups,
		Settings: snapshot.Settings,
	})
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func cloneTestHistoryEntry(entry *TestHistoryEntry) *TestHistoryEntry {
	return &TestHistoryEntry{
		Latency:        slices.Clone(entry.Latency),
		Loss:           slices.Clone(entry.Loss),
		Times:          slices.Clone(entry.Times),
		LastAt:         entry.LastAt,
		MinIntervalSec: entry.MinIntervalSec,
		AvgIntervalSec: entry.AvgIntervalSec,
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
		result[key] = cloneTestHistoryEntry(&TestHistoryEntry{
			Latency:        entry.Latency,
			Loss:           entry.Loss,
			Times:          entry.Times,
			LastAt:         entry.LastAt,
			MinIntervalSec: entry.MinIntervalSec,
			AvgIntervalSec: entry.AvgIntervalSec,
		})
	}
	return result
}

func (s *Store) snapshotTestHistory() map[string]map[string]*TestHistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneTestHistory(s.testHistory)
}

func (s *Store) HasNode(nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.nodes[nodeID]
	return exists
}

func (s *Store) QueryPublicNodeHistory(nodeID string, from, to time.Time) (map[string]*TestHistoryEntry, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return map[string]*TestHistoryEntry{}, nil
	}
	if s == nil || s.historyManager == nil || s.historyManager.NetworkStore() == nil {
		return map[string]*TestHistoryEntry{}, nil
	}
	entries, err := s.historyManager.NetworkStore().QueryPublicRange(nodeID, from, to)
	if err != nil {
		return nil, err
	}
	return convertNetworkHistoryToTestHistory(entries), nil
}

func cloneTestHistory(
	source map[string]map[string]*TestHistoryEntry,
) map[string]map[string]*TestHistoryEntry {
	if source == nil {
		return nil
	}
	result := make(map[string]map[string]*TestHistoryEntry, len(source))
	for nodeID, tests := range source {
		if tests == nil {
			continue
		}
		copiedTests := make(map[string]*TestHistoryEntry, len(tests))
		for key, entry := range tests {
			if entry == nil {
				continue
			}
			copiedTests[key] = cloneTestHistoryEntry(entry)
		}
		if len(copiedTests) > 0 {
			result[nodeID] = copiedTests
		}
	}
	return result
}

func (s *Store) Snapshot() []NodeView {
	return s.snapshot(false)
}

func (s *Store) AdminSnapshot() []NodeView {
	return s.snapshot(true)
}

func (s *Store) snapshot(includeProfileOnly bool) []NodeView {
	var persist bool
	s.mu.Lock()

	views := make([]NodeView, 0, len(s.nodes))
	now := time.Now()
	seenNodes := make(map[string]struct{}, len(s.nodes))
	for _, node := range s.nodes {
		seenNodes[node.Stats.NodeID] = struct{}{}
		profile := s.ensureProfileLocked(node.Stats.NodeID)
		if s.applyAutoRenewLocked(profile, now) {
			persist = true
		}
		view, ok := s.nodeViewLocked(node.Stats.NodeID, now)
		if ok {
			views = append(views, view)
		}
	}
	if includeProfileOnly {
		for nodeID, profile := range s.profiles {
			if _, ok := seenNodes[nodeID]; ok {
				continue
			}
			if s.applyAutoRenewLocked(profile, now) {
				persist = true
			}
			if view, ok := profileOnlyNodeView(nodeID, profile); ok {
				views = append(views, view)
			}
		}
	}
	sort.Slice(views, func(i, j int) bool {
		leftGroup := views[i].Group
		rightGroup := views[j].Group
		if leftGroup == rightGroup {
			if views[i].Alias == views[j].Alias {
				return views[i].Stats.NodeID < views[j].Stats.NodeID
			}
			return views[i].Alias < views[j].Alias
		}
		return leftGroup < rightGroup
	})
	s.mu.Unlock()

	if persist {
		s.persist()
	}
	return views
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
	group, tags := resolveProfileGroupTags(profile, stats)
	stats.NodeGroup = group
	groups := normalizeGroupSelections(profile.Groups)
	return NodeView{
		Stats:                    stats,
		Status:                   nodeStatusWaitingRegistration,
		ServerID:                 profile.ServerID,
		AlertEnabled:             isAlertEnabled(profile),
		Alias:                    alias,
		Group:                    group,
		Tags:                     cloneStringSlice(tags),
		Groups:                   cloneStringSlice(groups),
		Region:                   profile.Region,
		DiskType:                 profile.DiskType,
		NetSpeedMbps:             profile.NetSpeedMbps,
		ExpireAt:                 profile.ExpireAt,
		AutoRenew:                profile.AutoRenew,
		RenewIntervalSec:         profile.RenewIntervalSec,
		TestIntervalSec:          profile.TestIntervalSec,
		TestSelections:           cloneTestSelections(profile.TestSelections),
		AgentUpdateSupported:     false,
		AgentUpdateState:         strings.TrimSpace(profile.AgentUpdateState),
		AgentUpdateTargetVersion: strings.TrimSpace(profile.AgentUpdateTargetVersion),
		AgentUpdateMessage:       strings.TrimSpace(profile.AgentUpdateMessage),
	}, true
}

func (s *Store) PublicNodeDelta(nodeID string) (NodeDelta, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	node, ok := s.nodeViewLocked(nodeID, now)
	if !ok {
		return NodeDelta{}, false
	}
	return NodeDelta{
		Type:        "node_delta",
		GeneratedAt: now.Unix(),
		Node:        node,
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
	group, tags := resolveProfileGroupTags(profile, node.Stats)
	groups := normalizeGroupSelections(profile.Groups)
	updateSupported, updateMode, updateState, updateTargetVersion, updateMessage := resolveAgentUpdateView(profile, node.Stats)

	stats := cloneNodeStats(node.Stats)
	if status == nodeStatusOffline {
		// Offline nodes keep lifetime counters, but their last-reported
		// instantaneous rates are stale and must not feed live totals.
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
		Alias:                    profile.Alias,
		Group:                    group,
		Tags:                     cloneStringSlice(tags),
		Groups:                   cloneStringSlice(groups),
		Region:                   profile.Region,
		DiskType:                 profile.DiskType,
		NetSpeedMbps:             profile.NetSpeedMbps,
		ExpireAt:                 profile.ExpireAt,
		AutoRenew:                profile.AutoRenew,
		RenewIntervalSec:         profile.RenewIntervalSec,
		TestIntervalSec:          profile.TestIntervalSec,
		TestSelections:           cloneTestSelections(profile.TestSelections),
		AgentUpdateSupported:     updateSupported,
		AgentUpdateMode:          updateMode,
		AgentUpdateState:         updateState,
		AgentUpdateTargetVersion: updateTargetVersion,
		AgentUpdateMessage:       updateMessage,
	}, true
}

func resolveProfileGroupTags(profile *NodeProfile, stats metrics.NodeStats) (string, []string) {
	selections := normalizeGroupSelections(profile.Groups)
	if len(selections) == 0 {
		selections = selectionsFromGroupTags(profile.Group, profile.Tags)
	}
	group, tags := primaryGroupTagsFromSelections(selections)
	if group == "" && stats.NodeGroup != "" {
		group = strings.TrimSpace(stats.NodeGroup)
	}
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

func (h *Hub) Add(conn *websocket.Conn, variant string, adminTokenSalt string) *hubClient {
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
	return client
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

// BroadcastVariant/BroadcastAdmin share one immutable payload slice across
// clients: the payload is never mutated after marshal and every write loop
// only reads it, so per-client bytes.Clone allocations are pure waste.
func (h *Hub) BroadcastVariant(payload []byte, variant string) {
	clients := h.snapshotClients()
	for _, client := range clients {
		if client == nil || client.variant != variant {
			continue
		}
		if ok := client.enqueue(websocket.TextMessage, payload); !ok {
			h.removeClient(client)
		}
	}
}

func (h *Hub) BroadcastAdmin(payload []byte, tokenSalt string) {
	clients := h.snapshotClients()
	currentSalt := strings.TrimSpace(tokenSalt)
	for _, client := range clients {
		if client == nil || client.variant != adminVariant {
			continue
		}
		if client.adminTokenSalt != currentSalt {
			h.removeClient(client)
			continue
		}
		if ok := client.enqueue(websocket.TextMessage, payload); !ok {
			h.removeClient(client)
		}
	}
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
	conn.SetReadLimit(maxJSONBodySize)
	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})
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
		if ok := client.enqueue(websocket.PingMessage, nil); !ok {
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
			if err := client.writeMessage(msg.messageType, msg.payload); err != nil {
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
	Alias            *string          `json:"alias"`
	Group            *string          `json:"group"`
	Tags             *[]string        `json:"tags"`
	Groups           *[]string        `json:"groups"`
	Region           *string          `json:"region"`
	DiskType         *string          `json:"disk_type"`
	NetSpeedMbps     *int             `json:"net_speed_mbps"`
	ExpireAt         *int64           `json:"expire_at"`
	AutoRenew        *bool            `json:"auto_renew"`
	RenewIntervalSec *int64           `json:"renew_interval_sec"`
	TestIntervalSec  *int             `json:"test_interval_sec"`
	TestSelections   *[]TestSelection `json:"test_selections"`
	AlertEnabled     *bool            `json:"alert_enabled"`
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
	s.persist()
	return nil
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

func loginAttemptKey(username, remoteAddr string) string {
	user := strings.TrimSpace(username)
	if user == "" {
		user = "unknown"
	}
	host := strings.TrimSpace(remoteAddr)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	if host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("%s|%s", user, host)
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
		s.pruneLoginAttemptsLocked(now, window, lock)
		return true, 0
	}
	if !attempt.lockedUntil.IsZero() && now.Before(attempt.lockedUntil) {
		return false, attempt.lockedUntil.Sub(now)
	}
	if window > 0 && !attempt.firstAt.IsZero() && now.Sub(attempt.firstAt) > window {
		delete(s.loginAttempts, key)
		s.pruneLoginAttemptsLocked(now, window, lock)
		return true, 0
	}
	s.pruneLoginAttemptsLocked(now, window, lock)
	return true, 0
}

func (s *Store) recordLoginFailure(key string, now time.Time) (bool, time.Duration) {
	limit, window, lock := s.loginPolicy()
	if limit <= 0 {
		return false, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt := s.loginAttempts[key]
	if attempt == nil {
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
		s.pruneLoginAttemptsLocked(now, window, lock)
		return true, lock
	}
	s.pruneLoginAttemptsLocked(now, window, lock)
	return false, 0
}

func (s *Store) clearLoginAttempts(key string) {
	s.mu.Lock()
	delete(s.loginAttempts, key)
	s.mu.Unlock()
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
	for rateKey, windowState := range rates {
		if !windowState.until.IsZero() && !now.Before(windowState.until) {
			delete(rates, rateKey)
		}
	}
	state := rates[key]
	if state.until.IsZero() || !now.Before(state.until) {
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
	s.persist()
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
	}
}

// settingsViewLocked requires the caller to hold s.mu (read or write).
func (s *Store) settingsViewLocked() SettingsView {
	loginFailLimit := s.settings.LoginFailLimit
	if loginFailLimit < 0 {
		loginFailLimit = 0
	}
	return SettingsView{
		AdminPath:            s.settings.AdminPath,
		AdminUser:            s.settings.AdminUser,
		TurnstileSiteKey:     strings.TrimSpace(s.settings.TurnstileSiteKey),
		TurnstileSecretKey:   "",
		AgentEndpoint:        strings.TrimSpace(s.settings.AgentEndpoint),
		AgentToken:           s.settings.AgentToken,
		SiteTitle:            s.settings.SiteTitle,
		SiteIcon:             safeSiteIconURL(s.settings.SiteIcon),
		SiteBackgroundImage:  safeSiteBackgroundImageURL(s.settings.SiteBackgroundImage),
		HomeTitle:            s.settings.HomeTitle,
		HomeSubtitle:         s.settings.HomeSubtitle,
		Locale:               normalizeLocale(s.settings.Locale),
		AlertWebhook:         s.settings.AlertWebhook,
		AlertOfflineSec:      s.settings.AlertOfflineSec,
		AlertTelegramToken:   s.settings.AlertTelegramToken,
		AlertTelegramUserIDs: cloneInt64Slice(s.settings.AlertTelegramUserIDs),
		AlertTelegramUserID:  firstTelegramUserID(s.settings.AlertTelegramUserIDs),
		LoginFailLimit:       loginFailLimit,
		LoginFailWindowSec:   s.settings.LoginFailWindowSec,
		LoginLockSec:         s.settings.LoginLockSec,
		AdminAuth:            redactAdminAuthSettings(normalizeAdminAuthSettings(s.settings.AdminAuth)),
		AISettings:           cloneAISettings(s.settings.AISettings),
		Version:              s.buildVersion,
		Commit:               s.buildCommit,
		Groups:               cloneStringSlice(s.settings.Groups),
		GroupTree:            cloneGroupNodes(s.settings.GroupTree),
		TestCatalog:          cloneTestCatalogItems(s.settings.TestCatalog),
	}
}

func (s *Store) SettingsView() SettingsView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settingsViewLocked()
}

func (s *Store) ExportConfig() ConfigTransferData {
	view := redactSettingsViewForExport(s.SettingsView())
	s.mu.RLock()
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
	view.AlertWebhook = ""
	view.AlertTelegramToken = ""
	view.AlertTelegramUserIDs = nil
	view.AlertTelegramUserID = 0
	view.AdminAuth = redactAdminAuthSettings(view.AdminAuth)
	view.AISettings = redactAISettingsForExport(view.AISettings)
	view.Commit = ""
	view.SessionToken = ""
	view.SessionExpiresAt = 0
	return view
}

func redactAISettingsForExport(settings AISettings) AISettings {
	settings = cloneAISettings(settings)
	settings.OpenAI.APIKey = ""
	settings.Gemini.APIKey = ""
	settings.Volcengine.APIKey = ""
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
	alertTelegramUserIDs := cloneInt64Slice(view.AlertTelegramUserIDs)
	adminAuth := cloneAdminAuthSettings(view.AdminAuth)
	aiSettings := cloneAISettings(view.AISettings)
	groups := cloneStringSlice(view.Groups)
	groupTree := cloneGroupNodes(view.GroupTree)
	testCatalog := cloneTestCatalogItems(view.TestCatalog)

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
	}
	if agentToken != "" {
		update.AgentToken = stringPointer(agentToken)
	}
	if secret := strings.TrimSpace(view.TurnstileSecretKey); secret != "" {
		update.TurnstileSecretKey = stringPointer(secret)
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

func (s *Store) SiteTitle() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return normalizeSiteTitle(s.settings.SiteTitle)
}

func (s *Store) UpdateSettings(update SettingsUpdate) (SettingsView, error) {
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
		pass := strings.TrimSpace(*update.AdminPass)
		if pass == "" {
			return fail(errors.New("admin_pass invalid"))
		}
		if verifyPassword(pass, s.settings.AdminPass) {
			if !isBcryptHash(s.settings.AdminPass) {
				hash, err := hashPassword(pass)
				if err != nil {
					return fail(errors.New("admin_pass hash failed"))
				}
				s.settings.AdminPass = hash
			}
		} else {
			hash, err := hashPassword(pass)
			if err != nil {
				return fail(errors.New("admin_pass hash failed"))
			}
			s.settings.AdminPass = hash
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
		s.settings.AlertOfflineSec = offlineSec
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
	telegramIDsUpdated := false
	var telegramUserIDs []int64
	if update.AlertTelegramUserIDs != nil {
		telegramUserIDs = normalizeTelegramUserIDs(*update.AlertTelegramUserIDs)
		telegramIDsUpdated = true
	}
	if update.AlertTelegramUserID != nil && update.AlertTelegramUserIDs == nil {
		value := *update.AlertTelegramUserID
		if value > 0 {
			telegramUserIDs = []int64{value}
		} else {
			telegramUserIDs = []int64{}
		}
		telegramIDsUpdated = true
	}
	if telegramIDsUpdated {
		s.settings.AlertTelegramUserIDs = telegramUserIDs
	}
	s.settings.AlertTelegramUserID = 0
	if (s.settings.AlertTelegramToken != "" || len(s.settings.AlertTelegramUserIDs) > 0) &&
		(s.settings.AlertTelegramToken == "" || len(s.settings.AlertTelegramUserIDs) == 0) {
		return fail(errors.New("telegram token 与 telegram 用户 ID 需要同时配置"))
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
		s.settings.LoginLockSec = lockSec
	}
	if update.AdminAuth != nil {
		normalized := normalizeAdminAuthSettings(*update.AdminAuth)
		normalized = preserveAdminAuthSecrets(normalized, s.settings.AdminAuth)
		if err := validateAdminAuthSettings(normalized); err != nil {
			return fail(err)
		}
		if !adminAuthSettingsEqual(normalizeAdminAuthSettings(s.settings.AdminAuth), normalized) {
			s.settings.AdminAuth = normalized
			tokenSalt, err := randomToken(adminTokenLength)
			if err != nil {
				return fail(err)
			}
			s.settings.TokenSalt = tokenSalt
		}
	}
	if update.AISettings != nil {
		normalized, err := normalizeAISettings(*update.AISettings)
		if err != nil {
			return fail(err)
		}
		if err := validateAISettings(normalized); err != nil {
			return fail(err)
		}
		s.settings.AISettings = normalized
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
		previousCatalog := cloneTestCatalogItems(s.settings.TestCatalog)
		catalog, err := normalizeTestCatalog(*update.TestCatalog)
		if err != nil {
			return fail(err)
		}
		s.settings.TestCatalog = catalog
		s.markAgentConfigRefreshForCatalogChangeLocked(previousCatalog, catalog)
		s.pruneProfileTestSelectionsLocked()
	}
	view = s.settingsViewLocked()
	s.mu.Unlock()

	s.persist()
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
	s.profiles = normalizedProfiles
	s.reconcileAgentConfigRefreshLocked(previousAgentConfigs, now)
	s.mu.Unlock()
	s.persist()

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
	if strings.TrimSpace(imported.AlertWebhook) == "" {
		update.AlertWebhook = nil
	}
	if strings.TrimSpace(imported.AlertTelegramToken) == "" {
		update.AlertTelegramToken = nil
		update.AlertTelegramUserIDs = nil
		update.AlertTelegramUserID = nil
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
	imported.Gemini.APIKey = preserveRedactedString(imported.Gemini.APIKey, existing.Gemini.APIKey)
	imported.Volcengine.APIKey = preserveRedactedString(imported.Volcengine.APIKey, existing.Volcengine.APIKey)

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

func (s *Store) ReplaceProfiles(profiles map[string]*NodeProfile) error {
	s.agentMutationMu.Lock()
	defer s.agentMutationMu.Unlock()

	s.mu.Lock()
	normalized, err := s.normalizeProfilesForImportLocked(profiles)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	now := time.Now()
	previousAgentConfigs := s.agentConfigProjectionsLocked(now)
	s.profiles = normalized
	s.reconcileAgentConfigRefreshLocked(previousAgentConfigs, now)
	s.mu.Unlock()
	s.persist()
	return nil
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
		profile.Alias = strings.TrimSpace(profile.Alias)
		profile.Group = strings.TrimSpace(profile.Group)
		profile.Tags = normalizeGroups(profile.Tags)
		profile.Groups = normalizeGroupSelections(profile.Groups)
		if len(profile.Groups) == 0 && (profile.Group != "" || len(profile.Tags) > 0) {
			profile.Groups = selectionsFromGroupTags(profile.Group, profile.Tags)
		}
		if len(profile.Groups) > 0 {
			group, tags := primaryGroupTagsFromSelections(profile.Groups)
			profile.Group = group
			profile.Tags = tags
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
		profile.TestSelections = s.normalizeSelectionsLocked(cloneTestSelections(profile.TestSelections))
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
	if expectedBootstrapToken != "" && !isBootstrapAgentToken(expectedBootstrapToken, bootstrapToken) {
		s.mu.Unlock()
		return "", invalidBootstrapTokenError()
	}
	if profile := s.profiles[nodeID]; profile != nil {
		token := strings.TrimSpace(profile.AgentAuthToken)
		if token != "" && !s.isAgentAuthTokenDuplicateLocked(nodeID, token) {
			s.mu.Unlock()
			return token, nil
		}
	}
	if !s.allowAgentRateLocked("register:*", agentRegisterWindow, defaultAgentRegisterGlobalLimit, now, false) {
		s.mu.Unlock()
		return "", agentRateLimitError()
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
			rollbackProfile()
			s.mu.Unlock()
			return "", agentServiceUnavailable(err.Error())
		}
		profile.AgentAuthToken = token
		profile.UpdatedAt = time.Now().Unix()
		changed = true
	}
	token := strings.TrimSpace(profile.AgentAuthToken)
	s.mu.Unlock()
	if changed {
		s.persist()
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
	if expected == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(token)) != 1 {
		return false
	}
	return !s.isAgentAuthTokenDuplicateLocked(nodeID, expected)
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

func (s *Store) ensureServerIDLocked(nodeID string, profile *NodeProfile) (bool, error) {
	if profile == nil {
		return false, nil
	}
	original := strings.TrimSpace(profile.ServerID)
	if original == "" || s.isServerIDDuplicateLocked(nodeID, original) {
		id, err := s.generateServerIDLocked()
		if err != nil {
			return false, err
		}
		profile.ServerID = id
		return true, nil
	}
	return false, nil
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

func (s *Store) isServerIDDuplicateLocked(nodeID, id string) bool {
	if id == "" {
		return false
	}
	for key, profile := range s.profiles {
		if key == nodeID || profile == nil {
			continue
		}
		if strings.TrimSpace(profile.ServerID) == id {
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
		if id == "" || containsKey(used, id) {
			generatedID, err := randomToken(10)
			if err != nil {
				return err
			}
			id = generatedID
			for containsKey(used, id) {
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

func containsKey(seen map[string]struct{}, key string) bool {
	_, ok := seen[key]
	return ok
}

func (s *Store) UpdateProfile(nodeID string, update NodeProfileUpdate) (NodeProfile, bool) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return NodeProfile{}, false
	}
	unlock := s.lockAgentNodeRead(nodeID)
	defer unlock()

	s.mu.Lock()
	if _, nodeExists := s.nodes[nodeID]; !nodeExists {
		if _, profileExists := s.profiles[nodeID]; !profileExists {
			s.mu.Unlock()
			return NodeProfile{}, false
		}
	}

	profile := s.ensureProfileLocked(nodeID)
	configChanged := false
	if update.Alias != nil {
		profile.Alias = strings.TrimSpace(*update.Alias)
		configChanged = true
	}
	if update.Group != nil {
		profile.Group = strings.TrimSpace(*update.Group)
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
	if update.Region != nil {
		profile.Region = strings.ToUpper(strings.TrimSpace(*update.Region))
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
	s.persist()
	return result, true
}

func (s *Store) UpdateAlertEnabledByServerID(serverID string, enabled bool) (string, string, bool) {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return "", "", false
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
		return "", "", false
	}

	unlock := s.lockAgentNodeRead(nodeID)
	defer unlock()

	s.mu.Lock()
	profile := s.profiles[nodeID]
	if profile == nil || strings.TrimSpace(profile.ServerID) != serverID {
		s.mu.Unlock()
		return "", "", false
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
	s.persist()
	return nodeID, display, true
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
		s.persist()
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
		s.persist()
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
	store *Store,
	payload PersistedData,
) (PersistedData, error) {
	legacyMigrationComplete := true
	if migration, err := history.MigrateLegacyJSONIfNeeded(historyPath, historyManager.NetworkStore(), time.Now()); err != nil {
		legacyMigrationComplete = false
		log.Printf("%v", wrapDataPathError("迁移探测历史失败", historyPath, err))
	} else if migration.LegacyFound {
		legacyMigrationComplete = false
		now := time.Now()
		historyData, loaded, _, loadErr := loadTestHistoryData(migration.SourcePath)
		if loadErr != nil {
			log.Printf("%v", wrapDataPathError("读取 legacy 探测历史失败", migration.SourcePath, loadErr))
		} else if !loaded {
			log.Printf("legacy 探测历史源文件在迁移后不可用：%s", migration.SourcePath)
		} else {
			if store != nil {
				store.mu.Lock()
				if historyData.Nodes == nil {
					historyData.Nodes = make(map[string]map[string]*TestHistoryEntry)
				}
				store.testHistory = historyData.Nodes
				store.mu.Unlock()
			}

			backupReady := true
			if migration.SourcePath == historyPath {
				if err := history.EnsureLegacyMigrationBackup(historyPath); err != nil {
					backupReady = false
					log.Printf("%v", wrapDataPathError("备份 legacy 探测历史失败", historyPath, err))
				}
			}
			if backupReady {
				if migration.SourcePath == historyPath {
					if err := os.Remove(historyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
						backupReady = false
						log.Printf("%v", wrapDataPathError("清理 legacy 探测历史失败", historyPath, err))
					}
				}
				if backupReady {
					if err := history.MarkLegacyMigrationComplete(historyPath, now); err != nil {
						log.Printf("%v", wrapDataPathError("写入 legacy 迁移标记失败", migration.MarkerPath, err))
					} else {
						legacyMigrationComplete = true
						log.Printf("已将 legacy 探测历史迁移到 TSDB：%s", migration.SourcePath)
					}
				}
			}
		}
	}
	replayed, err := replayPendingHistoryCleanupWithIntentMode(dataPath, historyManager, payload, legacyMigrationComplete)
	if err != nil {
		return payload, err
	}
	applyPendingHistoryCleanupToStore(store, payload.PendingHistoryClear, payload.PendingHistoryDeletes)
	return replayed, nil
}

func applyPendingHistoryCleanupToStore(store *Store, pendingClear bool, pendingDeletes []string) {
	if store == nil || (!pendingClear && len(pendingDeletes) == 0) {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if pendingClear {
		store.testHistory = make(map[string]map[string]*TestHistoryEntry)
		return
	}
	for _, nodeID := range pendingDeletes {
		delete(store.testHistory, nodeID)
	}
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
	if s.testHistory != nil {
		delete(s.testHistory, nodeID)
	}
}

func (s *Store) clearNodesMemoryLocked() {
	s.nodes = make(map[string]NodeState)
	s.profiles = make(map[string]*NodeProfile)
	s.alerted = make(map[string]alertState)
	s.offlineSessions = make(map[string]OfflineSessionState)
	s.configRefresh = make(map[string]struct{})
	s.testHistory = make(map[string]map[string]*TestHistoryEntry)
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
	s.persist()
	return result, agentUpdateQueueQueued, nil
}

// applyAgentUpdateReportNodeLocked requires the caller to hold lockAgentNodeRead(nodeID).
func (s *Store) applyAgentUpdateReportNodeLocked(nodeID string, report AgentUpdateReport) (NodeProfile, bool) {
	s.mu.Lock()
	if _, nodeExists := s.nodes[nodeID]; !nodeExists {
		if _, profileExists := s.profiles[nodeID]; !profileExists {
			s.mu.Unlock()
			return NodeProfile{}, false
		}
	}
	profile := s.ensureProfileLocked(nodeID)
	reportedAt := time.Now().Unix()
	state, validState := normalizeAgentUpdateReportState(report.State)
	if !validState {
		result := cloneNodeProfileValue(profile)
		s.mu.Unlock()
		return result, false
	}
	if !agentUpdateReportMatchesPendingInstruction(profile, report) {
		result := cloneNodeProfileValue(profile)
		s.mu.Unlock()
		return result, false
	}
	if !agentUpdateReportAllowedForCurrentState(profile.AgentUpdateState, state) {
		result := cloneNodeProfileValue(profile)
		s.mu.Unlock()
		return result, false
	}
	applyAgentUpdateReport(profile, report, state, reportedAt)
	result := cloneNodeProfileValue(profile)
	s.mu.Unlock()
	s.persist()
	return result, true
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
			Tests:           []metrics.NetworkTestConfig{},
		}
	}
	tests := s.resolveTestsLocked(profile)
	group, _ := primaryGroupTagsFromSelections(profile.Groups)
	if group == "" {
		group = strings.TrimSpace(profile.Group)
	}
	if tests == nil {
		tests = []metrics.NetworkTestConfig{}
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
		Tests:           cloneNetworkTestConfigs(tests),
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
		pendingDeletes = append(pendingDeletes, nodeID)
	}
	if len(pendingDeletes) > 0 {
		sort.Strings(pendingDeletes)
		snapshot.PendingHistoryDeletes = pendingDeletes
	}
}

func (s *Store) persist() {
	if s.dataPath == "" {
		return
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.mu.RLock()
	data := s.snapshotPersistedLocked()
	s.mu.RUnlock()
	if err := s.writePersistedSnapshotLocked(data); err != nil {
		log.Printf("%v", err)
	}
}

// writePersistedSnapshotLocked expects persistMu to be held so queued snapshots
// keep the same write order as the mutations that produced them.
func (s *Store) writePersistedSnapshotLocked(data PersistedData) error {
	if err := savePersistedData(s.dataPath, data); err != nil {
		return wrapDataPathError("持久化失败", s.dataPath, err)
	}
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

func (s *Store) resolveTestsLocked(profile *NodeProfile) []metrics.NetworkTestConfig {
	if len(profile.TestSelections) == 0 {
		return nil
	}
	catalog := make(map[string]TestCatalogItem, len(s.settings.TestCatalog))
	for _, item := range s.settings.TestCatalog {
		catalog[item.ID] = item
	}
	results := make([]metrics.NetworkTestConfig, 0, len(profile.TestSelections))
	for _, sel := range profile.TestSelections {
		if sel.TestID == "" {
			continue
		}
		item, ok := catalog[sel.TestID]
		if !ok {
			continue
		}
		interval := 0
		if strings.ToLower(item.Type) == "tcp" {
			if sel.IntervalSec > 0 {
				interval = sel.IntervalSec
			} else if item.IntervalSec > 0 {
				interval = item.IntervalSec
			} else if profile.TestIntervalSec > 0 {
				interval = profile.TestIntervalSec
			} else {
				interval = defaultTestIntervalSec
			}
		}
		results = append(results, metrics.NetworkTestConfig{
			Name:        item.Name,
			Type:        item.Type,
			Host:        item.Host,
			Port:        item.Port,
			IntervalSec: interval,
		})
		if len(results) >= maxNetworkTestsPerNode {
			break
		}
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
		item, ok := valid[id]
		if !ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		interval := sel.IntervalSec
		if interval < 0 {
			interval = 0
		}
		if strings.ToLower(item.Type) == "icmp" {
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
			if !hasNext || !hadPrevious || previousItem != nextItem {
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

func validateWebhookURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("webhook 不能为空")
	}
	if err := validateHTTPCallbackURL(raw); err != nil {
		if errors.Is(err, errCallbackURLScheme) {
			return errors.New("webhook 协议无效")
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

type callbackResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type callbackDialContext func(context.Context, string, string) (net.Conn, error)

var (
	defaultCallbackResolver callbackResolver = net.DefaultResolver
	defaultCallbackDialer                    = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
)

func newWebhookHTTPClient() *http.Client {
	return newWebhookHTTPClientWithResolver(defaultCallbackResolver, defaultCallbackDialer)
}

func newWebhookHTTPClientWithResolver(resolver callbackResolver, dialContext callbackDialContext) *http.Client {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if dialContext == nil {
		dialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	return &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			DialContext:           restrictedCallbackDialContext(resolver, dialContext),
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 6 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("webhook redirect limit exceeded")
			}
			return validateWebhookURL(req.URL.String())
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
			return nil, errors.New("callback private ip rejected")
		}
	}
	return ips, nil
}

func validateHTTPCallbackURL(raw string) error {
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
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("callback private host rejected")
	}
	if strings.Contains(host, "%") {
		return errors.New("callback host invalid")
	}
	if isAmbiguousIPv4LiteralHost(host) {
		return errors.New("callback host invalid")
	}
	if ip := net.ParseIP(host); ip != nil && isPrivateCallbackIP(ip) {
		return errors.New("callback private ip rejected")
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
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func handleAdminUpdateNodeProfileRequest(w http.ResponseWriter, r *http.Request, store *Store, hub *Hub, nodeID string) {
	var update NodeProfileUpdate
	if err := decodeJSON(w, r, &update); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if _, ok := store.UpdateProfile(nodeID, update); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	broadcastStoreSnapshot(hub, store, false)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// adminNodeIDFromPath unescapes and normalizes the node ID carried in an
// admin API path segment, writing the 400 response itself on failure.
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

func defaultAgentReleaseChecker(ctx context.Context, stats metrics.NodeStats) (updater.ReleaseInfo, error) {
	client := updater.NewClient(updater.DefaultRepo, updater.KindAgent, strings.TrimSpace(stats.AgentVersion))
	return client.CheckLatest(ctx)
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
	releaseInfo, err := checkRelease(r.Context(), stats)
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
	releaseInfo, err := checkRelease(r.Context(), stats)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if err := validateReleaseTargetVersion(releaseInfo); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if !releaseInfo.HasUpdate && updater.VersionCurrentOrNewer(releaseInfo.CurrentVersion, releaseInfo.LatestVersion) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":         "up_to_date",
			"target_version": releaseInfo.LatestVersion,
		})
		return
	}
	if message := agentUpdateReleaseAssetError(stats, releaseInfo); message != "" {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": message})
		return
	}
	_, queueStatus, queueErr := store.QueueAgentUpdate(nodeID, AgentUpdateInstruction{
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
		broadcastStoreSnapshot(hub, store, false)
	}
	status := "in_progress"
	if queueStatus == agentUpdateQueueQueued {
		status = "queued"
	}
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":         status,
		"target_version": releaseInfo.LatestVersion,
	})
}

func handleAdminClearNodesRequest(w http.ResponseWriter, r *http.Request, store *Store, hub *Hub) {
	if err := store.ClearNodes(); err != nil {
		var partialHistoryErr *historyCleanupError
		if errors.As(err, &partialHistoryErr) {
			broadcastStoreSnapshot(hub, store, false)
			writeJSON(w, http.StatusOK, map[string]string{
				"status":        "cleared",
				"history_error": partialHistoryErr.HistoryError(),
			})
			return
		}
		writeClearNodesHistoryError(w, r, err)
		return
	}
	broadcastStoreSnapshot(hub, store, false)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func handleAdminDeleteNodeRequest(w http.ResponseWriter, r *http.Request, store *Store, hub *Hub, nodeID string) {
	deleted, err := store.DeleteNode(nodeID)
	if err != nil {
		var partialHistoryErr *historyCleanupError
		if errors.As(err, &partialHistoryErr) {
			broadcastStoreSnapshot(hub, store, false)
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
		writeNodeDeleteHistoryError(w, r, err)
		return
	}
	if !deleted {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	broadcastStoreSnapshot(hub, store, false)
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

func writeNodeDeleteHistoryError(w http.ResponseWriter, _ *http.Request, err error) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{
		"status": "delete_failed",
		"error":  fmt.Sprintf("删除节点失败，历史数据清理失败: %v", err),
	})
}

func writeClearNodesHistoryError(w http.ResponseWriter, _ *http.Request, err error) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{
		"status": "clear_failed",
		"error":  fmt.Sprintf("清空节点失败，历史数据清理失败: %v", err),
	})
}

func withNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// isPublicReadMethod reports whether the request is a safe read (GET/HEAD)
// for the public read-only endpoints; HEAD keeps uptime monitors happy and
// the net/http server discards any body written for HEAD.
func isPublicReadMethod(r *http.Request) bool {
	return r != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead)
}

func applyPublicCORSHeaders(w http.ResponseWriter) {
	// 公开只读数据（snapshot/health/公开历史）按设计就是免认证的，任意
	// Origin 可读。Vary: Origin 防止共享缓存把响应误用于按 Origin 变化的
	// 场景。该函数只允许用于公开端点，admin 端点绝不携带 CORS 头。
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Add("Vary", "Origin")
}

// withPublicCORS wraps a public read-only handler so the public dashboard can
// be statically hosted on another origin (Cloudflare Pages 等). Preflight
// OPTIONS is answered with 204. Do NOT wrap admin handlers — they must not
// emit CORS headers.
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

func parseBoolQuery(r *http.Request, key string) bool {
	value := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
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
