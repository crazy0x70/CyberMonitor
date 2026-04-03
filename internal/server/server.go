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
	"cyber_monitor/internal/updater"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxLogSize                = 10 * 1024 * 1024
	maxLogBackupCount         = 3
	maxTestHistoryPoints      = 5000
	testHistoryHotSeconds     = 60 * 60
	testHistoryMaxAgeSeconds  = 60 * 60 * 24 * 365
	maxJSONBodySize           = 4 * 1024 * 1024
	wsSendQueueSize           = 8
	wsWriteWait               = 10 * time.Second
	wsPongWait                = 60 * time.Second
	wsPingPeriod              = (wsPongWait * 9) / 10
	publicVariantConservative = "conservative"
	publicVariantBalanced     = "balanced"
	adminSessionCookieName    = "cm_admin_session"
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
	serverOutput := io.Writer(os.Stdout)
	reportOutput := io.Writer(os.Stdout)
	if dataDir == "" {
		log.SetOutput(serverOutput)
		reportLogger.SetOutput(reportOutput)
		return
	}
	serverPath := filepath.Join(dataDir, "server.log")
	reportPath := filepath.Join(dataDir, "report.log")
	serverWriter := &sizeLimitedWriter{path: serverPath, maxSize: maxLogSize}
	reportWriter := &sizeLimitedWriter{path: reportPath, maxSize: maxLogSize}
	serverOutput = io.MultiWriter(os.Stdout, serverWriter)
	reportOutput = reportWriter
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

//go:embed web/* web/assets/* web/admin-app/* web/admin-assets/*
var webFS embed.FS

type Config struct {
	Addr       string
	PublicAddr string
	AdminUser  string
	AdminPass  string
	AdminPath  string
	JWTSecret  string
	AgentToken string
	DataDir    string
	Version    string
	Commit     string
}

type Store struct {
	mu                 sync.RWMutex
	persistMu          sync.Mutex
	historyPersistMu   sync.Mutex
	nodes              map[string]NodeState
	profiles           map[string]*NodeProfile
	settings           Settings
	buildVersion       string
	buildCommit        string
	dataPath           string
	historyPath        string
	lastPersist        time.Time
	persistInterval    time.Duration
	alerted            map[string]alertState
	testHistory        map[string]map[string]*TestHistoryEntry
	loginAttempts      map[string]*loginAttempt
	historyDirty       bool
	historyLastPersist time.Time
}

type NodeState struct {
	Stats     metrics.NodeStats `json:"stats"`
	LastSeen  time.Time         `json:"last_seen"`
	FirstSeen time.Time         `json:"first_seen"`
}

type NodeProfile struct {
	ServerID                 string                      `json:"server_id,omitempty"`
	AgentAuthToken           string                      `json:"agent_auth_token,omitempty"`
	AlertEnabled             *bool                       `json:"alert_enabled,omitempty"`
	Alias                    string                      `json:"alias,omitempty"`
	Group                    string                      `json:"group,omitempty"`
	Tags                     []string                    `json:"tags,omitempty"`
	Groups                   []string                    `json:"groups,omitempty"`
	Region                   string                      `json:"region,omitempty"`
	DiskType                 string                      `json:"disk_type,omitempty"`
	NetSpeedMbps             int                         `json:"net_speed_mbps,omitempty"`
	ExpireAt                 int64                       `json:"expire_at,omitempty"`
	AutoRenew                bool                        `json:"auto_renew,omitempty"`
	RenewIntervalSec         int64                       `json:"renew_interval_sec,omitempty"`
	TestIntervalSec          int                         `json:"test_interval_sec"`
	Tests                    []metrics.NetworkTestConfig `json:"tests,omitempty"`
	TestSelections           []TestSelection             `json:"test_selections,omitempty"`
	AgentUpdate              *AgentUpdateInstruction     `json:"agent_update,omitempty"`
	AgentUpdateState         string                      `json:"agent_update_state,omitempty"`
	AgentUpdateTargetVersion string                      `json:"agent_update_target_version,omitempty"`
	AgentUpdateMessage       string                      `json:"agent_update_message,omitempty"`
	AgentUpdateReportedAt    int64                       `json:"agent_update_reported_at,omitempty"`
	UpdatedAt                int64                       `json:"updated_at,omitempty"`
}

type AgentUpdateInstruction struct {
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
	Stats                    metrics.NodeStats           `json:"stats"`
	LastSeen                 int64                       `json:"last_seen"`
	FirstSeen                int64                       `json:"first_seen,omitempty"`
	Status                   string                      `json:"status"`
	ServerID                 string                      `json:"server_id,omitempty"`
	AlertEnabled             bool                        `json:"alert_enabled"`
	Alias                    string                      `json:"alias,omitempty"`
	Group                    string                      `json:"group,omitempty"`
	Tags                     []string                    `json:"tags,omitempty"`
	Groups                   []string                    `json:"groups,omitempty"`
	Region                   string                      `json:"region,omitempty"`
	DiskType                 string                      `json:"disk_type,omitempty"`
	NetSpeedMbps             int                         `json:"net_speed_mbps,omitempty"`
	ExpireAt                 int64                       `json:"expire_at,omitempty"`
	AutoRenew                bool                        `json:"auto_renew,omitempty"`
	RenewIntervalSec         int64                       `json:"renew_interval_sec,omitempty"`
	TestIntervalSec          int                         `json:"test_interval_sec,omitempty"`
	Tests                    []metrics.NetworkTestConfig `json:"tests,omitempty"`
	TestSelections           []TestSelection             `json:"test_selections,omitempty"`
	AgentUpdateSupported     bool                        `json:"agent_update_supported"`
	AgentUpdateMode          string                      `json:"agent_update_mode,omitempty"`
	AgentUpdateState         string                      `json:"agent_update_state,omitempty"`
	AgentUpdateTargetVersion string                      `json:"agent_update_target_version,omitempty"`
	AgentUpdateMessage       string                      `json:"agent_update_message,omitempty"`
}

type PublicSettings struct {
	SiteTitle    string `json:"site_title,omitempty"`
	SiteIcon     string `json:"site_icon,omitempty"`
	HomeTitle    string `json:"home_title,omitempty"`
	HomeSubtitle string `json:"home_subtitle,omitempty"`
	Version      string `json:"version,omitempty"`
	Commit       string `json:"commit,omitempty"`
}

type Snapshot struct {
	Type        string                                  `json:"type"`
	GeneratedAt int64                                   `json:"generated_at"`
	Nodes       []NodeView                              `json:"nodes"`
	Groups      []string                                `json:"groups,omitempty"`
	Settings    PublicSettings                          `json:"settings,omitempty"`
	TestHistory map[string]map[string]*TestHistoryEntry `json:"test_history,omitempty"`
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
	conn    *websocket.Conn
	variant string
	mu      sync.Mutex
	send    chan hubMessage
	done    chan struct{}
	once    sync.Once
}

type loginAttempt struct {
	failCount   int
	firstAt     time.Time
	lastAt      time.Time
	lockedUntil time.Time
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
	applyDefaults(&cfg)
	setupLogger(cfg.DataDir)

	dataPath := filepath.Join(cfg.DataDir, "state.json")
	persisted, loaded, err := loadPersistedData(dataPath)
	if err != nil {
		return wrapDataPathError("读取持久化数据失败", dataPath, err)
	}
	historyPath := filepath.Join(cfg.DataDir, testHistoryFileName)
	historyPayload, _, historyNeedsRewrite, historyErr := loadTestHistoryData(historyPath)
	if historyErr != nil {
		log.Printf("%v", wrapDataPathError("读取探测历史失败", historyPath, historyErr))
	}
	tokenGenerated := !loaded
	defaultSettings := initSettings(cfg)
	settings := defaultSettings
	profiles := make(map[string]*NodeProfile)
	nodes := make(map[string]NodeState)
	testHistory := historyPayload.Nodes
	if testHistory == nil {
		testHistory = make(map[string]map[string]*TestHistoryEntry)
	}
	historyTrimmed := historyNeedsRewrite
	nowSec := time.Now().Unix()
	for _, tests := range testHistory {
		for _, entry := range tests {
			if trimHistoryEntry(entry, nowSec) {
				historyTrimmed = true
			}
		}
	}
	if loaded {
		settings = mergeSettings(persisted.Settings, defaultSettings)
		profiles = persisted.Profiles
		if persisted.Nodes != nil {
			nodes = persisted.Nodes
		}
	}
	ensureServerIDsForProfiles(profiles, nodes)
	if settings.AuthToken != "" {
		cfg.JWTSecret = settings.AuthToken
	}
	if settings.AgentToken != "" {
		cfg.AgentToken = settings.AgentToken
	}
	if err := savePersistedData(dataPath, PersistedData{
		Settings: settings,
		Profiles: profiles,
		Nodes:    nodes,
	}); err != nil {
		return wrapDataPathError("写入持久化数据失败", dataPath, err)
	}

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
		nodes:           nodes,
		profiles:        profiles,
		settings:        settings,
		buildVersion:    version,
		buildCommit:     commit,
		dataPath:        dataPath,
		historyPath:     historyPath,
		persistInterval: defaultPersistInterval,
		alerted:         make(map[string]alertState),
		testHistory:     testHistory,
		loginAttempts:   make(map[string]*loginAttempt),
	}
	if historyTrimmed {
		historyData := TestHistoryData{
			Version:   testHistoryVersion,
			UpdatedAt: time.Now().Unix(),
			Nodes:     store.snapshotTestHistory(),
		}
		store.persistHistory(historyData)
	}
	hub := &Hub{clients: make(map[*websocket.Conn]*hubClient)}
	agentAPI := newAgentAPI(store, hub, &cfg)
	systemUpdater := newSystemUpdateManager(version)
	splitMode := strings.TrimSpace(cfg.PublicAddr) != "" && cfg.PublicAddr != cfg.Addr

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
		attemptKey := loginAttemptKey(req.Username, r.RemoteAddr)
		if allowed, retryAfter := store.allowLoginAttempt(attemptKey, now); !allowed {
			writeLoginRateLimit(w, retryAfter)
			return
		}
		loginView := store.SettingsView()
		if turnstileConfigured(loginView.TurnstileSiteKey, loginView.TurnstileSecretKey) {
			if err := verifyTurnstileToken(r.Context(), loginView.TurnstileSecretKey, req.TurnstileToken, clientIPFromRemoteAddr(r.RemoteAddr)); err != nil {
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
		token, exp, err := generateToken(cfg.JWTSecret, req.Username, creds.TokenSalt)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
			return
		}
		setAdminSessionCookie(w, r, token, exp)
		log.Printf("管理员登录: %s (%s)", req.Username, r.RemoteAddr)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"expires_at": exp,
		})
	})

	adminMux.HandleFunc("/api/v1/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		clearAdminSessionCookie(w, r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	adminMux.HandleFunc("/api/v1/login/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		view := store.SettingsView()
		enabled := turnstileConfigured(view.TurnstileSiteKey, view.TurnstileSecretKey)
		payload := map[string]interface{}{
			"turnstile_enabled": enabled,
		}
		if enabled {
			payload["turnstile_site_key"] = strings.TrimSpace(view.TurnstileSiteKey)
		}
		writeJSON(w, http.StatusOK, payload)
	})

	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
	publicMux.HandleFunc("/api/v1/health", healthHandler)
	if splitMode {
		adminMux.HandleFunc("/api/v1/health", healthHandler)
	}

	publicMux.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		apiBase, socketURL := buildDefaultPublicConfig(r)
		writeJSON(w, http.StatusOK, map[string]string{
			"socket": socketURL,
			"apiURL": apiBase,
		})
	})

	publicMux.HandleFunc("/api/v1/public/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		snapshot := storeSnapshot(store, false)
		writeJSON(w, http.StatusOK, snapshot)
	})

	adminMux.HandleFunc("/api/v1/nodes", requireJWT(cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		snapshot := storeSnapshot(store, true)
		writeJSON(w, http.StatusOK, snapshot)
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
		if err := agentAPI.ingest(r.RemoteAddr, payload, r.Header.Get("X-AGENT-TOKEN")); err != nil {
			writeJSON(w, err.statusCode, map[string]string{"error": err.message})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	adminMux.HandleFunc("/api/v1/admin/nodes", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			snapshot := storeSnapshot(store, parseBoolQuery(r, "history"))
			writeJSON(w, http.StatusOK, snapshot)
		case http.MethodDelete:
			store.ClearNodes()
			writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}))

	adminMux.HandleFunc("/api/v1/admin/nodes/", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/nodes/")
		if strings.HasSuffix(path, "/agent/update") {
			if r.Method != http.MethodGet && r.Method != http.MethodPost {
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			rawNodeID := strings.TrimSuffix(path, "/agent/update")
			nodeID, err := url.PathUnescape(rawNodeID)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node id"})
				return
			}
			nodeID = strings.TrimSpace(nodeID)
			if nodeID == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node id required"})
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
				if !resolveAgentUpdateSupported(node.Stats) {
					writeJSON(w, http.StatusOK, buildAgentUpdateView(node.Stats, updater.ReleaseInfo{}, resolveAgentUpdateUnsupportedReason(node.Stats)))
					return
				}
				if strings.TrimSpace(node.Stats.AgentVersion) == "" {
					writeJSON(w, http.StatusOK, buildAgentUpdateView(node.Stats, updater.ReleaseInfo{}, "当前节点还没有上报 Agent 版本"))
					return
				}
				client := updater.NewClient(updater.DefaultRepo, updater.KindAgent, strings.TrimSpace(node.Stats.AgentVersion))
				releaseInfo, err := client.CheckLatest(r.Context())
				if err != nil {
					writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
					return
				}
				writeJSON(w, http.StatusOK, buildAgentUpdateView(node.Stats, releaseInfo, ""))
				return
			}

			if !resolveAgentUpdateSupported(node.Stats) {
				message := resolveAgentUpdateUnsupportedReason(node.Stats)
				if strings.TrimSpace(message) == "" {
					message = "当前节点平台暂不支持后台自更新"
				}
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": message})
				return
			}
			client := updater.NewClient(updater.DefaultRepo, updater.KindAgent, strings.TrimSpace(node.Stats.AgentVersion))
			releaseInfo, err := client.CheckLatest(r.Context())
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !releaseInfo.HasUpdate && updater.CompareVersions(releaseInfo.CurrentVersion, releaseInfo.LatestVersion) >= 0 {
				writeJSON(w, http.StatusOK, map[string]string{
					"status":         "up_to_date",
					"target_version": releaseInfo.LatestVersion,
				})
				return
			}
			if strings.TrimSpace(releaseInfo.DownloadURL) == "" {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "未找到当前节点平台对应的 Agent 安装包"})
				return
			}
			store.QueueAgentUpdate(nodeID, AgentUpdateInstruction{
				Version:     releaseInfo.LatestVersion,
				DownloadURL: releaseInfo.DownloadURL,
				ChecksumURL: releaseInfo.ChecksumURL,
			})
			snapshot := storeSnapshot(store, false)
			payload, _ := json.Marshal(snapshot)
			hub.Broadcast(payload)
			writeJSON(w, http.StatusAccepted, map[string]string{
				"status":         "queued",
				"target_version": releaseInfo.LatestVersion,
			})
			return
		}
		nodeID, err := url.PathUnescape(path)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node id"})
			return
		}
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node id required"})
			return
		}
		switch r.Method {
		case http.MethodPut, http.MethodPatch:
			var update NodeProfileUpdate
			if err := decodeJSON(w, r, &update); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			profile := store.UpdateProfile(nodeID, update)
			writeJSON(w, http.StatusOK, profile)
		case http.MethodDelete:
			deleted := store.DeleteNode(nodeID)
			if !deleted {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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
			if strings.TrimSpace(view.AgentToken) != "" {
				cfg.AgentToken = view.AgentToken
			}
			if splitMode && strings.TrimSpace(view.AgentEndpoint) == "" {
				view.AgentEndpoint = cfg.PublicAddr
			}
			if err := refreshAdminSessionCookie(w, r, cfg.JWTSecret, store); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session refresh failed"})
				return
			}
			snapshot := storeSnapshot(store, false)
			payload, _ := json.Marshal(snapshot)
			hub.Broadcast(payload)
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
			releaseInfo, err := systemUpdater.CheckLatest(r.Context())
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !releaseInfo.HasUpdate && updater.CompareVersions(releaseInfo.CurrentVersion, releaseInfo.LatestVersion) >= 0 {
				writeJSON(w, http.StatusOK, map[string]string{
					"status":         "up_to_date",
					"target_version": releaseInfo.LatestVersion,
				})
				return
			}
			if strings.TrimSpace(releaseInfo.DownloadURL) == "" {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "未找到当前平台对应的服务端安装包"})
				return
			}
			err = systemUpdater.Start(releaseInfo, func() error {
				if updater.CanDockerManagedUpdate() {
					dockerUpdater, err := updater.NewDockerManagedUpdater()
					if err != nil {
						return err
					}
					targetImage := updater.ResolveDockerTargetImage(dockerUpdater.CurrentImage(), releaseInfo.LatestVersion)
					return dockerUpdater.LaunchSelfContainerUpdate(context.Background(), targetImage)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				if err := systemUpdater.client.ApplyAsset(ctx, releaseInfo.DownloadURL, releaseInfo.ChecksumURL); err != nil {
					return err
				}
				time.Sleep(700 * time.Millisecond)
				return updater.RestartSelf()
			})
			if err != nil {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "当前已有服务端更新任务正在执行"})
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
		view, reauthRequired, err := store.ImportConfig(payload)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if strings.TrimSpace(view.AgentToken) != "" {
			cfg.AgentToken = view.AgentToken
		}
		if splitMode && strings.TrimSpace(view.AgentEndpoint) == "" {
			view.AgentEndpoint = cfg.PublicAddr
		}
		if err := refreshAdminSessionCookie(w, r, cfg.JWTSecret, store); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session refresh failed"})
			return
		}
		snapshot := storeSnapshot(store, false)
		broadcastPayload, _ := json.Marshal(snapshot)
		hub.Broadcast(broadcastPayload)
		writeJSON(w, http.StatusOK, map[string]any{
			"settings":        view,
			"reauth_required": reauthRequired,
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
			Provider string           `json:"provider"`
			Config   AIProviderConfig `json:"config"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if strings.TrimSpace(req.Provider) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider required"})
			return
		}
		settings := store.AISettings()
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
			Provider string           `json:"provider"`
			Config   AIProviderConfig `json:"config"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if strings.TrimSpace(req.Provider) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider required"})
			return
		}
		settings := store.AISettings()
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

	publicMux.HandleFunc("/api/v1/agent/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		config, err := agentAPI.config(r.URL.Query().Get("node_id"), r.Header.Get("X-AGENT-TOKEN"))
		if err != nil {
			writeJSON(w, err.statusCode, map[string]string{"error": err.message})
			return
		}
		writeJSON(w, http.StatusOK, httpAgentConfigResponse(config, r.Header.Get(agentrpc.AgentCapabilitiesHeader)))
	})

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

	publicMux.HandleFunc("/api/v1/agent/update/report", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			NodeID  string `json:"node_id"`
			State   string `json:"state"`
			Version string `json:"version,omitempty"`
			Message string `json:"message,omitempty"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if err := agentAPI.reportUpdate(req.NodeID, r.Header.Get("X-AGENT-TOKEN"), AgentUpdateReport{
			State:   req.State,
			Version: req.Version,
			Message: req.Message,
		}); err != nil {
			writeJSON(w, err.statusCode, map[string]string{"error": err.message})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	type wsAuthMode int
	const (
		wsAuthOptional wsAuthMode = iota
		wsAuthRequired
		wsAuthForbidden
	)

	resolvePublicVariant := func(r *http.Request) string {
		if r == nil {
			return publicVariantBalanced
		}
		switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("variant"))) {
		case publicVariantBalanced:
			return publicVariantBalanced
		default:
			return publicVariantBalanced
		}
	}

	wsHandler := func(mode wsAuthMode) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			explicitToken := extractExplicitToken(r)
			switch mode {
			case wsAuthRequired:
				sessionToken := extractToken(r)
				if sessionToken == "" {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
				if !isSameOrigin(r) {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
				if err := validateJWTFromRequest(cfg.JWTSecret, r); err != nil {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
			case wsAuthForbidden:
				if explicitToken != "" {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
			case wsAuthOptional:
				if explicitToken != "" {
					if err := validateJWTFromRequest(cfg.JWTSecret, r); err != nil {
						writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
						return
					}
				}
			}
			upgrader := websocket.Upgrader{
				CheckOrigin: func(request *http.Request) bool {
					if mode == wsAuthRequired {
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
			client := hub.Add(conn, resolvePublicVariant(r))

			// 首次连接立即推送快照
			snapshot := storeSnapshot(store, true)
			payload, _ := json.Marshal(snapshot)
			if client != nil {
				if ok := client.enqueue(websocket.TextMessage, bytes.Clone(payload)); !ok {
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
		publicMux.HandleFunc("/ws", wsHandler(wsAuthForbidden))
		adminMux.HandleFunc("/ws", wsHandler(wsAuthRequired))
	} else {
		publicMux.HandleFunc("/ws", wsHandler(wsAuthOptional))
	}

	assetsRoot, err := fs.Sub(webRoot, "assets")
	if err != nil {
		return err
	}
	assetsHandler := http.StripPrefix("/assets/", http.FileServer(http.FS(assetsRoot)))

	adminAssetsRoot, err := fs.Sub(webRoot, "admin-assets")
	if err != nil {
		return err
	}
	adminBundleRoot, err := fs.Sub(adminAssetsRoot, "assets")
	if err != nil {
		return err
	}
	adminAssetsFileServer := http.FileServer(http.FS(adminAssetsRoot))
	adminBundleFileServer := http.FileServer(http.FS(adminBundleRoot))
	adminAssetsHandler := http.StripPrefix("/admin-assets/", adminAssetsFileServer)
	if splitMode {
		adminMux.Handle("/assets/", assetsHandler)
		adminMux.Handle("/admin-assets/", adminAssetsHandler)
	} else {
		publicMux.Handle("/assets/", assetsHandler)
		publicMux.Handle("/admin-assets/", adminAssetsHandler)
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

	writeEmbeddedHTML := func(w http.ResponseWriter, path string, notFoundMessage string) {
		data, err := webFS.ReadFile(path)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": notFoundMessage})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}

	writeAdminAppHTML := func(w http.ResponseWriter, adminPath string) {
		data, err := webFS.ReadFile("web/admin-app/index.html")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "admin app not found"})
			return
		}
		assetBase := adminPath + "/"
		html := strings.ReplaceAll(string(data), "__CM_ADMIN_ASSET_BASE_PATH__", assetBase)
		html = strings.Replace(html, "<title>CyberMonitor 管理后台</title>", "<title>"+adminDocumentTitle(store.SiteTitle())+"</title>", 1)
		bootPayload, err := buildAdminBootPayload(store)
		if err == nil {
			bootMeta := `<meta name="cm-admin-boot" content="` + bootPayload + `" />`
			if strings.Contains(html, "</head>") {
				html = strings.Replace(html, "</head>", bootMeta+"</head>", 1)
			} else {
				html = bootMeta + html
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
	}

	serveAdminAssetsAt := func(w http.ResponseWriter, r *http.Request, prefix string) {
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
		adminBundleFileServer.ServeHTTP(w, next)
	}

	if splitMode {
		adminMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			adminPath := store.AdminPath()
			if r.URL.Path == adminPath+"/assets" {
				http.Redirect(w, r, adminPath+"/assets/", http.StatusFound)
				return
			}
			if strings.HasPrefix(r.URL.Path, adminPath+"/assets/") {
				serveAdminAssetsAt(w, r, adminPath+"/assets/")
				return
			}
			switch r.URL.Path {
			case adminPath + "/preview", adminPath + "/preview/":
				http.Redirect(w, r, adminPath, http.StatusFound)
				return
			case adminPath + "/legacy":
				writeEmbeddedHTML(w, "web/admin.html", "admin not found")
				return
			case adminPath, adminPath + "/":
				writeAdminAppHTML(w, adminPath)
				return
			default:
				http.NotFound(w, r)
				return
			}
		})

		publicMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	} else {
		publicMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			adminPath := store.AdminPath()
			if r.URL.Path == adminPath+"/assets" {
				http.Redirect(w, r, adminPath+"/assets/", http.StatusFound)
				return
			}
			if strings.HasPrefix(r.URL.Path, adminPath+"/assets/") {
				serveAdminAssetsAt(w, r, adminPath+"/assets/")
				return
			}
			switch r.URL.Path {
			case adminPath + "/preview", adminPath + "/preview/":
				http.Redirect(w, r, adminPath, http.StatusFound)
				return
			case adminPath + "/legacy":
				writeEmbeddedHTML(w, "web/admin.html", "admin not found")
				return
			case adminPath, adminPath + "/":
				writeAdminAppHTML(w, adminPath)
				return
			}
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			data, err := webFS.ReadFile("web/index.html")
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "index not found"})
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		})
	}

	grpcServer := newAgentRPCServer(agentAPI)
	publicHandler := wrapPublicHandler(publicMux, grpcServer)
	publicServer := &http.Server{
		Addr:              cfg.PublicAddr,
		Handler:           withSecurityHeaders(publicHandler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	adminServer := &http.Server{}
	if splitMode {
		adminServer = &http.Server{
			Addr:              cfg.Addr,
			Handler:           withSecurityHeaders(adminMux),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
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
				hasConservative := hub.HasVariant(publicVariantConservative)
				hasBalanced := hub.HasVariant(publicVariantBalanced)
				if hasConservative || hasBalanced {
					snapshot := storeSnapshot(store, false)
					if payload, err := json.Marshal(snapshot); err == nil {
						if hasConservative {
							hub.BroadcastVariant(payload, publicVariantConservative)
						}
						if hasBalanced {
							digest := digestPublicSnapshot(snapshot)
							if digest != lastBalancedDigest {
								hub.BroadcastVariant(payload, publicVariantBalanced)
								lastBalancedDigest = digest
							}
						}
					}
				}
				targets, offlineEvents, recoveredEvents := store.CollectAlertEvents(now)
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

	log.Printf("管理后台路径: %s", store.AdminPath())
	if splitMode {
		log.Printf("展示页监听: %s", cfg.PublicAddr)
		log.Printf("管理后台监听: %s", cfg.Addr)
	}
	if !loaded {
		log.Printf("初始管理员账号: %s", settings.AdminUser)
		if settings.AdminPassPlain != "" {
			log.Printf("初始管理员密码: %s", settings.AdminPassPlain)
		} else {
			log.Printf("初始管理员密码: 已设置")
		}
	}
	if tokenGenerated {
		log.Printf("初始 Agent Token: %s", cfg.AgentToken)
	}
	if splitMode {
		adminErr := make(chan error, 1)
		go func() {
			if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				adminErr <- err
				return
			}
			adminErr <- nil
		}()

		if err := publicServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		if err := <-adminErr; err != nil {
			return err
		}
		return nil
	}
	if err := publicServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func applyDefaults(cfg *Config) {
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
		cfg.JWTSecret = generateBootstrapToken()
		cfg.AgentToken = randomToken(32)
		return
	}
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = generateBootstrapToken()
	}
	if cfg.AgentToken == "" {
		cfg.AgentToken = randomToken(32)
	}
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

func generateBootstrapToken() string {
	secret := randomToken(32)
	claims := jwt.RegisteredClaims{
		Subject:  "bootstrap",
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return randomToken(48)
	}
	return signed
}

func (s *Store) Update(stats metrics.NodeStats) {
	var persist bool
	var data PersistedData
	var historyPersist bool
	var historyData TestHistoryData
	s.mu.Lock()

	now := time.Now()
	prev := s.nodes[stats.NodeID]
	firstSeen := prev.FirstSeen
	if firstSeen.IsZero() {
		firstSeen = now
	}
	s.nodes[stats.NodeID] = NodeState{
		Stats:     stats,
		LastSeen:  now,
		FirstSeen: firstSeen,
	}

	profile := s.ensureProfileLocked(stats.NodeID)
	if s.ensureServerIDLocked(stats.NodeID, profile) {
		persist = true
	}
	if profile.TestIntervalSec == 0 {
		profile.TestIntervalSec = defaultTestIntervalSec
		persist = true
	}
	if profile.Alias == "" {
		if stats.NodeAlias != "" {
			profile.Alias = stats.NodeAlias
		} else if stats.NodeName != "" {
			profile.Alias = stats.NodeName
		} else if stats.Hostname != "" {
			profile.Alias = stats.Hostname
		}
		if profile.Alias != "" {
			persist = true
		}
	}
	if stats.NodeGroup != "" {
		if profile.Group == "" {
			profile.Group = stats.NodeGroup
			persist = true
		}
		if len(profile.Groups) == 0 {
			profile.Groups = normalizeGroupSelections(selectionsFromGroupTags(stats.NodeGroup, nil))
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
	profile.UpdatedAt = now.Unix()

	if s.updateTestHistoryLocked(stats, now) {
		s.historyDirty = true
	}
	if s.shouldPersistLocked(now) {
		persist = true
	}
	if s.historyDirty && s.shouldPersistHistoryLocked(now) {
		historyPersist = true
		historyData = s.snapshotTestHistoryLocked(now)
		s.historyDirty = false
	}
	if persist {
		data = s.snapshotPersistedLocked()
	}
	s.mu.Unlock()

	if persist {
		s.persist(data)
	}
	if historyPersist {
		s.persistHistory(historyData)
	}
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
		entry.Latency = append(entry.Latency, normalizeFloatPointer(test.LatencyMs))
		entry.Loss = append(entry.Loss, normalizeFloatValue(test.PacketLoss))
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

func normalizeFloatPointer(value *float64) *float64 {
	if value == nil {
		return nil
	}
	v := *value
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	clone := v
	return &clone
}

func normalizeFloatValue(value float64) *float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return nil
	}
	clone := value
	return &clone
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
	if s.settings.AlertOfflineSec <= 0 || (targets.FeishuWebhook == "" && targets.TelegramToken == "") {
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
	client := &http.Client{Timeout: 6 * time.Second}
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

func cloneNodeStates(values map[string]NodeState) map[string]NodeState {
	if len(values) == 0 {
		return map[string]NodeState{}
	}
	cloned := make(map[string]NodeState, len(values))
	for id, value := range values {
		cloned[id] = value
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
	message := strings.TrimSpace(profile.AgentUpdateMessage)
	if !supported && message == "" {
		message = resolveAgentUpdateUnsupportedReason(stats)
	}
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

func storeSnapshot(s *Store, withHistory bool) Snapshot {
	nodes := s.Snapshot()
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

func (s *Store) snapshotTestHistory() map[string]map[string]*TestHistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneTestHistory(s.testHistory)
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
			copiedTests[key] = &TestHistoryEntry{
				Latency:        slices.Clone(entry.Latency),
				Loss:           slices.Clone(entry.Loss),
				Times:          slices.Clone(entry.Times),
				LastAt:         entry.LastAt,
				MinIntervalSec: entry.MinIntervalSec,
				AvgIntervalSec: entry.AvgIntervalSec,
			}
		}
		if len(copiedTests) > 0 {
			result[nodeID] = copiedTests
		}
	}
	return result
}

func (s *Store) Snapshot() []NodeView {
	var persist bool
	var data PersistedData
	s.mu.Lock()

	views := make([]NodeView, 0, len(s.nodes))
	now := time.Now()
	for _, node := range s.nodes {
		profile := s.ensureProfileLocked(node.Stats.NodeID)
		if s.applyAutoRenewLocked(profile, now) {
			persist = true
		}
		status := "online"
		if now.Sub(node.LastSeen) > 5*time.Second {
			status = "offline"
		}
		group, tags := resolveProfileGroupTags(profile, node.Stats)
		groups := normalizeGroupSelections(profile.Groups)
		updateSupported, updateMode, updateState, updateTargetVersion, updateMessage := resolveAgentUpdateView(profile, node.Stats)
		views = append(views, NodeView{
			Stats:                    node.Stats,
			LastSeen:                 node.LastSeen.Unix(),
			FirstSeen:                node.FirstSeen.Unix(),
			Status:                   status,
			ServerID:                 profile.ServerID,
			AlertEnabled:             isAlertEnabled(profile),
			Alias:                    profile.Alias,
			Group:                    group,
			Tags:                     tags,
			Groups:                   groups,
			Region:                   profile.Region,
			DiskType:                 profile.DiskType,
			NetSpeedMbps:             profile.NetSpeedMbps,
			ExpireAt:                 profile.ExpireAt,
			AutoRenew:                profile.AutoRenew,
			RenewIntervalSec:         profile.RenewIntervalSec,
			TestIntervalSec:          profile.TestIntervalSec,
			Tests:                    profile.Tests,
			TestSelections:           profile.TestSelections,
			AgentUpdateSupported:     updateSupported,
			AgentUpdateMode:          updateMode,
			AgentUpdateState:         updateState,
			AgentUpdateTargetVersion: updateTargetVersion,
			AgentUpdateMessage:       updateMessage,
		})
	}
	sort.Slice(views, func(i, j int) bool {
		leftGroup := views[i].Group
		rightGroup := views[j].Group
		if leftGroup == rightGroup {
			return views[i].Alias < views[j].Alias
		}
		return leftGroup < rightGroup
	})
	if persist {
		data = s.snapshotPersistedLocked()
	}
	s.mu.Unlock()

	if persist {
		s.persist(data)
	}
	return views
}

func (s *Store) PublicNodeDelta(nodeID string) (NodeDelta, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return NodeDelta{}, false
	}
	node, ok := s.nodes[nodeID]
	if !ok {
		return NodeDelta{}, false
	}

	profile := s.profiles[nodeID]
	if profile == nil {
		profile = &NodeProfile{TestIntervalSec: defaultTestIntervalSec}
	}

	status := "online"
	if time.Since(node.LastSeen) > 5*time.Second {
		status = "offline"
	}
	group, tags := resolveProfileGroupTags(profile, node.Stats)
	groups := normalizeGroupSelections(profile.Groups)
	updateSupported, updateMode, updateState, updateTargetVersion, updateMessage := resolveAgentUpdateView(profile, node.Stats)

	return NodeDelta{
		Type:        "node_delta",
		GeneratedAt: time.Now().Unix(),
		Node: NodeView{
			Stats:                    node.Stats,
			LastSeen:                 node.LastSeen.Unix(),
			FirstSeen:                node.FirstSeen.Unix(),
			Status:                   status,
			ServerID:                 profile.ServerID,
			AlertEnabled:             isAlertEnabled(profile),
			Alias:                    profile.Alias,
			Group:                    group,
			Tags:                     tags,
			Groups:                   groups,
			Region:                   profile.Region,
			DiskType:                 profile.DiskType,
			NetSpeedMbps:             profile.NetSpeedMbps,
			ExpireAt:                 profile.ExpireAt,
			AutoRenew:                profile.AutoRenew,
			RenewIntervalSec:         profile.RenewIntervalSec,
			TestIntervalSec:          profile.TestIntervalSec,
			Tests:                    profile.Tests,
			TestSelections:           profile.TestSelections,
			AgentUpdateSupported:     updateSupported,
			AgentUpdateMode:          updateMode,
			AgentUpdateState:         updateState,
			AgentUpdateTargetVersion: updateTargetVersion,
			AgentUpdateMessage:       updateMessage,
		},
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

func (h *Hub) Add(conn *websocket.Conn, variant string) *hubClient {
	client := &hubClient{
		conn:    conn,
		variant: variant,
		send:    make(chan hubMessage, wsSendQueueSize),
		done:    make(chan struct{}),
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

func (h *Hub) Broadcast(payload []byte) {
	clients := h.snapshotClients()
	for _, client := range clients {
		copied := bytes.Clone(payload)
		if ok := client.enqueue(websocket.TextMessage, copied); !ok {
			h.removeClient(client)
		}
	}
}

func (h *Hub) BroadcastVariant(payload []byte, variant string) {
	clients := h.snapshotClients()
	for _, client := range clients {
		if client == nil || client.variant != variant {
			continue
		}
		copied := bytes.Clone(payload)
		if ok := client.enqueue(websocket.TextMessage, copied); !ok {
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

func buildDefaultPublicConfig(r *http.Request) (string, string) {
	scheme := "http"
	if r != nil {
		if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); strings.EqualFold(proto, "https") {
			scheme = "https"
		} else if r.TLS != nil {
			scheme = "https"
		}
	}
	host := ""
	if r != nil {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	wsScheme := "ws"
	if scheme == "https" {
		wsScheme = "wss"
	}
	apiBase := fmt.Sprintf("%s://%s", scheme, host)
	socketURL := fmt.Sprintf("%s://%s/ws", wsScheme, host)
	return apiBase, socketURL
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' ws: wss:")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
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
	Alias            *string                      `json:"alias"`
	Group            *string                      `json:"group"`
	Tags             *[]string                    `json:"tags"`
	Groups           *[]string                    `json:"groups"`
	Region           *string                      `json:"region"`
	DiskType         *string                      `json:"disk_type"`
	NetSpeedMbps     *int                         `json:"net_speed_mbps"`
	ExpireAt         *int64                       `json:"expire_at"`
	AutoRenew        *bool                        `json:"auto_renew"`
	RenewIntervalSec *int64                       `json:"renew_interval_sec"`
	TestIntervalSec  *int                         `json:"test_interval_sec"`
	Tests            *[]metrics.NetworkTestConfig `json:"tests"`
	TestSelections   *[]TestSelection             `json:"test_selections"`
	AlertEnabled     *bool                        `json:"alert_enabled"`
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
	data := s.snapshotPersistedLocked()
	s.mu.Unlock()
	s.persist(data)
}

func (s *Store) PublicSettings() PublicSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return PublicSettings{
		SiteTitle:    s.settings.SiteTitle,
		SiteIcon:     s.settings.SiteIcon,
		HomeTitle:    s.settings.HomeTitle,
		HomeSubtitle: s.settings.HomeSubtitle,
		Version:      s.buildVersion,
		Commit:       s.buildCommit,
	}
}

func (s *Store) SettingsView() SettingsView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	loginFailLimit := s.settings.LoginFailLimit
	if loginFailLimit < 0 {
		loginFailLimit = 0
	}
	return SettingsView{
		AdminPath:            s.settings.AdminPath,
		AdminUser:            s.settings.AdminUser,
		TurnstileSiteKey:     strings.TrimSpace(s.settings.TurnstileSiteKey),
		TurnstileSecretKey:   strings.TrimSpace(s.settings.TurnstileSecretKey),
		AgentEndpoint:        strings.TrimSpace(s.settings.AgentEndpoint),
		AgentToken:           s.settings.AgentToken,
		SiteTitle:            s.settings.SiteTitle,
		SiteIcon:             s.settings.SiteIcon,
		HomeTitle:            s.settings.HomeTitle,
		HomeSubtitle:         s.settings.HomeSubtitle,
		AlertWebhook:         s.settings.AlertWebhook,
		AlertOfflineSec:      s.settings.AlertOfflineSec,
		AlertAll:             s.settings.AlertAll,
		AlertNodes:           cloneStringSlice(s.settings.AlertNodes),
		AlertTelegramToken:   s.settings.AlertTelegramToken,
		AlertTelegramUserIDs: cloneInt64Slice(s.settings.AlertTelegramUserIDs),
		AlertTelegramUserID:  firstTelegramUserID(s.settings.AlertTelegramUserIDs),
		LoginFailLimit:       loginFailLimit,
		LoginFailWindowSec:   s.settings.LoginFailWindowSec,
		LoginLockSec:         s.settings.LoginLockSec,
		AISettings:           cloneAISettings(s.settings.AISettings),
		Version:              s.buildVersion,
		Commit:               s.buildCommit,
		Groups:               cloneStringSlice(s.settings.Groups),
		GroupTree:            cloneGroupNodes(s.settings.GroupTree),
		TestCatalog:          cloneTestCatalogItems(s.settings.TestCatalog),
	}
}

func (s *Store) ExportConfig() ConfigTransferData {
	view := s.SettingsView()
	view.AgentToken = ""
	view.Commit = ""
	view.SessionToken = ""
	view.SessionExpiresAt = 0
	s.mu.RLock()
	profiles := cloneProfiles(s.profiles)
	s.mu.RUnlock()
	return ConfigTransferData{
		Version:    configExportVersion,
		ExportedAt: time.Now().Unix(),
		Settings:   view,
		Profiles:   profiles,
	}
}

func refreshAdminSessionCookie(w http.ResponseWriter, r *http.Request, secret string, store *Store) error {
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
	setAdminSessionCookie(w, r, token, exp)
	return nil
}

func setAdminSessionCookie(w http.ResponseWriter, r *http.Request, token string, exp int64) {
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
	if requestIsSecure(r) {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

func clearAdminSessionCookie(w http.ResponseWriter, r *http.Request) {
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
	if requestIsSecure(r) {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

func requestIsSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func settingsViewToUpdate(view SettingsView) SettingsUpdate {
	adminPath := strings.TrimSpace(view.AdminPath)
	adminUser := strings.TrimSpace(view.AdminUser)
	agentToken := strings.TrimSpace(view.AgentToken)
	agentEndpoint := strings.TrimSpace(view.AgentEndpoint)
	siteTitle := strings.TrimSpace(view.SiteTitle)
	siteIcon := strings.TrimSpace(view.SiteIcon)
	homeTitle := strings.TrimSpace(view.HomeTitle)
	homeSubtitle := strings.TrimSpace(view.HomeSubtitle)
	alertWebhook := strings.TrimSpace(view.AlertWebhook)
	alertTelegramToken := strings.TrimSpace(view.AlertTelegramToken)
	alertNodes := cloneStringSlice(view.AlertNodes)
	alertTelegramUserIDs := cloneInt64Slice(view.AlertTelegramUserIDs)
	aiSettings := cloneAISettings(view.AISettings)
	groups := cloneStringSlice(view.Groups)
	groupTree := cloneGroupNodes(view.GroupTree)
	testCatalog := cloneTestCatalogItems(view.TestCatalog)
	alertAll := view.AlertAll

	update := SettingsUpdate{
		AdminPath:            stringPointer(adminPath),
		AdminUser:            stringPointer(adminUser),
		TurnstileSiteKey:     stringPointer(strings.TrimSpace(view.TurnstileSiteKey)),
		TurnstileSecretKey:   stringPointer(strings.TrimSpace(view.TurnstileSecretKey)),
		AgentEndpoint:        stringPointer(agentEndpoint),
		SiteTitle:            stringPointer(siteTitle),
		SiteIcon:             stringPointer(siteIcon),
		HomeTitle:            stringPointer(homeTitle),
		HomeSubtitle:         stringPointer(homeSubtitle),
		AlertWebhook:         stringPointer(alertWebhook),
		AlertOfflineSec:      int64Pointer(view.AlertOfflineSec),
		AlertAll:             &alertAll,
		AlertNodes:           &alertNodes,
		AlertTelegramToken:   stringPointer(alertTelegramToken),
		AlertTelegramUserIDs: &alertTelegramUserIDs,
		LoginFailLimit:       intPointer(view.LoginFailLimit),
		LoginFailWindowSec:   int64Pointer(view.LoginFailWindowSec),
		LoginLockSec:         int64Pointer(view.LoginLockSec),
		AISettings:           &aiSettings,
		Groups:               &groups,
		TestCatalog:          &testCatalog,
	}
	if agentToken != "" {
		update.AgentToken = stringPointer(agentToken)
	}
	if len(groupTree) > 0 {
		update.GroupTree = &groupTree
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
	var data PersistedData
	var view SettingsView
	s.mu.Lock()
	if update.AdminPath != nil {
		normalized, err := normalizeAdminPath(*update.AdminPath)
		if err != nil {
			s.mu.Unlock()
			return SettingsView{}, err
		}
		s.settings.AdminPath = normalized
	}
	if update.AdminUser != nil {
		user := strings.TrimSpace(*update.AdminUser)
		if user == "" {
			s.mu.Unlock()
			return SettingsView{}, errors.New("admin_user invalid")
		}
		if user != s.settings.AdminUser {
			s.settings.AdminUser = user
			s.settings.TokenSalt = randomToken(adminTokenLength)
		}
	}
	if update.AdminPass != nil {
		pass := strings.TrimSpace(*update.AdminPass)
		if pass == "" {
			s.mu.Unlock()
			return SettingsView{}, errors.New("admin_pass invalid")
		}
		if verifyPassword(pass, s.settings.AdminPass) {
			if !isBcryptHash(s.settings.AdminPass) {
				hash, err := hashPassword(pass)
				if err != nil {
					s.mu.Unlock()
					return SettingsView{}, errors.New("admin_pass hash failed")
				}
				s.settings.AdminPass = hash
			}
		} else {
			hash, err := hashPassword(pass)
			if err != nil {
				s.mu.Unlock()
				return SettingsView{}, errors.New("admin_pass hash failed")
			}
			s.settings.AdminPass = hash
			s.settings.TokenSalt = randomToken(adminTokenLength)
		}
		s.settings.AdminPassPlain = ""
	}
	if update.AgentToken != nil {
		token := strings.TrimSpace(*update.AgentToken)
		if token == "" {
			s.mu.Unlock()
			return SettingsView{}, errors.New("agent_token invalid")
		}
		s.settings.AgentToken = token
	}
	if update.AgentEndpoint != nil {
		s.settings.AgentEndpoint = strings.TrimSpace(*update.AgentEndpoint)
	}
	if update.TurnstileSiteKey != nil {
		s.settings.TurnstileSiteKey = strings.TrimSpace(*update.TurnstileSiteKey)
	}
	if update.TurnstileSecretKey != nil {
		s.settings.TurnstileSecretKey = strings.TrimSpace(*update.TurnstileSecretKey)
	}
	if (s.settings.TurnstileSiteKey == "") != (s.settings.TurnstileSecretKey == "") {
		s.mu.Unlock()
		return SettingsView{}, errors.New("turnstile 站点 Key 与 Secret Key 需要同时配置")
	}
	if update.SiteTitle != nil {
		s.settings.SiteTitle = strings.TrimSpace(*update.SiteTitle)
		if s.settings.SiteTitle == "" {
			s.settings.SiteTitle = defaultSiteTitle
		}
	}
	if update.SiteIcon != nil {
		s.settings.SiteIcon = strings.TrimSpace(*update.SiteIcon)
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
	if update.AlertWebhook != nil {
		value := strings.TrimSpace(*update.AlertWebhook)
		if value != "" {
			if err := validateWebhookURL(value); err != nil {
				s.mu.Unlock()
				return SettingsView{}, err
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
	if update.AlertAll != nil {
		s.settings.AlertAll = *update.AlertAll
	}
	if update.AlertNodes != nil {
		s.settings.AlertNodes = normalizeAlertNodes(*update.AlertNodes)
	}
	if update.AlertTelegramToken != nil {
		value := strings.TrimSpace(*update.AlertTelegramToken)
		if value != "" {
			if err := validateTelegramToken(value); err != nil {
				s.mu.Unlock()
				return SettingsView{}, err
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
		s.mu.Unlock()
		return SettingsView{}, errors.New("telegram token 与 telegram 用户 ID 需要同时配置")
	}
	if update.LoginFailLimit != nil {
		limit := *update.LoginFailLimit
		if limit < -1 {
			s.mu.Unlock()
			return SettingsView{}, errors.New("login_fail_limit invalid")
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
			s.mu.Unlock()
			return SettingsView{}, errors.New("login_fail_window_sec invalid")
		}
		if windowSec == 0 {
			windowSec = defaultLoginFailWindow
		}
		s.settings.LoginFailWindowSec = windowSec
	}
	if update.LoginLockSec != nil {
		lockSec := *update.LoginLockSec
		if lockSec < 0 {
			s.mu.Unlock()
			return SettingsView{}, errors.New("login_lock_sec invalid")
		}
		if lockSec == 0 {
			lockSec = defaultLoginLockSec
		}
		s.settings.LoginLockSec = lockSec
	}
	if update.AISettings != nil {
		normalized := normalizeAISettings(*update.AISettings)
		if err := validateAISettings(normalized); err != nil {
			s.mu.Unlock()
			return SettingsView{}, err
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
		catalog, err := normalizeTestCatalog(*update.TestCatalog)
		if err != nil {
			s.mu.Unlock()
			return SettingsView{}, err
		}
		s.settings.TestCatalog = catalog
	}
	data = s.snapshotPersistedLocked()
	loginFailLimit := s.settings.LoginFailLimit
	if loginFailLimit < 0 {
		loginFailLimit = 0
	}
	view = SettingsView{
		AdminPath:            s.settings.AdminPath,
		AdminUser:            s.settings.AdminUser,
		TurnstileSiteKey:     strings.TrimSpace(s.settings.TurnstileSiteKey),
		TurnstileSecretKey:   strings.TrimSpace(s.settings.TurnstileSecretKey),
		AgentEndpoint:        strings.TrimSpace(s.settings.AgentEndpoint),
		AgentToken:           s.settings.AgentToken,
		SiteTitle:            s.settings.SiteTitle,
		SiteIcon:             s.settings.SiteIcon,
		HomeTitle:            s.settings.HomeTitle,
		HomeSubtitle:         s.settings.HomeSubtitle,
		AlertWebhook:         s.settings.AlertWebhook,
		AlertOfflineSec:      s.settings.AlertOfflineSec,
		AlertAll:             s.settings.AlertAll,
		AlertNodes:           cloneStringSlice(s.settings.AlertNodes),
		AlertTelegramToken:   s.settings.AlertTelegramToken,
		AlertTelegramUserIDs: cloneInt64Slice(s.settings.AlertTelegramUserIDs),
		AlertTelegramUserID:  firstTelegramUserID(s.settings.AlertTelegramUserIDs),
		LoginFailLimit:       loginFailLimit,
		LoginFailWindowSec:   s.settings.LoginFailWindowSec,
		LoginLockSec:         s.settings.LoginLockSec,
		AISettings:           cloneAISettings(s.settings.AISettings),
		Version:              s.buildVersion,
		Commit:               s.buildCommit,
		Groups:               cloneStringSlice(s.settings.Groups),
		GroupTree:            cloneGroupNodes(s.settings.GroupTree),
		TestCatalog:          cloneTestCatalogItems(s.settings.TestCatalog),
	}
	s.mu.Unlock()

	s.persist(data)
	return view, nil
}

func (s *Store) ImportConfig(payload ConfigTransferData) (SettingsView, bool, error) {
	if payload.Version <= 0 {
		return SettingsView{}, false, errors.New("导入文件版本无效")
	}

	current := s.SettingsView()
	s.mu.RLock()
	staged := &Store{
		nodes:    cloneNodeStates(s.nodes),
		profiles: cloneProfiles(s.profiles),
		settings: s.settings,
	}
	s.mu.RUnlock()

	if _, err := staged.UpdateSettings(settingsViewToUpdate(payload.Settings)); err != nil {
		return SettingsView{}, false, err
	}
	staged.mu.Lock()
	normalizedProfiles, err := staged.normalizeProfilesForImportLocked(payload.Profiles)
	staged.mu.Unlock()
	if err != nil {
		return SettingsView{}, false, err
	}

	var data PersistedData
	s.mu.Lock()
	s.settings = staged.settings
	s.profiles = normalizedProfiles
	data = s.snapshotPersistedLocked()
	s.mu.Unlock()
	s.persist(data)

	reauthRequired := current.AdminUser != payload.Settings.AdminUser
	return s.SettingsView(), reauthRequired, nil
}

func (s *Store) ReplaceProfiles(profiles map[string]*NodeProfile) error {
	var data PersistedData
	s.mu.Lock()
	normalized, err := s.normalizeProfilesForImportLocked(profiles)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.profiles = normalized
	data = s.snapshotPersistedLocked()
	s.mu.Unlock()
	s.persist(data)
	return nil
}

func (s *Store) normalizeProfilesForImportLocked(profiles map[string]*NodeProfile) (map[string]*NodeProfile, error) {
	if profiles == nil {
		return map[string]*NodeProfile{}, nil
	}

	now := time.Now().Unix()
	normalized := make(map[string]*NodeProfile, len(profiles))
	for rawNodeID, rawProfile := range profiles {
		nodeID := strings.TrimSpace(rawNodeID)
		if nodeID == "" {
			return nil, errors.New("profiles 节点 ID 不能为空")
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
		profile.Tests = cloneNetworkTestConfigs(profile.Tests)
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
	ensureServerIDsForProfiles(normalized, s.nodes)
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

func (s *Store) ensureAgentAuthToken(nodeID string) string {
	var data PersistedData
	changed := false
	s.mu.Lock()
	profile := s.ensureProfileLocked(strings.TrimSpace(nodeID))
	if strings.TrimSpace(profile.AgentAuthToken) == "" || s.isAgentAuthTokenDuplicateLocked(nodeID, profile.AgentAuthToken) {
		profile.AgentAuthToken = s.generateAgentAuthTokenLocked()
		profile.UpdatedAt = time.Now().Unix()
		data = s.snapshotPersistedLocked()
		changed = true
	}
	token := strings.TrimSpace(profile.AgentAuthToken)
	s.mu.Unlock()
	if changed {
		s.persist(data)
	}
	return token
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
	return subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}

func isBootstrapAgentToken(expected, token string) bool {
	expected = strings.TrimSpace(expected)
	token = strings.TrimSpace(token)
	if expected == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}

func (s *Store) validateOrProvisionAgentAuthToken(nodeID, token, bootstrapToken string) bool {
	if s.validateAgentAuthToken(nodeID, token) {
		return true
	}
	if !isBootstrapAgentToken(bootstrapToken, token) {
		return false
	}
	s.ensureAgentAuthToken(nodeID)
	return true
}

func (s *Store) generateAgentAuthTokenLocked() string {
	for {
		token := randomToken(40)
		if !s.isAgentAuthTokenUsedLocked(token) {
			return token
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

func (s *Store) ensureServerIDLocked(nodeID string, profile *NodeProfile) bool {
	if profile == nil {
		return false
	}
	original := strings.TrimSpace(profile.ServerID)
	if original == "" || s.isServerIDDuplicateLocked(nodeID, original) {
		profile.ServerID = s.generateServerIDLocked()
		return true
	}
	return false
}

func (s *Store) generateServerIDLocked() string {
	for {
		id := randomToken(10)
		if !s.isServerIDUsedLocked(id) {
			return id
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

func ensureServerIDsForProfiles(profiles map[string]*NodeProfile, nodes map[string]NodeState) {
	if profiles == nil {
		return
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
			id = randomToken(10)
			for containsKey(used, id) {
				id = randomToken(10)
			}
			profile.ServerID = id
		}
		used[id] = struct{}{}
	}
}

func containsKey(seen map[string]struct{}, key string) bool {
	_, ok := seen[key]
	return ok
}

func (s *Store) UpdateProfile(nodeID string, update NodeProfileUpdate) NodeProfile {
	var data PersistedData
	s.mu.Lock()

	profile := s.ensureProfileLocked(nodeID)
	if update.Alias != nil {
		profile.Alias = strings.TrimSpace(*update.Alias)
	}
	if update.Group != nil {
		profile.Group = strings.TrimSpace(*update.Group)
	}
	if update.Tags != nil {
		profile.Tags = normalizeGroups(*update.Tags)
	}
	if update.Groups != nil {
		profile.Groups = normalizeGroupSelections(*update.Groups)
		group, tags := primaryGroupTagsFromSelections(profile.Groups)
		profile.Group = group
		profile.Tags = tags
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
	}
	if update.Tests != nil {
		profile.Tests = *update.Tests
	}
	if update.TestSelections != nil {
		profile.TestSelections = s.normalizeSelectionsLocked(*update.TestSelections)
	}
	if update.AlertEnabled != nil {
		value := *update.AlertEnabled
		profile.AlertEnabled = &value
	}
	profile.UpdatedAt = time.Now().Unix()
	data = s.snapshotPersistedLocked()
	s.mu.Unlock()
	s.persist(data)
	return *profile
}

func (s *Store) UpdateAlertEnabledByServerID(serverID string, enabled bool) (string, string, bool) {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return "", "", false
	}
	var data PersistedData
	var nodeID string
	var display string
	s.mu.Lock()
	for id, profile := range s.profiles {
		if profile == nil {
			continue
		}
		if strings.TrimSpace(profile.ServerID) != serverID {
			continue
		}
		nodeID = id
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
		data = s.snapshotPersistedLocked()
		break
	}
	s.mu.Unlock()
	if nodeID == "" {
		return "", "", false
	}
	s.persist(data)
	return nodeID, display, true
}

func (s *Store) DeleteNode(nodeID string) bool {
	var data PersistedData
	var historyData TestHistoryData
	var historyPersist bool
	now := time.Now()
	s.mu.Lock()
	_, exists := s.nodes[nodeID]
	delete(s.nodes, nodeID)
	delete(s.profiles, nodeID)
	if s.testHistory != nil {
		if _, ok := s.testHistory[nodeID]; ok {
			delete(s.testHistory, nodeID)
			s.historyDirty = true
		}
	}
	if s.historyDirty && s.shouldPersistHistoryLocked(now) {
		historyPersist = true
		historyData = s.snapshotTestHistoryLocked(now)
		s.historyDirty = false
	}
	data = s.snapshotPersistedLocked()
	s.mu.Unlock()
	s.persist(data)
	if historyPersist {
		s.persistHistory(historyData)
	}
	return exists
}

func (s *Store) ClearNodes() {
	var data PersistedData
	var historyData TestHistoryData
	var historyPersist bool
	now := time.Now()
	s.mu.Lock()
	s.nodes = make(map[string]NodeState)
	s.profiles = make(map[string]*NodeProfile)
	s.testHistory = make(map[string]map[string]*TestHistoryEntry)
	s.historyDirty = true
	if s.shouldPersistHistoryLocked(now) {
		historyPersist = true
		historyData = s.snapshotTestHistoryLocked(now)
		s.historyDirty = false
	}
	data = s.snapshotPersistedLocked()
	s.mu.Unlock()
	s.persist(data)
	if historyPersist {
		s.persistHistory(historyData)
	}
}

type AgentUpdateReport struct {
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
	Message string `json:"message,omitempty"`
}

func (s *Store) QueueAgentUpdate(nodeID string, instruction AgentUpdateInstruction) NodeProfile {
	var data PersistedData
	s.mu.Lock()
	profile := s.ensureProfileLocked(nodeID)
	instruction.Version = strings.TrimSpace(instruction.Version)
	instruction.DownloadURL = strings.TrimSpace(instruction.DownloadURL)
	instruction.ChecksumURL = strings.TrimSpace(instruction.ChecksumURL)
	instruction.RequestedAt = time.Now().Unix()
	profile.AgentUpdate = cloneAgentUpdateInstruction(&instruction)
	profile.AgentUpdateState = "pending"
	profile.AgentUpdateTargetVersion = instruction.Version
	profile.AgentUpdateMessage = "已下发更新任务，等待 Agent 执行"
	profile.AgentUpdateReportedAt = instruction.RequestedAt
	profile.UpdatedAt = instruction.RequestedAt
	data = s.snapshotPersistedLocked()
	s.mu.Unlock()
	s.persist(data)
	return *profile
}

func (s *Store) ApplyAgentUpdateReport(nodeID string, report AgentUpdateReport) NodeProfile {
	var data PersistedData
	s.mu.Lock()
	profile := s.ensureProfileLocked(nodeID)
	reportedAt := time.Now().Unix()
	state := strings.TrimSpace(report.State)
	if state == "" {
		state = "unknown"
	}
	profile.AgentUpdateState = state
	if version := strings.TrimSpace(report.Version); version != "" {
		profile.AgentUpdateTargetVersion = version
	}
	profile.AgentUpdateMessage = strings.TrimSpace(report.Message)
	profile.AgentUpdateReportedAt = reportedAt
	if state == "succeeded" || state == "failed" {
		profile.AgentUpdate = nil
	}
	profile.UpdatedAt = reportedAt
	data = s.snapshotPersistedLocked()
	s.mu.Unlock()
	s.persist(data)
	return *profile
}

func (s *Store) AgentConfig(nodeID string) AgentConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
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
	return AgentConfig{
		Alias:           profile.Alias,
		Group:           group,
		AgentToken:      strings.TrimSpace(profile.AgentAuthToken),
		TestIntervalSec: profile.TestIntervalSec,
		Tests:           tests,
		Update:          cloneAgentUpdateInstruction(profile.AgentUpdate),
	}
}

func (s *Store) snapshotPersistedLocked() PersistedData {
	profiles := cloneProfiles(s.profiles)
	nodes := make(map[string]NodeState, len(s.nodes))
	for id, node := range s.nodes {
		nodes[id] = node
	}
	return PersistedData{
		Settings: s.settings,
		Profiles: profiles,
		Nodes:    nodes,
	}
}

func (s *Store) snapshotTestHistoryLocked(now time.Time) TestHistoryData {
	return TestHistoryData{
		Version:   testHistoryVersion,
		UpdatedAt: now.Unix(),
		Nodes:     cloneTestHistory(s.testHistory),
	}
}

func (s *Store) persist(data PersistedData) {
	if s.dataPath == "" {
		return
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	if err := savePersistedData(s.dataPath, data); err != nil {
		log.Printf("%v", wrapDataPathError("持久化失败", s.dataPath, err))
		return
	}
	s.mu.Lock()
	s.lastPersist = time.Now()
	s.mu.Unlock()
}

func (s *Store) persistHistory(data TestHistoryData) {
	if s.historyPath == "" {
		return
	}
	s.historyPersistMu.Lock()
	defer s.historyPersistMu.Unlock()
	if err := saveTestHistoryData(s.historyPath, data); err != nil {
		log.Printf("%v", wrapDataPathError("探测历史持久化失败", s.historyPath, err))
		return
	}
	s.mu.Lock()
	s.historyLastPersist = time.Now()
	s.mu.Unlock()
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

func (s *Store) shouldPersistHistoryLocked(now time.Time) bool {
	if s.persistInterval <= 0 {
		return false
	}
	if s.historyLastPersist.IsZero() {
		return true
	}
	return now.Sub(s.historyLastPersist) >= s.persistInterval
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
		return profile.Tests
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
	}
	return results
}

func (s *Store) normalizeSelectionsLocked(selections []TestSelection) []TestSelection {
	if len(selections) == 0 {
		return nil
	}
	valid := make(map[string]TestCatalogItem, len(s.settings.TestCatalog))
	for _, item := range s.settings.TestCatalog {
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
	}
	return result
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

func requireJWT(secret string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := validateJWTFromRequest(secret, r); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func requireAdminJWT(store *Store, secret string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := validateAdminJWT(store, secret, r); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func validateJWTFromRequest(secret string, r *http.Request) error {
	token := extractToken(r)
	if token == "" {
		return errors.New("token required")
	}
	parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
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
	return nil
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
		if err == nil {
			return errors.New("extra json content")
		}
		return errors.New("extra json content")
	}
	return nil
}

func validateWebhookURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("webhook 不能为空")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("webhook 无效")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("webhook 协议无效")
	}
	if parsed.Host == "" {
		return errors.New("webhook 无效")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func buildAdminBootPayload(store *Store) (string, error) {
	payload := struct {
		Settings PublicSettings `json:"settings"`
	}{
		Settings: store.PublicSettings(),
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
