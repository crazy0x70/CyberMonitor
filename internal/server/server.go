package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxLogSize               = 10 * 1024 * 1024
	maxTestHistoryPoints     = 5000
	testHistoryHotSeconds    = 60 * 60
	testHistoryMaxAgeSeconds = 60 * 60 * 24 * 365
	maxJSONBodySize          = 4 * 1024 * 1024
)

type sizeLimitedWriter struct {
	path    string
	maxSize int64
	mu      sync.Mutex
}

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

	file, err := os.OpenFile(w.path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return len(p), err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return len(p), err
	}

	if info.Size()+int64(len(p)) > w.maxSize {
		if err := file.Truncate(0); err != nil {
			return len(p), err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
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

func setupLogger(dataDir string) {
	if dataDir == "" {
		return
	}
	logPath := filepath.Join(dataDir, "server.log")
	writer := &sizeLimitedWriter{path: logPath, maxSize: maxLogSize}
	log.SetOutput(io.MultiWriter(os.Stdout, writer))
}

const (
	defaultAddr            = ":25012"
	defaultTestIntervalSec = 5
	defaultPersistInterval = 10 * time.Second
)

//go:embed web/*
var webFS embed.FS

type Config struct {
	Addr       string
	AdminUser  string
	AdminPass  string
	AdminPath  string
	JWTSecret  string
	AgentToken string
	DataDir    string
	Commit     string
}

type Store struct {
	mu                 sync.RWMutex
	nodes              map[string]NodeState
	profiles           map[string]*NodeProfile
	settings           Settings
	buildCommit        string
	dataPath           string
	historyPath        string
	lastPersist        time.Time
	persistInterval    time.Duration
	alerted            map[string]alertState
	testHistory        map[string]map[string]*TestHistoryEntry
	historyDirty       bool
	historyLastPersist time.Time
}

type NodeState struct {
	Stats     metrics.NodeStats `json:"stats"`
	LastSeen  time.Time         `json:"last_seen"`
	FirstSeen time.Time         `json:"first_seen"`
}

type NodeProfile struct {
	ServerID         string                      `json:"server_id,omitempty"`
	AlertEnabled     *bool                       `json:"alert_enabled,omitempty"`
	Alias            string                      `json:"alias,omitempty"`
	Group            string                      `json:"group,omitempty"`
	Tags             []string                    `json:"tags,omitempty"`
	Groups           []string                    `json:"groups,omitempty"`
	Region           string                      `json:"region,omitempty"`
	DiskType         string                      `json:"disk_type,omitempty"`
	NetSpeedMbps     int                         `json:"net_speed_mbps,omitempty"`
	ExpireAt         int64                       `json:"expire_at,omitempty"`
	AutoRenew        bool                        `json:"auto_renew,omitempty"`
	RenewIntervalSec int64                       `json:"renew_interval_sec,omitempty"`
	TestIntervalSec  int                         `json:"test_interval_sec"`
	Tests            []metrics.NetworkTestConfig `json:"tests,omitempty"`
	TestSelections   []TestSelection             `json:"test_selections,omitempty"`
	UpdatedAt        int64                       `json:"updated_at,omitempty"`
}

type TestSelection struct {
	TestID      string `json:"test_id"`
	IntervalSec int    `json:"interval_sec,omitempty"`
}

type AgentConfig struct {
	Alias           string                      `json:"alias,omitempty"`
	Group           string                      `json:"group,omitempty"`
	TestIntervalSec int                         `json:"test_interval_sec"`
	Tests           []metrics.NetworkTestConfig `json:"tests"`
}

type NodeView struct {
	Stats            metrics.NodeStats           `json:"stats"`
	LastSeen         int64                       `json:"last_seen"`
	FirstSeen        int64                       `json:"first_seen,omitempty"`
	Status           string                      `json:"status"`
	ServerID         string                      `json:"server_id,omitempty"`
	AlertEnabled     bool                        `json:"alert_enabled"`
	Alias            string                      `json:"alias,omitempty"`
	Group            string                      `json:"group,omitempty"`
	Tags             []string                    `json:"tags,omitempty"`
	Groups           []string                    `json:"groups,omitempty"`
	Region           string                      `json:"region,omitempty"`
	DiskType         string                      `json:"disk_type,omitempty"`
	NetSpeedMbps     int                         `json:"net_speed_mbps,omitempty"`
	ExpireAt         int64                       `json:"expire_at,omitempty"`
	AutoRenew        bool                        `json:"auto_renew,omitempty"`
	RenewIntervalSec int64                       `json:"renew_interval_sec,omitempty"`
	TestIntervalSec  int                         `json:"test_interval_sec,omitempty"`
	Tests            []metrics.NetworkTestConfig `json:"tests,omitempty"`
	TestSelections   []TestSelection             `json:"test_selections,omitempty"`
}

type PublicSettings struct {
	SiteTitle    string `json:"site_title,omitempty"`
	SiteIcon     string `json:"site_icon,omitempty"`
	HomeTitle    string `json:"home_title,omitempty"`
	HomeSubtitle string `json:"home_subtitle,omitempty"`
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

type Hub struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]*hubClient
}

type hubClient struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (c *hubClient) writeMessage(messageType int, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(messageType, payload)
}

func (c *hubClient) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Close()
}

func Run(ctx context.Context, cfg Config) error {
	applyDefaults(&cfg)
	setupLogger(cfg.DataDir)

	dataPath := filepath.Join(cfg.DataDir, "state.json")
	persisted, loaded, err := loadPersistedData(dataPath)
	if err != nil {
		log.Printf("读取持久化数据失败: %v", err)
	}
	historyPath := filepath.Join(cfg.DataDir, testHistoryFileName)
	historyPayload, _, historyErr := loadTestHistoryData(historyPath)
	if historyErr != nil {
		log.Printf("读取探测历史失败: %v", historyErr)
	}
	tokenGenerated := !loaded || persisted.Settings.AuthToken == ""
	defaultSettings := initSettings(cfg)
	settings := defaultSettings
	profiles := make(map[string]*NodeProfile)
	nodes := make(map[string]NodeState)
	testHistory := historyPayload.Nodes
	if testHistory == nil {
		testHistory = make(map[string]map[string]*TestHistoryEntry)
	}
	historyTrimmed := false
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
		cfg.AgentToken = settings.AuthToken
	}
	if err := savePersistedData(dataPath, PersistedData{
		Settings: settings,
		Profiles: profiles,
		Nodes:    nodes,
	}); err != nil {
		log.Printf("写入持久化数据失败: %v", err)
	}

	commit := strings.TrimSpace(cfg.Commit)
	if commit == "none" {
		commit = ""
	}
	if len(commit) > 7 {
		commit = commit[:7]
	}

	store := &Store{
		nodes:           nodes,
		profiles:        profiles,
		settings:        settings,
		buildCommit:     commit,
		dataPath:        dataPath,
		historyPath:     historyPath,
		persistInterval: defaultPersistInterval,
		alerted:         make(map[string]alertState),
		testHistory:     testHistory,
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

	mux := http.NewServeMux()
	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		return err
	}

	mux.HandleFunc("/api/v1/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		creds := store.Credentials()
		if req.Username != creds.AdminUser || !store.VerifyAdminPassword(req.Password) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		token, exp, err := generateToken(cfg.JWTSecret, req.Username, creds.TokenSalt)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
			return
		}
		log.Printf("管理员登录: %s (%s)", req.Username, r.RemoteAddr)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"token":      token,
			"expires_at": exp,
		})
	})

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/v1/nodes", requireJWT(cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		snapshot := storeSnapshot(store, true)
		writeJSON(w, http.StatusOK, snapshot)
	}))

	mux.HandleFunc("/api/v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if cfg.AgentToken != "" {
			token := r.Header.Get("X-AGENT-TOKEN")
			if token != cfg.AgentToken {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid agent token"})
				return
			}
		}

		var payload metrics.NodeStats
		if err := decodeJSON(w, r, &payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if payload.NodeID == "" {
			if payload.NodeName != "" {
				payload.NodeID = payload.NodeName
			} else if payload.Hostname != "" {
				payload.NodeID = payload.Hostname
			}
		}
		if payload.NodeID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node_id required"})
			return
		}
		if payload.NodeName == "" {
			payload.NodeName = payload.NodeID
		}
		store.Update(payload)
		log.Printf("Agent 上报: %s (%s)", payload.NodeID, r.RemoteAddr)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/v1/admin/nodes", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			snapshot := storeSnapshot(store, true)
			writeJSON(w, http.StatusOK, snapshot)
		case http.MethodDelete:
			store.ClearNodes()
			writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}))

	mux.HandleFunc("/api/v1/admin/nodes/", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		nodeID := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/nodes/")
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

	mux.HandleFunc("/api/v1/admin/settings", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, store.SettingsView())
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
			snapshot := storeSnapshot(store, false)
			payload, _ := json.Marshal(snapshot)
			hub.Broadcast(payload)
			writeJSON(w, http.StatusOK, view)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}))

	mux.HandleFunc("/api/v1/admin/alerts/test", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("/api/v1/admin/ai/test", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("/api/v1/agent/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if cfg.AgentToken != "" {
			token := r.Header.Get("X-AGENT-TOKEN")
			if token != cfg.AgentToken {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid agent token"})
				return
			}
		}
		nodeID := r.URL.Query().Get("node_id")
		if nodeID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node_id required"})
			return
		}
		config := store.AgentConfig(nodeID)
		writeJSON(w, http.StatusOK, config)
	})

	upgrader := websocket.Upgrader{
		CheckOrigin: isAllowedOrigin,
	}

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if extractToken(r) != "" {
			if err := validateJWTFromRequest(cfg.JWTSecret, r); err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		client := hub.Add(conn)

		// 首次连接立即推送快照
		snapshot := storeSnapshot(store, true)
		payload, _ := json.Marshal(snapshot)
		if client != nil {
			if err := client.writeMessage(websocket.TextMessage, payload); err != nil {
				hub.Remove(conn)
				return
			}
		}

		go readLoop(conn, hub)
	})

	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(webRoot))))

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dashboard" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		adminPath := store.AdminPath()
		if r.URL.Path == adminPath {
			data, err := webFS.ReadFile("web/admin.html")
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "admin not found"})
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
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

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           withSecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				snapshot := storeSnapshot(store, false)
				payload, _ := json.Marshal(snapshot)
				hub.Broadcast(payload)
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
		_ = server.Shutdown(context.Background())
	}()

	log.Printf("管理后台路径: %s", store.AdminPath())
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
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.Addr == "" {
		cfg.Addr = defaultAddr
	}
	if cfg.DataDir == "" {
		cfg.DataDir = defaultDataDir
	}
	if cfg.JWTSecret == "" && cfg.AgentToken == "" {
		token := generateBootstrapToken()
		cfg.JWTSecret = token
		cfg.AgentToken = token
		return
	}
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = cfg.AgentToken
	}
	if cfg.AgentToken == "" {
		cfg.AgentToken = cfg.JWTSecret
	}
	if cfg.JWTSecret != cfg.AgentToken {
		cfg.AgentToken = cfg.JWTSecret
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
	return fmt.Sprintf("%s|%s|%d|%s", kind, host, test.Port, name)
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
	OfflineAt time.Time
}

func (s *Store) CollectAlertEvents(now time.Time) (AlertTargets, []AlertEvent, []AlertEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	targets := AlertTargets{
		FeishuWebhook:   strings.TrimSpace(s.settings.AlertWebhook),
		TelegramToken:   strings.TrimSpace(s.settings.AlertTelegramToken),
		TelegramUserIDs: normalizeTelegramUserIDs(append([]int64(nil), s.settings.AlertTelegramUserIDs...)),
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
				offlineSec := int64(now.Sub(state.OfflineAt).Seconds())
				if state.OfflineAt.IsZero() {
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
		s.alerted[nodeID] = alertState{OfflineAt: node.LastSeen}
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
		body, _ := io.ReadAll(resp.Body)
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

func isAlertEnabled(profile *NodeProfile) bool {
	if profile == nil {
		return true
	}
	if profile.AlertEnabled == nil {
		return true
	}
	return *profile.AlertEnabled
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
				Latency:        append([]*float64(nil), entry.Latency...),
				Loss:           append([]*float64(nil), entry.Loss...),
				Times:          append([]int64(nil), entry.Times...),
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
		views = append(views, NodeView{
			Stats:            node.Stats,
			LastSeen:         node.LastSeen.Unix(),
			FirstSeen:        node.FirstSeen.Unix(),
			Status:           status,
			ServerID:         profile.ServerID,
			AlertEnabled:     isAlertEnabled(profile),
			Alias:            profile.Alias,
			Group:            group,
			Tags:             tags,
			Groups:           groups,
			Region:           profile.Region,
			DiskType:         profile.DiskType,
			NetSpeedMbps:     profile.NetSpeedMbps,
			ExpireAt:         profile.ExpireAt,
			AutoRenew:        profile.AutoRenew,
			RenewIntervalSec: profile.RenewIntervalSec,
			TestIntervalSec:  profile.TestIntervalSec,
			Tests:            profile.Tests,
			TestSelections:   profile.TestSelections,
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

func (h *Hub) Add(conn *websocket.Conn) *hubClient {
	client := &hubClient{conn: conn}
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
		if err := client.writeMessage(websocket.TextMessage, payload); err != nil {
			h.removeClient(client)
		}
	}
}

func (h *Hub) snapshotClients() []*hubClient {
	h.mu.Lock()
	defer h.mu.Unlock()
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

func readLoop(conn *websocket.Conn, hub *Hub) {
	defer hub.Remove(conn)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func isAllowedOrigin(r *http.Request) bool {
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

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		Commit:       s.buildCommit,
	}
}

func (s *Store) SettingsView() SettingsView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return SettingsView{
		AdminPath:            s.settings.AdminPath,
		AdminUser:            s.settings.AdminUser,
		AgentEndpoint:        s.settings.AgentEndpoint,
		AgentToken:           s.settings.AuthToken,
		SiteTitle:            s.settings.SiteTitle,
		SiteIcon:             s.settings.SiteIcon,
		HomeTitle:            s.settings.HomeTitle,
		HomeSubtitle:         s.settings.HomeSubtitle,
		AlertWebhook:         s.settings.AlertWebhook,
		AlertOfflineSec:      s.settings.AlertOfflineSec,
		AlertAll:             s.settings.AlertAll,
		AlertNodes:           s.settings.AlertNodes,
		AlertTelegramToken:   s.settings.AlertTelegramToken,
		AlertTelegramUserIDs: s.settings.AlertTelegramUserIDs,
		AlertTelegramUserID:  firstTelegramUserID(s.settings.AlertTelegramUserIDs),
		AISettings:           s.settings.AISettings,
		Commit:               s.buildCommit,
		Groups:               s.settings.Groups,
		GroupTree:            s.settings.GroupTree,
		TestCatalog:          s.settings.TestCatalog,
	}
}

func (s *Store) AlertWebhook() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.settings.AlertWebhook)
}

func (s *Store) TelegramSettings() (string, []int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.settings.AlertTelegramToken), append([]int64(nil), s.settings.AlertTelegramUserIDs...)
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
	if update.AgentEndpoint != nil {
		s.settings.AgentEndpoint = strings.TrimSpace(*update.AgentEndpoint)
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
	view = SettingsView{
		AdminPath:            s.settings.AdminPath,
		AdminUser:            s.settings.AdminUser,
		SiteTitle:            s.settings.SiteTitle,
		SiteIcon:             s.settings.SiteIcon,
		HomeTitle:            s.settings.HomeTitle,
		HomeSubtitle:         s.settings.HomeSubtitle,
		AlertWebhook:         s.settings.AlertWebhook,
		AlertOfflineSec:      s.settings.AlertOfflineSec,
		AlertAll:             s.settings.AlertAll,
		AlertNodes:           s.settings.AlertNodes,
		AlertTelegramToken:   s.settings.AlertTelegramToken,
		AlertTelegramUserIDs: s.settings.AlertTelegramUserIDs,
		AlertTelegramUserID:  firstTelegramUserID(s.settings.AlertTelegramUserIDs),
		AISettings:           s.settings.AISettings,
		Commit:               s.buildCommit,
		Groups:               s.settings.Groups,
		GroupTree:            s.settings.GroupTree,
		TestCatalog:          s.settings.TestCatalog,
	}
	s.mu.Unlock()

	s.persist(data)
	return view, nil
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

func (s *Store) AgentConfig(nodeID string) AgentConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	profile := s.ensureProfileLocked(nodeID)
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
		TestIntervalSec: profile.TestIntervalSec,
		Tests:           tests,
	}
}

func (s *Store) snapshotPersistedLocked() PersistedData {
	profiles := make(map[string]*NodeProfile, len(s.profiles))
	for id, profile := range s.profiles {
		if profile == nil {
			continue
		}
		copyProfile := *profile
		profiles[id] = &copyProfile
	}
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
	if err := savePersistedData(s.dataPath, data); err != nil {
		log.Printf("持久化失败: %v", err)
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
	if err := saveTestHistoryData(s.historyPath, data); err != nil {
		log.Printf("探测历史持久化失败: %v", err)
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
	_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	return err
}

func validateAdminJWT(store *Store, secret string, r *http.Request) error {
	token := extractToken(r)
	if token == "" {
		return errors.New("token required")
	}
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return err
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

func extractToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return parts[1]
		}
	}
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}
	return ""
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(target)
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
