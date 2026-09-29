package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cyber_monitor/internal/metrics"
	"cyber_monitor/internal/updater"

	"github.com/gorilla/websocket"
)

// publicHistoryQueryTimeout 是公开历史查询的最大处理器预算；newHTTPServer 的
// WriteTimeout 必须≥它（见 server_test.go 的回归断言）。
const publicHistoryQueryTimeout = 30 * time.Second

type routeDeps struct {
	cfg                 Config
	store               *Store
	hub                 *Hub
	agentAPI            *agentAPI
	systemUpdater       *systemUpdateManager
	splitMode           bool
	trustedProxyHeaders bool
	webRoot             fs.FS
}

// 页面 HTML 来自 go:embed，内容固定：包级缓存原始文本，按请求只做前缀/标题/boot 注入。
var (
	publicIndexHTML = sync.OnceValues(func() (string, error) {
		data, err := webFS.ReadFile("web/public/index.html")
		return string(data), err
	})
	adminIndexHTML = sync.OnceValues(func() (string, error) {
		data, err := webFS.ReadFile("web/dist/admin/index.html")
		return string(data), err
	})
)

func newRouteMuxes(deps routeDeps) (publicMux *http.ServeMux, adminMux *http.ServeMux, err error) {
	cfg := deps.cfg
	store := deps.store
	hub := deps.hub
	agentAPI := deps.agentAPI
	systemUpdater := deps.systemUpdater
	splitMode := deps.splitMode
	trustedProxyHeaders := deps.trustedProxyHeaders
	webRoot := deps.webRoot

	// 分端口模式下，Agent 接入点为空时用 public 端口地址兜底（settings/export/import 统一走这里）。
	fillAgentEndpoint := func(view *SettingsView) {
		if splitMode && strings.TrimSpace(view.AgentEndpoint) == "" {
			view.AgentEndpoint = cfg.PublicAddr
		}
	}

	publicMux = http.NewServeMux()
	adminMux = publicMux
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
		if turnstileConfigured(creds.TurnstileSiteKey, creds.TurnstileSecretKey) {
			if err := verifyTurnstileToken(r.Context(), creds.TurnstileSecretKey, req.TurnstileToken, clientIPFromRemoteAddr(r.RemoteAddr)); err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
				return
			}
		}
		if req.Username != creds.AdminUser || !store.VerifyAdminPassword(req.Password) {
			if req.Username != creds.AdminUser {
				verifyAdminPasswordDummy(req.Password)
			}
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
		snapshot := storeSnapshot(store)
		writeJSON(w, http.StatusOK, snapshot)
	})
	publicMux.HandleFunc("/api/v1/public/snapshot", publicSnapshotHandler)
	if splitMode {
		adminMux.HandleFunc("/api/v1/public/snapshot", publicSnapshotHandler)
	}

	publicHistorySem := make(chan struct{}, 4)
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

		// 总预算含排队时间：先起 30s 截止再等 semaphore，避免「排队 + 查询」
		// 叠加超过 WriteTimeout(35s) 后写回被截断。
		queryCtx, cancelQuery := context.WithTimeout(r.Context(), publicHistoryQueryTimeout)
		select {
		case publicHistorySem <- struct{}{}:
		case <-queryCtx.Done():
			cancelQuery()
			return
		}
		tests, err := store.QueryPublicNodeHistory(queryCtx, nodeID, from, to)
		cancelQuery()
		<-publicHistorySem
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
		refreshConfig, err := agentAPI.ingest(payload, r.Header.Get("X-AGENT-TOKEN"))
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
			snapshot := adminStoreSnapshot(store)
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
			fillAgentEndpoint(&view)
			writeJSON(w, http.StatusOK, view)
		case http.MethodPatch, http.MethodPut:
			var update SettingsUpdate
			if err := decodeJSON(w, r, &update); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			view, err := store.UpdateSettings(update)
			if err != nil {
				if errors.Is(err, errPersistFailed) {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "保存已生效但落盘失败，请检查服务端磁盘"})
					return
				}
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			fillAgentEndpoint(&view)
			if err := refreshAdminSessionCookie(w, r, cfg.JWTSecret, store, trustedProxyHeaders); err != nil {
				log.Printf("更新设置后刷新会话 cookie 失败: %v", err)
			}
			broadcastStoreSnapshot(hub, store)
			writeJSON(w, http.StatusOK, view)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}))

	adminMux.HandleFunc("/api/v1/admin/system/update", requireAdminJWT(store, cfg.JWTSecret, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			viewCtx, cancelView := releaseCheckContext(r)
			writeJSON(w, http.StatusOK, systemUpdater.View(viewCtx, false))
			cancelView()
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
			started := false
			defer func() {
				if !started {
					reservation.Cancel()
				}
			}()
			checkCtx, cancelCheck := releaseCheckContext(r)
			releaseInfo, err := systemUpdater.CheckLatest(checkCtx)
			cancelCheck()
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if handleReleaseUpdateGate(w, releaseInfo) {
				return
			}
			dockerManaged := updater.CanDockerManagedUpdate()
			if message := systemUpdateReleaseAssetError(releaseInfo, dockerManaged); message != "" {
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
					defer dockerUpdater.Close()
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
			started = true
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
		fillAgentEndpoint(&payload.Settings)
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
			if errors.Is(err, errPersistFailed) {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "保存已生效但落盘失败，请检查服务端磁盘"})
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		fillAgentEndpoint(&view)
		if err := refreshAdminSessionCookie(w, r, cfg.JWTSecret, store, trustedProxyHeaders); err != nil {
			log.Printf("导入配置后刷新会话 cookie 失败: %v", err)
		}
		broadcastStoreSnapshot(hub, store)
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
		selection, err := resolveAIProviderSelection(settings, req.Provider, req.Config)
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
		selection, err := resolveAIProviderSelection(settings, req.Provider, req.Config)
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
				EnableCompression: true,
				CheckOrigin: func(request *http.Request) bool {
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
			snapshot := storeSnapshot(store)
			if audience == "admin" {
				variant = adminVariant
				snapshot = adminStoreSnapshot(store)
			}
			payload, err := json.Marshal(snapshot)
			if err != nil {
				log.Printf("序列化初始节点快照失败: %v", err)
				_ = conn.Close()
				return
			}
			client, err := hub.Add(conn, variant, adminTokenSalt, payload)
			if err != nil {
				log.Printf("WebSocket 初始入队失败: %v", err)
				_ = conn.Close()
				return
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
		return publicMux, adminMux, err
	}
	assetsHandler := withNoStore(http.StripPrefix("/assets/", http.FileServer(http.FS(assetsRoot))))

	adminDistRoot, err := fs.Sub(webRoot, "dist/admin")
	if err != nil {
		return publicMux, adminMux, err
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
		htmlText, err := publicIndexHTML()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "index not found"})
			return
		}
		if prefix := forwardedPrefix(r, trustedProxyHeaders); prefix != "" {
			baseTag := `<base href="` + html.EscapeString(prefix+"/") + `" />`
			if strings.Contains(htmlText, "<head>") {
				htmlText = strings.Replace(htmlText, "<head>", "<head>"+baseTag, 1)
			} else {
				htmlText = baseTag + htmlText
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(htmlText))
	}

	writeAdminAppHTML := func(w http.ResponseWriter, r *http.Request) {
		htmlText, err := adminIndexHTML()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "admin app not found"})
			return
		}
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
		w.Header().Set("Cache-Control", "no-store")
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

	return publicMux, adminMux, nil
}
