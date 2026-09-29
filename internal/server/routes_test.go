package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type routeSpec struct {
	path    string
	pattern string
}

var publicRoutes = []routeSpec{
	{"/api/v1/health", "/api/v1/health"},
	{"/api/v1/public/snapshot", "/api/v1/public/snapshot"},
	{"/api/v1/public/nodes/node-1/history", "/api/v1/public/nodes/"},
	{"/api/v1/ingest", "/api/v1/ingest"},
	{"/api/v1/agent/config", "/api/v1/agent/config"},
	{"/api/v1/agent/register", "/api/v1/agent/register"},
	{"/api/v1/agent/update/report", "/api/v1/agent/update/report"},
	{"/ws", "/ws"},
	{"/assets/app.js", "/assets/"},
	{"/", "/"},
}

var adminRoutes = []routeSpec{
	{"/api/v1/login", "/api/v1/login"},
	{"/api/v1/login/oauth/start", "/api/v1/login/oauth/start"},
	{"/api/v1/login/oauth/callback", "/api/v1/login/oauth/callback"},
	{"/api/v1/logout", "/api/v1/logout"},
	{"/api/v1/login/config", "/api/v1/login/config"},
	{"/api/v1/admin/nodes", "/api/v1/admin/nodes"},
	{"/api/v1/admin/nodes/node-1", "/api/v1/admin/nodes/"},
	{"/api/v1/admin/session", "/api/v1/admin/session"},
	{"/api/v1/admin/logs", "/api/v1/admin/logs"},
	{"/api/v1/admin/settings", "/api/v1/admin/settings"},
	{"/api/v1/admin/system/update", "/api/v1/admin/system/update"},
	{"/api/v1/admin/config/export", "/api/v1/admin/config/export"},
	{"/api/v1/admin/config/import", "/api/v1/admin/config/import"},
	{"/api/v1/admin/alerts/test", "/api/v1/admin/alerts/test"},
	{"/api/v1/admin/ai/test", "/api/v1/admin/ai/test"},
	{"/api/v1/admin/ai/models", "/api/v1/admin/ai/models"},
}

var splitSharedAdminRoutes = []routeSpec{
	{"/api/v1/health", "/api/v1/health"},
	{"/api/v1/public/snapshot", "/api/v1/public/snapshot"},
	{"/ws", "/ws"},
	{"/assets/app.js", "/assets/"},
	{"/", "/"},
}

var splitOnlyPublicRoutes = []string{
	"/api/v1/ingest",
	"/api/v1/agent/config",
	"/api/v1/agent/register",
	"/api/v1/agent/update/report",
	"/api/v1/public/nodes/node-1/history",
}

func buildRouteDeps(t *testing.T, cfg Config, store *Store) routeDeps {
	t.Helper()
	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		t.Fatalf("fs.Sub(webFS, \"web\") 失败: %v", err)
	}
	if store == nil {
		store = &Store{}
	}
	hub := &Hub{}
	return routeDeps{
		cfg:                 cfg,
		store:               store,
		hub:                 hub,
		agentAPI:            newAgentAPI(store, hub),
		systemUpdater:       newSystemUpdateManager("test"),
		splitMode:           strings.TrimSpace(cfg.PublicAddr) != "" && cfg.PublicAddr != cfg.Addr,
		trustedProxyHeaders: cfg.TrustedProxyHeaders,
		webRoot:             webRoot,
	}
}

func buildTestMuxes(t *testing.T, cfg Config, store *Store) (*http.ServeMux, *http.ServeMux) {
	t.Helper()
	publicMux, adminMux, err := newRouteMuxes(buildRouteDeps(t, cfg, store))
	if err != nil {
		t.Fatalf("newRouteMuxes 失败: %v", err)
	}
	return publicMux, adminMux
}

func assertMuxPattern(t *testing.T, mux *http.ServeMux, scope, path, want string) {
	t.Helper()
	_, got := mux.Handler(httptest.NewRequest(http.MethodGet, path, nil))
	if got != want {
		t.Errorf("%s: %s 匹配到 pattern %q, want %q", scope, path, got, want)
	}
}

func TestNewRouteMuxesSinglePort(t *testing.T) {
	publicMux, adminMux := buildTestMuxes(t, Config{}, nil)
	if publicMux != adminMux {
		t.Fatalf("单端口模式下 adminMux 必须与 publicMux 为同一实例")
	}
	for _, spec := range publicRoutes {
		assertMuxPattern(t, publicMux, "单端口", spec.path, spec.pattern)
	}
	for _, spec := range adminRoutes {
		assertMuxPattern(t, publicMux, "单端口(admin 路由)", spec.path, spec.pattern)
	}

	assertMuxPattern(t, publicMux, "单端口", "/dashboard", "/dashboard")

	assertMuxPattern(t, publicMux, "单端口", "/not-registered", "/")
}

func TestNewRouteMuxesSplitPort(t *testing.T) {
	cfg := Config{Addr: ":25012", PublicAddr: ":25013"}
	publicMux, adminMux := buildTestMuxes(t, cfg, nil)
	if publicMux == adminMux {
		t.Fatalf("分端口模式下 adminMux 必须是独立实例")
	}

	for _, spec := range publicRoutes {
		assertMuxPattern(t, publicMux, "分端口 publicMux", spec.path, spec.pattern)
	}
	for _, spec := range adminRoutes {
		assertMuxPattern(t, adminMux, "分端口 adminMux", spec.path, spec.pattern)
	}
	for _, spec := range splitSharedAdminRoutes {
		assertMuxPattern(t, adminMux, "分端口 adminMux(共用)", spec.path, spec.pattern)
	}

	for _, spec := range adminRoutes {
		assertMuxPattern(t, publicMux, "分端口 publicMux(不得有 admin 路由)", spec.path, "/")
	}

	for _, path := range splitOnlyPublicRoutes {
		assertMuxPattern(t, adminMux, "分端口 adminMux(不得有 public 专属路由)", path, "/")
	}

	assertMuxPattern(t, publicMux, "分端口 publicMux", "/dashboard", "/")
	assertMuxPattern(t, adminMux, "分端口 adminMux", "/dashboard", "/")
}

// 回归：首页 HTML 包级缓存原始文本，按请求只做前缀注入；缓存副本不得被逐请求篡改。
func TestPublicIndexHTMLCacheInjectsPrefixPerRequest(t *testing.T) {
	settings, err := initSettings(Config{AdminPath: "/cm-admin"})
	if err != nil {
		t.Fatalf("initSettings 失败: %v", err)
	}
	publicMux, _ := buildTestMuxes(t, Config{TrustedProxyHeaders: true}, &Store{settings: settings})

	serve := func(headers map[string]string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		publicMux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET / 状态码 = %d, want %d", rec.Code, http.StatusOK)
		}
		return rec.Body.String()
	}

	base := `<base href="/sub/" />`
	plain := serve(nil)
	if strings.Contains(plain, "<base") {
		t.Fatalf("无 X-Forwarded-Prefix 时不应注入 base 标签")
	}
	for i := 0; i < 2; i++ {
		prefixed := serve(map[string]string{"X-Forwarded-Prefix": "/sub"})
		if !strings.Contains(prefixed, base) {
			t.Fatalf("第 %d 次带前缀请求未注入 base 标签", i+1)
		}
	}
	if again := serve(nil); strings.Contains(again, "<base") {
		t.Fatalf("前缀注入污染了缓存副本，无前缀请求不应带 base 标签")
	}
}

func TestRouteCustomAdminPath(t *testing.T) {
	settings, err := initSettings(Config{AdminPath: "/cm-admin"})
	if err != nil {
		t.Fatalf("initSettings 失败: %v", err)
	}
	if settings.AdminPath != "/cm-admin" {
		t.Fatalf("AdminPath = %q, want %q", settings.AdminPath, "/cm-admin")
	}
	publicMux, _ := buildTestMuxes(t, Config{}, &Store{settings: settings})

	rec := httptest.NewRecorder()
	publicMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cm-admin", nil))
	if rec.Code != http.StatusFound {
		t.Errorf("GET /cm-admin 状态码 = %d, want %d", rec.Code, http.StatusFound)
	}
	if loc := rec.Header().Get("Location"); loc != "/cm-admin/" {
		t.Errorf("GET /cm-admin Location = %q, want %q", loc, "/cm-admin/")
	}

	rec = httptest.NewRecorder()
	publicMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cm-admin/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /cm-admin/ 状态码 = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET /cm-admin/ Content-Type = %q, want text/html", ct)
	}
	if rec.Body.Len() == 0 {
		t.Errorf("GET /cm-admin/ 响应体为空")
	}

	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Errorf("GET /cm-admin/ 未返回后台页面（缺少 #root 挂载点）")
	}

	rec = httptest.NewRecorder()
	publicMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET / 状态码 = %d, want %d", rec.Code, http.StatusOK)
	}
	rec = httptest.NewRecorder()
	publicMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/not-registered", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /not-registered 状态码 = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestRouteAuthBoundaries(t *testing.T) {
	secret := "test-jwt-secret"
	settings, err := initSettings(Config{AdminUser: "admin", AdminPath: "/cm-admin", JWTSecret: secret})
	if err != nil {
		t.Fatalf("initSettings 失败: %v", err)
	}
	store := &Store{settings: settings, deltaDigests: map[string]uint64{}}

	singlePublic, singleAdmin := buildTestMuxes(t, Config{JWTSecret: secret}, store)
	if singlePublic != singleAdmin {
		t.Fatalf("单端口模式下 adminMux 必须与 publicMux 为同一实例")
	}

	rec := httptest.NewRecorder()
	singleAdmin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/nodes", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("单端口 GET /api/v1/admin/nodes 未认证状态码 = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	rec = httptest.NewRecorder()
	issueReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/nodes", nil)
	if _, err := issueAdminSession(rec, issueReq, secret, store, false); err != nil {
		t.Fatalf("issueAdminSession 失败: %v", err)
	}
	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/nodes", nil)
	for _, cookie := range rec.Result().Cookies() {
		authReq.AddCookie(cookie)
	}
	rec = httptest.NewRecorder()
	singleAdmin.ServeHTTP(rec, authReq)
	if rec.Code == http.StatusUnauthorized {
		t.Errorf("单端口 GET /api/v1/admin/nodes 持合法会话应放行，实际 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	singleAdmin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ws", nil))
	if rec.Code == http.StatusUnauthorized {
		t.Errorf("单端口 GET /ws 无 token 不应要求鉴权（wsAuthMixed 应放行为公开受众）")
	}

	cfg := Config{Addr: ":25012", PublicAddr: ":25013"}
	splitPublic, splitAdmin := buildTestMuxes(t, cfg, nil)

	rec = httptest.NewRecorder()
	splitPublic.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/nodes", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("分端口 publicMux GET /api/v1/admin/nodes 状态码 = %d, want %d（admin 路由泄漏到 public 侧）", rec.Code, http.StatusNotFound)
	}

	rec = httptest.NewRecorder()
	splitAdmin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ws", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("分端口 adminMux GET /ws 未认证状态码 = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	rec = httptest.NewRecorder()
	splitPublic.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ws", nil))
	if rec.Code == http.StatusUnauthorized {
		t.Errorf("分端口 publicMux GET /ws 不应要求鉴权（wsAuthPublic）")
	}
}
