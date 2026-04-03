package server

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRootForUITest(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return root
}

func readRepoFileForUITest(t *testing.T, relativePath string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRootForUITest(t), relativePath))
	if err != nil {
		t.Fatalf("read %s: %v", relativePath, err)
	}
	return string(data)
}

func TestUIHTMLHasThemeColorMeta(t *testing.T) {
	t.Parallel()

	files := []string{
		"admin-ui/index.html",
		"internal/server/web/index.html",
		"internal/server/web/dashboard.html",
	}

	for _, relativePath := range files {
		content := readRepoFileForUITest(t, relativePath)
		if !strings.Contains(content, `name="theme-color"`) {
			t.Fatalf("%s missing theme-color meta", relativePath)
		}
	}
}

func TestAdminPagesUseH1Title(t *testing.T) {
	t.Parallel()

	files := []string{
		"admin-ui/src/pages/Dashboard.tsx",
		"admin-ui/src/pages/ServerManagement.tsx",
		"admin-ui/src/pages/GroupManagement.tsx",
		"admin-ui/src/pages/ProbeSettings.tsx",
		"admin-ui/src/pages/BasicSettings.tsx",
		"admin-ui/src/pages/NotificationAlert.tsx",
		"admin-ui/src/pages/AIProvider.tsx",
	}

	for _, relativePath := range files {
		content := readRepoFileForUITest(t, relativePath)
		if !strings.Contains(content, `<h1 className={adminPageTitleClass}>`) {
			t.Fatalf("%s should render page title as h1", relativePath)
		}
	}
}

func TestDashboardNavigationUsesAnchors(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "admin-ui/src/pages/Dashboard.tsx")
	if !strings.Contains(content, "href={dashboardPageHref(item.page)}") {
		t.Fatal("Dashboard summary navigation should render href links")
	}
	if !strings.Contains(content, `href={dashboardPageHref("settings")}`) {
		t.Fatal("Dashboard settings shortcut should render href link")
	}
	if !strings.Contains(content, `href={dashboardPageHref("probes")}`) {
		t.Fatal("Dashboard quick actions should render href links")
	}
}

func TestPublicPagesRenderSemanticH1(t *testing.T) {
	t.Parallel()

	files := []string{
		"internal/server/web/index.html",
		"internal/server/web/dashboard.html",
	}

	for _, relativePath := range files {
		content := readRepoFileForUITest(t, relativePath)
		if !strings.Contains(content, "<h1") {
			t.Fatalf("%s should contain h1", relativePath)
		}
	}
}

func TestAdminSourceAvoidsTransitionAll(t *testing.T) {
	t.Parallel()

	files := []string{
		"admin-ui/lib/admin-ui.ts",
		"admin-ui/components/ui/badge.tsx",
		"admin-ui/components/ui/tabs.tsx",
		"admin-ui/components/ui/switch.tsx",
		"admin-ui/components/ui/accordion.tsx",
	}

	for _, relativePath := range files {
		content := readRepoFileForUITest(t, relativePath)
		if strings.Contains(content, "transition-all") {
			t.Fatalf("%s still contains transition-all", relativePath)
		}
	}
}

func TestDestructiveFlowsUseManagedConfirmation(t *testing.T) {
	t.Parallel()

	serverManagement := readRepoFileForUITest(t, "admin-ui/src/pages/ServerManagement.tsx")
	if strings.Contains(serverManagement, "window.confirm(") {
		t.Fatal("ServerManagement still uses window.confirm")
	}

	probeSettings := readRepoFileForUITest(t, "admin-ui/src/pages/ProbeSettings.tsx")
	if !strings.Contains(probeSettings, "AlertDialog") {
		t.Fatal("ProbeSettings should use AlertDialog for destructive actions")
	}
}

func TestAdminNavigationUsesAnchors(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "admin-ui/src/App.tsx")
	if !strings.Contains(content, "href={pageHref(item.id)}") {
		t.Fatal("admin navigation should render href links")
	}
}

func TestAdminAppWarnsBeforeLeavingDirtyPages(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "admin-ui/src/App.tsx")
	if !strings.Contains(content, "beforeunload") {
		t.Fatal("App should warn before leaving dirty pages")
	}
	if !strings.Contains(content, "离开当前页面前先处理未保存内容") {
		t.Fatal("App should present an unsaved changes confirmation dialog")
	}
}

func TestFormsRenderInlineValidationFeedback(t *testing.T) {
	t.Parallel()

	files := []string{
		"admin-ui/src/pages/NotificationAlert.tsx",
		"admin-ui/src/pages/ProbeSettings.tsx",
		"admin-ui/src/pages/GroupManagement.tsx",
	}

	for _, relativePath := range files {
		content := readRepoFileForUITest(t, relativePath)
		if !strings.Contains(content, `aria-live="polite"`) {
			t.Fatalf("%s should expose inline validation feedback", relativePath)
		}
	}
}

func TestIconButtonsExposeAccessibleLabels(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "admin-ui/src/pages/ProbeSettings.tsx")
	if !strings.Contains(content, "编辑探测节点") {
		t.Fatal("ProbeSettings edit icon button should expose an aria-label")
	}
	if !strings.Contains(content, "删除探测节点") {
		t.Fatal("ProbeSettings delete icon button should expose an aria-label")
	}
}

func TestLoginTurnstileErrorsAreAnnounced(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "admin-ui/src/pages/Login.tsx")
	if !strings.Contains(content, `aria-live="polite"`) {
		t.Fatal("Login should announce turnstile errors with aria-live")
	}
}

func TestServerSearchUsesSearchSemantics(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "admin-ui/src/pages/ServerManagement.tsx")
	if !strings.Contains(content, `type="search"`) {
		t.Fatal("ServerManagement search should use input type search")
	}
	if !strings.Contains(content, `name="node-search"`) {
		t.Fatal("ServerManagement search should expose a name")
	}
	if !strings.Contains(content, `autoComplete="off"`) {
		t.Fatal("ServerManagement search should disable autocomplete")
	}
}

func TestAdminPlaceholderCopyFollowsGuidelines(t *testing.T) {
	t.Parallel()

	cases := map[string][]string{
		"admin-ui/src/pages/Login.tsx": {
			`placeholder="例如：admin…"`,
		},
		"admin-ui/src/pages/BasicSettings.tsx": {
			`placeholder="例如：/cm-admin…"`,
			`placeholder="例如：https://monitor.example.com…"`,
			`placeholder="例如：cm-agent-token-abc123…"`,
		},
		"admin-ui/src/pages/ProbeSettings.tsx": {
			`placeholder="例如：主站 TCP 443…"`,
			`placeholder="例如：1.1.1.1 / example.com…"`,
			`placeholder="例如：443…"`,
			`placeholder={` + "`例如：${DEFAULT_TCP_INTERVAL}…`" + `}`,
		},
		"admin-ui/src/pages/GroupManagement.tsx": {
			`placeholder="例如：美国、香港、日本…"`,
			`placeholder="例如：CN2、BGP、GIA…"`,
		},
		"admin-ui/src/pages/NotificationAlert.tsx": {
			`placeholder="例如：123456789,987654321…"`,
		},
		"admin-ui/src/pages/AIProvider.tsx": {
			`placeholder="选择命令服务商…"`,
			`placeholder="例如：请重点关注网络流量、下载量与离线情况…"`,
		},
		"admin-ui/src/pages/ServerManagement.tsx": {
			`placeholder="例如：搜索节点名、Node ID、主机名、地区…"`,
			`placeholder="选择续费方案…"`,
		},
	}

	for relativePath, expectedSnippets := range cases {
		content := readRepoFileForUITest(t, relativePath)
		for _, snippet := range expectedSnippets {
			if !strings.Contains(content, snippet) {
				t.Fatalf("%s missing expected placeholder snippet: %s", relativePath, snippet)
			}
		}
	}
}

func TestDashboardActionClassesUseInlineFlexLayout(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "admin-ui/lib/admin-ui.ts")
	requiredSnippets := []string{
		"adminCompactActionButtonClass =",
		"inline-flex items-center justify-center gap-1.5 h-9 px-4 text-xs font-bold",
		"adminQuickActionButtonClass =",
		"inline-flex h-11 w-full items-center justify-start gap-3 rounded-xl",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("dashboard action layout regression: missing snippet %q", snippet)
		}
	}
}

func TestSidebarNavigationAvoidsHoverTransformFlicker(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "admin-ui/src/App.tsx")
	disallowedSnippets := []string{
		"group-hover:scale-110",
		"group-hover:-translate-x-1",
	}

	for _, snippet := range disallowedSnippets {
		if strings.Contains(content, snippet) {
			t.Fatalf("sidebar hover jitter regression: %q should not appear in App.tsx", snippet)
		}
	}
}

func TestBuildReleaseWorkflowUsesNode24CompatibleActions(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, ".github/workflows/build-release.yml")
	requiredSnippets := []string{
		"FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true",
		"uses: actions/checkout@v5",
		"uses: actions/setup-go@v6",
		"uses: actions/setup-node@v5",
		"uses: actions/download-artifact@v7",
		"uses: actions/upload-artifact@v6",
		"uses: docker/setup-qemu-action@v4",
		"uses: docker/setup-buildx-action@v4",
		"uses: docker/login-action@v4",
		"uses: docker/build-push-action@v7",
		`pattern: "!*.dockerbuild"`,
		"needs: [version, build-server, build-agent, build-web, docker-server, docker-agent]",
	}
	disallowedSnippets := []string{
		"uses: actions/checkout@v4",
		"uses: actions/setup-go@v5",
		"uses: actions/setup-node@v4",
		"uses: actions/download-artifact@v5",
		"uses: actions/download-artifact@v6",
		"uses: actions/upload-artifact@v4",
		"uses: docker/setup-qemu-action@v3",
		"uses: docker/setup-buildx-action@v3",
		"uses: docker/login-action@v3",
		"uses: docker/build-push-action@v5",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("build-release workflow missing %q", snippet)
		}
	}
	for _, snippet := range disallowedSnippets {
		if strings.Contains(content, snippet) {
			t.Fatalf("build-release workflow still contains deprecated reference %q", snippet)
		}
	}
}

func TestAdminActionClassesExposeFocusVisibleStates(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "admin-ui/lib/admin-ui.ts")
	requiredSnippets := []string{
		"focus-visible:border-sky-300",
		"focus-visible:ring-2",
		"focus-visible:ring-sky-400/60",
		"adminSidebarNavItemClass =",
		"adminQuickActionButtonClass =",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("shared admin action styles should expose keyboard focus state: missing %q", snippet)
		}
	}
}

func TestAdminAppUsesSessionProbeForAnonymousRestore(t *testing.T) {
	t.Parallel()

	appContent := readRepoFileForUITest(t, "admin-ui/src/App.tsx")
	apiContent := readRepoFileForUITest(t, "admin-ui/lib/admin-api.ts")

	if !strings.Contains(appContent, "fetchSessionStatus()") {
		t.Fatal("App should use session probe instead of protected settings request for anonymous restore")
	}
	if !strings.Contains(apiContent, "export async function fetchSessionStatus()") {
		t.Fatal("admin api should expose fetchSessionStatus")
	}
}

func TestTaggedNodeCardsShareSameSurfaceStyle(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/styles.css")
	requiredSnippets := []string{
		".node-list {\n  display: grid;\n  gap: 16px;",
		".tag-section {\n  display: grid;\n  gap: 16px;",
		".tag-list {\n  display: grid;\n  gap: 16px;",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("tagged node section regression: missing %q", snippet)
		}
	}

	disallowedSnippets := []string{
		".node-card {\n  background: var(--glass);\n  border: 1px solid var(--glass-border);\n  border-radius: 20px;\n  overflow: hidden;\n  backdrop-filter: blur(18px);\n  box-shadow: var(--shadow);\n  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;\n  content-visibility: auto;",
		".tag-section {\n  display: grid;\n  gap: 16px;\n  content-visibility: auto;",
		".tag-list .node-card {\n  box-shadow: none;",
		".tag-list .node-card:hover {\n  transform: none;\n  box-shadow: none;",
		".tag-list .node-card[open] {\n  box-shadow: none;",
	}

	for _, snippet := range disallowedSnippets {
		if strings.Contains(content, snippet) {
			t.Fatalf("tagged node cards should share the default surface styling: found %q", snippet)
		}
	}
}

func TestLatencyAxisUsesCompactWholeMillisecondLabels(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/monitor.js")
	disallowedSnippets := []string{
		"if (value >= 10) return `${value.toFixed(0)}${unit}`;",
	}
	requiredSnippets := []string{
		"function formatLatencyTick(value) {",
		"if (value >= 1) return `${Math.round(value)}${unit}`;",
		"return `${value.toFixed(1)}${unit}`;",
	}

	for _, snippet := range disallowedSnippets {
		if strings.Contains(content, snippet) {
			t.Fatalf("latency labels should avoid decimal millisecond formatting: found %q", snippet)
		}
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("latency formatting regression: missing %q", snippet)
		}
	}
}

func TestLatencyHoverAddsLeaveFallbacks(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/monitor.js")
	requiredSnippets := []string{
		`container.addEventListener("pointerleave", handleLeave);`,
		`window.addEventListener("pointermove", handleGlobalPointerMove, true);`,
		`window.addEventListener("scroll", handleScrollOrBlur, true);`,
		`container.__latencyHoverCleanup = () => {`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("latency hover dismissal regression: missing %q", snippet)
		}
	}
}

func TestPublicMonitorAddsSmoothToggleAndEWMA(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/monitor.js")
	requiredSnippets := []string{
		`testSmooth: new Map(),`,
		`<div class="smooth-control">`,
		`<span class="smooth-control-label">平滑</span>`,
		`class="smooth-toggle"`,
		`data-field="test-smooth"`,
		`aria-label="切换平滑"`,
		`<span class="smooth-toggle-track">`,
		`<span class="smooth-toggle-thumb"></span>`,
		`function renderSmoothToggle(fields, nodeId, enabled) {`,
		`const smoothEnabled = Boolean(state.testSmooth.get(nodeId));`,
		`const latencySeries = smoothEnabled`,
		`function applyEWMA(series, alpha = LATENCY_SMOOTH_ALPHA) {`,
	}
	disallowedSnippets := []string{
		`data-field="test-legend"`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("public monitor smoothing regression: missing %q", snippet)
		}
	}
	for _, snippet := range disallowedSnippets {
		if strings.Contains(content, snippet) {
			t.Fatalf("public monitor smoothing regression: found stale snippet %q", snippet)
		}
	}
}

func TestPublicMonitorUsesUpdatedRangeLabelsAndDailyInterval(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/monitor.js")
	requiredSnippets := []string{
		`{ key: "24h", label: "1D", seconds: 60 * 60 * 24 },`,
		`{ key: "7d", label: "1W", seconds: 60 * 60 * 24 * 7 },`,
		`{ key: "30d", label: "1M", seconds: 60 * 60 * 24 * 30 },`,
		`"24h": 30,`,
	}
	disallowedSnippets := []string{
		`{ key: "24h", label: "24H", seconds: 60 * 60 * 24 },`,
		`{ key: "7d", label: "7D", seconds: 60 * 60 * 24 * 7 },`,
		`{ key: "30d", label: "30D", seconds: 60 * 60 * 24 * 30 },`,
		`"24h": 60 * 2,`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("public monitor range label regression: missing %q", snippet)
		}
	}
	for _, snippet := range disallowedSnippets {
		if strings.Contains(content, snippet) {
			t.Fatalf("public monitor range label regression: found stale snippet %q", snippet)
		}
	}
}

func TestPublicMonitorHidesVariantSwitcherBanner(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/monitor.js")
	disallowedSnippets := []string{
		`class="demo-variant-banner"`,
		`>保守版<`,
		`>平衡版<`,
		`ensureVariantBanner();`,
	}

	for _, snippet := range disallowedSnippets {
		if strings.Contains(content, snippet) {
			t.Fatalf("public monitor should not expose variant switcher banner: found %q", snippet)
		}
	}
}

func TestPublicMonitorLatencyAxisUsesJetBrainsMonoAndGreenToggle(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/styles.css")
	requiredSnippets := []string{
		`.latency-chart-svg .latency-axis text {`,
		`font-family: "Inter", "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", system-ui, sans-serif;`,
		`font-size: 8px;`,
		`font-weight: 300;`,
		`font-variant-numeric: tabular-nums;`,
		`font-feature-settings: "tnum" 1, "lnum" 1;`,
		`.smooth-toggle.active .smooth-toggle-track {`,
		`background: #16a34a;`,
		`border-color: #15803d;`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("latency chart visual regression: missing %q", snippet)
		}
	}
}

func TestPublicMonitorUsesSystemFirstFontStackAndDarkNetworkCards(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/styles.css")
	requiredSnippets := []string{
		`--font-base: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Helvetica Neue", "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;`,
		`.network-card {`,
		`background: var(--card-bg);`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("public monitor font and dark card regression: missing %q", snippet)
		}
	}
}

func TestExpandedNodeNetworkUsesRealtimeRatesAndPercent(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/monitor.js")
	requiredSnippets := []string{
		`<div class="info-row"><span>累计上传</span><strong data-field="detail-upload">--</strong></div>`,
		`<div class="info-row"><span>累计下载</span><strong data-field="detail-download">--</strong></div>`,
		"fields.netTotal.textContent = hasNetSpeed ? `${netPercent.toFixed(0)}%` : \"--\";",
		"fields.netDetail.textContent = `↑ ${formatRate(net.tx_bytes_per_sec)} · ↓ ${formatRate(",
		`fields.detailUpload.textContent = formatBytes(net.bytes_sent);`,
		`fields.detailDownload.textContent = formatBytes(net.bytes_recv);`,
		`const padding = { top: 20, right: 18, bottom: 18, left: 46 };`,
		"`<text x=\"${padding.left - 4}\" y=\"${y.toFixed(",
		`const regionNames = typeof Intl !== "undefined" && Intl.DisplayNames`,
		`const fallbackRegionNames = {`,
		`CN: "China",`,
		`CA: "Canada",`,
		"return `${flagEmoji(normalized)}${resolved}`.trim();",
	}
	disallowedSnippets := []string{
		"fields.netDetail.textContent = `累计 ${formatBytes(net.bytes_sent)} / ${formatBytes(",
		`fields.detailUpload.textContent = formatRate(net.tx_bytes_per_sec);`,
		`fields.detailDownload.textContent = formatRate(net.rx_bytes_per_sec);`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("expanded node network regression: missing %q", snippet)
		}
	}
	for _, snippet := range disallowedSnippets {
		if strings.Contains(content, snippet) {
			t.Fatalf("expanded node network regression: found stale snippet %q", snippet)
		}
	}
}

func TestPublicMonitorReconnectsRealtimeFeedAggressively(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/monitor.js")
	requiredSnippets := []string{
		`wsReconnectAttempts: new Map(),`,
		`wsWatchdogs: new Map(),`,
		`wsLastMessageAt: new Map(),`,
		`function fetchPublicSnapshotForTarget(target, options = {}) {`,
		`function armWSWatchdog(target, socket) {`,
		`function handleTargetSocketSilence(target, socket) {`,
		`const delay = Math.min(`,
		`WS_RECONNECT_BASE_DELAY * Math.pow(2, attempt)`,
		`fetchPublicSnapshotForTarget(target, { dropOnFailure: false });`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("public monitor realtime reconnect regression: missing %q", snippet)
		}
	}
}

func TestAdminPlaceholderCopyAvoidsInstructionalText(t *testing.T) {
	t.Parallel()

	files := []string{
		"admin-ui/src/pages/BasicSettings.tsx",
		"admin-ui/src/pages/NotificationAlert.tsx",
		"admin-ui/src/pages/ProbeSettings.tsx",
	}

	disallowed := []string{
		`placeholder="留空则不修改"`,
		`placeholder="输入新的 Agent Token"`,
		`placeholder="多个 ID 用逗号分隔"`,
		`placeholder={` + "`默认 ${DEFAULT_TCP_INTERVAL}`" + `}`,
	}

	for _, relativePath := range files {
		content := readRepoFileForUITest(t, relativePath)
		for _, snippet := range disallowed {
			if strings.Contains(content, snippet) {
				t.Fatalf("%s still contains instructional placeholder: %s", relativePath, snippet)
			}
		}
	}
}

func TestPublicMonitorPreservesLegacyHistoryCharts(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "internal/server/web/assets/monitor.js")
	requiredSnippets := []string{
		"const historyMap = state.testHistory.get(nodeId) || new Map();",
		"if (!tests.length && historyMap.size === 0) {",
		`const activeRange = state.testRange.get(nodeId) || defaultTestRangeForHistory(historyMap);`,
		`if (spanSec > 60 * 60 * 24) return "7d";`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("public monitor legacy history regression: missing %q", snippet)
		}
	}
}

func TestReadmeWindowsExamplesUseDirectPowerShellCommands(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "README.md")
	disallowed := `powershell -ExecutionPolicy Bypass -Command`
	if strings.Contains(content, disallowed) {
		t.Fatalf("README Windows examples should avoid nested PowerShell invocation: %q", disallowed)
	}

	requiredSnippets := []string{
		`$script = Join-Path $env:TEMP 'agent.ps1'`,
		`Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.ps1' -OutFile $script`,
		`$script = Join-Path $env:TEMP 'agent-uninstall.ps1'`,
		`Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent-uninstall.ps1' -OutFile $script`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("README Windows example regression: missing %q", snippet)
		}
	}
}

func TestWindowsAgentInstallCommandsAvoidNestedPowerShell(t *testing.T) {
	t.Parallel()

	files := []string{
		"README.md",
		"admin-ui/lib/agent-install.ts",
		"internal/server/web/assets/admin.js",
	}

	for _, relativePath := range files {
		content := readRepoFileForUITest(t, relativePath)
		if strings.Contains(content, `powershell -ExecutionPolicy Bypass -Command`) {
			t.Fatalf("%s should not emit nested PowerShell install commands", relativePath)
		}
		if !strings.Contains(content, "Join-Path $env:TEMP 'agent.ps1'") {
			t.Fatalf("%s should build Windows install commands via Join-Path temp script", relativePath)
		}
	}
}

func TestWindowsAgentScriptBuildsServiceArgsWithoutInlineEscapes(t *testing.T) {
	t.Parallel()

	content := readRepoFileForUITest(t, "agent.ps1")
	disallowedSnippets := []string{
		`$args = "--server-url ` + "`" + `"$ServerUrl`,
		`$([Uri]::EscapeDataString($CurrentNodeId))`,
		"Agent 注册成功但未返回专属凭据。",
		"::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol `",
	}

	for _, snippet := range disallowedSnippets {
		if strings.Contains(content, snippet) {
			t.Fatalf("agent.ps1 should avoid fragile PowerShell parsing pattern %q", snippet)
		}
	}

	requiredSnippets := []string{
		"$serviceArgs = @(",
		`('"{0}"' -f $ServerUrl)`,
		`('"{0}"' -f $NodeId)`,
		`('"{0}"' -f $nodeToken)`,
		`$serviceBinPath = ('"{0}" {1}' -f $binary, ($serviceArgs -join ' '))`,
		`$registerNodeId = [Uri]::EscapeDataString($CurrentNodeId)`,
		`$uri = "{0}/api/v1/agent/register?node_id={1}" -f $RegisterServerUrl.TrimEnd('/'), $registerNodeId`,
		`Write-Host "Agent registration succeeded but the server did not return a dedicated token."`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("agent.ps1 Windows service argument regression: missing %q", snippet)
		}
	}
}

func TestWindowsPowerShellScriptsStayASCIIOnly(t *testing.T) {
	t.Parallel()

	files := []string{
		"agent.ps1",
		"agent-uninstall.ps1",
	}

	for _, relativePath := range files {
		content := readRepoFileForUITest(t, relativePath)
		for i := 0; i < len(content); i++ {
			b := content[i]
			if b == '\n' || b == '\r' || b == '\t' {
				continue
			}
			if b < 0x20 || b > 0x7e {
				t.Fatalf("%s should stay ASCII-only for Windows PowerShell 5.1 compatibility; found byte 0x%02x at offset %d", relativePath, b, i)
			}
		}
	}
}
