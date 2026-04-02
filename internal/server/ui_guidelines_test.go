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
		"uses: actions/upload-artifact@v6",
		`pattern: "!*.dockerbuild"`,
		"needs: [version, build-server, build-agent, build-web, docker-server, docker-agent]",
	}
	disallowedSnippets := []string{
		"uses: actions/checkout@v4",
		"uses: actions/setup-go@v5",
		"uses: actions/setup-node@v4",
		"uses: actions/upload-artifact@v4",
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
