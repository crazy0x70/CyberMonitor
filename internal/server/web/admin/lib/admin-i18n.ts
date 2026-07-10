export type AdminLocale = "zh-CN" | "en-US";

export const ADMIN_LOCALE_STORAGE_KEY = "cm_admin_locale";

export const ADMIN_LOCALE_OPTIONS: Array<{ value: AdminLocale; label: string; shortLabel: string }> = [
  { value: "zh-CN", label: "简体中文", shortLabel: "中" },
  { value: "en-US", label: "English", shortLabel: "EN" },
];

const ADMIN_ZH_TO_EN_ENTRIES = [
  ["管理后台", "Admin"],
  ["总览", "Overview"],
  ["首页", "Dashboard"],
  ["节点与策略", "Nodes & Policy"],
  ["节点管理", "Nodes"],
  ["分组管理", "Groups"],
  ["探测设置", "Probes"],
  ["系统配置", "System"],
  ["基础设置", "Settings"],
  ["通知告警", "Alerts"],
  ["AI 服务商", "AI Providers"],
  ["日志查看", "Logs"],
  ["退出登录", "Sign out"],
  ["打开监控页", "Open monitor page"],
  ["打开导航菜单", "Open navigation menu"],
  ["跳转到主要内容", "Skip to main content"],
  ["切换到浅色模式", "Switch to light mode"],
  ["切换到深色模式", "Switch to dark mode"],
  ["主题模式", "Theme mode"],
  ["跟随系统", "Follow system"],
  ["浅色主题", "Light theme"],
  ["深色主题", "Dark theme"],
  ["界面语言", "Language"],
  ["简体中文", "Simplified Chinese"],
  ["界面语言已更新", "Language updated"],
  ["界面语言更新失败", "Failed to update language"],
  ["正在加载页面…", "Loading page..."],
  ["正在加载首页…", "Loading dashboard..."],
  ["正在加载节点管理…", "Loading nodes..."],
  ["正在加载分组管理…", "Loading groups..."],
  ["正在加载探测设置…", "Loading probes..."],
  ["正在加载基础设置…", "Loading settings..."],
  ["正在加载通知告警…", "Loading alerts..."],
  ["正在加载 AI 服务商…", "Loading AI providers..."],
  ["正在加载日志查看…", "Loading logs..."],
  ["正在加载登录页…", "Loading login..."],
  ["正在加载数据…", "Loading data..."],
  ["离开当前页面前先处理未保存内容？", "Handle unsaved changes before leaving this page?"],
  ["继续编辑", "Keep editing"],
  ["放弃未保存修改", "Discard changes"],
  ["有未保存的修改", "Unsaved changes"],
  ["保存中…", "Saving..."],
  ["保存更改", "Save changes"],
  ["确认保存", "Confirm save"],
  ["取消", "Cancel"],
  ["确认删除", "Confirm delete"],
  ["删除节点", "Delete node"],
  ["欢迎回来", "Welcome back"],
  ["验证管理员凭证以继续", "Verify administrator credentials to continue"],
  ["登录失败", "Login failed"],
  ["登录已失效", "Session expired"],
  ["账号已锁定", "Account locked"],
  ["主机监控", "Host monitoring"],
  ["账号", "Username"],
  ["密码", "Password"],
  ["人机验证", "Human verification"],
  ["Turnstile 脚本加载失败", "Turnstile script failed to load"],
  ["Turnstile 加载失败", "Turnstile failed to load"],
  ["完成验证后再提交管理员凭证。", "Complete verification before submitting administrator credentials."],
  ["正在验证身份…", "Verifying..."],
  ["确 认 登 录", "Sign in"],
  ["账号或密码错误，请检查后重试。", "The username or password is incorrect. Check it and try again."],
  ["您的登录状态已过期或后台凭证已被修改，请重新登录。", "Your session expired or admin credentials changed. Sign in again."],
  ["连续登录失败次数过多，触发防爆破保护。", "Too many failed login attempts triggered brute-force protection."],
  ["人机验证已过期，请重新完成验证。", "Human verification expired. Complete it again."],
  ["人机验证加载失败，请稍后重试。", "Human verification failed to load. Try again later."],
  ["请先完成人机验证。", "Complete human verification first."],
  ["或使用管理员密码", "Or use admin password"],
  ["没有可用登录方式", "No login method available"],
  ["请联系管理员启用密码登录或 OAuth / OIDC 登录。", "Contact an administrator to enable password login or OAuth / OIDC login."],
  ["总节点数", "Total nodes"],
  ["在线节点", "Online nodes"],
  ["离线节点", "Offline nodes"],
  ["未分组节点", "Ungrouped nodes"],
  ["告警渠道", "Alert channels"],
  ["安全入口", "Security entry"],
  ["核心配置", "Core configuration"],
  ["快捷入口", "Quick actions"],
  ["管理", "Manage"],
  ["配置", "Configure"],
  ["未配置", "Not configured"],
  ["兼容服务商", "Compatible provider"],
  ["TG 已配", "TG configured"],
  ["TG 未配", "TG not configured"],
  ["飞书已配", "Feishu configured"],
  ["飞书未配", "Feishu not configured"],
  ["安全控制", "Security"],
  ["Agent 配置", "Agent"],
  ["站点展示", "Site display"],
  ["备份与更新", "Backup & Updates"],
  ["后台入口与凭证", "Admin entry & credentials"],
  ["后台路径", "Admin path"],
  ["管理员账号", "Admin username"],
  ["新密码", "New password"],
  ["留空则不修改当前密码。", "Leave blank to keep the current password."],
  ["OAuth / OIDC 登录", "OAuth / OIDC login"],
  ["启用密码登录", "Enable password login"],
  ["关闭后只能通过已配置的 OAuth / OIDC 提供商登录。", "When disabled, only configured OAuth / OIDC providers can sign in."],
  ["使用 GitHub 用户、邮箱或邮箱域名作为允许列表。", "Use GitHub usernames, emails, or email domains as the allowlist."],
  ["留空则保留当前 Secret", "Leave blank to keep the current secret"],
  ["允许的 GitHub 用户名", "Allowed GitHub usernames"],
  ["允许的邮箱", "Allowed emails"],
  ["允许的邮箱域名", "Allowed email domains"],
  ["要求已验证邮箱", "Require verified email"],
  ["自定义 OIDC", "Custom OIDC"],
  ["支持 Google、Authelia、Zitadel 或其他 OpenID Connect Issuer。", "Supports Google, Authelia, Zitadel, or another OpenID Connect issuer."],
  ["允许的 Subject", "Allowed subjects"],
  ["要求 email_verified", "Require email_verified"],
  ["防爆破策略", "Brute-force protection"],
  ["失败次数上限", "Failure limit"],
  ["统计窗口（分钟）", "Window (minutes)"],
  ["锁定时长（分钟）", "Lock duration (minutes)"],
  ["Agent 对接地址", "Agent endpoint"],
  ["建议使用高强度随机 Token，修改后新接入 Agent 需使用新 Token。", "Use a high-entropy random token. New Agents must use the new token after it changes."],
  ["站点 Title", "Site title"],
  ["站点 Icon", "Site icon"],
  ["首页背景图", "Home background"],
  ["首页标题", "Home title"],
  ["首页副标题", "Home subtitle"],
  ["选择语言…", "Select language..."],
  ["服务端更新", "Server update"],
  ["当前版本", "Current version"],
  ["最新版本", "Latest version"],
  ["检查中…", "Checking..."],
  ["当前已为最新版", "Already latest"],
  ["未检查", "Not checked"],
  ["检查更新", "Check updates"],
  ["更新中", "Updating"],
  ["立即更新", "Update now"],
  ["查看发布说明", "View release notes"],
  ["配置备份", "Configuration backup"],
  ["导出配置", "Export configuration"],
  ["导入配置", "Import configuration"],
  ["确认保存基础设置？", "Save basic settings?"],
  ["确认导入配置？当前环境凭证与 Agent 运行时任务会保留。", "Import configuration? Current credentials and Agent runtime tasks will be preserved."],
  ["导入中…", "Importing..."],
  ["确认导入", "Confirm import"],
  ["基础设置已保存", "Basic settings saved"],
  ["配置已导入", "Configuration imported"],
  ["服务端基础设置已更新，当前未保存修改已保留。", "Server-side basic settings changed. Your unsaved edits were kept."],
  ["保存基础设置失败", "Failed to save basic settings"],
  ["导入配置失败", "Failed to import configuration"],
  ["刷新服务端更新状态失败", "Failed to refresh server update status"],
  ["服务端更新操作失败", "Server update action failed"],
  ["节点数据拉取失败，当前登录态已失效，请重新登录。", "Failed to load node data. Your session expired. Sign in again."],
  ["当前登录态已失效，请重新登录。", "Your session expired. Sign in again."],
  ["初始化节点数据失败", "Failed to initialize node data"],
  ["登录失败，请稍后重试。", "Login failed. Try again later."],
  ["退出登录失败", "Failed to sign out"],
  ["初始化后台数据失败", "Failed to initialize admin data"],
  ["恢复登录会话失败", "Failed to restore login session"],
  ["加载登录配置失败", "Failed to load login configuration"],
  ["加载服务端更新状态失败", "Failed to load server update status"],
  ["刷新服务端更新状态失败", "Failed to refresh server update status"],
  ["设置已保存", "Settings saved"],
  ["配置已导入", "Configuration imported"],
  ["当前服务端已经是最新正式版", "The server is already on the latest stable release"],
  ["节点配置已保存并下发", "Node configuration saved and dispatched"],
  ["节点已删除", "Node deleted"],
  ["节点列表刷新失败", "Failed to refresh node list"],
  ["路径:", "Path:"],
  ["全部", "All"],
  ["信息", "Info"],
  ["警告", "Warning"],
  ["错误", "Error"],
  ["调试", "Debug"],
  ["静默", "Silent"],
  ["实时同步中", "Live syncing"],
  ["运行日志", "Runtime logs"],
  ["加载日志失败", "Failed to load logs"],
  ["暂无日志", "No logs"],
  ["OpenAI 兼容", "OpenAI compatible"],
  ["已验证可用", "Verified"],
  ["已配置未验证", "Configured, unverified"],
  ["服务端 AI 配置已更新，当前未保存修改已保留。", "Server-side AI configuration changed. Your unsaved edits were kept."],
  ["新兼容服务商", "New compatible provider"],
  ["验证失败", "Validation failed"],
  ["获取模型列表失败", "Failed to fetch model list"],
  ["AI 服务商配置已保存", "AI provider configuration saved"],
  ["保存 AI 配置失败", "Failed to save AI configuration"],
  ["全局 AI 策略", "Global AI policy"],
  ["Telegram AI 指令服务商", "Telegram AI command provider"],
  ["选择命令服务商…", "Select command provider..."],
  ["（未配置）", " (not configured)"],
  ["AI 运维提示词", "AI operations prompt"],
  ["提示词内容", "Prompt"],
  ["例如：请重点关注网络流量、下载量与离线情况…", "Example: focus on network traffic, downloads, and offline status..."],
  ["服务商配置详情", "Provider configuration"],
  ["新增兼容服务商", "Add compatible provider"],
  ["显示名称", "Display name"],
  ["模型", "Model"],
  ["尚未获取模型列表", "No model list loaded"],
  ["获取中…", "Fetching..."],
  ["获取模型列表", "Fetch models"],
  ["验证中…", "Testing..."],
  ["测试连接", "Test connection"],
  ["删除", "Delete"],
  ["服务端告警配置已更新，当前未保存修改已保留。", "Server-side alert configuration changed. Your unsaved edits were kept."],
  ["请输入大于或等于 1 的离线阈值。", "Enter an offline threshold greater than or equal to 1."],
  ["Webhook 地址需为有效的 http 或 https 地址。", "Webhook URL must be a valid http or https URL."],
  ["测试飞书告警前，请先填写 Webhook 地址。", "Enter a Webhook URL before testing Feishu alerts."],
  ["请输入 Telegram Bot Token。", "Enter a Telegram Bot Token."],
  ["请输入至少一个 Telegram 用户 ID。", "Enter at least one Telegram user ID."],
  ["用户 ID 必须为正整数，多个 ID 请用逗号分隔。", "User IDs must be positive integers. Separate multiple IDs with commas."],
  ["告警配置已保存", "Alert configuration saved"],
  ["保存告警配置失败", "Failed to save alert configuration"],
  ["测试消息已发送", "Test message sent"],
  ["测试发送失败", "Failed to send test message"],
  ["节点总数", "Total nodes"],
  ["已启用告警", "Alerts enabled"],
  ["已关闭告警", "Alerts disabled"],
  ["离线阈值", "Offline threshold"],
  ["全局告警策略", "Global alert policy"],
  ["离线阈值（分钟）", "Offline threshold (minutes)"],
  ["当节点超过此时间未上报心跳时，将触发离线通知。", "An offline notification is triggered when a node stops reporting heartbeats longer than this time."],
  ["Telegram 告警", "Telegram alerts"],
  ["用户 ID", "User IDs"],
  ["多个用户 ID 请使用逗号分隔。", "Separate multiple user IDs with commas."],
  ["正在发送…", "Sending..."],
  ["测试推送", "Test push"],
  ["飞书告警", "Feishu alerts"],
  ["Webhook 地址", "Webhook URL"],
  ["至少需要保留一个一级分组。", "Keep at least one top-level group."],
  ["一级分组名称不能使用“全部”。", "Top-level group name cannot be \"All\"."],
  ["服务端分组配置已更新，当前未保存修改已保留。", "Server-side group configuration changed. Your unsaved edits were kept."],
  ["一级分组", "Top-level group"],
  ["二级标签", "Tags"],
  ["节点归属", "Node ownership"],
  ["分组配置已保存。", "Group configuration saved."],
  ["保存分组失败。", "Failed to save groups."],
  ["新建分组", "New group"],
  ["分组编辑", "Group editor"],
  ["还没有一级分组", "No top-level groups yet"],
  ["拖动排序", "Drag to sort"],
  ["一级分组名称", "Top-level group name"],
  ["添加标签", "Add tag"],
  ["删除一级分组", "Delete top-level group"],
  ["确认删除一级分组？", "Delete this top-level group?"],
  ["暂无二级标签", "No tags yet"],
  ["删除标签", "Delete tag"],
  ["探测节点名称不能为空。", "Probe name cannot be empty."],
  ["探测节点名称包含非法字符。", "Probe name contains invalid characters."],
  ["探测节点地址不能为空。", "Probe target cannot be empty."],
  ["探测节点地址格式不正确。", "Probe target format is invalid."],
  ["固定", "Fixed"],
  ["服务端探测配置已更新，当前未保存修改已保留。", "Server-side probe configuration changed. Your unsaved edits were kept."],
  ["探测节点已添加", "Probe added"],
  ["探测节点已更新", "Probe updated"],
  ["探测节点已移除", "Probe removed"],
  ["探测节点配置已保存", "Probe configuration saved"],
  ["保存探测节点配置失败", "Failed to save probe configuration"],
  ["新增探测节点", "Add probe"],
  ["暂无探测节点", "No probes yet"],
  ["未命名探测节点", "Unnamed probe"],
  ["目标", "Target"],
  ["协议", "Protocol"],
  ["间隔", "Interval"],
  ["编辑探测节点", "Edit probe"],
  ["名称", "Name"],
  ["类型", "Type"],
  ["目标地址", "Target address"],
  ["端口", "Port"],
  ["默认间隔（秒）", "Default interval (seconds)"],
  ["留空或填写", "Leave blank or enter"],
  ["时，将沿用默认间隔", "to use the default interval of"],
  ["秒。", "seconds."],
  ["保存探测节点", "Save probe"],
  ["确认删除探测节点？", "Delete this probe?"],
  ["按月续费", "Monthly renewal"],
  ["按季度续费", "Quarterly renewal"],
  ["按半年续费", "Half-year renewal"],
  ["按年续费", "Yearly renewal"],
  ["不自动续费", "No auto-renewal"],
  ["到期时间格式无效，请重新选择", "Expiration date is invalid. Select it again."],
  ["在线", "Online"],
  ["离线", "Offline"],
  ["请选择分组与标签", "Select groups and tags"],
  ["服务端节点配置已更新，当前未保存修改已保留。请取消后重新打开再保存。", "Server-side node configuration changed. Your unsaved edits were kept. Cancel and reopen before saving."],
  ["已启用离线告警", "Offline alerts enabled"],
  ["已关闭离线告警", "Offline alerts disabled"],
  ["请选择节点后再执行更新", "Select a node before updating"],
  ["当前 Agent 已禁用远程更新", "Remote Agent updates are disabled"],
  ["当前节点还没有上报 Agent 版本", "This node has not reported an Agent version"],
  ["当前 Agent 已是最新版", "Agent is already latest"],
  ["已禁用更新", "Updates disabled"],
  ["节点配置有未保存修改，请先保存或使用放弃修改。", "Node configuration has unsaved changes. Save or discard them first."],
  ["当前节点配置有未保存修改，请先保存或取消后再刷新。", "The current node has unsaved changes. Save or cancel before refreshing."],
  ["节点列表已刷新", "Node list refreshed"],
  ["刷新节点列表失败", "Failed to refresh node list"],
  ["服务端节点配置已更新，请取消后重新打开再保存。", "Server-side node configuration changed. Cancel and reopen before saving."],
  ["保存节点配置失败", "Failed to save node configuration"],
  ["删除节点失败", "Failed to delete node"],
  ["命令已复制", "Command copied"],
  ["复制失败，请手动选择命令后复制", "Copy failed. Select the command manually and copy it."],
  ["当前节点平台暂不支持后台自更新", "This node platform does not support admin-side self-update"],
  ["已完成 Agent 版本检查", "Agent version check completed"],
  ["检查 Agent 更新失败", "Failed to check Agent updates"],
  ["当前 Agent 已是最新版本", "Agent is already latest"],
  ["当前 Agent 已经是最新正式版", "Agent is already on the latest stable release"],
  ["下发 Agent 更新失败", "Failed to dispatch Agent update"],
  ["搜索节点", "Search nodes"],
  ["刷新节点", "Refresh nodes"],
  ["Agent 快速接入", "Quick Agent onboarding"],
  ["单击复制完整命令，拖拽可自由选择局部内容", "Click to copy the full command. Drag to select part of it."],
  ["请先在基础设置的 Agent 配置中填写对接地址与 Agent Token。", "Fill the Agent endpoint and Agent token in Basic Settings first."],
  ["服务器管理", "Server management"],
  ["当前还没有节点接入。", "No nodes have connected yet."],
  ["没有匹配的节点，请调整搜索条件。", "No matching nodes. Adjust the search criteria."],
  ["告警已关闭", "Alerts off"],
  ["编辑配置", "Edit configuration"],
  ["最近状态", "Recent status"],
  ["当前在线，可直接下发配置", "Online now. Configuration can be dispatched immediately."],
  ["当前离线，配置会在恢复后生效", "Offline now. Configuration will take effect after recovery."],
  ["资源快照", "Resource snapshot"],
  ["运行环境", "Runtime environment"],
  ["地区：", "Region:"],
  ["归属与续费", "Ownership & renewal"],
  ["未分组", "Ungrouped"],
  ["未设置到期时间", "No expiration date set"],
  ["节点配置编辑", "Node configuration editor"],
  ["选择节点后编辑", "Select a node to edit"],
  ["编辑目标", "Edit target"],
  ["Agent 更新", "Agent update"],
  ["节点资料", "Node profile"],
  ["识别信息", "Identity"],
  ["地区代码", "Region code"],
  ["当前主机名", "Current hostname"],
  ["资源标注", "Resource labels"],
  ["磁盘类型", "Disk type"],
  ["带宽（Mbps）", "Bandwidth (Mbps)"],
  ["探测下发策略", "Probe dispatch policy"],
  ["请先在“探测设置”页配置探测节点。", "Configure probe nodes on the Probes page first."],
  ["固定执行", "Fixed execution"],
  ["生命周期与告警", "Lifecycle & alerts"],
  ["到期与续费", "Expiration & renewal"],
  ["到期时间", "Expiration date"],
  ["自动续费方案", "Auto-renewal plan"],
  ["选择续费方案…", "Select renewal plan..."],
  ["按月续费（30 天）", "Monthly renewal (30 days)"],
  ["按季度续费（90 天）", "Quarterly renewal (90 days)"],
  ["按半年续费（180 天）", "Half-year renewal (180 days)"],
  ["按年续费（365 天）", "Yearly renewal (365 days)"],
  ["离线告警", "Offline alerts"],
  ["开启", "On"],
  ["关闭", "Off"],
  ["分组与标签", "Groups & tags"],
  ["当前还没有分组树，请先在“分组管理”页维护结构。", "No group tree yet. Maintain it on the Groups page first."],
  ["点击一级分组或其下方标签即可选择；同一一级分组下会在分组与标签之间互斥。", "Click a top-level group or its tags to select. Groups and tags under the same top-level group are mutually exclusive."],
  ["删除节点", "Delete node"],
  ["确认删除节点？", "Delete this node?"],
  ["放弃修改", "Discard changes"],
  ["保存配置", "Save configuration"],
  ["确认保存", "Confirm save"],
  ["后台路径已更新为", "Admin path updated to"],
  ["管理员凭证或会话已更新，请重新登录后继续。", "Admin credentials or session changed. Sign in again to continue."],
  ["服务端更新状态查询失败，当前登录态已失效，请重新登录。", "Failed to query server update status. Your session expired. Sign in again."],
  ["节点配置保存失败，当前登录态已失效，请重新登录。", "Failed to save node configuration. Your session expired. Sign in again."],
  ["节点删除失败，当前登录态已失效，请重新登录。", "Failed to delete node. Your session expired. Sign in again."],
  ["管理员账号已变更，登录态已自动刷新", "Admin username changed. Session was refreshed automatically."],
  ["密码已更新，登录态已自动刷新", "Password changed. Session was refreshed automatically."],
  ["刚刚", "Just now"],
  ["加载公开展示配置失败", "Failed to load public display configuration"],
  ["检测登录会话失败", "Failed to check login session"],
  ["加载设置失败", "Failed to load settings"],
  ["保存设置失败", "Failed to save settings"],
  ["导出配置失败", "Failed to export configuration"],
  ["加载节点失败", "Failed to load nodes"],
  ["保存节点失败", "Failed to save node"],
  ["获取服务端更新状态失败", "Failed to fetch server update status"],
  ["触发服务端更新失败", "Failed to trigger server update"],
  ["获取 Agent 更新状态失败", "Failed to fetch Agent update status"],
  ["测试告警失败", "Failed to test alerts"],
  ["测试 Provider 失败", "Failed to test provider"],
  ["例如：/cm-admin…", "Example: /cm-admin..."],
  ["例如：https://monitor.example.com…", "Example: https://monitor.example.com..."],
  ["例如：cm-agent-token-abc123…", "Example: cm-agent-token-abc123..."],
  ["例如：搜索节点名、Node ID、主机名、地区…", "Example: search node name, Node ID, hostname, region..."],
  ["例如：123456789:ABC…", "Example: 123456789:ABC..."],
  ["例如：123456789,987654321…", "Example: 123456789,987654321..."],
  ["例如：美国、香港、日本…", "Example: United States, Hong Kong, Japan..."],
  ["例如：CN2、BGP、GIA…", "Example: CN2, BGP, GIA..."],
  ["例如：主站 TCP 443…", "Example: main site TCP 443..."],
  ["例如：1.1.1.1 / example.com…", "Example: 1.1.1.1 / example.com..."],
  ["例如：443…", "Example: 443..."],
  ["例如：US", "Example: US"],
] as const;

const zhToEn = new Map<string, string>(ADMIN_ZH_TO_EN_ENTRIES);
const enToZh = new Map<string, string>(ADMIN_ZH_TO_EN_ENTRIES.map(([zh, en]) => [en, zh]));

const ADMIN_TEXT_PATTERNS: Array<{
  zh: RegExp;
  toEn: (match: RegExpMatchArray) => string;
  en: RegExp;
  toZh: (match: RegExpMatchArray) => string;
}> = [
  {
    zh: /^实时同步\s+(.+)$/,
    toEn: (match) => `Live sync ${match[1]}`,
    en: /^Live sync\s+(.+)$/,
    toZh: (match) => `实时同步 ${match[1]}`,
  },
  {
    zh: /^路径:\s*(.*)$/,
    toEn: (match) => `Path: ${match[1]}`.trimEnd(),
    en: /^Path:\s*(.*)$/,
    toZh: (match) => `路径: ${match[1]}`.trimEnd(),
  },
  {
    zh: /^TG\s+(已配|未配)，飞书(已配|未配)$/,
    toEn: (match) =>
      `TG ${match[1] === "已配" ? "configured" : "not configured"}, Feishu ${
        match[2] === "已配" ? "configured" : "not configured"
      }`,
    en: /^TG\s+(configured|not configured),\s+Feishu\s+(configured|not configured)$/,
    toZh: (match) =>
      `TG ${match[1] === "configured" ? "已配" : "未配"}，飞书${
        match[2] === "configured" ? "已配" : "未配"
      }`,
  },
  {
    zh: /^请在\s+(\d+)\s+分\s+(\d+)\s+秒后重试。$/,
    toEn: (match) => `Retry in ${match[1]} min ${match[2]} sec.`,
    en: /^Retry in\s+(\d+)\s+min\s+(\d+)\s+sec\.$/,
    toZh: (match) => `请在 ${match[1]} 分 ${match[2]} 秒后重试。`,
  },
  {
    zh: /^使用\s+(.+)\s+登录$/,
    toEn: (match) => `Sign in with ${match[1]}`,
    en: /^Sign in with\s+(.+)$/,
    toZh: (match) => `使用 ${match[1]} 登录`,
  },
  {
    zh: /^后台路径已更新为\s+(.+)$/,
    toEn: (match) => `Admin path updated to ${match[1]}`,
    en: /^Admin path updated to\s+(.+)$/,
    toZh: (match) => `后台路径已更新为 ${match[1]}`,
  },
  {
    zh: /^服务端更新已开始，目标版本\s+(.+)$/,
    toEn: (match) => `Server update started. Target version: ${match[1]}`,
    en: /^Server update started\. Target version:\s+(.+)$/,
    toZh: (match) => `服务端更新已开始，目标版本 ${match[1]}`,
  },
  {
    zh: /^复制\s+(.+)\s+Agent 接入命令$/,
    toEn: (match) => `Copy ${match[1]} Agent onboarding command`,
    en: /^Copy\s+(.+)\s+Agent onboarding command$/,
    toZh: (match) => `复制 ${match[1]} Agent 接入命令`,
  },
  {
    zh: /^Node ID:\s+(.+)\s+\/\s+主机名：(.+)\s+\/\s+Agent:\s+(.+)$/,
    toEn: (match) => `Node ID: ${match[1]} / Hostname: ${match[2]} / Agent: ${match[3]}`,
    en: /^Node ID:\s+(.+)\s+\/\s+Hostname:\s+(.+)\s+\/\s+Agent:\s+(.+)$/,
    toZh: (match) => `Node ID: ${match[1]} / 主机名：${match[2]} / Agent: ${match[3]}`,
  },
  {
    zh: /^CPU\s+(.+)%\s+\/\s+内存\s+(.+)%$/,
    toEn: (match) => `CPU ${match[1]}% / Memory ${match[2]}%`,
    en: /^CPU\s+(.+)%\s+\/\s+Memory\s+(.+)%$/,
    toZh: (match) => `CPU ${match[1]}% / 内存 ${match[2]}%`,
  },
  {
    zh: /^带宽：(.+)$/,
    toEn: (match) => `Bandwidth: ${match[1]}`,
    en: /^Bandwidth:\s*(.+)$/,
    toZh: (match) => `带宽：${match[1]}`,
  },
  {
    zh: /^留空或填写\s+0\s+时，将沿用默认间隔\s+(\d+)\s+秒。$/,
    toEn: (match) => `Leave blank or enter 0 to use the default ${match[1]} seconds.`,
    en: /^Leave blank or enter 0 to use the default\s+(\d+)\s+seconds\.$/,
    toZh: (match) => `留空或填写 0 时，将沿用默认间隔 ${match[1]} 秒。`,
  },
  {
    zh: /^已缓存\s+(\d+)\s+个模型候选$/,
    toEn: (match) => `Cached ${match[1]} model candidates`,
    en: /^Cached\s+(\d+)\s+model candidates$/,
    toZh: (match) => `已缓存 ${match[1]} 个模型候选`,
  },
  {
    zh: /^(\d+)\s+个节点$/,
    toEn: (match) => `${match[1]} nodes`,
    en: /^(\d+)\s+nodes$/,
    toZh: (match) => `${match[1]} 个节点`,
  },
  {
    zh: /^(\d+)\s+个标签$/,
    toEn: (match) => `${match[1]} tags`,
    en: /^(\d+)\s+tags$/,
    toZh: (match) => `${match[1]} 个标签`,
  },
  {
    zh: /^共\s+(\d+)\s+个有效标签$/,
    toEn: (match) => `${match[1]} valid tags total`,
    en: /^(\d+)\s+valid tags total$/,
    toZh: (match) => `共 ${match[1]} 个有效标签`,
  },
  {
    zh: /^已选\s+(\d+)\s+个探测节点。\s+其中\s+(\d+)\s+个 TCP 节点使用了自定义间隔。$/,
    toEn: (match) => `${match[1]} probes selected. ${match[2]} TCP probes use a custom interval.`,
    en: /^(\d+)\s+probes selected\.\s+(\d+)\s+TCP probes use a custom interval\.$/,
    toZh: (match) => `已选 ${match[1]} 个探测节点。 其中 ${match[2]} 个 TCP 节点使用了自定义间隔。`,
  },
  {
    zh: /^已选\s+(\d+)\s+个探测节点。$/,
    toEn: (match) => `${match[1]} probes selected.`,
    en: /^(\d+)\s+probes selected\.$/,
    toZh: (match) => `已选 ${match[1]} 个探测节点。`,
  },
  {
    zh: /^其中\s+(\d+)\s+个 TCP 节点使用了自定义间隔。$/,
    toEn: (match) => `${match[1]} TCP probes use a custom interval.`,
    en: /^(\d+)\s+TCP probes use a custom interval\.$/,
    toZh: (match) => `其中 ${match[1]} 个 TCP 节点使用了自定义间隔。`,
  },
  {
    zh: /^默认\s+(\d+)\s+秒$/,
    toEn: (match) => `Default ${match[1]} seconds`,
    en: /^Default\s+(\d+)\s+seconds$/,
    toZh: (match) => `默认 ${match[1]} 秒`,
  },
  {
    zh: /^(\d+)\s+秒$/,
    toEn: (match) => `${match[1]} seconds`,
    en: /^(\d+)\s+seconds$/,
    toZh: (match) => `${match[1]} 秒`,
  },
  {
    zh: /^(\d+)\s+秒前$/,
    toEn: (match) => `${match[1]} seconds ago`,
    en: /^(\d+)\s+seconds ago$/,
    toZh: (match) => `${match[1]} 秒前`,
  },
  {
    zh: /^(\d+)\s+分钟前$/,
    toEn: (match) => `${match[1]} minutes ago`,
    en: /^(\d+)\s+minutes ago$/,
    toZh: (match) => `${match[1]} 分钟前`,
  },
  {
    zh: /^(\d+)\s+小时前$/,
    toEn: (match) => `${match[1]} hours ago`,
    en: /^(\d+)\s+hours ago$/,
    toZh: (match) => `${match[1]} 小时前`,
  },
  {
    zh: /^(\d+)\s+天前$/,
    toEn: (match) => `${match[1]} days ago`,
    en: /^(\d+)\s+days ago$/,
    toZh: (match) => `${match[1]} 天前`,
  },
  {
    zh: /^(.+)\s+验证成功$/,
    toEn: (match) => `${match[1]} validation succeeded`,
    en: /^(.+)\s+validation succeeded$/,
    toZh: (match) => `${match[1]} 验证成功`,
  },
  {
    zh: /^(.+)\s+模型列表已刷新$/,
    toEn: (match) => `${match[1]} model list refreshed`,
    en: /^(.+)\s+model list refreshed$/,
    toZh: (match) => `${match[1]} 模型列表已刷新`,
  },
  {
    zh: /^(.+)\s+等\s+(\d+)\s+项$/,
    toEn: (match) => `${match[1]} and ${match[2]} items`,
    en: /^(.+)\s+and\s+(\d+)\s+items$/,
    toZh: (match) => `${match[1]} 等 ${match[2]} 项`,
  },
  {
    zh: /^已检查到最新版本\s+(.+)$/,
    toEn: (match) => `Latest version detected: ${match[1]}`,
    en: /^Latest version detected:\s+(.+)$/,
    toZh: (match) => `已检查到最新版本 ${match[1]}`,
  },
  {
    zh: /^Agent 更新任务已下发，目标版本\s+(.+)$/,
    toEn: (match) => `Agent update task dispatched. Target version: ${match[1]}`,
    en: /^Agent update task dispatched\. Target version:\s+(.+)$/,
    toZh: (match) => `Agent 更新任务已下发，目标版本 ${match[1]}`,
  },
  {
    zh: /^确认删除节点“(.+)”？$/,
    toEn: (match) => `Delete node "${match[1]}"?`,
    en: /^Delete node "(.+)"\?$/,
    toZh: (match) => `确认删除节点“${match[1]}”？`,
  },
  {
    zh: /^TCP 端口需为 1 - (\d+)。$/,
    toEn: (match) => `TCP port must be 1 - ${match[1]}.`,
    en: /^TCP port must be 1 - (\d+)\.$/,
    toZh: (match) => `TCP 端口需为 1 - ${match[1]}。`,
  },
  {
    zh: /^TCP 默认间隔需为 0 - (\d+) 秒，留空或 0 表示默认 (\d+) 秒。$/,
    toEn: (match) => `TCP default interval must be 0 - ${match[1]} seconds. Leave blank or enter 0 to use the default ${match[2]} seconds.`,
    en: /^TCP default interval must be 0 - (\d+) seconds\. Leave blank or enter 0 to use the default (\d+) seconds\.$/,
    toZh: (match) => `TCP 默认间隔需为 0 - ${match[1]} 秒，留空或 0 表示默认 ${match[2]} 秒。`,
  },
  {
    zh: /^(.+)\s+名称不能为空。$/,
    toEn: (match) => `${match[1]} name cannot be empty.`,
    en: /^(.+)\s+name cannot be empty\.$/,
    toZh: (match) => `${match[1]} 名称不能为空。`,
  },
];

export function normalizeAdminLocale(value?: string | null): AdminLocale {
  return String(value || "").trim().toLowerCase().replace("_", "-") === "en-us" ? "en-US" : "zh-CN";
}

export function readStoredAdminLocale(): AdminLocale | null {
  if (typeof window === "undefined") {
    return null;
  }
  try {
    const raw = window.localStorage.getItem(ADMIN_LOCALE_STORAGE_KEY);
    return raw ? normalizeAdminLocale(raw) : null;
  } catch {
    return null;
  }
}

export function writeStoredAdminLocale(locale: AdminLocale) {
  if (typeof window === "undefined") {
    return;
  }
  try {
    window.localStorage.setItem(ADMIN_LOCALE_STORAGE_KEY, locale);
  } catch {
    // storage may be disabled by browser policy
  }
}

export function adminText(locale: AdminLocale, zhText: string) {
  return locale === "en-US" ? zhToEn.get(zhText) || zhText : zhText;
}

export function adminBrowserTitleForLocale(locale: AdminLocale, siteTitle: string) {
  const normalizedTitle = siteTitle.trim() || "CyberMonitor";
  return `${normalizedTitle} ${adminText(locale, "管理后台")}`;
}

function translateExact(value: string, locale: AdminLocale) {
  const trimmed = value.trim();
  if (!trimmed) {
    return value;
  }
  const translated = (locale === "en-US" ? zhToEn : enToZh).get(trimmed);
  if (translated) {
    return value.replace(trimmed, translated);
  }
  for (const pattern of ADMIN_TEXT_PATTERNS) {
    const match = trimmed.match(locale === "en-US" ? pattern.zh : pattern.en);
    if (match) {
      return value.replace(trimmed, locale === "en-US" ? pattern.toEn(match) : pattern.toZh(match));
    }
  }
  return value;
}

function shouldSkipElement(element: Element | null) {
  if (!element) {
    return false;
  }
  const tag = element.tagName;
  return (
    tag === "SCRIPT" ||
    tag === "STYLE" ||
    tag === "TEXTAREA" ||
    tag === "INPUT" ||
    element.closest("[data-admin-i18n-skip]") != null
  );
}

export function translateAdminDOM(root: ParentNode | null, locale: AdminLocale) {
  if (!root) {
    return;
  }

  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      return shouldSkipElement(node.parentElement)
        ? NodeFilter.FILTER_REJECT
        : NodeFilter.FILTER_ACCEPT;
    },
  });
  const textNodes: Text[] = [];
  while (walker.nextNode()) {
    textNodes.push(walker.currentNode as Text);
  }
  textNodes.forEach((node) => {
    const next = translateExact(node.nodeValue || "", locale);
    if (next !== node.nodeValue) {
      node.nodeValue = next;
    }
  });

  root.querySelectorAll?.("[placeholder], [aria-label], [title]").forEach((element) => {
    if (shouldSkipElement(element)) {
      return;
    }
    ["placeholder", "aria-label", "title"].forEach((attribute) => {
      const current = element.getAttribute(attribute);
      if (!current) {
        return;
      }
      const next = translateExact(current, locale);
      if (next !== current) {
        element.setAttribute(attribute, next);
      }
    });
  });
}
