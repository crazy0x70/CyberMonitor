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
  ["运维助手", "Ops Assistant"],
  ["日志查看", "Logs"],
  ["退出登录", "Sign out"],
  ["打开监控页", "Open monitor page"],
  ["打开导航菜单", "Open navigation menu"],
  ["展开子菜单", "Expand submenu"],
  ["收起子菜单", "Collapse submenu"],
  ["跳转到主要内容", "Skip to main content"],
  [
    "服务端更新失败，当前登录态已失效，请重新登录。",
    "Server update failed: your session has expired. Please sign in again.",
  ],
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
  ["正在加载运维助手…", "Loading ops assistant..."],
  ["正在加载日志查看…", "Loading logs..."],
  ["正在加载登录页…", "Loading login..."],
  ["正在加载数据…", "Loading data..."],
  ["离开当前页面前先处理未保存内容？", "Handle unsaved changes before leaving this page?"],
  ["继续编辑", "Keep editing"],
  ["Close", "关闭"],
  ["放弃未保存修改", "Discard changes"],
  ["放弃修改", "Discard modifications"],
  ["有未保存的修改", "Unsaved changes"],
  ["保存中…", "Saving..."],
  ["保存更改", "Save changes"],
  // A-03：保存条「放弃修改」与二次确认弹窗（D-07）。
  ["放弃未保存的修改？", "Discard unsaved changes?"],
  ["本页所有未保存的修改将丢失，恢复为当前已保存的配置。", "All unsaved changes on this page will be lost and restored to the currently saved configuration."],
  ["已放弃修改", "Changes discarded"],
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
  ["Cloudflare Turnstile", "Cloudflare Turnstile"],
  ["完成验证后再提交管理员凭证。", "Complete verification before submitting administrator credentials."],
  ["正在验证身份…", "Verifying..."],
  ["确认登录", "Sign in"],
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
  ["节点总数", "Nodes tracked"],
  ["在线节点", "Online nodes"],
  ["离线节点", "Offline nodes"],
  ["未分组节点", "Ungrouped nodes"],
  ["快捷入口", "Quick actions"],
  ["管理", "Manage"],
  ["配置", "Configure"],
  ["未配置", "Not configured"],
  ["已配置", "Configured"],
  ["节点列表", "Node list"],
  ["节点概览", "Node overview"],
  ["节点统计", "Node statistics"],
  ["统计摘要", "Summary"],
  ["状态", "Status"],
  ["内存", "Memory"],
  ["磁盘", "Disk"],
  ["网速", "Network"],
  ["系统", "OS"],
  ["续期", "Renewal"],
  ["当前值", "Current value"],
  ["操作", "Actions"],
  ["接入地址", "Endpoint"],
  ["未设置", "Not set"],
  ["复制 Windows Agent 接入命令", "Copy Windows agent install command"],
  ["复制 Linux / macOS Agent 接入命令", "Copy Linux and macOS agent install command"],
  ["兼容服务商", "Compatible provider"],
  ["TG 已配", "TG configured"],
  ["TG 未配", "TG not configured"],
  ["飞书已配", "Feishu configured"],
  ["飞书未配", "Feishu not configured"],
  ["安全控制", "Security"],
  ["安全设置", "Security settings"],
  ["接入配置", "Agent onboarding"],
  ["站点展示", "Site display"],
  ["备份与更新", "Backup & Updates"],
  ["入口凭证", "Entry credentials"],
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
  ["系统信息", "System info"],
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
  ["版本", "Version"],
  ["检查", "Check"],
  ["发布说明", "Release notes"],
  ["更新", "Update"],
  ["更新中…", "Updating..."],
  ["已是最新", "Up to date"],
  ["正在检查…", "Checking..."],
  ["检查失败", "Check failed"],
  ["当前部署不支持在线更新", "Online updates are not supported by this deployment"],
  ["导出", "Export"],
  ["导入…", "Import..."],
  ["下载当前配置（不含密钥）", "Download the current configuration (secrets excluded)"],
  ["从备份文件恢复，密钥保持不变", "Restore from a backup file; secrets are kept unchanged"],
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
  ["刷新节点列表失败", "Failed to refresh the node list"],
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
  ["通过 Telegram /ai 命令，用自然语言查询节点状态。", "Query node status in natural language via the Telegram /ai command."],
  ["新兼容服务商", "New compatible provider"],
  ["验证失败", "Validation failed"],
  ["获取模型列表失败", "Failed to fetch model list"],
  ["运维助手配置已保存", "Ops assistant configuration saved"],
  ["保存 AI 配置失败", "Failed to save AI configuration"],
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
  ["请输入大于或等于 1 的离线判定时间。", "Enter an offline detection time greater than or equal to 1."],
  ["告警配置已保存", "Alert configuration saved"],
  ["保存告警配置失败", "Failed to save alert configuration"],
  ["测试消息已发送", "Test message sent"],
  ["测试发送失败", "Failed to send test message"],
  ["告警策略", "Alert policy"],
  ["渠道设置", "Channels"],
  ["离线判定时间", "Offline detection time"],
  ["对所有节点生效：节点超过该时长未上报，即判定为离线并触发离线告警。", "Applies to all nodes: a node that stops reporting for longer than this duration is considered offline and triggers the offline alert."],
  // F4「告警策略」：全局设置行、规则列表、规则抽屉与模拟评估文案。
  ["分钟", "min"],
  ["全局设置", "Global settings"],
  ["告警规则", "Alert rules"],
  ["新增规则", "New rule"],
  ["编辑规则", "Edit rule"],
  ["未命名规则", "Unnamed rule"],
  ["暂无告警规则", "No alert rules"],
  ["启用规则", "Enable rule"],
  ["条件", "Condition"],
  ["范围", "Scope"],
  ["渠道", "Channels"],
  ["告警", "Alerting"],
  ["未知", "Unknown"],
  ["节点", "Node"],
  ["模拟评估", "Simulate"],
  ["评估中…", "Simulating..."],
  ["模拟评估失败", "Failed to simulate the alert rule"],
  ["没有适用节点。", "No applicable nodes."],
  ["指标", "Metric"],
  ["比较符", "Operator"],
  ["持续时间", "Duration"],
  ["立即", "Immediately"],
  ["请选择探测目标…", "Select a probe target..."],
  ["请选择探测目标。", "Select a probe target."],
  ["请输入规则名称。", "Enter a rule name."],
  ["请输入有效的阈值。", "Enter a valid threshold."],
  ["指定范围时至少选择一个节点或分组。", "Select at least one node or group for a custom scope."],
  ["例如：CPU 使用率过高", "Example: high CPU usage"],
  ["指定范围", "Custom scope"],
  ["全部节点", "All nodes"],
  ["个", "count"],
  ["指定节点", "Specific nodes"],
  ["指定分组", "Specific groups"],
  ["排除节点", "Excluded nodes"],
  ["未选择", "None selected"],
  ["暂无节点", "No nodes"],
  ["暂无分组", "No groups"],
  ["通知", "Notifications"],
  ["全部已启用渠道", "All enabled channels"],
  ["留空 = 全部已启用渠道。", "Leave empty for all enabled channels."],
  ["恢复时通知", "Notify on recovery"],
  ["指标恢复正常时发送恢复通知。", "Send a recovery notification when the metric returns to normal."],
  ["重复提醒", "Repeat"],
  ["仅一次", "Once"],
  ["递增间隔重复", "Repeat with increasing intervals"],
  ["内置规则：条件由「离线判定时间」决定，不可删除。", "Built-in rule: its condition follows the offline detection time and it cannot be deleted."],
  ["条件与持续时间由「离线判定时间」决定，仅可停用或调整范围与渠道。", "The condition and duration follow the offline detection time; the rule can only be disabled, or have its scope and channels adjusted."],
  ["节点离线", "Node offline"],
  ["CPU 使用率", "CPU usage"],
  ["1 分钟负载", "1-min load"],
  ["5 分钟负载", "5-min load"],
  ["15 分钟负载", "15-min load"],
  ["内存使用率", "Memory usage"],
  ["磁盘使用率", "Disk usage"],
  ["GPU 使用率", "GPU usage"],
  ["GPU 温度", "GPU temperature"],
  ["入站带宽", "Inbound bandwidth"],
  ["出站带宽", "Outbound bandwidth"],
  ["TCP 连接数", "TCP connections"],
  ["进程数", "Process count"],
  ["探测延迟", "Probe latency"],
  ["丢包率", "Packet loss"],
  ["到期提醒", "Expiry reminder"],
  ["流量配额", "Traffic quota"],
  ["资源", "Resources"],
  ["网络", "Network"],
  ["探测", "Probes"],
  ["生命周期", "Lifecycle"],
  ["Webhook 地址", "Webhook URL"],
  // F5「渠道设置」：列表、抽屉与校验文案。
  ["通知渠道", "Notification channels"],
  ["添加渠道", "Add channel"],
  ["还没有通知渠道", "No channels yet"],
  // A-06：空态文案不再指向「右上角」（按钮在标题行右侧与空态内各一份）。
  ["配置飞书、Telegram、邮件等 7 种通知方式。", "Configure Feishu, Telegram, email, and other channel types — 7 in total."],
  ["钉钉", "DingTalk"],
  ["企业微信", "WeCom"],
  ["邮件", "Email"],
  ["正常", "OK"],
  ["未测试", "Not tested"],
  ["测试失败", "Test failed"],
  ["测试", "Test"],
  ["测试中…", "Testing..."],
  ["发送测试", "Send test"],
  ["启用渠道", "Enable channel"],
  ["编辑渠道", "Edit channel"],
  ["基础", "Basics"],
  ["凭据", "Credentials"],
  ["会话", "Chats"],
  ["会话 ID", "Chat ID"],
  ["话题 ID", "Thread ID"],
  ["API 地址", "API endpoint"],
  ["签名密钥", "Signing secret"],
  ["服务器地址", "Server URL"],
  ["设备 Key", "Device key"],
  ["通知级别", "Notification level"],
  ["声音", "Sound"],
  ["图标", "Icon"],
  ["@手机号", "@ Phones"],
  ["@所有人", "@ everyone"],
  ["SMTP 服务器", "SMTP server"],
  ["服务器", "Server"],
  ["连接安全", "Connection security"],
  ["用户名", "Username"],
  ["发件地址", "From address"],
  ["发件人名称", "Sender name"],
  ["收件地址", "Recipients"],
  ["收发", "Send & receive"],
  ["留空使用 https://api.telegram.org。", "Leave blank to use https://api.telegram.org."],
  ["留空使用 https://api.day.app。", "Leave blank to use https://api.day.app."],
  ["留空发送到主会话。", "Leave blank to send to the main chat."],
  ["多个会话 ID 请使用逗号分隔。", "Separate multiple chat IDs with commas."],
  ["多个手机号请使用逗号分隔。", "Separate multiple phone numbers with commas."],
  ["多个收件地址请使用逗号分隔。", "Separate multiple recipient addresses with commas."],
  ["停用后该渠道不再发送任何告警通知。", "When disabled, this channel no longer sends alert notifications."],
  ["请输入 Bot Token。", "Enter the bot token."],
  ["请输入至少一个会话 ID。", "Enter at least one chat ID."],
  ["请输入 Webhook 地址。", "Enter the webhook URL."],
  ["请输入设备 Key。", "Enter the device key."],
  ["请输入 SMTP 服务器地址。", "Enter the SMTP server address."],
  ["请输入端口号。", "Enter the port."],
  ["请输入发件地址。", "Enter the sender address."],
  ["请输入至少一个收件地址。", "Enter at least one recipient address."],
  ["请输入有效的 https 地址。", "Enter a valid https URL."],
  ["请输入有效的 http 或 https 地址。", "Enter a valid http or https URL."],
  ["端口需为 1 - 65535。", "Port must be between 1 and 65535."],
  ["至少需要保留一个分组。", "Keep at least one group."],
  ["服务端分组配置已更新，当前未保存修改已保留。", "Server-side group configuration changed. Your unsaved edits were kept."],
  ["分组", "Group"],
  ["标签", "Tag"],
  ["节点归属", "Node ownership"],
  ["分组配置已保存。", "Group configuration saved."],
  ["保存分组失败。", "Failed to save groups."],
  ["新建分组", "New group"],
  ["分组编辑", "Group editor"],
  ["还没有分组", "No groups yet"],
  ["拖动排序", "Drag to sort"],
  ["分组名称", "Group name"],
  ["添加标签", "Add tag"],
  ["删除分组", "Delete group"],
  ["确认删除分组？", "Delete this group?"],
  ["暂无标签", "No tags yet"],
  ["删除标签", "Delete tag"],
  ["探测节点名称不能为空。", "Probe name cannot be empty."],
  ["探测节点名称包含非法字符。", "Probe name contains invalid characters."],
  ["探测节点地址不能为空。", "Probe target cannot be empty."],
  ["探测节点地址格式不正确。", "Probe target format is invalid."],
  ["持续", "Continuous"],
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
  ["探测间隔（秒）", "Probe interval (seconds)"],
  ["留空或填 0 为持续探测。", "Leave blank or enter 0 for continuous probing."],
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
  ["请选择节点后再执行更新", "Select a node before updating"],
  ["当前 Agent 已禁用远程更新", "Remote Agent updates are disabled"],
  ["当前节点还没有上报 Agent 版本", "This node has not reported an Agent version"],
  ["当前 Agent 已是最新版", "Agent is already latest"],

  ["当前 Agent 已是最新版本", "The agent is already up to date"],
  ["已禁用更新", "Updates disabled"],
  ["节点配置有未保存修改，请先保存或使用放弃修改。", "Node configuration has unsaved changes. Save or discard them first."],
  ["当前节点配置有未保存修改，请先保存或取消后再刷新。", "The current node has unsaved changes. Save or cancel before refreshing."],
  ["节点列表已刷新", "Node list refreshed"],

  ["服务端节点配置已更新，请取消后重新打开再保存。", "Server-side node configuration changed. Cancel and reopen before saving."],
  ["保存节点配置失败", "Failed to save node configuration"],
  ["删除节点失败", "Failed to delete node"],
  ["命令已复制", "Command copied"],
  ["复制失败，请手动选择命令后复制", "Copy failed. Select the command manually and copy it."],
  ["当前节点平台暂不支持后台自更新", "This node platform does not support admin-side self-update"],
  ["已完成 Agent 版本检查", "Agent version check completed"],
  ["检查 Agent 更新失败", "Failed to check Agent updates"],

  ["当前 Agent 已经是最新正式版", "Agent is already on the latest stable release"],
  ["下发 Agent 更新失败", "Failed to dispatch Agent update"],
  ["搜索节点", "Search nodes"],
  ["刷新节点", "Refresh nodes"],
  ["Agent 快速接入", "Quick Agent onboarding"],
  ["单击复制完整命令，拖拽可自由选择局部内容", "Click to copy the full command. Drag to select part of it."],
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
  ["远程更新要求 Agent 使用 HTTPS 控制面", "Remote updates require the agent to use an HTTPS control plane"],
  ["节点资料", "Node profile"],
  ["识别信息", "Identity"],
  ["地区代码", "Region code"],
  ["当前主机名", "Current hostname"],

  ["/ 主机名：", "/ Hostname: "],
  ["配置文件不是有效的 JSON", "The configuration file is not valid JSON"],
  ["服务商配置", "Providers"],
  ["编辑服务商", "Edit provider"],
  ["接入参数", "Connection parameters"],
  ["连接验证", "Connection test"],
  ["探测目标", "Probe targets"],
  ["地址", "Address"],
  ["TCP 参数", "TCP parameters"],
  ["ICMP 参数", "ICMP parameters"],
  ["确认登录", "Sign in"],
  ["运维助手配置已保存", "Ops assistant configuration saved"],
  ["尚未获取模型列表", "No model list fetched yet"],
  ["验证失败", "Test failed"],
  ["获取模型列表失败", "Failed to fetch model list"],
  ["端点或模型有未保存修改，请先保存后再测试。", "Endpoint or model has unsaved changes. Save before testing."],
  ["端点或模型有未保存修改，请先保存后再获取模型。", "Endpoint or model has unsaved changes. Save before fetching models."],
  ["资源标注", "Resource labels"],
  ["磁盘类型", "Disk type"],
  ["带宽（Mbps）", "Bandwidth (Mbps)"],
  ["探测下发策略", "Probe dispatch policy"],
  ["请先在“探测设置”页配置探测节点。", "Configure probe nodes on the Probes page first."],
  // O-01：探测目标「下发范围」（探测设置抽屉 / 列表「下发」列 / 节点抽屉标注）。
  ["下发范围", "Deployment scope"],
  ["不下发", "Do not deploy"],
  ["下发", "Delivery"],
  ["来自探测设置", "From probe settings"],
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
  ["接收告警", "Receive alerts"],
  ["开启", "On"],
  ["关闭", "Off"],
  // F4 节点抽屉个性化：适用告警规则列表、「为此节点新增规则」抽屉与流量配额三行。
  ["暂无适用规则", "No applicable rules"],
  ["设置数据未加载，无法查看告警规则。", "Settings not loaded; alert rules are unavailable."],
  ["设置数据未加载，无法新增规则。", "Settings not loaded; cannot add rules."],
  ["已停用", "Disabled"],
  ["为此节点新增规则", "Add a rule for this node"],
  ["适用范围已预设为当前节点。", "The scope is preset to this node."],
  ["保存后可在「告警策略」页调整范围、渠道与启用状态。", "After saving, adjust the scope, channels, and enabled state on the Alert policy page."],
  ["仅当前节点", "This node only"],
  ["当前节点", "Current node"],
  ["保存", "Save"],
  ["规则已新增", "Rule added"],
  ["新增规则失败", "Failed to add the rule"],
  ["配额（GB）", "Quota (GB)"],
  ["配额（GB）需为大于或等于 0 的数字。", "Quota (GB) must be a number greater than or equal to 0."],
  ["不限量", "Unlimited"],
  ["计算方式", "Calculation"],
  ["总量（上传 + 下载）", "Total (upload + download)"],
  ["上下行取较大值", "Larger of upload and download"],
  ["仅上传", "Upload only"],
  ["仅下载", "Download only"],
  ["每月重置日", "Monthly reset day"],
  ["分组与标签", "Groups & tags"],
  ["当前还没有分组树，请先在“分组管理”页维护结构。", "No group tree yet. Maintain it on the Groups page first."],
  ["点击分组或其下方标签即可选择；同一分组下会在分组与标签之间互斥。", "Click a group or its tags to select. Groups and tags under the same group are mutually exclusive."],
  ["删除节点", "Delete node"],
  ["确认删除节点？", "Delete this node?"],

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
  ["搜索名称、ID、主机名、IP", "Search name, ID, hostname, IP"],
  ["例如：123456789:ABC…", "Example: 123456789:ABC..."],
  ["例如：美国、香港、日本…", "Example: United States, Hong Kong, Japan..."],
  ["例如：CN2、BGP、GIA…", "Example: CN2, BGP, GIA..."],
  ["例如：主站 TCP 443…", "Example: main site TCP 443..."],
  ["例如：1.1.1.1 / example.com…", "Example: 1.1.1.1 / example.com..."],
  ["例如：443…", "Example: 443..."],
  ["地区代码无效：请输入两位字母代码（如 SG / JP / HK）。", "Invalid region code: enter a two-letter code (e.g. SG / JP / HK)."],
  ["两位代码，如 SG / JP / HK", "Two-letter code, e.g. SG / JP / HK"],
  ["没有可下发更新的节点", "No nodes available for update"],
  ["命令已内嵌当前配置的 Agent Token，复制后即可直接执行。", "The command embeds the configured Agent token and is ready to run once copied."],
  ["尚未配置 Agent Token：请先在基础设置的接入配置中填写，命令占位符将自动替换为真实 Token。", "No Agent token configured: fill it in under Basic settings first; the command placeholder will be replaced with the real token."],
  ["请先在基础设置的接入配置中填写 Agent 对接地址。", "Fill in the Agent endpoint under Basic settings first."],
  ["在 C&R 视图显示", "Show in C&R view"],
  ["在 ALL 视图显示", "Show in ALL view"],
  ["分组名称与展示页固定标签冲突，请换一个名称。", "Group name conflicts with a fixed monitor page label; choose another name."],
  ["分组名称不能包含“:”或“/”。", "Group names cannot contain \":\" or \"/\"."],
  ["分组条目无效：请检查空白、重名或保留名（如“全部”）。", "Invalid group entry: check for blank values, duplicates, or reserved names (such as \"All\")"],
  ["要求成对配置", "Must be configured as a pair"],
  ["保留", "Keep"],
  ["双空=停用", "Both empty = disabled"],
  ["已配置（留空保持不变）", "Configured (leave blank to keep)"],
  ["尚未配置任何通知渠道：所有告警都不会发出。请先在渠道设置中添加并启用通知渠道。", "No notification channels configured: no alerts will be sent at all. Add and enable a channel under Channels first."],
  ["尚未配置任何通知渠道：", "No notification channels configured: "],
  // A-08：横幅文案从「节点离线时」改为「所有告警」；规则「渠道」列新增两态文字。
  ["所有告警都不会发出。请先在渠道设置中添加并启用通知渠道。", "No alerts will be sent at all. Add and enable a channel under Channels first."],
  ["全部渠道", "All channels"],
  ["无可用渠道", "No channels available"],
  ["清除", "Clear"],
  // 节点抽屉「到期时间」「告警设置」两卡文案（第 6 轮 M-04 / M-05）。
  ["截止时间", "Deadline"],
  ["告警设置", "Alert settings"],
  ["此节点暂无专属规则", "No rules exclusive to this node"],
  ["续费周期", "Renewal cycle"],
  ["不续费", "No renewal"],
  ["每月", "Monthly"],
  ["每季", "Quarterly"],
  ["每半年", "Every 6 months"],
  ["每年", "Yearly"],
  ["关闭后此节点不再触发任何告警", "When off, this node no longer triggers any alerts"],
  ["删除规则", "Delete rule"],
  ["告警规则已保存，节点设置保存失败", "Alert rules saved, but saving node settings failed"],
  // A-02：流量配额一行三列。
  ["配额", "Quota"],
  ["单位", "Unit"],
  ["重置日", "Reset day"],
  ["上下行合计", "Upload + download"],
  ["取较大值", "Higher of the two"],
  ["仅上行", "Upload only"],
  ["仅下行", "Download only"],
  ["已配置的 Agent Token 不能清空；如需更换请输入新值。", "A configured Agent token cannot be emptied; enter a new value to replace it."],
  ["已配置（输入新值可更换）", "Configured (enter a new value to replace)"],
  ["当前 Token 已回显，可选中复制；输入新值并保存即完成更换，更换后新接入 Agent 需使用新 Token。", "The current token is shown and can be copied; enter a new value and save to replace it. New agents must use the new token afterward."],
  ["国家地区分组导航", "Country/region group navigation"],
  ["展示页按节点地区代码（C&R）二级分组。", "Group the monitor page by node region code (C&R) as a second level."],
  ["端点或模型有未保存修改，请先保存后再测试。", "Unsaved changes to endpoint or model. Save before testing."],
  ["端点或模型有未保存修改，请先保存后再获取模型。", "Unsaved changes to endpoint or model. Save before fetching models."],
  ["获取模型列表", "Fetch model list"],
  ["测试连接", "Test connection"],
  ["已放弃本地修改，已重置为服务端当前配置。", "Local changes discarded; reset to the current server configuration."],
  ["该条目已被服务端更新重置，请关闭抽屉后重新编辑。", "This entry was reset by a server update; close the drawer and edit it again."],
  ["已移除", "Removed"],
  ["该条目已被服务端更新重置。", "This entry was reset by a server update."],
  ["服务端探测配置已更新，请放弃本地修改后重试，以免覆盖他人改动。", "Probe settings were updated on the server; discard local changes and retry to avoid overwriting others."],
  ["服务端配置已更新，保存已被阻止", "Server configuration changed; saving was blocked"],
  ["放弃本地修改", "Discard local changes"],

  ["时间", "Time"],
  ["来源", "Source"],
  ["等级", "Level"],
  ["消息", "Message"],
  ["日志", "Logs"],
  ["等级统计", "Level statistics"],
  ["完整消息", "Full message"],
  ["仅展示最近", "Showing the most recent"],
  ["条日志；计数为当前过滤窗口内的分布。", "logs; counts reflect the current filter window."],
  ["分组列表", "Group list"],
  ["分组信息", "Group details"],
  ["标签信息", "Tag details"],
  ["未命名分组", "Unnamed group"],
  ["未命名标签", "Unnamed tag"],
  ["拖拽排序", "Drag to sort"],
  ["上级分组", "Parent group"],
  ["—（顶级）", "— (top level)"],
  ["标签数", "Tags"],
  ["节点数", "Nodes"],
  ["排序", "Order"],
  ["上移", "Move up"],
  ["下移", "Move down"],
  ["还没有分组，点击右上角「新建分组」开始。", "No groups yet. Click \"New group\" at the top right to start."],
  ["飞书", "Feishu"],
  ["前往 →", "Open →"],
  ["助手设置", "Assistant settings"],
  ["指令服务商", "Command provider"],
  ["运维提示词", "Operations prompt"],
  ["服务商", "Providers"],
  ["还没有服务商。", "No providers yet."],
  ["未设置 Base URL", "No Base URL set"],
  ["端点", "Endpoint"],
  ["服务商列表", "Provider list"],
  ["基础信息", "Basic information"],
  ["完成", "Done"],
  ["验证与获取模型使用当前抽屉内的端点与密钥；端点改动需先完成并保存后再验证存储密钥。", "Testing and fetching models use the endpoint and key currently in this drawer. Save endpoint changes before testing a stored key."],
  ["目标列表", "Target list"],
  ["暂无探测节点，点击右上角「新增探测节点」开始。", "No probes yet. Click \"Add probe\" at the top right to start."],
  ["配置探测目标的基础信息与协议参数。", "Configure the probe target's basic information and protocol parameters."],
  ["允许的用户名", "Allowed usernames"],
  ["分区导航", "Section navigation"],
  ["启用", "Enabled"],
  ["重置后留空 = 保留当前 Secret，不会清空。", "Leave blank after a reset to keep the current secret; it is never cleared."],
  ["显示与标注", "Display & labels"],
  ["全部更新", "Update all"],
  ["确认对全部", "Dispatch Agent updates to all"],
  ["台节点下发 Agent 更新？", "nodes?"],
  ["确认下发", "Confirm dispatch"],
  ["秒", "sec"],
  ["点击复制完整接入命令，也可拖选部分文本手动复制", "Click to copy the full onboarding command, or drag to select part of the text"],
  // F7 首页（KPI、网络连通性、主控状态、资源热点）与 F3「运行信息」卡文案。
  ["实时", "Live"],
  ["在线率", "Online rate"],
  ["离线率", "Offline rate"],
  ["探测可用率", "Probe availability"],
  ["主控负载", "Server load"],
  ["网络连通性", "Network connectivity"],
  ["主控状态", "Server status"],
  ["资源热点", "Resource hotspots"],
  ["资源使用正常", "Resource usage is normal"],
  ["CPU、内存、磁盘使用率 ≥ 80% 的节点会显示在这里", "Nodes with CPU, memory or disk usage ≥ 80% appear here"],
  // A-10：第二张 KPI 卡改为「告警中」（原「离线率」删除）；「涉及 N 台节点」
  // 为动态模板（见下方 pattern 表）。
  ["告警中", "Alerting"],
  ["一切正常", "All clear"],
  ["暂无探测数据", "No probe data"],
  ["可用率", "Availability"],
  ["平均延迟", "Avg latency"],
  ["丢包", "Loss"],
  ["运行时长", "Uptime"],
  ["数据目录占用", "Data directory usage"],
  ["WS 连接（后台 / 前台）", "WS connections (admin / public)"],
  ["1 小时", "1 hour"],
  ["24 小时", "24 hours"],
  ["时间范围", "Time range"],
  ["运行信息", "Runtime info"],
  ["提交", "Commit"],
  ["Go 版本", "Go version"],
  ["启动时间", "Started at"],
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
    zh: /^编辑服务商\s+(.+)$/,
    toEn: (match) => `Edit provider ${match[1]}`,
    en: /^Edit provider\s+(.+)$/,
    toZh: (match) => `编辑服务商 ${match[1]}`,
  },
  {
    zh: /^(.+?)\s+验证成功$/,
    toEn: (match) => `${match[1]} verified successfully`,
    en: /^(.+?)\s+verified successfully$/,
    toZh: (match) => `${match[1]} 验证成功`,
  },
  {
    zh: /^(.+?)\s+模型列表已刷新$/,
    toEn: (match) => `Model list refreshed for ${match[1]}`,
    en: /^Model list refreshed for\s+(.+)$/,
    toZh: (match) => `${match[1]} 模型列表已刷新`,
  },
  {
    zh: /^已缓存\s+(\d+)\s+个模型候选$/,
    toEn: (match) => `${match[1]} model candidates cached`,
    en: /^(\d+)\s+model candidates cached$/,
    toZh: (match) => `已缓存 ${match[1]} 个模型候选`,
  },
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
    zh: /^尝试次数过多，请在\s+(\d+)\s+秒后重试$/,
    toEn: (match) => `Too many attempts. Retry in ${match[1]} sec.`,
    en: /^Too many attempts\. Retry in\s+(\d+)\s+sec\.$/,
    toZh: (match) => `尝试次数过多，请在 ${match[1]} 秒后重试`,
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
    zh: /^发现新版本\s+(.+)$/,
    toEn: (match) => `New version ${match[1]} available`,
    en: /^New version\s+(.+?)\s+available$/,
    toZh: (match) => `发现新版本 ${match[1]}`,
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
    zh: /^留空或填 0 为每\s+(\d+)\s+秒。$/,
    toEn: (match) => `Leave blank or enter 0 for every ${match[1]} seconds.`,
    en: /^Leave blank or enter 0 for every\s+(\d+)\s+seconds\.$/,
    toZh: (match) => `留空或填 0 为每 ${match[1]} 秒。`,
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
    // O-01：探测设置「下发」列的「N 个分组」。
    zh: /^(\d+)\s+个分组$/,
    toEn: (match) => `${match[1]} groups`,
    en: /^(\d+)\s+groups$/,
    toZh: (match) => `${match[1]} 个分组`,
  },
  {
    zh: /^(\d+)\s+个标签$/,
    toEn: (match) => `${match[1]} tags`,
    en: /^(\d+)\s+tags$/,
    toZh: (match) => `${match[1]} 个标签`,
  },
  {
    zh: /^(\d+)\s+个标签 · (\d+)\s+个节点$/,
    toEn: (match) => `${match[1]} tags · ${match[2]} nodes`,
    en: /^(\d+)\s+tags · (\d+)\s+nodes$/,
    toZh: (match) => `${match[1]} 个标签 · ${match[2]} 个节点`,
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
  // F4 告警规则：列表「条件 / 范围 / 状态」列、抽屉多选摘要与模拟评估值的动态文案。
  // 具体的「分组：X 等 N 项」须排在通用「X 等 N 项」之前。
  {
    zh: /^告警中\s+(\d+)\s+台$/,
    toEn: (match) => `${match[1]} alerting`,
    en: /^(\d+)\s+alerting$/,
    toZh: (match) => `告警中 ${match[1]} 台`,
  },
  {
    zh: /^离线判定\s+(\d+)\s+分钟$/,
    toEn: (match) => `Offline after ${match[1]} min`,
    en: /^Offline after\s+(\d+)\s+min$/,
    toZh: (match) => `离线判定 ${match[1]} 分钟`,
  },
  {
    zh: /^提前\s+([0-9][0-9\s·]*?)\s*天提醒$/,
    toEn: (match) => `Remind ${match[1]} days ahead`,
    en: /^Remind\s+([0-9][0-9\s·]*?)\s+days ahead$/,
    toZh: (match) => `提前 ${match[1]} 天提醒`,
  },
  {
    zh: /^流量配额\s+≥\s+([0-9.]+)%$/,
    toEn: (match) => `Traffic quota ≥ ${match[1]}%`,
    en: /^Traffic quota\s+≥\s+([0-9.]+)%$/,
    toZh: (match) => `流量配额 ≥ ${match[1]}%`,
  },
  {
    zh: /^(.+?)\s+(>|<)\s+([0-9.]+)\s*(%|℃|ms|个|Mbps)?\s*·\s*持续\s+(\d+)\s+分钟$/,
    toEn: (match) =>
      `${translateSegment(match[1], "en-US")} ${match[2]} ${match[3]}${translateRuleUnit(match[4])} · for ${match[5]} min`,
    en: /^(.+?)\s+(>|<)\s+([0-9.]+)\s*(%|°C|ms|Mbps)?\s*·\s*for\s+(\d+)\s+min$/,
    toZh: (match) =>
      `${translateSegment(match[1], "zh-CN")} ${match[2]} ${match[3]}${translateRuleUnitToZh(match[4])} · 持续 ${match[5]} 分钟`,
  },
  {
    zh: /^(.+?)\s+(>|<)\s+([0-9.]+)\s*(%|℃|ms|个|Mbps)?$/,
    toEn: (match) =>
      `${translateSegment(match[1], "en-US")} ${match[2]} ${match[3]}${translateRuleUnit(match[4])}`,
    en: /^(.+?)\s+(>|<)\s+([0-9.]+)(%|°C|ms|Mbps)?$/,
    toZh: (match) =>
      `${translateSegment(match[1], "zh-CN")} ${match[2]} ${match[3]}${translateRuleUnitToZh(match[4])}`,
  },
  {
    zh: /^全部节点\s+·\s+排除\s+(\d+)\s+台$/,
    toEn: (match) => `All nodes · ${match[1]} excluded`,
    en: /^All nodes\s+·\s+(\d+)\s+excluded$/,
    toZh: (match) => `全部节点 · 排除 ${match[1]} 台`,
  },
  {
    zh: /^(\d+)\s+个节点\s+·\s+分组：(.+)$/,
    toEn: (match) => `${match[1]} nodes · Group: ${translateNameSegment(match[2], "en-US")}`,
    en: /^(\d+)\s+nodes\s+·\s+Group:\s+(.+)$/,
    toZh: (match) => `${match[1]} 个节点 · 分组：${translateNameSegment(match[2], "zh-CN")}`,
  },
  {
    zh: /^分组：(.+?)\s+等\s+(\d+)\s+项$/,
    toEn: (match) => `Group: ${translateNameSegment(match[1], "en-US")} +${match[2]}`,
    en: /^Group:\s+(.+?)\s+\+(\d+)$/,
    toZh: (match) => `分组：${translateNameSegment(match[1], "zh-CN")} 等 ${match[2]} 项`,
  },
  {
    zh: /^分组：(.+)$/,
    toEn: (match) => `Group: ${translateNameSegment(match[1], "en-US")}`,
    en: /^Group:\s+(.+)$/,
    toZh: (match) => `分组：${translateNameSegment(match[1], "zh-CN")}`,
  },
  {
    zh: /^已选\s+(\d+)\s+个节点$/,
    toEn: (match) => `${match[1]} nodes selected`,
    en: /^(\d+)\s+nodes selected$/,
    toZh: (match) => `已选 ${match[1]} 个节点`,
  },
  {
    zh: /^已选\s+(\d+)\s+项$/,
    toEn: (match) => `${match[1]} selected`,
    en: /^(\d+)\s+selected$/,
    toZh: (match) => `已选 ${match[1]} 项`,
  },
  {
    zh: /^(\d+)\s+分钟$/,
    toEn: (match) => `${match[1]} min`,
    en: /^(\d+)\s+min$/,
    toZh: (match) => `${match[1]} 分钟`,
  },
  {
    zh: /^(\d+)\s+个$/,
    toEn: (match) => `${match[1]} count`,
    en: /^(\d+)\s+count$/,
    toZh: (match) => `${match[1]} 个`,
  },
  {
    zh: /^(\d+)\s+天$/,
    toEn: (match) => `${match[1]} days`,
    en: /^(\d+)\s+days$/,
    toZh: (match) => `${match[1]} 天`,
  },
  {
    zh: /^(.+?)\s+等\s+(\d+)\s+项$/,
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
    zh: /^探测间隔需为 0 - (\d+) 秒。$/,
    toEn: (match) => `Probe interval must be 0 - ${match[1]} seconds.`,
    en: /^Probe interval must be 0 - (\d+) seconds\.$/,
    toZh: (match) => `探测间隔需为 0 - ${match[1]} 秒。`,
  },
  {
    zh: /^兼容服务商\s+(\d+)$/,
    toEn: (match) => `Compatible provider ${match[1]}`,
    en: /^Compatible provider\s+(\d+)$/,
    toZh: (match) => `兼容服务商 ${match[1]}`,
  },
  {
    zh: /^服务商类型：(.+)$/,
    toEn: (match) => `Provider type: ${translateSegment(match[1], "en-US")}`,
    en: /^Provider type:\s*(.+)$/,
    toZh: (match) => `服务商类型：${translateSegment(match[1], "zh-CN")}`,
  },
  {
    // §6 术语表：分组排序副标题统一为新术语「分组 · 第 N 位 / 共 M 个」。
    zh: /^分组 · 第\s+(\d+)\s+位 \/ 共\s+(\d+)\s+个$/,
    toEn: (match) => `Group · position ${match[1]} of ${match[2]}`,
    en: /^Group · position (\d+) of (\d+)$/,
    toZh: (match) => `分组 · 第 ${match[1]} 位 / 共 ${match[2]} 个`,
  },
  {
    zh: /^标签 · 所属分组\s+(.+)$/,
    toEn: (match) => `Tag · group ${translateNameSegment(match[1], "en-US")}`,
    en: /^Tag · group\s+(.+)$/,
    toZh: (match) => `标签 · 所属分组 ${translateNameSegment(match[1], "zh-CN")}`,
  },
  {
    zh: /^第\s+(\d+)\s+\/\s+(\d+)\s+位$/,
    toEn: (match) => `Position ${match[1]} of ${match[2]}`,
    en: /^Position (\d+) of (\d+)$/,
    toZh: (match) => `第 ${match[1]} / ${match[2]} 位`,
  },
  {
    zh: /^第\s+(\d+)\s+个分组$/,
    toEn: (match) => `group ${match[1]}`,
    en: /^group (\d+)$/,
    toZh: (match) => `第 ${match[1]} 个分组`,
  },
  {
    zh: /^第\s+(\d+)\s+个分组\s+名称不能为空。$/,
    toEn: (match) => `Group ${match[1]}: name cannot be empty.`,
    en: /^Group (\d+): name cannot be empty\.$/,
    toZh: (match) => `第 ${match[1]} 个分组 名称不能为空。`,
  },
  {
    zh: /^分组“(.+)”重复，请保留唯一名称。$/,
    toEn: (match) => `Group "${match[1]}" is duplicated; keep names unique.`,
    en: /^Group "(.+)" is duplicated; keep names unique\.$/,
    toZh: (match) => `分组“${match[1]}”重复，请保留唯一名称。`,
  },
  {
    zh: /^(.+?)\s+下第\s+(\d+)\s+个标签名称不能为空。$/,
    toEn: (match) =>
      `Tag ${match[2]} under ${translateNameSegment(match[1], "en-US")}: name cannot be empty.`,
    en: /^Tag\s+(\d+)\s+under\s+(.+?): name cannot be empty\.$/,
    toZh: (match) =>
      `${translateNameSegment(match[2], "zh-CN")} 下第 ${match[1]} 个标签名称不能为空。`,
  },
  {
    zh: /^(.+?)\s+下的标签与展示页固定标签冲突，请换一个名称。$/,
    toEn: (match) =>
      `Tags under ${translateNameSegment(match[1], "en-US")} conflict with a fixed monitor page label; choose another name.`,
    en: /^Tags under (.*?) conflict with a fixed monitor page label; choose another name\.$/,
    toZh: (match) =>
      `${translateNameSegment(match[1], "zh-CN")} 下的标签与展示页固定标签冲突，请换一个名称。`,
  },
  {
    zh: /^(.+?)\s+下标签“(.+)”重复，请保留唯一名称。$/,
    toEn: (match) =>
      `Tag "${match[2]}" under ${translateNameSegment(match[1], "en-US")} is duplicated; keep names unique.`,
    en: /^Tag "(.*)" under (.*?) is duplicated; keep names unique\.$/,
    toZh: (match) =>
      `${translateNameSegment(match[2], "zh-CN")} 下标签“${match[1]}”重复，请保留唯一名称。`,
  },
  {
    zh: /^单个节点最多选择\s+(\d+)\s+个探测项。$/,
    toEn: (match) => `A node can select at most ${match[1]} probes.`,
    en: /^A node can select at most (\d+) probes\.$/,
    toZh: (match) => `单个节点最多选择 ${match[1]} 个探测项。`,
  },
  {
    zh: /^已下发\s+(\d+)$/,
    toEn: (match) => `Dispatched ${match[1]}`,
    en: /^Dispatched (\d+)$/,
    toZh: (match) => `已下发 ${match[1]}`,
  },
  {
    zh: /^已是最新\s+(\d+)$/,
    toEn: (match) => `Up to date ${match[1]}`,
    en: /^Up to date (\d+)$/,
    toZh: (match) => `已是最新 ${match[1]}`,
  },
  {
    zh: /^失败\s+(\d+)$/,
    toEn: (match) => `Failed ${match[1]}`,
    en: /^Failed (\d+)$/,
    toZh: (match) => `失败 ${match[1]}`,
  },
  {
    zh: /^批量更新完成：(.+)$/,
    toEn: (match) =>
      `Bulk update completed: ${match[1]
        .split("，")
        .map((part) => translateSegment(part.trim(), "en-US"))
        .join(", ")}`,
    en: /^Bulk update completed: (.+)$/,
    toZh: (match) =>
      `批量更新完成：${match[1]
        .split(", ")
        .map((part) => translateSegment(part.trim(), "zh-CN"))
        .join("，")}`,
  },
  {
    zh: /^例如：(\d+)…$/,
    toEn: (match) => `Example: ${match[1]}...`,
    en: /^Example: (\d+)\.\.\.$/,
    toZh: (match) => `例如：${match[1]}…`,
  },
  {
    zh: /^(.+)\s+名称不能为空。$/,
    toEn: (match) => `${match[1]} name cannot be empty.`,
    en: /^(.+)\s+name cannot be empty\.$/,
    toZh: (match) => `${match[1]} 名称不能为空。`,
  },
  // F5 渠道测试结果与列表行摘要（动态数字）。
  {
    zh: /^已送达 · (\d+) ms$/,
    toEn: (match) => `Delivered in ${match[1]} ms`,
    en: /^Delivered in (\d+) ms$/,
    toZh: (match) => `已送达 · ${match[1]} ms`,
  },
  {
    zh: /^(\d+) 个会话$/,
    toEn: (match) => `${match[1]} chats`,
    en: /^(\d+) chats$/,
    toZh: (match) => `${match[1]} 个会话`,
  },
  {
    zh: /^@ (\d+) 个手机号$/,
    toEn: (match) => `@ ${match[1]} phone numbers`,
    en: /^@ (\d+) phone numbers$/,
    toZh: (match) => `@ ${match[1]} 个手机号`,
  },
  // F7 首页动态文案：KPI 副标题、运行时长与「内存 · 运行」组合（时长内部再走
  // 下方的天/小时模板逐段翻译）。
  {
    zh: /^(\d+) \/ (\d+) 在线$/,
    toEn: (match) => `${match[1]} / ${match[2]} online`,
    en: /^(\d+) \/ (\d+) online$/,
    toZh: (match) => `${match[1]} / ${match[2]} 在线`,
  },
  {
    zh: /^(\d+) 台离线$/,
    toEn: (match) => `${match[1]} offline`,
    en: /^(\d+) offline$/,
    toZh: (match) => `${match[1]} 台离线`,
  },
  {
    zh: /^平均延迟 ([\d.]+) ms$/,
    toEn: (match) => `Avg latency ${match[1]} ms`,
    en: /^Avg latency ([\d.]+) ms$/,
    toZh: (match) => `平均延迟 ${match[1]} ms`,
  },
  {
    zh: /^内存 (.+) · 运行 (.+)$/,
    toEn: (match) => `Memory ${match[1]} · up ${translateSegment(match[2], "en-US")}`,
    en: /^Memory (.+) · up (.+)$/,
    toZh: (match) => `内存 ${translateSegment(match[1], "zh-CN")} · 运行 ${translateSegment(match[2], "zh-CN")}`,
  },
  {
    zh: /^(\d+) 天 (\d+) 小时$/,
    toEn: (match) => `${match[1]}d ${match[2]}h`,
    en: /^(\d+)d (\d+)h$/,
    toZh: (match) => `${match[1]} 天 ${match[2]} 小时`,
  },
  {
    zh: /^(\d+) 小时 (\d+) 分钟$/,
    toEn: (match) => `${match[1]}h ${match[2]}m`,
    en: /^(\d+)h (\d+)m$/,
    toZh: (match) => `${match[1]} 小时 ${match[2]} 分钟`,
  },
  // A-01 步骤 3：节点抽屉「仅此节点」规则删除确认与保存合并提示（动态规则名）。
  {
    zh: /^删除规则『(.+?)』？此规则只作用于本节点，删除后不可恢复。$/,
    toEn: (match) => `Delete rule "${translateNameSegment(match[1], "en-US")}"? It only applies to this node and cannot be restored once deleted.`,
    en: /^Delete rule "(.+?)"\? It only applies to this node and cannot be restored once deleted\.$/,
    toZh: (match) => `删除规则『${translateNameSegment(match[1], "zh-CN")}』？此规则只作用于本节点，删除后不可恢复。`,
  },
  {
    zh: /^规则『(.+?)』已在别处删除，未保存对它的修改$/,
    toEn: (match) => `Rule "${translateNameSegment(match[1], "en-US")}" was deleted elsewhere; your changes to it were not saved`,
    en: /^Rule "(.+?)" was deleted elsewhere; your changes to it were not saved$/,
    toZh: (match) => `规则『${translateNameSegment(match[1], "zh-CN")}』已在别处删除，未保存对它的修改`,
  },
  // A-02：流量配额下拉与已用量行（动态数字 / 日期）。
  {
    zh: /^每月 (\d+) 日$/,
    toEn: (match) => `Day ${match[1]} monthly`,
    en: /^Day (\d+) monthly$/,
    toZh: (match) => `每月 ${match[1]} 日`,
  },
  // A-10：首页「告警中」KPI 卡副标题（动态节点数）。
  {
    zh: /^涉及 (\d+) 台节点$/,
    toEn: (match) => `Across ${match[1]} node${Number(match[1]) === 1 ? "" : "s"}`,
    en: /^Across (\d+) nodes?$/,
    toZh: (match) => `涉及 ${match[1]} 台节点`,
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
    // localStorage 不可用（隐私模式等）时放弃持久化，语言仅存于内存。
  }
}

export function adminText(locale: AdminLocale, zhText: string) {
  return locale === "en-US" ? zhToEn.get(zhText) || zhText : zhText;
}

export function adminBrowserTitleForLocale(locale: AdminLocale, siteTitle: string) {
  const normalizedTitle = siteTitle.trim() || "CyberMonitor";
  return `${normalizedTitle} ${adminText(locale, "管理后台")}`;
}

function translateSegment(segment: string, locale: AdminLocale) {
  const exact = (locale === "en-US" ? zhToEn : enToZh).get(segment);
  if (exact) {
    return exact;
  }
  for (const pattern of ADMIN_TEXT_PATTERNS) {
    const match = segment.match(locale === "en-US" ? pattern.zh : pattern.en);
    if (match) {
      return locale === "en-US" ? pattern.toEn(match) : pattern.toZh(match);
    }
  }
  return segment;
}

// F4 规则条件单位：℃ → °C，「个」在英文中省略；% / ms / Mbps 保持原样。
function translateRuleUnit(unit: string | undefined) {
  switch (unit) {
    case "℃":
      return "°C";
    case "个":
      return "";
    default:
      return unit || "";
  }
}

function translateRuleUnitToZh(unit: string | undefined) {
  switch (unit) {
    case "°C":
      return "℃";
    default:
      return unit || "";
  }
}

// 分组/标签名等用户自定义名称不参与翻译；仅组件内置兑底文案（未命名分组/标签、第 N 个分组）允许翻译。
const ADMIN_NAME_FALLBACK_PATTERNS = [/^未命名分组$/, /^未命名标签$/, /^第\s+\d+\s+个分组$/];

function translateNameSegment(segment: string, locale: AdminLocale) {
  return ADMIN_NAME_FALLBACK_PATTERNS.some((pattern) => pattern.test(segment))
    ? translateSegment(segment, locale)
    : segment;
}

function translateExact(value: string, locale: AdminLocale) {
  const trimmed = value.trim();
  if (!trimmed) {
    return value;
  }
  const translated = translateSegment(trimmed, locale);
  if (translated !== trimmed) {
    return value.replace(trimmed, translated);
  }
  // 复合 toast 用「；」拼接多个独立句子：逐段翻译后重组。
  const listSeparator = locale === "en-US" ? "；" : "; ";
  if (trimmed.includes(listSeparator)) {
    const translatedList = trimmed
      .split(listSeparator)
      .map((segment) => translateSegment(segment.trim(), locale))
      .join(locale === "en-US" ? "; " : "；");
    if (translatedList !== trimmed) {
      return value.replace(trimmed, translatedList);
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

    element.closest("[data-admin-i18n-skip]") != null
  );
}

function shouldSkipTextNodeElement(element: HTMLElement | null): boolean {
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
      return shouldSkipTextNodeElement(node.parentElement)
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
