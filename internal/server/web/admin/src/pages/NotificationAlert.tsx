import { useEffect, useMemo, useState, type ChangeEvent, type ComponentType, type ReactNode } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import {
  AdminGroupedCard,
  AdminGroupedFieldRow,
  AdminGroupedSwitchRow,
  AdminSectionPanel,
  adminGroupedCardRowClass,
} from "@/components/admin-section-panel";
import { AdminDataTable, adminStatusBadgeClass } from "@/components/admin-data-table";
import { AdminSaveBar } from "@/components/admin-save-bar";
import { AdminDrawer } from "@/components/admin-drawer";
import { AdminEmptyState } from "@/components/admin-empty-state";
import { AlertRuleDrawer } from "@/components/alert-rule-drawer";
import {
  BarkIcon,
  DingtalkIcon,
  FeishuIcon,
  TelegramIcon,
  WecomIcon,
  type BrandIconProps,
} from "@/components/brand-icons";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Bell,
  BellRing,
  ChevronRight,
  Hash,
  Mail,
  Plus,
  Send,
  Trash2,
} from "lucide-react";
import {
  draftSignature,
  useAsyncAction,
  useDirtyNotification,
  useDraftReconcile,
} from "@/lib/admin-hooks";
import { testNotifyChannelDraft } from "@/lib/admin-api";
import { cn } from "@/lib/utils";
import {
  adminCompactActionButtonClass,
  adminDangerBadgeClass,
  adminDangerOutlineButtonClass,
  adminDrawerSectionTitleClass,
  adminFieldErrorClass,
  adminInputClass,
  adminNeutralBadgeClass,
  adminNarrowPageShellClass,
  adminOutlineButtonClass,
  adminPrimaryButtonClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
  adminSubtleOutlineBadgeClass,
  adminSuccessBadgeClass,
  adminTextButtonClass,
} from "@/lib/admin-ui";
import { adminPageSections, resolveAdminSection } from "@/lib/admin-sections";
import type {
  AlertTestPayload,
  ChannelTestResult,
  NodeView,
  NotifyChannel,
  SettingsUpdate,
  SettingsView,
} from "@/lib/admin-types";
import {
  OFFLINE_ALERT_RULE_ID,
  buildRulePayload,
  copyRuleDraft,
  generateRuleID,
  makeRuleDrafts,
  ruleConditionText,
  ruleScopeText,
  validateRuleDraft,
  type AlertRuleDraft,
} from "@/lib/alert-rules";

// =====================================================================
// F5「渠道设置」分区：多渠道模型（7 种类型）的列表、抽屉与草稿测试。
// 原「Telegram 告警」「飞书告警」两分区（webhook / telegramToken 等平铺字段）已
// 由渠道列表取代；旧字段由后端在加载时迁移为 id "feishu" / "telegram" 的渠道，
// 保存 notify_channels 后旧字段由服务端双向同步（红线：旧数据必须能加载）。
// =====================================================================

// F5 定稿的 7 种渠道类型。
export type NotifyChannelType =
  | "telegram"
  | "feishu"
  | "bark"
  | "slack"
  | "dingtalk"
  | "wecom"
  | "email";

// 校验错误文案（doc 指定）。
const INVALID_HTTPS_URL_ERROR = "请输入有效的 https 地址。";
const INVALID_HTTP_URL_ERROR = "请输入有效的 http 或 https 地址。";
const EMAIL_PORT_RANGE_ERROR = "端口需为 1 - 65535。";

// 渠道抽屉中单个字段的渲染与校验规格（字段 key 与后端 Config/Secrets map 对应）。
interface ChannelFieldSpec {
  key: string;
  label: string;
  // 必填：草稿值为空且（敏感字段）服务端也未配置过时，字段下方报错。
  required?: boolean;
  requiredError?: string;
  // 敏感字段：保存后 View 中不可见（secrets_set 标记已配置），输入框留空保持不变。
  secret?: boolean;
  placeholder?: string;
  hint?: string;
  // URL 字段：非空时校验协议。
  url?: "https" | "http";
  // 数值字段范围（端口）。
  numericRange?: { min: number; max: number };
  options?: Array<{ value: string; label: string }>;
  // Select 草稿值为空时的展示与保存回落值（与后端 Notifier 的缺省一致）。
  defaultOption?: string;
  switch?: boolean;
}

interface ChannelGroupSpec {
  title: string;
  fields: ChannelFieldSpec[];
}

interface ChannelTypeSpec {
  groups: ChannelGroupSpec[];
  // 新建渠道时的 Config 默认值（与后端各 Notifier 的缺省一致）。
  defaults?: Record<string, string>;
}

// 7 种渠道的字段规格（evolution_log.md F5 字段表；* 为必填，🔒 为敏感字段）。
const CHANNEL_TYPE_SPECS: Record<NotifyChannelType, ChannelTypeSpec> = {
  telegram: {
    groups: [
      {
        title: "凭据",
        fields: [
          {
            key: "bot_token",
            label: "Bot Token",
            required: true,
            secret: true,
            requiredError: "请输入 Bot Token。",
            placeholder: "例如：123456789:ABC…",
          },
          {
            key: "api_endpoint",
            label: "API 地址",
            url: "http",
            placeholder: "https://api.telegram.org",
            hint: "留空使用 https://api.telegram.org。",
          },
        ],
      },
      {
        title: "会话",
        fields: [
          {
            key: "chat_ids",
            label: "会话 ID",
            required: true,
            requiredError: "请输入至少一个会话 ID。",
            hint: "多个会话 ID 请使用逗号分隔。",
          },
          {
            key: "message_thread_id",
            label: "话题 ID",
            hint: "留空发送到主会话。",
          },
        ],
      },
    ],
  },
  feishu: {
    groups: [
      {
        title: "飞书",
        fields: [
          {
            key: "webhook",
            label: "Webhook 地址",
            required: true,
            secret: true,
            url: "https",
            requiredError: "请输入 Webhook 地址。",
            placeholder: "https://open.feishu.cn/open-apis/bot/v2/hook/…",
          },
          { key: "sign_secret", label: "签名密钥", secret: true },
        ],
      },
    ],
  },
  bark: {
    groups: [
      {
        title: "Bark",
        fields: [
          {
            key: "server_url",
            label: "服务器地址",
            url: "http",
            placeholder: "https://api.day.app",
            hint: "留空使用 https://api.day.app。",
          },
          {
            key: "device_key",
            label: "设备 Key",
            required: true,
            secret: true,
            requiredError: "请输入设备 Key。",
          },
          { key: "group", label: "分组", placeholder: "CyberMonitor" },
          {
            key: "level",
            label: "通知级别",
            defaultOption: "timeSensitive",
            options: [
              { value: "active", label: "active" },
              { value: "timeSensitive", label: "timeSensitive" },
              { value: "passive", label: "passive" },
              { value: "critical", label: "critical" },
            ],
          },
          { key: "sound", label: "声音" },
          { key: "icon", label: "图标", url: "http", placeholder: "https://…" },
        ],
      },
    ],
    defaults: { level: "timeSensitive" },
  },
  slack: {
    groups: [
      {
        title: "Slack",
        fields: [
          {
            key: "webhook",
            label: "Webhook 地址",
            required: true,
            secret: true,
            url: "https",
            requiredError: "请输入 Webhook 地址。",
            placeholder: "https://hooks.slack.com/services/…",
          },
        ],
      },
    ],
  },
  dingtalk: {
    groups: [
      {
        title: "钉钉",
        fields: [
          {
            key: "webhook",
            label: "Webhook 地址",
            required: true,
            secret: true,
            url: "https",
            requiredError: "请输入 Webhook 地址。",
            placeholder: "https://oapi.dingtalk.com/robot/send?access_token=…",
          },
          { key: "sign_secret", label: "签名密钥", secret: true },
          {
            key: "at_mobiles",
            label: "@手机号",
            hint: "多个手机号请使用逗号分隔。",
          },
          { key: "at_all", label: "@所有人", switch: true },
        ],
      },
    ],
  },
  wecom: {
    groups: [
      {
        title: "企业微信",
        fields: [
          {
            key: "webhook",
            label: "Webhook 地址",
            required: true,
            secret: true,
            url: "https",
            requiredError: "请输入 Webhook 地址。",
            placeholder: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=…",
          },
          {
            key: "mentioned_mobiles",
            label: "@手机号",
            hint: "多个手机号请使用逗号分隔。",
          },
        ],
      },
    ],
  },
  email: {
    groups: [
      {
        title: "服务器",
        fields: [
          {
            key: "host",
            label: "SMTP 服务器",
            required: true,
            requiredError: "请输入 SMTP 服务器地址。",
            placeholder: "smtp.example.com",
          },
          {
            key: "port",
            label: "端口",
            required: true,
            requiredError: "请输入端口号。",
            numericRange: { min: 1, max: 65535 },
            placeholder: "587",
          },
          {
            key: "security",
            label: "连接安全",
            defaultOption: "starttls",
            options: [
              { value: "starttls", label: "starttls" },
              { value: "tls", label: "tls（465）" },
              { value: "none", label: "none" },
            ],
          },
          { key: "username", label: "用户名" },
          { key: "password", label: "密码", secret: true },
        ],
      },
      {
        title: "收发",
        fields: [
          {
            key: "from",
            label: "发件地址",
            required: true,
            requiredError: "请输入发件地址。",
            placeholder: "monitor@example.com",
          },
          { key: "from_name", label: "发件人名称" },
          {
            key: "to",
            label: "收件地址",
            required: true,
            requiredError: "请输入至少一个收件地址。",
            hint: "多个收件地址请使用逗号分隔。",
            placeholder: "ops@example.com",
          },
        ],
      },
    ],
    defaults: { port: "587", security: "starttls" },
  },
};

// 类型展示元数据：类型名与图标（A-04：除邮件外均为官方品牌标识，Slack 保留
// lucide Hash——官方 Logo 包无法获取，见 evolution_log.md §12.4）。
// 列表行 32px / 菜单 20px 图标方块，标识占方块 60%。
const CHANNEL_TYPE_META: Record<NotifyChannelType, { label: string; icon: ComponentType<BrandIconProps> }> = {
  telegram: {
    label: "Telegram",
    icon: TelegramIcon,
  },
  feishu: {
    label: "飞书",
    icon: FeishuIcon,
  },
  bark: {
    label: "Bark",
    icon: BarkIcon,
  },
  slack: {
    label: "Slack",
    icon: Hash,
  },
  dingtalk: {
    label: "钉钉",
    icon: DingtalkIcon,
  },
  wecom: {
    label: "企业微信",
    icon: WecomIcon,
  },
  email: {
    label: "邮件",
    icon: Mail,
  },
};

const CHANNEL_TYPES = Object.keys(CHANNEL_TYPE_SPECS) as NotifyChannelType[];

// =====================================================================
// F4「告警策略」分区：告警规则列表（规则抽屉与元数据已抽到
// components/alert-rule-drawer.tsx / lib/alert-rules.ts，A-01 步骤 1）。
// 规则在抽屉内独立编辑，「完成」只写回本页草稿 rules；真正保存走浮动保存条
// （alert_rules 随 SettingsUpdate 整份下发，内置 offline 规则随列表回传，
// 服务端 normalizeAlertRules 兜底补回）。
// =====================================================================

// 校验字段 key → 所在分区（沿用 alertFieldSectionMap 机制：渠道字段改为
// `${渠道 id}:${字段 key}` 的动态 key，全部映射到 channels 分区；规则字段为
// `rule:${规则 id}:${字段}`，与 offlineMinutes 一样映射到 policy）。侧栏子项红点
// 按 section id 匹配。
const OFFLINE_MINUTES_FIELD = "offlineMinutes";

function alertFieldSectionOf(field: string): string {
  return field === OFFLINE_MINUTES_FIELD || field.startsWith("rule:") ? "policy" : "channels";
}

function channelFieldErrorKey(channelId: string, fieldKey: string) {
  return `${channelId}:${fieldKey}`;
}

// 渠道草稿：config 为可见非敏感字段；secrets 只存本次输入的新值（留空 =
// 保持已存值，由服务端按同 ID 渠道合并）；secretsSet 来自视图（已配置标记）；
// secretsClear（B-08 / D-04）为待清除的可选密钥 key，随保存 / 测试载荷提交。
type ChannelDraft = {
  id: string;
  type: NotifyChannelType;
  name: string;
  enabled: boolean;
  config: Record<string, string>;
  secrets: Record<string, string>;
  secretsSet: Record<string, boolean>;
  secretsClear: string[];
  lastTest: ChannelTestResult | null;
};

type AlertSettingsDraft = {
  offlineMinutes: string;
  channels: ChannelDraft[];
  rules: AlertRuleDraft[];
};

function isValidHTTPURL(value: string) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function isValidHTTPSURL(value: string) {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

// 逗号分隔列表修剪（摘要统计用）。
function splitConfigList(raw: string | undefined): string[] {
  if (!raw) {
    return [];
  }
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

// 新渠道 id："c_" + 10 位随机字母数字，与后端 normalizeNotifyChannels 的生成规则一致。
function generateChannelID(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  let id = "";
  for (const byte of bytes) {
    id += alphabet[byte % alphabet.length];
  }
  return `c_${id}`;
}

function normalizeChannelType(raw: string | undefined): NotifyChannelType {
  return CHANNEL_TYPES.some((type) => type === raw) ? (raw as NotifyChannelType) : "telegram";
}

function makeChannelDrafts(settings: SettingsView | null): ChannelDraft[] {
  return (settings?.notify_channels ?? []).map((channel) => ({
    id: channel.id || generateChannelID(),
    type: normalizeChannelType(channel.type),
    name: channel.name || "",
    enabled: Boolean(channel.enabled),
    config: { ...(channel.config || {}) },
    secrets: {},
    secretsSet: { ...(channel.secrets_set || {}) },
    secretsClear: [],
    lastTest: channel.last_test ?? null,
  }));
}

function makeAlertSettingsDraft(settings: SettingsView | null): AlertSettingsDraft {
  return {
    offlineMinutes:
      settings?.alert_offline_sec && settings.alert_offline_sec > 0
        ? String(Math.round(settings.alert_offline_sec / 60))
        : "5",
    channels: makeChannelDrafts(settings),
    rules: makeRuleDrafts(settings),
  };
}

// 脏检测签名：排除 lastTest（行内「测试」会本地回写测试结果，不应触发保存条）。
// secretsClear 参与签名（B-08：标记清除 / 撤销清除都是未保存修改）。
function channelDirtySignature(channel: ChannelDraft): string {
  return JSON.stringify([
    channel.id,
    channel.type,
    channel.name.trim(),
    channel.enabled,
    channel.config,
    channel.secrets,
    [...channel.secretsClear].sort(),
  ]);
}

// 规则签名取保存载荷形态：alert_rule_status 等运行时数据不参与脏检测。
function ruleDirtySignature(rule: AlertRuleDraft): string {
  return JSON.stringify(buildRulePayload(rule));
}

// 草稿整体签名（reconcile 用）：与 channelDirtySignature 保持同一形态，
// 保证保存成功回填后的 absorb 比较与服务端 source 比较落在同一坐标系。
function alertSettingsSignature(draft: AlertSettingsDraft): string {
  return draftSignature([
    draft.offlineMinutes,
    draft.channels.map(channelDirtySignature),
    draft.rules.map(ruleDirtySignature),
  ]);
}

// 列表行摘要：类型名下方「类型名 · 摘要」中的摘要部分（如「2 个会话」「ops@example.com」）。
function channelSummary(channel: ChannelDraft): string {
  switch (channel.type) {
    case "telegram": {
      const count = splitConfigList(channel.config.chat_ids).length;
      return count > 0 ? `${count} 个会话` : "";
    }
    case "email":
      return splitConfigList(channel.config.to)[0] || "";
    case "dingtalk": {
      if (channel.config.at_all === "true") {
        return "@所有人";
      }
      const count = splitConfigList(channel.config.at_mobiles).length;
      return count > 0 ? `@ ${count} 个手机号` : "";
    }
    case "wecom": {
      const count = splitConfigList(channel.config.mentioned_mobiles).length;
      return count > 0 ? `@ ${count} 个手机号` : "";
    }
    default:
      return "";
  }
}

function channelDisplayName(channel: ChannelDraft): string {
  const name = channel.name.trim();
  return name || CHANNEL_TYPE_META[channel.type].label;
}

// 单渠道草稿校验：必填为空 / URL 协议 / 端口范围。返回 字段 key → 错误文案。
function validateChannelDraft(channel: ChannelDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  const spec = CHANNEL_TYPE_SPECS[channel.type];
  for (const group of spec.groups) {
    for (const field of group.fields) {
      const value = ((field.secret ? channel.secrets[field.key] : channel.config[field.key]) || "").trim();
      if (!value) {
        if (field.required && !(field.secret && channel.secretsSet[field.key])) {
          errors[field.key] = field.requiredError || `请输入${field.label}。`;
        }
        continue;
      }
      if (field.url === "https" && !isValidHTTPSURL(value)) {
        errors[field.key] = INVALID_HTTPS_URL_ERROR;
        continue;
      }
      if (field.url === "http" && !isValidHTTPURL(value)) {
        errors[field.key] = INVALID_HTTP_URL_ERROR;
        continue;
      }
      if (field.numericRange) {
        const port = Number(value);
        if (
          !Number.isInteger(port) ||
          port < field.numericRange.min ||
          port > field.numericRange.max
        ) {
          errors[field.key] = EMAIL_PORT_RANGE_ERROR;
        }
      }
    }
  }
  return errors;
}

// 保存载荷：视图/草稿 → 后端 NotifyChannel 更新形态（只带非空值；secrets_set 与
// last_test 为视图专属字段不下发，服务端按 ID 合并保留旧 secret 与已记录的测试结果；
// secrets_clear 为 B-08 的清除标记，服务端合并后丢弃）。
function buildChannelPayload(channel: ChannelDraft): NotifyChannel {
  const payload: NotifyChannel = {
    id: channel.id,
    type: channel.type,
    name: channel.name.trim(),
    enabled: channel.enabled,
    config: {},
    secrets: {},
  };
  for (const group of CHANNEL_TYPE_SPECS[channel.type].groups) {
    for (const field of group.fields) {
      const value = ((field.secret ? channel.secrets[field.key] : channel.config[field.key]) || "").trim();
      if (value) {
        const target = field.secret ? payload.secrets! : payload.config!;
        target[field.key] = value;
      }
    }
  }
  if (channel.secretsClear.length > 0) {
    payload.secrets_clear = [...channel.secretsClear];
  }
  return payload;
}

// 类型图标方块：--r-sm 圆角、--surface-raised 底、1px --hairline 描边，
// 原色品牌标识占方块 60%（A-04）。
function ChannelTypeIcon({
  type,
  className,
}: {
  type: NotifyChannelType;
  className?: string;
}) {
  const meta = CHANNEL_TYPE_META[type];
  const Icon = meta.icon;
  return (
    <span
      aria-hidden="true"
      className={cn(
        "flex shrink-0 items-center justify-center rounded-[var(--r-sm)] border border-[var(--hairline)] bg-[var(--surface-raised)]",
        className,
      )}
    >
      <Icon className="h-[60%] w-[60%]" />
    </span>
  );
}

// 列表行状态徽标：正常（LastTest 成功）/ 测试失败（--danger，hover 经 title 显示
// 错误原文）/ 未测试（中性）。
function ChannelTestStatusBadge({ lastTest }: { lastTest: ChannelTestResult | null }) {
  const tested = lastTest !== null;
  const failed = tested && !lastTest.ok;
  return (
    <span
      title={failed && lastTest.error ? lastTest.error : undefined}
      className={cn(
        "inline-flex h-6 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 text-xs font-medium",
        failed ? adminDangerBadgeClass : tested ? adminSuccessBadgeClass : adminNeutralBadgeClass,
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          "h-1.5 w-1.5 rounded-full",
          failed ? "bg-[var(--danger)]" : tested ? "bg-[var(--status-ok)]" : "bg-[var(--label-4)]",
        )}
      />
      {failed ? "测试失败" : tested ? "正常" : "未测试"}
    </span>
  );
}

// E-01 / A-07 第 1 条：分区图标方块的图标与分区专属底色，随 h1 展示在页头左侧。
// evolution_log.md 第 4 节图标表：告警策略 BellRing·橙 / 渠道设置 Send·蓝。
const SECTION_ICON_META: Record<string, { icon: ReactNode; background: string }> = {
  policy: {
    icon: <BellRing className="h-5 w-5" />,
    background: "bg-linear-to-br from-[#ffb35c] to-[#ff8a1f]",
  },
  channels: {
    icon: <Send className="h-5 w-5" />,
    background: "bg-linear-to-br from-[#4f8bff] to-[#0a64ff]",
  },
};

// 规则列表「渠道」列（A-08）：未指定渠道时显示「全部渠道」文字；没有任何启用
// 渠道时显示「无可用渠道」（--warn）；指定渠道时仍显示渠道类型小图标，最多 3 个
// 加「+N」（channel_ids 为空 = 全部已启用渠道）。
function RuleChannelIcons({ rule, channels }: { rule: AlertRuleDraft; channels: ChannelDraft[] }) {
  if (rule.channelIds.length === 0) {
    if (channels.every((channel) => !channel.enabled)) {
      return <span className="text-[13px] text-[var(--warn)]">无可用渠道</span>;
    }
    return <span className="text-[13px] text-[var(--label-2)]">全部渠道</span>;
  }
  const resolved = rule.channelIds
    .map((id) => channels.find((channel) => channel.id === id))
    .filter((channel): channel is ChannelDraft => Boolean(channel));
  if (resolved.length === 0) {
    return <span className="text-[13px] text-[var(--label-4)]">—</span>;
  }
  const shown = resolved.slice(0, 3);
  const rest = resolved.length - shown.length;
  return (
    <span className="inline-flex items-center gap-1">
      {shown.map((channel) => (
        <ChannelTypeIcon
          key={channel.id}
          type={channel.type}
          className="size-5 [&_svg]:size-3"
        />
      ))}
      {rest > 0 ? (
        <span className="text-[11px] font-semibold text-[var(--label-3)]">+{rest}</span>
      ) : null}
    </span>
  );
}

export interface NotificationAlertProps {
  settings: SettingsView | null;
  nodes: NodeView[];
  // 当前分区（alerts 页 2 分区之一，由 App 依据 URL 解析后传入）。
  section?: string | null;
  onDirtyChange?: (dirty: boolean) => void;
  saving?: boolean;
  onSave: (payload: SettingsUpdate) => Promise<SettingsView>;
  // 旧 webhook/telegram 请求体的测试通道（App 传入，保留接口签名兼容）；F5 渠道
  // 测试已改走草稿请求体（testNotifyChannelDraft），本页不再调用。
  onTest?: (payload: AlertTestPayload) => Promise<void>;
  // 校验定位：目标字段不在当前分区时，先请求 App 切换到目标分区再聚焦。
  onRequestSectionChange?: (section: string) => void;
  // 上报存在校验错误的分区（侧栏子项红点）；传空数组表示全部清除。
  onValidationErrorSectionsChange?: (sections: readonly string[]) => void;
}

export default function NotificationAlert({
  settings,
  nodes,
  section,
  onDirtyChange,
  saving = false,
  onSave,
  onRequestSectionChange,
  onValidationErrorSectionsChange,
}: NotificationAlertProps) {
  const [initialDraft] = useState(() => makeAlertSettingsDraft(settings));
  const [offlineMinutes, setOfflineMinutes] = useState(initialDraft.offlineMinutes);
  const [channels, setChannels] = useState<ChannelDraft[]>(initialDraft.channels);
  const [editingChannelId, setEditingChannelId] = useState<string | null>(null);
  const [testingChannelId, setTestingChannelId] = useState<string | null>(null);
  // 抽屉内「发送测试」的内联结果（按钮上方显示：成功「已送达 · N ms」/ 失败错误原文）。
  const [drawerTestResult, setDrawerTestResult] = useState<ChannelTestResult | null>(null);
  // F4 规则草稿与抽屉：rules 为本页草稿（含行内启停开关的改动）；ruleForm 是抽屉
  // 当前编辑的规则（表单副本在共享组件内独立维护，「完成」才写回 rules）。
  const [rules, setRules] = useState<AlertRuleDraft[]>(initialDraft.rules);
  const [ruleForm, setRuleForm] = useState<AlertRuleDraft | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const isBusy = isSaving || saving || testingChannelId !== null;
  // settings 尚未加载成功时草稿为空，保存会整份覆盖告警配置；settings===null 一律禁止保存。
  const settingsLoaded = settings !== null;
  const currentDraftSignature = draftSignature([
    offlineMinutes,
    channels.map(channelDirtySignature),
    rules.map(ruleDirtySignature),
  ]);

  const editingChannel = channels.find((channel) => channel.id === editingChannelId) || null;

  const [sourceSignature, absorbSourceSignature, discardDraft] = useDraftReconcile({
    draftSignature: currentDraftSignature,
    nextSourceSignature: alertSettingsSignature(makeAlertSettingsDraft(settings)),
    isBusy,
    resetDraft: () => {
      const draft = makeAlertSettingsDraft(settings);
      setOfflineMinutes(draft.offlineMinutes);
      setChannels(draft.channels);
      setRules(draft.rules);
      setEditingChannelId(null);
      setRuleForm(null);
    },
    warningText: "服务端告警配置已更新，当前未保存修改已保留。",
    onCleaned: () => {
      setFieldErrors({});
    },
  });
  // A-03：isDirty 由「草稿签名 ≠ 已吸收的服务端签名」派生——改回原值后保存条自动消失。
  const isDirty = sourceSignature !== currentDraftSignature;
  useDirtyNotification(onDirtyChange, isDirty);

  // 与侧栏共用 ADMIN_PAGE_SECTIONS 这一份分区定义；非法 section 回落第一分区。
  const alertSections = adminPageSections("alerts");
  const activeSection = resolveAdminSection("alerts", section);
  const activeSectionLabel =
    alertSections.find((item) => item.id === activeSection)?.label || alertSections[0].label;
  const activeSectionIconMeta = SECTION_ICON_META[activeSection || ""];

  // 横幅条件（F5）：已保存的渠道中没有任何启用渠道时提示（渠道设置与告警策略
  // 两个分区顶部都会渲染本横幅）。
  const hasEnabledChannel = (settings?.notify_channels ?? []).some((channel) => channel.enabled);

  // 存在校验错误的分区上报给侧栏红点；fieldErrors 清空（保存成功/修正输入）后自动消失。
  useEffect(() => {
    const sections = new Set<string>();
    for (const field of Object.keys(fieldErrors)) {
      if (fieldErrors[field]) {
        sections.add(alertFieldSectionOf(field));
      }
    }
    onValidationErrorSectionsChange?.(Array.from(sections));
  }, [fieldErrors, onValidationErrorSectionsChange]);

  // 跨页导航卸载本页时清除侧栏红点。
  useEffect(() => () => onValidationErrorSectionsChange?.([]), [onValidationErrorSectionsChange]);

  const focusFieldElement = (elementId: string, attempt = 0) => {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        const element = document.getElementById(elementId);
        if (element instanceof HTMLElement) {
          element.focus();
          return;
        }
        // 抽屉（Sheet portal）挂载可能晚于双 rAF：再补一次 120ms 定时重试。
        if (attempt < 1) {
          window.setTimeout(() => focusFieldElement(elementId, attempt + 1), 120);
        }
      });
    });
  };

  // 保存校验：offlineMinutes + 全部渠道草稿 + 全部规则草稿。渠道字段 key 为
  // `${渠道 id}:${字段 key}`、规则字段 key 为 `rule:${规则 id}:${字段}`，
  // 用于侧栏红点映射与抽屉内字段下方报错。
  const validateAlertForm = () => {
    const nextErrors: Record<string, string> = {};
    const minutes = Number.parseInt(offlineMinutes, 10);
    if (!Number.isFinite(minutes) || minutes < 1) {
      nextErrors[OFFLINE_MINUTES_FIELD] = "请输入大于或等于 1 的离线判定时间。";
    }
    for (const channel of channels) {
      for (const [fieldKey, message] of Object.entries(validateChannelDraft(channel))) {
        nextErrors[channelFieldErrorKey(channel.id, fieldKey)] = message;
      }
    }
    for (const rule of rules) {
      for (const [fieldKey, message] of Object.entries(validateRuleDraft(rule))) {
        nextErrors[`rule:${rule.id}:${fieldKey}`] = message;
      }
    }
    const firstField = (Object.keys(nextErrors) as string[]).find((field) => nextErrors[field]);
    return {
      errors: nextErrors,
      firstField,
      normalizedMinutes: Number.isFinite(minutes) && minutes > 0 ? minutes : 5,
    };
  };

  const applyValidationResult = (validation: ReturnType<typeof validateAlertForm>) => {
    setFieldErrors(validation.errors);
    if (!validation.firstField) {
      return true;
    }
    const firstField = validation.firstField;
    if (firstField === OFFLINE_MINUTES_FIELD) {
      if (activeSection !== "policy") {
        // 出错字段不在当前分区：先切到目标分区（同页导航，不触发拦截、不清草稿），
        // 双 rAF 等新分区渲染后再聚焦，避免 getElementById 落空导致保存“无反应”。
        onRequestSectionChange?.("policy");
      }
      focusFieldElement("offline-minutes");
      return false;
    }
    // 规则字段：切到 policy 分区并打开对应规则抽屉（以列表草稿为准重建表单），再聚焦字段。
    if (firstField.startsWith("rule:")) {
      if (activeSection !== "policy") {
        onRequestSectionChange?.("policy");
      }
      const separator = firstField.indexOf(":");
      const secondSeparator = firstField.indexOf(":", separator + 1);
      const ruleId = firstField.slice(separator + 1, secondSeparator);
      const fieldKey = firstField.slice(secondSeparator + 1);
      const ruleDraft = rules.find((item) => item.id === ruleId);
      if (ruleDraft) {
        setRuleForm(copyRuleDraft(ruleDraft));
      }
      focusFieldElement(`alert-rule-${fieldKey}`);
      return false;
    }
    // 渠道字段：确保切到 channels 分区并打开对应渠道的抽屉，再聚焦字段。
    if (activeSection !== "channels") {
      onRequestSectionChange?.("channels");
    }
    const separator = firstField.indexOf(":");
    const channelId = firstField.slice(0, separator);
    const fieldKey = firstField.slice(separator + 1);
    if (editingChannelId !== channelId) {
      setEditingChannelId(channelId);
      setDrawerTestResult(null);
    }
    focusFieldElement(`notify-channel-${fieldKey}`);
    return false;
  };

  const runAction = useAsyncAction();

  const runSave = (payload: SettingsUpdate) => {
    void runAction({
      action: () => onSave(payload),
      fallbackError: "保存告警配置失败",
      successToast: "告警配置已保存",
      onSuccess: (savedSettings) => {
        const canonicalDraft = makeAlertSettingsDraft(savedSettings);
        setOfflineMinutes(canonicalDraft.offlineMinutes);
        setChannels(canonicalDraft.channels);
        setRules(canonicalDraft.rules);
        // 抽屉保持打开：渠道 id 保存后不变（normalize 仅在空/冲突时重新生成），
        // 抽屉内容随 canonical 草稿自然回填。
        absorbSourceSignature(alertSettingsSignature(canonicalDraft));
        setFieldErrors({});
      },
      setBusy: setIsSaving,
    });
  };

  const handleSave = () => {
    if (isBusy || !settingsLoaded) {
      return;
    }
    const validation = validateAlertForm();
    if (!applyValidationResult(validation)) {
      return;
    }
    runSave({
      alert_offline_sec: validation.normalizedMinutes * 60,
      // F5：渠道列表为权威表示；服务端按 ID 合并 secret、保留 LastTest，
      // 并回填旧告警字段（Telegram Bot 轮询继续可用）。
      notify_channels: channels.map(buildChannelPayload),
      // F4：规则列表整份下发（含内置 offline 规则；服务端 normalizeAlertRules
      // 校验并兜底补回 offline 规则）。
      alert_rules: rules.map(buildRulePayload),
    });
  };

  // ---- 渠道草稿编辑 ----

  const patchChannel = (channelId: string, patch: Partial<ChannelDraft>) => {
    setChannels((current) =>
      current.map((channel) => (channel.id === channelId ? { ...channel, ...patch } : channel)),
    );
  };

  const openChannelDrawer = (channelId: string) => {
    setEditingChannelId(channelId);
    setDrawerTestResult(null);
  };

  const closeChannelDrawer = () => {
    setEditingChannelId(null);
    setDrawerTestResult(null);
  };

  const handleChannelFieldValueChange = (
    channel: ChannelDraft,
    field: ChannelFieldSpec,
    value: string,
  ) => {
    if (isBusy) {
      return;
    }
    if (field.secret) {
      patchChannel(channel.id, {
        secrets: { ...channel.secrets, [field.key]: value },
      });
    } else {
      patchChannel(channel.id, {
        config: { ...channel.config, [field.key]: value },
      });
    }
    const errorKey = channelFieldErrorKey(channel.id, field.key);
    setFieldErrors((current) =>
      current[errorKey] ? { ...current, [errorKey]: "" } : current,
    );
  };

  // B-08 / D-04：可选密钥「清除」——标记进 secretsClear，输入框清空并禁用，
  // 保存时由服务端从已存值中删除；「撤销」取消标记恢复输入。
  const handleChannelSecretClear = (channel: ChannelDraft, field: ChannelFieldSpec) => {
    if (isBusy) {
      return;
    }
    if (channel.secretsClear.includes(field.key)) {
      return;
    }
    patchChannel(channel.id, {
      secretsClear: [...channel.secretsClear, field.key],
      secrets: { ...channel.secrets, [field.key]: "" },
    });
  };

  const handleChannelSecretClearUndo = (channel: ChannelDraft, field: ChannelFieldSpec) => {
    if (isBusy) {
      return;
    }
    patchChannel(channel.id, {
      secretsClear: channel.secretsClear.filter((key) => key !== field.key),
    });
  };

  const clearChannelFieldErrors = (channelId: string) => {
    const prefix = `${channelId}:`;
    setFieldErrors((current) => {
      const next: Record<string, string> = {};
      for (const key of Object.keys(current)) {
        if (!key.startsWith(prefix) && current[key]) {
          next[key] = current[key];
        }
      }
      return next;
    });
  };

  const handleChannelEnabledChange = (channel: ChannelDraft, enabled: boolean) => {
    if (isBusy) {
      return;
    }
    patchChannel(channel.id, { enabled });
  };

  const addChannel = (type: NotifyChannelType) => {
    if (isBusy) {
      return;
    }
    const spec = CHANNEL_TYPE_SPECS[type];
    const draft: ChannelDraft = {
      id: generateChannelID(),
      type,
      name: "",
      enabled: true,
      config: { ...spec.defaults },
      secrets: {},
      secretsSet: {},
      secretsClear: [],
      lastTest: null,
    };
    setChannels((current) => [...current, draft]);
    openChannelDrawer(draft.id);
  };

  const removeChannel = (channelId: string) => {
    if (isBusy) {
      return;
    }
    setChannels((current) => current.filter((channel) => channel.id !== channelId));
    closeChannelDrawer();
    clearChannelFieldErrors(channelId);
  };

  // ---- F4 规则草稿编辑（抽屉表单在共享组件内独立编辑，「完成」才写回 rules 草稿） ----

  const clearRuleFieldErrors = (ruleId: string) => {
    const prefix = `rule:${ruleId}:`;
    setFieldErrors((current) => {
      const next: Record<string, string> = {};
      for (const key of Object.keys(current)) {
        if (!key.startsWith(prefix) && current[key]) {
          next[key] = current[key];
        }
      }
      return next;
    });
  };

  const openRuleDrawer = (rule: AlertRuleDraft) => {
    setRuleForm(copyRuleDraft(rule));
  };

  const closeRuleDrawer = () => {
    setRuleForm(null);
  };

  const addRule = () => {
    if (isBusy) {
      return;
    }
    // 默认形态对齐文档示例：「CPU > 90% · 持续 5 分钟」。
    setRuleForm({
      id: generateRuleID(),
      name: "",
      enabled: true,
      metric: "cpu",
      op: "gt",
      threshold: "90",
      durationSec: 300,
      scopeMode: "all",
      scopeNodes: [],
      scopeGroups: [],
      scopeExclude: [],
      channelIds: [],
      notifyRecover: true,
      repeat: "once",
      probeName: "",
      leadDays: [],
    });
  };

  const handleRuleEnabledChange = (rule: AlertRuleDraft, enabled: boolean) => {
    if (isBusy) {
      return;
    }
    setRules((current) => current.map((item) => (item.id === rule.id ? { ...item, enabled } : item)));
  };

  // 抽屉「完成」（onDone）：只写回本页规则草稿（真正保存走浮动保存条），
  // 随后关闭抽屉。校验已在共享抽屉内完成。
  const handleRuleDone = (form: AlertRuleDraft) => {
    if (isBusy) {
      return;
    }
    setRules((current) => {
      const index = current.findIndex((item) => item.id === form.id);
      if (index < 0) {
        return [...current, copyRuleDraft(form)];
      }
      const next = [...current];
      next[index] = copyRuleDraft(form);
      return next;
    });
    clearRuleFieldErrors(form.id);
    closeRuleDrawer();
  };

  // 抽屉「删除」（onDelete）：从草稿移除（内置 offline 规则不传 onDelete，不显示删除）。
  const removeRule = (ruleId: string) => {
    if (isBusy) {
      return;
    }
    setRules((current) => current.filter((item) => item.id !== ruleId));
    closeRuleDrawer();
    clearRuleFieldErrors(ruleId);
  };

  // ---- 测试（草稿请求体：服务端按同 ID 已存渠道补齐空 secret，并写入 LastTest）----

  const applyTestResult = (channelId: string, result: ChannelTestResult) => {
    setChannels((current) =>
      current.map((channel) =>
        channel.id === channelId
          ? {
              ...channel,
              lastTest: { ...result, at: result.at || Math.floor(Date.now() / 1000) },
            }
          : channel,
      ),
    );
  };

  // 列表行「测试」：结果回写徽标；失败弹 toast 展示错误原文。
  const handleRowTest = (channel: ChannelDraft) => {
    if (isBusy) {
      return;
    }
    const errors = validateChannelDraft(channel);
    if (Object.keys(errors).length > 0) {
      setFieldErrors((current) => {
        const next = { ...current };
        for (const [fieldKey, message] of Object.entries(errors)) {
          next[channelFieldErrorKey(channel.id, fieldKey)] = message;
        }
        return next;
      });
      openChannelDrawer(channel.id);
      focusFieldElement(`notify-channel-${Object.keys(errors)[0]}`);
      return;
    }
    // 失败（HTTP 200 但 ok=false）经 onSuccess 抛出走统一错误 toast，展示错误原文。
    void runAction({
      action: () => testNotifyChannelDraft(buildChannelPayload(channel)),
      fallbackError: "测试发送失败",
      successToast: (result) => (result.ok ? "测试消息已发送" : null),
      setBusy: (on) => setTestingChannelId(on ? channel.id : null),
      onSuccess: (result) => {
        applyTestResult(channel.id, result);
        if (result.ok) {
          return;
        }
        throw new Error(result.error || "测试发送失败");
      },
    });
  };

  // 抽屉「发送测试」：用当前草稿；结果内联显示在按钮上方。
  const handleDrawerTest = (channel: ChannelDraft) => {
    if (isBusy) {
      return;
    }
    const errors = validateChannelDraft(channel);
    if (Object.keys(errors).length > 0) {
      setFieldErrors((current) => {
        const next = { ...current };
        for (const [fieldKey, message] of Object.entries(errors)) {
          next[channelFieldErrorKey(channel.id, fieldKey)] = message;
        }
        return next;
      });
      const firstFieldKey = Object.keys(errors)[0];
      focusFieldElement(`notify-channel-${firstFieldKey}`);
      return;
    }
    clearChannelFieldErrors(channel.id);
    void runAction({
      action: () => testNotifyChannelDraft(buildChannelPayload(channel)),
      fallbackError: "测试发送失败",
      setBusy: (on) => setTestingChannelId(on ? channel.id : null),
      onSuccess: (result) => {
        setDrawerTestResult(result);
        applyTestResult(channel.id, result);
      },
    });
  };

  const offlineMinutesError = fieldErrors[OFFLINE_MINUTES_FIELD];

  return (
    // E-03：设置页窄版外壳（页头、横幅、表单同宽 880px）；A-12：保存入口移入浮动保存条，
    // isDirty 为假时页头不显示保存按钮（0.1.2）。
    <div className={adminNarrowPageShellClass}>
      <AdminPageHeader
        breadcrumb={
          <>
            <span>通知告警</span>
            <ChevronRight aria-hidden="true" className="h-3 w-3" />
          </>
        }
        icon={activeSectionIconMeta?.icon}
        iconClassName={activeSectionIconMeta?.background}
        title={activeSectionLabel}
      />

      {!hasEnabledChannel ? (
        // F5：没有任何启用渠道时在「渠道设置」「告警策略」两分区顶部提示（A-14 横幅样式）。
        <div className="flex items-start gap-4 rounded-[var(--r-md)] bg-[var(--warn-tint)] px-4 py-3">
          <span
            aria-hidden="true"
            className="flex size-5 shrink-0 items-center justify-center rounded-full bg-[var(--warn)] text-xs font-semibold leading-none text-white"
          >
            !
          </span>
          <p className="text-[13px] leading-relaxed">
            <span className="font-semibold text-[var(--label-1)]">尚未配置任何通知渠道：</span>
            <span className="text-[var(--label-2)]">
              {/* A-08：改为「所有告警都不会发出」（不只离线告警），其余文字不变。 */}
              所有告警都不会发出。请先在渠道设置中添加并启用通知渠道。
            </span>
          </p>
        </div>
      ) : null}

      {activeSection === "policy" ? (
        // F4：删除顶部统计卡；「全局设置」单行 + 「告警规则」列表（新增规则 /
        // 点击行开抽屉 / 行内启停开关改草稿走浮动保存条）。
        <>
          <AdminSectionPanel label="全局设置">
            <AdminGroupedCard>
              <AdminGroupedFieldRow
                label="离线判定时间"
                htmlFor="offline-minutes"
                hint="对所有节点生效：节点超过该时长未上报，即判定为离线并触发离线告警。"
              >
                <div className="flex w-full flex-col gap-1.5 sm:items-end">
                  {/* A-09：数字输入 96px 宽 + 「分钟」后缀，整组靠右。 */}
                  <div className="flex items-center justify-end gap-2">
                    <Input
                      id="offline-minutes"
                      type="number"
                      name="offline-minutes"
                      min={1}
                      autoComplete="off"
                      inputMode="numeric"
                      className={`${adminInputClass} tabular-nums w-[96px] text-right`}
                      aria-invalid={Boolean(offlineMinutesError)}
                      aria-describedby={offlineMinutesError ? "offline-minutes-error" : undefined}
                      value={offlineMinutes}
                      disabled={isBusy}
                      onChange={(event: ChangeEvent<HTMLInputElement>) => {
                        if (isBusy) {
                          return;
                        }
                        setOfflineMinutes(event.target.value);
                        setFieldErrors((current) =>
                          current[OFFLINE_MINUTES_FIELD]
                            ? { ...current, [OFFLINE_MINUTES_FIELD]: "" }
                            : current,
                        );
                      }}
                    />
                    <span className="text-[13px] font-medium text-[var(--label-2)]">分钟</span>
                  </div>
                  {offlineMinutesError ? (
                    <p id="offline-minutes-error" className="text-xs font-medium text-[var(--status-danger)] sm:text-right" aria-live="polite">
                      {offlineMinutesError}
                    </p>
                  ) : null}
                </div>
              </AdminGroupedFieldRow>
            </AdminGroupedCard>
          </AdminSectionPanel>

          {/* A-06：改用 AdminPanel（带标题行，「新增规则」在标题行右侧）。 */}
          <AdminPanel
            title="告警规则"
            actions={
              <Button
                type="button"
                variant="outline"
                className={adminCompactActionButtonClass}
                disabled={isBusy}
                onClick={addRule}
              >
                <Plus className="h-3.5 w-3.5" />
                新增规则
              </Button>
            }
          >
            <AdminDataTable
              ariaLabel="告警规则"
              emptyLabel="暂无告警规则"
              rows={rules}
              rowKey={(rule) => rule.id}
              onRowClick={(rule) => openRuleDrawer(rule)}
              columns={[
                {
                  key: "name",
                  label: "名称",
                  render: (rule) => (
                    <span
                      className="text-sm font-medium"
                      data-admin-i18n-skip={rule.name.trim() ? true : undefined}
                    >
                      {rule.name.trim() ||
                        (rule.metric === OFFLINE_ALERT_RULE_ID ? "节点离线" : "未命名规则")}
                    </span>
                  ),
                },
                {
                  key: "condition",
                  label: "条件",
                  render: (rule) => (
                    <span className="text-[13px] text-[var(--label-2)]">
                      {ruleConditionText(rule)}
                    </span>
                  ),
                },
                {
                  key: "scope",
                  label: "范围",
                  render: (rule) => (
                    <span className="text-[13px] text-[var(--label-2)]">{ruleScopeText(rule)}</span>
                  ),
                },
                {
                  key: "channels",
                  label: "渠道",
                  render: (rule) => <RuleChannelIcons rule={rule} channels={channels} />,
                },
                {
                  key: "status",
                  label: "状态",
                  render: (rule) => {
                    // F4：状态来自 SettingsView.alert_rule_status（运行时聚合，只读）。
                    const firing = settings?.alert_rule_status?.[rule.id]?.firing || 0;
                    return firing > 0 ? (
                      <span className={cn(adminStatusBadgeClass("danger"), "whitespace-nowrap")}>
                        告警中 {firing} 台
                      </span>
                    ) : (
                      <span className={cn(adminStatusBadgeClass("neutral"), "whitespace-nowrap")}>
                        正常
                      </span>
                    );
                  },
                },
                {
                  key: "enabled",
                  label: "启用",
                  align: "center",
                  render: (rule) => (
                    // 行内开关：阻止冒泡，避免触发整行点击（打开抽屉）与行键盘事件。
                    <span
                      className="inline-flex justify-center"
                      onClick={(event) => event.stopPropagation()}
                      onKeyDown={(event) => event.stopPropagation()}
                    >
                      <Switch
                        size="sm"
                        checked={rule.enabled}
                        disabled={isBusy}
                        onCheckedChange={(checked) => handleRuleEnabledChange(rule, Boolean(checked))}
                        aria-label="启用规则"
                      />
                    </span>
                  ),
                },
              ]}
            />
          </AdminPanel>
        </>
      ) : null}

      {activeSection === "channels" ? (
        // F5「渠道设置」：单卡片渠道列表 + 「添加渠道」类型菜单（A-06：标题行右侧）。
        <AdminPanel
          title="通知渠道"
          actions={
            <DropdownMenu>
              <DropdownMenuTrigger
                render={(
                  <Button
                    type="button"
                    variant="outline"
                    className={adminCompactActionButtonClass}
                    disabled={isBusy}
                  >
                    <Plus className="h-3.5 w-3.5" />
                    添加渠道
                  </Button>
                )}
              />
              <DropdownMenuContent align="end" className="w-48">
                {CHANNEL_TYPES.map((type) => {
                  const meta = CHANNEL_TYPE_META[type];
                  return (
                    <DropdownMenuItem key={type} onClick={() => addChannel(type)}>
                      <ChannelTypeIcon type={type} className="size-5" />
                      <span className="ml-2.5">{meta.label}</span>
                    </DropdownMenuItem>
                  );
                })}
              </DropdownMenuContent>
            </DropdownMenu>
          }
        >
          <AdminGroupedCard>
            {channels.length === 0 ? (
              <div className="px-4 py-10">
                {/* A-06：空态文案不再指向「右上角」，主按钮「添加渠道」复用同一类型下拉菜单。 */}
                <AdminEmptyState
                  icon={<Bell />}
                  title="还没有通知渠道"
                  description="配置飞书、Telegram、邮件等 7 种通知方式。"
                  action={
                    <DropdownMenu>
                      <DropdownMenuTrigger
                        render={(
                          <Button type="button" disabled={isBusy}>
                            <Plus className="h-4 w-4" />
                            添加渠道
                          </Button>
                        )}
                      />
                      <DropdownMenuContent align="center" className="w-48">
                        {CHANNEL_TYPES.map((type) => {
                          const meta = CHANNEL_TYPE_META[type];
                          return (
                            <DropdownMenuItem key={type} onClick={() => addChannel(type)}>
                              <ChannelTypeIcon type={type} className="size-5" />
                              <span className="ml-2.5">{meta.label}</span>
                            </DropdownMenuItem>
                          );
                        })}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  }
                />
              </div>
            ) : (
              channels.map((channel) => {
                const meta = CHANNEL_TYPE_META[channel.type];
                const summary = channelSummary(channel);
                return (
                  <div
                    key={channel.id}
                    className={cn(adminGroupedCardRowClass, "flex items-center gap-2")}
                  >
                    <div
                      role="button"
                      tabIndex={0}
                      onClick={() => openChannelDrawer(channel.id)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          openChannelDrawer(channel.id);
                        }
                      }}
                      className="flex min-w-0 flex-1 cursor-pointer items-center gap-3 rounded-md py-1 pr-1 pl-1 outline-none hover:bg-[rgba(0,0,0,0.025)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)] dark:hover:bg-[rgba(255,255,255,0.05)]"
                    >
                      <ChannelTypeIcon type={channel.type} className="size-8" />
                      <span className="min-w-0 flex-1">
                        <span
                          className="block truncate text-[15px] font-semibold leading-5 text-[var(--label-1)]"
                          data-admin-i18n-skip={channel.name.trim() ? true : undefined}
                        >
                          {channelDisplayName(channel)}
                        </span>
                        <span className="block truncate text-[13px] leading-4 text-[var(--label-3)]">
                          {meta.label}
                          {summary ? (
                            <>
                              <span aria-hidden="true" className="mx-1">·</span>
                              <span data-admin-i18n-skip={channel.type === "email" ? true : undefined}>
                                {summary}
                              </span>
                            </>
                          ) : null}
                        </span>
                      </span>
                    </div>
                    <ChannelTestStatusBadge lastTest={channel.lastTest} />
                    <button
                      type="button"
                      className={cn(adminTextButtonClass, "h-8 shrink-0 px-2.5 text-[13px]")}
                      disabled={isBusy}
                      onClick={() => handleRowTest(channel)}
                    >
                      {testingChannelId === channel.id ? "测试中…" : "测试"}
                    </button>
                    <Switch
                      size="sm"
                      checked={channel.enabled}
                      disabled={isBusy}
                      onCheckedChange={(checked) => handleChannelEnabledChange(channel, Boolean(checked))}
                      aria-label="启用渠道"
                    />
                    <button
                      type="button"
                      aria-label="编辑渠道"
                      className="flex size-8 shrink-0 items-center justify-center rounded-full text-[var(--label-4)] outline-none transition-colors duration-[var(--dur-2)] hover:text-[var(--label-2)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)]"
                      disabled={isBusy}
                      onClick={() => openChannelDrawer(channel.id)}
                    >
                      <ChevronRight aria-hidden="true" className="h-4 w-4" />
                    </button>
                  </div>
                );
              })
            )}
          </AdminGroupedCard>
        </AdminPanel>
      ) : null}

      {isDirty ? (
        // A-12：保存入口移入浮动保存条；handleSave 的校验与禁用条件复用原有逻辑，
        // 只改呈现位置。A-03：左侧「放弃修改」带二次确认（D-07），确认后回到服务端
        // 当前配置（discard 经 onCleaned 清空校验错误，侧栏红点随之清除）。
        <AdminSaveBar
          saving={isSaving || saving}
          disabled={isBusy || !settingsLoaded}
          onSave={handleSave}
          onDiscard={discardDraft}
        />
      ) : null}

      <AdminDrawer
        open={editingChannel !== null}
        onOpenChange={(open) => {
          if (!open) {
            closeChannelDrawer();
          }
        }}
        title={
          editingChannel ? (
            <span data-admin-i18n-skip={editingChannel.name.trim() ? true : undefined}>
              {channelDisplayName(editingChannel)}
            </span>
          ) : null
        }
        description={
          editingChannel ? (
            <span className="data-text">
              {`${CHANNEL_TYPE_META[editingChannel.type].label} · ${editingChannel.id}`}
            </span>
          ) : null
        }
        footer={
          editingChannel ? (
            <div>
              {drawerTestResult ? (
                <p
                  aria-live="polite"
                  className={cn(
                    "mb-2.5 text-[13px] font-medium leading-relaxed",
                    drawerTestResult.ok
                      ? "text-[var(--status-ok)]"
                      : "text-[var(--danger)]",
                  )}
                >
                  {drawerTestResult.ok
                    ? `已送达 · ${drawerTestResult.latency_ms ?? 0} ms`
                    : drawerTestResult.error || "测试发送失败"}
                </p>
              ) : null}
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className={cn(adminDangerOutlineButtonClass, "min-w-[84px] px-4")}
                  disabled={isBusy}
                  onClick={() => removeChannel(editingChannel.id)}
                >
                  <Trash2 className="h-4 w-4" />
                  删除
                </Button>
                <div className="ml-auto flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    className={cn(adminOutlineButtonClass, "min-w-[92px] px-4")}
                    disabled={isBusy}
                    onClick={() => handleDrawerTest(editingChannel)}
                  >
                    <Send className="h-3.5 w-3.5" />
                    {testingChannelId === editingChannel.id ? "测试中…" : "发送测试"}
                  </Button>
                  <Button
                    type="button"
                    className={cn(adminPrimaryButtonClass, "min-w-[84px] px-4")}
                    disabled={isBusy}
                    onClick={closeChannelDrawer}
                  >
                    完成
                  </Button>
                </div>
              </div>
            </div>
          ) : null
        }
      >
        {editingChannel
          ? (() => {
              const channel = editingChannel;
              const meta = CHANNEL_TYPE_META[channel.type];
              const spec = CHANNEL_TYPE_SPECS[channel.type];
              return (
                <>
                  <section>
                    <h3 className={adminDrawerSectionTitleClass}>基础</h3>
                    <AdminGroupedFieldRow label="名称" htmlFor="notify-channel-name">
                      <div className="w-full space-y-1.5">
                        <Input
                          id="notify-channel-name"
                          name="notify-channel-name"
                          autoComplete="off"
                          className={`${adminInputClass} w-full`}
                          value={channel.name}
                          placeholder={meta.label}
                          disabled={isBusy}
                          onChange={(event) =>
                            patchChannel(channel.id, { name: event.target.value })
                          }
                        />
                      </div>
                    </AdminGroupedFieldRow>
                    <AdminGroupedFieldRow label="类型">
                      <Badge variant="outline" className={adminSubtleOutlineBadgeClass}>
                        {meta.label}
                      </Badge>
                    </AdminGroupedFieldRow>
                    <AdminGroupedSwitchRow
                      label="启用"
                      htmlFor="notify-channel-enabled"
                      hint="停用后该渠道不再发送任何告警通知。"
                    >
                      <Switch
                        id="notify-channel-enabled"
                        checked={channel.enabled}
                        disabled={isBusy}
                        onCheckedChange={(checked) =>
                          handleChannelEnabledChange(channel, Boolean(checked))
                        }
                      />
                    </AdminGroupedSwitchRow>
                  </section>
                    {spec.groups.map((group) => (
                    <section key={group.title}>
                      <h3 className={adminDrawerSectionTitleClass}>{group.title}</h3>
                      {group.fields.map((field) => {
                        const value = (
                          (field.secret ? channel.secrets[field.key] : channel.config[field.key]) ||
                          ""
                        );
                        const error =
                          fieldErrors[channelFieldErrorKey(channel.id, field.key)] || "";
                        const fieldID = `notify-channel-${field.key}`;
                        const configured = field.secret ? Boolean(channel.secretsSet[field.key]) : false;
                        // B-08 / D-04：可选密钥（非必填的敏感字段）在已配置时可「清除」。
                        const clearable = Boolean(field.secret) && !field.required && configured;
                        const clearing = channel.secretsClear.includes(field.key);
                        // Select 草稿值为空时回落到与后端一致的缺省值。
                        const selectValue = field.options
                          ? value || field.defaultOption || field.options[0].value
                          : "";
                        if (field.switch) {
                          const checked = channel.config[field.key] === "true";
                          return (
                            <AdminGroupedSwitchRow
                              key={field.key}
                              label={field.label}
                              htmlFor={fieldID}
                              hint={field.hint}
                            >
                              <Switch
                                id={fieldID}
                                checked={checked}
                                disabled={isBusy}
                                onCheckedChange={(on) =>
                                  handleChannelFieldValueChange(
                                    channel,
                                    field,
                                    on ? "true" : "",
                                  )
                                }
                              />
                            </AdminGroupedSwitchRow>
                          );
                        }
                        if (field.options) {
                          return (
                            <AdminGroupedFieldRow
                              key={field.key}
                              label={field.label}
                              htmlFor={fieldID}
                              hint={field.hint}
                            >
                              <div className="w-full space-y-1.5">
                                <Select
                                  value={selectValue}
                                  onValueChange={(next) =>
                                    handleChannelFieldValueChange(channel, field, next || "")
                                  }
                                >
                                  <SelectTrigger
                                    id={fieldID}
                                    size="sm"
                                    disabled={isBusy}
                                    className={`${adminSelectTriggerClass} w-full`}
                                  >
                                    <SelectValue>
                                      {field.options.find((item) => item.value === selectValue)?.label || selectValue}
                                    </SelectValue>
                                  </SelectTrigger>
                                  <SelectContent className={adminSelectContentClass}>
                                    {field.options.map((item) => (
                                      <SelectItem key={item.value} value={item.value}>
                                        {item.label}
                                      </SelectItem>
                                    ))}
                                  </SelectContent>
                                </Select>
                                {error ? (
                                  <p className={adminFieldErrorClass} aria-live="polite">
                                    {error}
                                  </p>
                                ) : null}
                              </div>
                            </AdminGroupedFieldRow>
                          );
                        }
                        return (
                          <AdminGroupedFieldRow
                            key={field.key}
                            label={field.label}
                            htmlFor={fieldID}
                            hint={field.hint}
                          >
                            <div className="w-full space-y-1.5">
                              <div className={cn("w-full", clearable && "flex items-center gap-1.5")}>
                                <Input
                                  id={fieldID}
                                  name={fieldID}
                                  type={field.secret ? "password" : field.numericRange ? "number" : field.url ? "url" : "text"}
                                  inputMode={field.numericRange ? "numeric" : field.url ? "url" : undefined}
                                  min={field.numericRange ? field.numericRange.min : undefined}
                                  max={field.numericRange ? field.numericRange.max : undefined}
                                  autoComplete="off"
                                  spellCheck={false}
                                  className={cn(
                                    adminInputClass,
                                    clearable ? "min-w-0 flex-1" : "w-full",
                                    field.secret && "data-text placeholder:font-sans",
                                  )}
                                  aria-invalid={Boolean(error)}
                                  aria-describedby={error ? `${fieldID}-error` : undefined}
                                  value={clearing ? "" : value}
                                  disabled={isBusy || clearing}
                                  onChange={(event) =>
                                    handleChannelFieldValueChange(channel, field, event.target.value)
                                  }
                                  placeholder={
                                    clearing
                                      ? "保存后清除"
                                      : field.secret
                                        ? configured
                                          ? "已配置（留空保持不变）"
                                          : field.placeholder
                                        : field.placeholder
                                  }
                                />
                                {clearable ? (
                                  <Button
                                    type="button"
                                    variant={null}
                                    className={cn(
                                      adminTextButtonClass,
                                      "h-9 shrink-0 whitespace-nowrap",
                                      !clearing && "text-[var(--danger)] hover:bg-[var(--danger-tint)] hover:text-[var(--danger)]",
                                    )}
                                    disabled={isBusy}
                                    onClick={() =>
                                      clearing
                                        ? handleChannelSecretClearUndo(channel, field)
                                        : handleChannelSecretClear(channel, field)
                                    }
                                  >
                                    {clearing ? "撤销" : "清除"}
                                  </Button>
                                ) : null}
                              </div>
                              {error ? (
                                <p id={`${fieldID}-error`} className={adminFieldErrorClass} aria-live="polite">
                                  {error}
                                </p>
                              ) : null}
                            </div>
                          </AdminGroupedFieldRow>
                        );
                      })}
                    </section>
                  ))}
                </>
              );
            })()
          : null}
      </AdminDrawer>


      {/* F4 规则抽屉（A-01 步骤 1 起为共享组件）：基础 / 范围 / 通知分组卡片 +
          底部「删除 → 模拟评估 → 完成」；「完成」只写回本页规则草稿，真正保存走
          浮动保存条。内置 offline 规则不传 onDelete（不显示删除）。 */}
      {ruleForm ? (
        <AlertRuleDrawer
          open
          rule={ruleForm}
          isNew={!rules.some((item) => item.id === ruleForm.id)}
          nodes={nodes}
          groupTree={settings?.group_tree || []}
          channels={channels}
          probes={settings?.test_catalog || []}
          onDone={handleRuleDone}
          onDelete={ruleForm.metric === OFFLINE_ALERT_RULE_ID ? undefined : () => removeRule(ruleForm.id)}
          onClose={closeRuleDrawer}
        />
      ) : null}
    </div>
  );
}
