// 通知渠道字段规格与必填判定（F5 的 7 种渠道）。
// 规格表与「必填是否齐全」的判定集中在这里，供渠道抽屉校验、列表徽标、告警策略
// 渠道列与配置导入提示共用同一份口径——不另起第二套必填规则。
// 展示层元数据（类型名 / 图标）与草稿编辑仍在 pages/NotificationAlert.tsx。

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
export interface ChannelFieldSpec {
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

export interface ChannelGroupSpec {
  title: string;
  fields: ChannelFieldSpec[];
}

export interface ChannelTypeSpec {
  groups: ChannelGroupSpec[];
  // 新建渠道时的 Config 默认值（与后端各 Notifier 的缺省一致）。
  defaults?: Record<string, string>;
}

// 7 种渠道的字段规格（evolution_log.md F5 字段表；* 为必填，🔒 为敏感字段）。
export const CHANNEL_TYPE_SPECS: Record<NotifyChannelType, ChannelTypeSpec> = {
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

export const CHANNEL_TYPES = Object.keys(CHANNEL_TYPE_SPECS) as NotifyChannelType[];

export function normalizeChannelType(raw: string | undefined): NotifyChannelType {
  return CHANNEL_TYPES.some((type) => type === raw) ? (raw as NotifyChannelType) : "telegram";
}

// 单字段必填判定（validateChannelDraft 与「必填是否齐全」共用同一口径）：
// 值为空，且不是「敏感字段已由服务端保存」（secrets_set）的必填字段，即视为缺失。
function requiredFieldMissing(
  field: ChannelFieldSpec,
  configValue: string | undefined,
  secretValue: string | undefined,
  secretSet: boolean | undefined,
): boolean {
  if (!field.required) {
    return false;
  }
  const value = ((field.secret ? secretValue : configValue) || "").trim();
  return !value && !(field.secret && secretSet);
}

// 渠道必填项缺失清单（按规格表顺序）。config / secrets 取自草稿或视图，
// secretsSet 对应草稿 secretsSet 或视图 secrets_set。
export function missingRequiredChannelFields(
  type: string,
  config: Record<string, string> | null | undefined,
  secrets: Record<string, string> | null | undefined,
  secretsSet: Record<string, boolean> | null | undefined,
): ChannelFieldSpec[] {
  const missing: ChannelFieldSpec[] = [];
  for (const group of CHANNEL_TYPE_SPECS[normalizeChannelType(type)].groups) {
    for (const field of group.fields) {
      if (
        requiredFieldMissing(
          field,
          config?.[field.key],
          secrets?.[field.key],
          secretsSet?.[field.key],
        )
      ) {
        missing.push(field);
      }
    }
  }
  return missing;
}

// 视图 / 草稿渠道的最小形态：导入提示只需判断已保存渠道是否缺必填（视图里
// Secrets 恒为空，靠 secrets_set 判断敏感字段是否已配置）。
export interface ChannelCompletenessView {
  type?: string;
  enabled?: boolean;
  config?: Record<string, string> | null;
  secrets_set?: Record<string, boolean> | null;
}

export function channelViewMissingRequiredFields(channel: ChannelCompletenessView): ChannelFieldSpec[] {
  return missingRequiredChannelFields(
    channel.type || "",
    channel.config,
    null,
    channel.secrets_set,
  );
}

// 已启用且必填不全的渠道数（配置导入后的提示与横幅共用）。
export function countEnabledChannelsMissingRequired(
  settings: { notify_channels?: ChannelCompletenessView[] | null } | null | undefined,
): number {
  return (settings?.notify_channels ?? []).filter(
    (channel) => channel.enabled && channelViewMissingRequiredFields(channel).length > 0,
  ).length;
}

// 配置导入后的「N 个通知渠道需要重新填写密钥」提示：导出配置不含密钥，导入后必填
// 项不全的渠道会静默失败。后台导入成功 toast 与刷新节点失败提示共这一处文案，
// 避免两处各拼一遍后逐渐不一致；返回空字符串表示无需提示。
export function missingSecretChannelsNotice(
  settings: { notify_channels?: ChannelCompletenessView[] | null } | null | undefined,
): string {
  const missing = countEnabledChannelsMissingRequired(settings);
  return missing > 0 ? `${missing} 个通知渠道需要重新填写密钥` : "";
}

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

// 单渠道草稿校验：必填为空 / URL 协议 / 端口范围。返回 字段 key → 错误文案。
export function validateChannelDraft(channel: {
  type: NotifyChannelType;
  config: Record<string, string>;
  secrets: Record<string, string>;
  secretsSet: Record<string, boolean>;
}): Record<string, string> {
  const errors: Record<string, string> = {};
  const spec = CHANNEL_TYPE_SPECS[channel.type];
  for (const group of spec.groups) {
    for (const field of group.fields) {
      const value = ((field.secret ? channel.secrets[field.key] : channel.config[field.key]) || "").trim();
      if (!value) {
        if (requiredFieldMissing(field, channel.config[field.key], channel.secrets[field.key], channel.secretsSet[field.key])) {
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
