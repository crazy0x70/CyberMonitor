import type { AdminPage } from "@/lib/admin-format";

export type AdminSectionItem = { id: string; label: string };

// 设置类页面分区的唯一定义（evolution_log.md 第 4 节最终版菜单）：
// 侧栏二级导航与页面内单分区视图共用这一份，勿在页面里另写一份。
// ai 页（运维助手）已改为无子菜单单页，不再登记分区。
export const ADMIN_PAGE_SECTIONS: Readonly<
  Partial<Record<AdminPage, readonly AdminSectionItem[]>>
> = {
  settings: [
    { id: "credentials", label: "入口凭证" },
    { id: "security", label: "安全设置" },
    { id: "agent", label: "接入配置" },
    { id: "site", label: "站点展示" },
    { id: "system", label: "系统信息" },
  ],
  alerts: [
    { id: "policy", label: "告警策略" },
    { id: "channels", label: "渠道设置" },
  ],
};

// 旧地址兼容（evolution_log.md 第 4 节）：分区合并后，历史 section 参数 / 锚点
// 经此别名表映射到新分区；旧链接（收藏夹、文档）继续可用。
const LEGACY_SECTION_ALIASES: Readonly<
  Partial<Record<AdminPage, Readonly<Record<string, string>>>>
> = {
  settings: {
    oauth: "security",
    bruteforce: "security",
    turnstile: "security",
    update: "system",
    backup: "system",
  },
  alerts: {
    telegram: "channels",
    feishu: "channels",
  },
};

export function adminPageSections(page: AdminPage): readonly AdminSectionItem[] {
  return ADMIN_PAGE_SECTIONS[page] || [];
}

export function hasAdminPageSections(page: AdminPage): boolean {
  return adminPageSections(page).length > 0;
}

// 单个候选值（section 参数或锚点后缀）→ 新分区 id；无效返回 null。
function normalizeSectionCandidate(page: AdminPage, value: string | null | undefined) {
  const sections = adminPageSections(page);
  const candidate = String(value || "").trim();
  if (sections.some((item) => item.id === candidate)) {
    return candidate;
  }
  const aliased = LEGACY_SECTION_ALIASES[page]?.[candidate];
  if (aliased && sections.some((item) => item.id === aliased)) {
    return aliased;
  }
  return null;
}

// 解析分区：优先 section 查询参数；旧分区 id 经 LEGACY_SECTION_ALIASES 映射；
// 兼容旧锚点 #settings-oauth（同样过别名表）；非法或缺省回落该页第一个分区；
// 页面无分区时返回 null（?page=ai&section=xxx 的 section 直接忽略）。
export function resolveAdminSection(
  page: AdminPage,
  rawSection: string | null | undefined,
  hash = "",
): string | null {
  const sections = adminPageSections(page);
  if (!sections.length) {
    return null;
  }
  const direct = normalizeSectionCandidate(page, rawSection);
  if (direct) {
    return direct;
  }
  const legacyAnchor = String(hash || "").replace(/^#/, "").trim();
  const anchorPrefix = `${page}-`;
  if (legacyAnchor.startsWith(anchorPrefix)) {
    const anchored = normalizeSectionCandidate(page, legacyAnchor.slice(anchorPrefix.length));
    if (anchored) {
      return anchored;
    }
  }
  return sections[0].id;
}
