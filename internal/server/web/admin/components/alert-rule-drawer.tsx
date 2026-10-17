import { useEffect, useState } from "react";
import { AdminDrawer } from "@/components/admin-drawer";
import { adminStatusBadgeClass } from "@/components/admin-data-table";
import {
  AdminGroupedFieldRow,
  AdminGroupedSwitchRow,
} from "@/components/admin-section-panel";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { ChevronsUpDown, Trash2 } from "lucide-react";
import { useAsyncAction } from "@/lib/admin-hooks";
import { previewAlertRule } from "@/lib/admin-api";
import { cn } from "@/lib/utils";
import {
  adminDrawerSectionTitleClass,
  adminFieldErrorClass,
  adminInputClass,
  adminOutlineButtonClass,
  adminPrimaryButtonClass,
  adminSelectContentClass,
  adminSelectTriggerClass,
} from "@/lib/admin-ui";
import { flattenGroupTree, resolveNodeId, resolveNodeName } from "@/lib/admin-format";
import type {
  AlertRulePreviewItem,
  GroupNode,
  NodeView,
  NotifyChannel,
  TestCatalogItem,
} from "@/lib/admin-types";
import {
  ALERT_METRIC_GROUP_LABELS,
  ALERT_METRIC_SPECS,
  OFFLINE_ALERT_RULE_ID,
  alertMetricLabel,
  alertMetricSpec,
  buildRulePayload,
  copyRuleDraft,
  formatRulePreviewValue,
  ruleDurationChoices,
  ruleDurationLabel,
  validateRuleDraft,
  type AlertRuleDraft,
} from "@/lib/alert-rules";

// =====================================================================
// A-01 步骤 1：共享规则抽屉（从 NotificationAlert.tsx 原样抽出）。
// 基础 / 范围 / 通知三张分组卡 + 底部「删除 → 模拟评估 → 完成」+ 模拟评估
// 结果表。「完成」只通过 onDone 回写草稿，真正保存由页面决定；onDelete 不传
// 则不显示删除按钮（内置 offline 规则不传）。
// =====================================================================

export type AlertRuleDrawerProps = {
  open: boolean;
  rule: AlertRuleDraft; // 编辑对象（新建时为预设草稿）
  isNew: boolean;
  nodes: NodeView[];
  groupTree: GroupNode[];
  channels: NotifyChannel[];
  probes: TestCatalogItem[];
  onDone: (draft: AlertRuleDraft) => void; // 「完成」：只回写草稿
  onDelete?: () => void; // 不传则不显示删除（offline 规则不传）
  onClose: () => void;
  lockedNodeId?: string; // 传入时表示「节点抽屉内编辑仅此节点规则」
};

// 渠道类型中文标签（与 NotificationAlert 的 CHANNEL_TYPE_META.label 同一份）。
const CHANNEL_TYPE_LABELS: Record<string, string> = {
  telegram: "Telegram",
  feishu: "飞书",
  bark: "Bark",
  slack: "Slack",
  dingtalk: "钉钉",
  wecom: "企业微信",
  email: "邮件",
};

function channelDisplayName(channel: NotifyChannel): string {
  const name = channel.name?.trim();
  return name || CHANNEL_TYPE_LABELS[channel.type || ""] || channel.type || "";
}

// 抽屉内通用多选（范围节点 / 分组标签、通知渠道）：DropdownMenu + 勾选项，
// 触发按钮显示摘要，无选择时显示占位文案。
// O-01：从本模块抽出为共享「范围选择」子组件（导出）——探测设置抽屉的
// 「下发范围」多选器复用同一实现；组件本体与规则抽屉内的用法不变。
export function RuleMultiSelect({
  id,
  summary,
  emptyText,
  options,
  selected,
  onToggle,
  disabled,
}: {
  id: string;
  summary: string;
  emptyText: string;
  options: Array<{ value: string; label: string; indent?: boolean }>;
  selected: string[];
  onToggle: (value: string, checked: boolean) => void;
  disabled?: boolean;
}) {
  const hasSelection = selected.length > 0;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={(
          <button
            id={id}
            type="button"
            className={cn(
              adminSelectTriggerClass,
              "flex h-9 w-full items-center justify-between gap-2 text-left",
            )}
            disabled={disabled}
          >
            <span className={cn("truncate", !hasSelection && "text-[var(--label-4)]")}>
              {hasSelection ? summary : emptyText}
            </span>
            <ChevronsUpDown aria-hidden="true" className="h-3.5 w-3.5 shrink-0 text-[var(--label-3)]" />
          </button>
        )}
      />
      <DropdownMenuContent align="end" className="w-[min(20rem,calc(100vw-3rem))]">
        {options.length === 0 ? (
          <p className="px-2 py-3 text-center text-xs text-[var(--label-3)]">{emptyText}</p>
        ) : (
          <div className="max-h-64 overflow-y-auto p-1">
            {options.map((option) => (
              <DropdownMenuCheckboxItem
                key={option.value}
                checked={selected.includes(option.value)}
                closeOnClick={false}
                onCheckedChange={(checked) => onToggle(option.value, Boolean(checked))}
                className={option.indent ? "pl-6" : undefined}
              >
                {option.label}
              </DropdownMenuCheckboxItem>
            ))}
          </div>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// F4 规则抽屉「删除」危险文字按钮：规格对齐 adminTextButtonClass，仅换 danger 色
// （admin-ui.ts 不在本批文件范围内，类内联在本组件）。
const adminRuleDangerTextButtonClass =
  "inline-flex h-9 items-center gap-1 rounded-full px-2 text-sm font-medium text-[var(--danger)] outline-none [transition:transform_var(--dur-1),scale_var(--dur-1),background-color_var(--dur-2)] hover:bg-[var(--danger-tint)] active:scale-[0.97] focus-visible:ring-[3px] focus-visible:ring-[var(--primary-ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-transparent disabled:pointer-events-none disabled:opacity-50";

export function AlertRuleDrawer({
  open,
  rule,
  isNew,
  nodes,
  groupTree,
  channels,
  probes,
  onDone,
  onDelete,
  onClose,
  lockedNodeId,
}: AlertRuleDrawerProps) {
  // 抽屉内的独立编辑副本：「完成」才通过 onDone 写回页面草稿。
  const [form, setForm] = useState<AlertRuleDraft>(() => copyRuleDraft(rule));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<AlertRulePreviewItem[] | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const busy = previewing;
  const runAction = useAsyncAction();

  // 打开（或外部换入新规则）时重建编辑副本，与「以列表草稿为准重建表单」的
  // 原行为一致。
  useEffect(() => {
    if (open) {
      setForm(copyRuleDraft(rule));
      setErrors({});
      setPreview(null);
    }
  }, [open, rule]);

  const patchForm = (patch: Partial<AlertRuleDraft>) => {
    setForm((current) => (current ? { ...current, ...patch } : current));
    // 表单变化后上一次「模拟评估」结果已过期。
    setPreview(null);
  };

  const clearErrorField = (field: string) => {
    setErrors((current) => (current[field] ? { ...current, [field]: "" } : current));
  };

  // 抽屉（Sheet portal）挂载可能晚于渲染：双 rAF 后再聚焦校验出错的字段，
  // 仍未挂载时再补一次 120ms 定时重试。
  const focusFieldElement = (elementId: string, attempt = 0) => {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        const element = document.getElementById(elementId);
        if (element instanceof HTMLElement) {
          element.focus();
          return;
        }
        if (attempt < 1) {
          window.setTimeout(() => focusFieldElement(elementId, attempt + 1), 120);
        }
      });
    });
  };

  // 抽屉内校验失败时的统一呈现：写入错误并聚焦第一个出错字段。
  const applyFormErrors = (nextErrors: Record<string, string>): boolean => {
    const keys = Object.keys(nextErrors);
    if (keys.length === 0) {
      return true;
    }
    setErrors(nextErrors);
    focusFieldElement(`alert-rule-${keys[0]}`);
    return false;
  };

  // 「完成」：只回写页面规则草稿（真正保存由页面决定），随后由页面关闭抽屉。
  // lockedNodeId 有值（节点抽屉内）时强制范围 = 仅此节点，且范围校验不再报错。
  const handleDone = () => {
    if (busy) {
      return;
    }
    const draft: AlertRuleDraft = lockedNodeId
      ? {
          ...form,
          scopeMode: "include",
          scopeNodes: [lockedNodeId],
          scopeGroups: [],
          scopeExclude: [],
        }
      : form;
    if (!applyFormErrors(validateRuleDraft(draft))) {
      return;
    }
    onDone(copyRuleDraft(draft));
  };

  // 「删除」：交由页面从草稿移除。
  const handleDelete = () => {
    if (busy) {
      return;
    }
    onDelete?.();
  };

  // 「模拟评估」：用抽屉当前草稿请求 preview，结果内联显示在抽屉底部。
  const handlePreview = () => {
    if (busy) {
      return;
    }
    const current = form;
    if (!applyFormErrors(validateRuleDraft(current))) {
      return;
    }
    setErrors({});
    void runAction({
      action: () => previewAlertRule(buildRulePayload(current)),
      fallbackError: "模拟评估失败",
      setBusy: setPreviewing,
      onSuccess: (data) => {
        setPreview(data.results || []);
      },
    });
  };

  const spec = alertMetricSpec(form.metric);
  const isOfflineRule = form.metric === OFFLINE_ALERT_RULE_ID;
  const ruleErrors = {
    name: errors.name || "",
    threshold: errors.threshold || "",
    probe: errors.probe || "",
    scope: errors.scope || "",
  };
  const showOpControl = spec?.kind === "threshold";
  const showThresholdControl =
    !isOfflineRule && (spec?.kind === "threshold" || form.metric === "traffic_quota");
  const showDurationControl = spec?.kind === "threshold";
  const nodeOptions = nodes
    .map((node) => {
      const id = resolveNodeId(node);
      return { value: id, label: resolveNodeName(node) || id };
    })
    .filter((option) => option.value);
  const groupOptions = flattenGroupTree(groupTree || []).flatMap((entry) => [
    { value: entry.group, label: entry.group },
    ...entry.tags.map((tag) => ({
      value: `${entry.group}:${tag}`,
      label: `${entry.group} / ${tag}`,
      indent: true,
    })),
  ]);
  const channelOptions = channels
    .filter((channel) => channel.enabled)
    .map((channel) => ({
      value: channel.id || "",
      label: `${channelDisplayName(channel)}（${CHANNEL_TYPE_LABELS[channel.type || ""] || channel.type || ""}）`,
    }))
    .filter((option) => option.value);
  const probeOptions = (probes || [])
    .map((item) => item.name)
    .filter(Boolean)
    .map((name) => ({ value: name, label: name }));
  const toggleListValue = (list: string[], value: string, checked: boolean) =>
    checked
      ? [...list, value]
      : list.filter((item) => item !== value);

  return (
    <AdminDrawer
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          onClose();
        }
      }}
      title={
        isOfflineRule ? (
          <span>节点离线</span>
        ) : (
          <span data-admin-i18n-skip={form.name.trim() ? true : undefined}>
            {isNew ? "新增规则" : form.name.trim() || "编辑规则"}
          </span>
        )
      }
      description={
        isOfflineRule ? (
          <span>内置规则：条件由「离线判定时间」决定，不可删除。</span>
        ) : (
          <span className="data-text">{form.id}</span>
        )
      }
      footer={
        <div className="flex flex-wrap items-center gap-2">
          {onDelete ? (
            <button
              type="button"
              className={adminRuleDangerTextButtonClass}
              disabled={busy}
              onClick={handleDelete}
            >
              <Trash2 className="h-4 w-4" />
              删除
            </button>
          ) : null}
          <div className="ml-auto flex gap-2">
            <Button
              type="button"
              variant="outline"
              className={cn(adminOutlineButtonClass, "min-w-[92px] px-4")}
              disabled={busy}
              onClick={handlePreview}
            >
              {previewing ? "评估中…" : "模拟评估"}
            </Button>
            <Button
              type="button"
              className={cn(adminPrimaryButtonClass, "min-w-[84px] px-4")}
              disabled={busy}
              onClick={handleDone}
            >
              完成
            </Button>
          </div>
        </div>
      }
    >
      <section>
        <h3 className={adminDrawerSectionTitleClass}>基础</h3>
        <AdminGroupedFieldRow label="名称" htmlFor="alert-rule-name">
          <div className="w-full space-y-1.5">
            <Input
              id="alert-rule-name"
              name="alert-rule-name"
              autoComplete="off"
              className={`${adminInputClass} w-full`}
              value={form.name}
              placeholder="例如：CPU 使用率过高"
              disabled={busy || isOfflineRule}
              aria-invalid={Boolean(ruleErrors.name)}
              onChange={(event) => {
                patchForm({ name: event.target.value });
                clearErrorField("name");
              }}
            />
            {ruleErrors.name ? (
              <p className={adminFieldErrorClass} aria-live="polite">
                {ruleErrors.name}
              </p>
            ) : null}
          </div>
        </AdminGroupedFieldRow>
        <AdminGroupedFieldRow label="指标" htmlFor="alert-rule-metric">
          <Select
            value={form.metric}
            onValueChange={(next) => {
              if (!next) {
                return;
              }
              const nextSpec = alertMetricSpec(next);
              patchForm({
                metric: next,
                threshold: nextSpec ? nextSpec.defaultThreshold : form.threshold,
                probeName: nextSpec?.needsProbe ? form.probeName : "",
              });
              clearErrorField("threshold");
              clearErrorField("probe");
            }}
          >
            <SelectTrigger
              id="alert-rule-metric"
              size="sm"
              disabled={busy || isOfflineRule}
              className={`${adminSelectTriggerClass} w-full`}
            >
              <SelectValue>{alertMetricLabel(form.metric)}</SelectValue>
            </SelectTrigger>
            <SelectContent className={adminSelectContentClass}>
              {isOfflineRule ? (
                <SelectItem value={OFFLINE_ALERT_RULE_ID}>节点离线</SelectItem>
              ) : (
                (["resource", "network", "probe", "lifecycle"] as const).map(
                  (groupID) => (
                    <SelectGroup key={groupID}>
                      <SelectLabel className="px-2 text-xs text-[var(--label-3)]">
                        {ALERT_METRIC_GROUP_LABELS[groupID]}
                      </SelectLabel>
                      {ALERT_METRIC_SPECS.filter((item) => item.group === groupID).map(
                        (item) => (
                          <SelectItem key={item.value} value={item.value}>
                            {item.label}
                          </SelectItem>
                        ),
                      )}
                    </SelectGroup>
                  ),
                )
              )}
            </SelectContent>
          </Select>
        </AdminGroupedFieldRow>
        {spec?.needsProbe ? (
          <AdminGroupedFieldRow label="探测目标" htmlFor="alert-rule-probe">
            <div className="w-full space-y-1.5">
              {probeOptions.length === 0 ? (
                <p className="text-xs leading-relaxed text-[var(--label-3)]">
                  请先在“探测设置”页配置探测节点。
                </p>
              ) : (
                <Select
                  value={form.probeName}
                  onValueChange={(next) => {
                    patchForm({ probeName: next || "" });
                    clearErrorField("probe");
                  }}
                >
                  <SelectTrigger
                    id="alert-rule-probe"
                    size="sm"
                    disabled={busy}
                    className={`${adminSelectTriggerClass} w-full`}
                  >
                    <SelectValue>{form.probeName || "请选择探测目标…"}</SelectValue>
                  </SelectTrigger>
                  <SelectContent className={adminSelectContentClass}>
                    {probeOptions.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
              {ruleErrors.probe ? (
                <p className={adminFieldErrorClass} aria-live="polite">
                  {ruleErrors.probe}
                </p>
              ) : null}
            </div>
          </AdminGroupedFieldRow>
        ) : null}
        {showThresholdControl ? (
          <AdminGroupedFieldRow label="条件" htmlFor="alert-rule-threshold">
            <div className="flex w-full flex-col gap-1.5 sm:items-end">
              <div className="flex w-full items-center justify-end gap-2">
                {showOpControl ? (
                  <Select
                    value={form.op}
                    onValueChange={(next) => patchForm({ op: next || "gt" })}
                  >
                    <SelectTrigger
                      size="sm"
                      disabled={busy}
                      aria-label="比较符"
                      className={`${adminSelectTriggerClass} w-[76px]`}
                    >
                      <SelectValue>{form.op === "lt" ? "<" : ">"}</SelectValue>
                    </SelectTrigger>
                    <SelectContent className={adminSelectContentClass}>
                      <SelectItem value="gt">&gt;</SelectItem>
                      <SelectItem value="lt">&lt;</SelectItem>
                    </SelectContent>
                  </Select>
                ) : null}
                <Input
                  id="alert-rule-threshold"
                  name="alert-rule-threshold"
                  type="number"
                  min={0}
                  step="any"
                  inputMode="decimal"
                  autoComplete="off"
                  className={`${adminInputClass} tabular-nums w-[96px] text-right`}
                  value={form.threshold}
                  disabled={busy}
                  aria-invalid={Boolean(ruleErrors.threshold)}
                  onChange={(event) => {
                    patchForm({ threshold: event.target.value });
                    clearErrorField("threshold");
                  }}
                />
                <span className="w-12 text-[13px] font-medium text-[var(--label-2)]">
                  {spec?.unit}
                </span>
              </div>
              {ruleErrors.threshold ? (
                <p className={adminFieldErrorClass} aria-live="polite">
                  {ruleErrors.threshold}
                </p>
              ) : null}
            </div>
          </AdminGroupedFieldRow>
        ) : null}
        {showDurationControl ? (
          <AdminGroupedFieldRow label="持续时间" htmlFor="alert-rule-duration">
            <Select
              value={String(form.durationSec)}
              onValueChange={(next) =>
                patchForm({ durationSec: Number(next) || 0 })
              }
            >
              <SelectTrigger
                id="alert-rule-duration"
                size="sm"
                disabled={busy}
                className={`${adminSelectTriggerClass} w-full`}
              >
                <SelectValue>
                  {ruleDurationLabel(form.durationSec)}
                </SelectValue>
              </SelectTrigger>
              <SelectContent className={adminSelectContentClass}>
                {ruleDurationChoices().map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </AdminGroupedFieldRow>
        ) : null}
        {isOfflineRule ? (
          <p className="text-xs leading-relaxed text-[var(--label-3)]">
            条件与持续时间由「离线判定时间」决定，仅可停用或调整范围与渠道。
          </p>
        ) : null}
      </section>

      {lockedNodeId ? null : (
        <section>
          <h3 className={adminDrawerSectionTitleClass}>范围</h3>
          <AdminGroupedFieldRow label="范围" htmlFor="alert-rule-scope">
            <div className="w-full space-y-1.5">
              <Select
                value={form.scopeMode}
                onValueChange={(next) => {
                  patchForm({ scopeMode: next === "include" ? "include" : "all" });
                  clearErrorField("scope");
                }}
              >
                <SelectTrigger
                  id="alert-rule-scope"
                  size="sm"
                  disabled={busy}
                  className={`${adminSelectTriggerClass} w-full`}
                >
                  <SelectValue>
                    {form.scopeMode === "include" ? "指定范围" : "全部节点"}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent className={adminSelectContentClass}>
                  <SelectItem value="all">全部节点</SelectItem>
                  <SelectItem value="include">指定范围</SelectItem>
                </SelectContent>
              </Select>
              {ruleErrors.scope ? (
                <p className={adminFieldErrorClass} aria-live="polite">
                  {ruleErrors.scope}
                </p>
              ) : null}
            </div>
          </AdminGroupedFieldRow>
          {form.scopeMode === "include" ? (
            <>
              <AdminGroupedFieldRow label="指定节点" htmlFor="alert-rule-scope-nodes">
                <RuleMultiSelect
                  id="alert-rule-scope-nodes"
                  summary={`已选 ${form.scopeNodes.length} 个节点`}
                  emptyText={nodeOptions.length === 0 ? "暂无节点" : "未选择"}
                  options={nodeOptions}
                  selected={form.scopeNodes}
                  disabled={busy}
                  onToggle={(value, checked) => {
                    patchForm({
                      scopeNodes: toggleListValue(form.scopeNodes, value, checked),
                    });
                    clearErrorField("scope");
                  }}
                />
              </AdminGroupedFieldRow>
              <AdminGroupedFieldRow label="指定分组" htmlFor="alert-rule-scope-groups">
                <RuleMultiSelect
                  id="alert-rule-scope-groups"
                  summary={`已选 ${form.scopeGroups.length} 项`}
                  emptyText={groupOptions.length === 0 ? "暂无分组" : "未选择"}
                  options={groupOptions}
                  selected={form.scopeGroups}
                  disabled={busy}
                  onToggle={(value, checked) => {
                    patchForm({
                      scopeGroups: toggleListValue(form.scopeGroups, value, checked),
                    });
                    clearErrorField("scope");
                  }}
                />
              </AdminGroupedFieldRow>
            </>
          ) : null}
          <AdminGroupedFieldRow label="排除节点" htmlFor="alert-rule-scope-exclude">
            <RuleMultiSelect
              id="alert-rule-scope-exclude"
              summary={`已选 ${form.scopeExclude.length} 个节点`}
              emptyText={nodeOptions.length === 0 ? "暂无节点" : "未选择"}
              options={nodeOptions}
              selected={form.scopeExclude}
              disabled={busy}
              onToggle={(value, checked) =>
                patchForm({
                  scopeExclude: toggleListValue(form.scopeExclude, value, checked),
                })
              }
            />
          </AdminGroupedFieldRow>
        </section>
      )}

      <section>
        <h3 className={adminDrawerSectionTitleClass}>通知</h3>
        <AdminGroupedFieldRow
          label="渠道"
          htmlFor="alert-rule-channels"
          hint="留空 = 全部已启用渠道。"
        >
          <RuleMultiSelect
            id="alert-rule-channels"
            summary={`已选 ${form.channelIds.length} 项`}
            emptyText="全部已启用渠道"
            options={channelOptions}
            selected={form.channelIds}
            disabled={busy}
            onToggle={(value, checked) =>
              patchForm({
                channelIds: toggleListValue(form.channelIds, value, checked),
              })
            }
          />
        </AdminGroupedFieldRow>
        <AdminGroupedSwitchRow
          label="恢复时通知"
          htmlFor="alert-rule-notify-recover"
          hint="指标恢复正常时发送恢复通知。"
        >
          <Switch
            id="alert-rule-notify-recover"
            checked={form.notifyRecover}
            disabled={busy || isOfflineRule}
            onCheckedChange={(checked) =>
              patchForm({ notifyRecover: Boolean(checked) })
            }
          />
        </AdminGroupedSwitchRow>
        <AdminGroupedFieldRow label="重复提醒" htmlFor="alert-rule-repeat">
          <Select
            value={form.repeat}
            onValueChange={(next) =>
              patchForm({ repeat: next === "backoff" ? "backoff" : "once" })
            }
          >
            <SelectTrigger
              id="alert-rule-repeat"
              size="sm"
              disabled={busy || isOfflineRule}
              className={`${adminSelectTriggerClass} w-full`}
            >
              <SelectValue>
                {form.repeat === "backoff" ? "递增间隔重复" : "仅一次"}
              </SelectValue>
            </SelectTrigger>
            <SelectContent className={adminSelectContentClass}>
              <SelectItem value="once">仅一次</SelectItem>
              <SelectItem value="backoff">递增间隔重复</SelectItem>
            </SelectContent>
          </Select>
        </AdminGroupedFieldRow>
      </section>

      {preview !== null ? (
        // 「模拟评估」结果：内联表格（节点 | 当前值 | 状态）。
        <section>
          <h3 className={adminDrawerSectionTitleClass}>模拟评估</h3>
          {preview.length === 0 ? (
            <p className="text-[13px] text-[var(--label-3)]">没有适用节点。</p>
          ) : (
            <table className="w-full text-[13px]">
              <thead>
                <tr className="text-left text-[var(--label-3)] [font:var(--t-caption)]">
                  <th className="pb-2 pr-3 font-medium">节点</th>
                  <th className="pb-2 pr-3 font-medium">当前值</th>
                  <th className="pb-2 font-medium">状态</th>
                </tr>
              </thead>
              <tbody>
                {preview.map((item) => (
                  <tr key={item.node_id} className="border-t border-[var(--hairline)]">
                    <td
                      className="py-2 pr-3 text-[var(--label-1)]"
                      data-admin-i18n-skip={true}
                    >
                      {item.name || item.node_id}
                    </td>
                    <td className="py-2 pr-3 data-text text-[var(--label-2)]">
                      {formatRulePreviewValue(form.metric, item.value)}
                    </td>
                    <td className="py-2">
                      {item.state === "fail" ? (
                        <span className={adminStatusBadgeClass("danger")}>告警</span>
                      ) : item.state === "pass" ? (
                        <span className={adminStatusBadgeClass("ok")}>正常</span>
                      ) : (
                        <span className="text-[var(--label-3)]">未知</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      ) : null}
    </AdminDrawer>
  );
}
