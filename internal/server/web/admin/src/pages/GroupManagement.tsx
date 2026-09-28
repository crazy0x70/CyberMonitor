import { useMemo, useState } from "react";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminDataTable, type AdminDataTableColumn } from "@/components/admin-data-table";
import { AdminDrawer } from "@/components/admin-drawer";
import { AdminKVField } from "@/components/admin-kv-field";
import { AdminMetricStrip } from "@/components/admin-metric-strip";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  ArrowDown,
  ArrowUp,
  FolderTree,
  Plus,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import {
  adminActionButtonClass,
  adminDirtyBadgeClass,
  adminDangerIconButtonClass,
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminNeutralBadgeClass,
  adminOutlineButtonClass,
  adminPageShellClass,
  adminPrimaryButtonClass,
  adminStatEyebrowClass,
  adminSubtleOutlineBadgeClass,
  adminWideInputClass,
} from "@/lib/admin-ui";
import { useAsyncAction, useDirtyNotification, useDraftReconcile } from "@/lib/admin-hooks";
import { resolveNodeSelections } from "@/lib/admin-format";
import type { GroupNode, NodeView, SettingsView } from "@/lib/admin-types";

export interface GroupManagementProps {
  groupTree: GroupNode[];
  nodes: NodeView[];
  onDirtyChange?: (dirty: boolean) => void;
  saving?: boolean;
  onSave: (groupTree: GroupNode[]) => Promise<SettingsView>;
}

type ValidationIssue = {
  key: string;
  message: string;
  target?: {
    groupIndex: number;
    tagIndex?: number;
  };
};

type DraftTreeAnalysis = {
  validationIssues: ValidationIssue[];
  validationLookup: {
    groupErrors: Record<string, string>;
    tagErrors: Record<string, string>;
  };
  generalValidationMessage: string;
  summary: {
    totalGroups: number;
    totalTags: number;
  };
};

type EditableTagNode = {
  id: string;
  name: string;
};

type EditableGroupNode = {
  id: string;
  name: string;
  children: EditableTagNode[];
};

let editableNodeCounter = 0;

function createEditableID(prefix: "group" | "tag") {
  editableNodeCounter += 1;
  return `${prefix}-${editableNodeCounter}`;
}

function createEmptyEditableGroup(): EditableGroupNode {
  return {
    id: createEditableID("group"),
    name: "",
    children: [],
  };
}

function createEmptyEditableTag(): EditableTagNode {
  return {
    id: createEditableID("tag"),
    name: "",
  };
}

function updateItemAt<T>(items: T[], index: number, updater: (item: T) => T): T[] {
  return items.map((item, currentIndex) =>
    currentIndex === index ? updater(item) : item,
  );
}

function removeItemAt<T>(items: T[], index: number): T[] {
  return items.filter((_, currentIndex) => currentIndex !== index);
}

function moveItemAt<T>(items: T[], index: number, offset: -1 | 1): T[] {
  const target = index + offset;
  if (target < 0 || target >= items.length) {
    return items;
  }
  const next = [...items];
  const [moved] = next.splice(index, 1);
  next.splice(target, 0, moved);
  return next;
}

function updateGroupChildren(
  tree: EditableGroupNode[],
  groupIndex: number,
  updater: (children: EditableTagNode[]) => EditableTagNode[],
): EditableGroupNode[] {
  return updateItemAt(tree, groupIndex, (group) => ({
    ...group,
    children: updater(group.children || []),
  }));
}

function toEditableTree(tree: GroupNode[]): EditableGroupNode[] {
  return Array.isArray(tree)
    ? tree.map((group) => ({
        id: createEditableID("group"),
        name: String(group?.name ?? ""),
        children: Array.isArray(group?.children)
          ? group.children.map((tag) => ({
              id: createEditableID("tag"),
              name: String(tag?.name ?? ""),
            }))
          : [],
      }))
    : [];
}

function normalizeGroupTree(tree: EditableGroupNode[]): GroupNode[] {
  const seenGroups = new Set<string>();

  return tree
    .map((group) => ({
      name: String(group.name || "").trim(),
      children: (group.children || []).map((tag) => ({
        name: String(tag.name || "").trim(),
      })),
    }))
    .filter((group) => {
      if (!group.name || group.name === "全部" || seenGroups.has(group.name)) {
        return false;
      }
      seenGroups.add(group.name);
      return true;
    })
    .map((group) => {
      const seenTags = new Set<string>();
      return {
        name: group.name,
        children: group.children.filter((tag) => {
          if (!tag.name || tag.name === "全部" || seenTags.has(tag.name)) {
            return false;
          }
          seenTags.add(tag.name);
          return true;
        }),
      };
    });
}

function serializeEditableTree(tree: EditableGroupNode[]) {
  return JSON.stringify(
    tree.map((group) => ({
      name: String(group.name || ""),
      children: (group.children || []).map((tag) => ({
        name: String(tag.name || ""),
      })),
    })),
  );
}

const RESERVED_GROUP_NAMES = new Set(["全部", "ALL", "C&R"]);

function analyzeDraftTree(tree: EditableGroupNode[]): DraftTreeAnalysis {
  const validationIssues: ValidationIssue[] = [];
  const groupErrors: Record<string, string> = {};
  const tagErrors: Record<string, string> = {};
  const seenGroups = new Set<string>();
  let totalGroups = 0;
  let totalTags = 0;

  if (tree.length === 0) {
    validationIssues.push({
      key: "group-empty",
      message: "至少需要保留一个一级分组。",
    });
  }

  tree.forEach((group, groupIndex) => {
    const groupName = String(group.name || "").trim();
    const groupLabel = groupName || `第 ${groupIndex + 1} 个一级分组`;

    if (groupName) {
      totalGroups += 1;
    }

    if (!groupName) {
      const message = `${groupLabel} 名称不能为空。`;
      validationIssues.push({
        key: `group-name-${groupIndex}`,
        message,
        target: { groupIndex },
      });
      groupErrors[String(groupIndex)] = message;
    } else if (RESERVED_GROUP_NAMES.has(groupName)) {
      const message = "一级分组名称与展示页固定标签冲突，请换一个名称。";
      validationIssues.push({
        key: `group-reserved-${groupIndex}`,
        message,
        target: { groupIndex },
      });
      groupErrors[String(groupIndex)] = message;
    } else if (groupName.includes(":") || groupName.includes("/")) {

      const message = "一级分组名称不能包含“:”或“/”。";
      validationIssues.push({
        key: `group-separator-${groupIndex}`,
        message,
        target: { groupIndex },
      });
      groupErrors[String(groupIndex)] = message;
    } else if (seenGroups.has(groupName)) {
      const message = `一级分组“${groupName}”重复，请保留唯一名称。`;
      validationIssues.push({
        key: `group-duplicate-${groupIndex}`,
        message,
        target: { groupIndex },
      });
      groupErrors[String(groupIndex)] = message;
    } else {
      seenGroups.add(groupName);
    }

    const seenTags = new Set<string>();
    (group.children || []).forEach((tag, tagIndex) => {
      const tagName = String(tag.name || "").trim();
      if (tagName) {
        totalTags += 1;
      }

      if (!tagName) {
        const message = `${groupLabel} 下第 ${tagIndex + 1} 个标签名称不能为空。`;
        validationIssues.push({
          key: `tag-name-${groupIndex}-${tagIndex}`,
          message,
          target: { groupIndex, tagIndex },
        });
        tagErrors[`${groupIndex}-${tagIndex}`] = message;
        return;
      }

      if (RESERVED_GROUP_NAMES.has(tagName)) {
        const message = `${groupLabel} 下的标签与展示页固定标签冲突，请换一个名称。`;
        validationIssues.push({
          key: `tag-reserved-${groupIndex}-${tagIndex}`,
          message,
          target: { groupIndex, tagIndex },
        });
        tagErrors[`${groupIndex}-${tagIndex}`] = message;
        return;
      }

      if (seenTags.has(tagName)) {
        const message = `${groupLabel} 下标签“${tagName}”重复，请保留唯一名称。`;
        validationIssues.push({
          key: `tag-duplicate-${groupIndex}-${tagIndex}`,
          message,
          target: { groupIndex, tagIndex },
        });
        tagErrors[`${groupIndex}-${tagIndex}`] = message;
        return;
      }

      seenTags.add(tagName);
    });
  });

  return {
    validationIssues,
    validationLookup: { groupErrors, tagErrors },
    generalValidationMessage:
      validationIssues.find((issue) => !issue.target)?.message || "",
    summary: {
      totalGroups,
      totalTags,
    },
  };
}

type GroupLedgerRow =
  | {
      kind: "group";
      id: string;
      groupIndex: number;
      group: EditableGroupNode;
      tagCount: number;
      nodeCount: number;
      order: number;
    }
  | {
      kind: "tag";
      id: string;
      groupIndex: number;
      tagIndex: number;
      tag: EditableTagNode;
      groupName: string;
      nodeCount: number;
    };

export default function GroupManagement({
  groupTree,
  nodes,
  onDirtyChange,
  saving = false,
  onSave,
}: GroupManagementProps) {
  const incomingTree = useMemo(() => toEditableTree(groupTree), [groupTree]);
  const incomingSignature = useMemo(() => serializeEditableTree(incomingTree), [incomingTree]);
  const [draftTree, setDraftTree] = useState<EditableGroupNode[]>(incomingTree);
  const [isSaving, setIsSaving] = useState(false);

  const [editingGroupId, setEditingGroupId] = useState<string | null>(null);
  const [editingTagId, setEditingTagId] = useState<string | null>(null);
  const isBusy = isSaving || saving;

  const draftSignature = useMemo(() => serializeEditableTree(draftTree), [draftTree]);

  const [absorbedSignature, absorbSourceSignature] = useDraftReconcile({
    draftSignature,
    nextSourceSignature: incomingSignature,
    isBusy,
    resetDraft: () => setDraftTree(incomingTree),
    warningText: "服务端分组配置已更新，当前未保存修改已保留。",
  });
  const isDirty = absorbedSignature !== draftSignature;
  useDirtyNotification(onDirtyChange, isDirty);

  const draftTreeAnalysis = useMemo(() => analyzeDraftTree(draftTree), [draftTree]);
  const {
    validationIssues,
    validationLookup,
    generalValidationMessage,
    summary,
  } = draftTreeAnalysis;

  const usageStats = useMemo(() => {
    const groupCount = new Map<string, number>();
    const tagCount = new Map<string, number>();
    let assignedNodes = 0;

    nodes.forEach((node) => {
      const selections = resolveNodeSelections(node);
      if (selections.length > 0) {
        assignedNodes += 1;
      }

      const seenGroups = new Set<string>();
      const seenTags = new Set<string>();

      selections.forEach((selection) => {
        if (!seenGroups.has(selection.group)) {
          groupCount.set(selection.group, (groupCount.get(selection.group) || 0) + 1);
          seenGroups.add(selection.group);
        }

        if (selection.tag) {
          const tagKey = `${selection.group}::${selection.tag}`;
          if (!seenTags.has(tagKey)) {
            tagCount.set(tagKey, (tagCount.get(tagKey) || 0) + 1);
            seenTags.add(tagKey);
          }
        }
      });
    });

    return {
      assignedNodes,
      groupCount,
      tagCount,
      ungroupedNodes: Math.max(0, nodes.length - assignedNodes),
    };
  }, [nodes]);

  const metricItems = [
    { label: "一级分组", value: summary.totalGroups },
    { label: "二级标签", value: summary.totalTags },
    { label: "节点归属", value: usageStats.assignedNodes },
  ] as const;

  const ledgerRows = useMemo<GroupLedgerRow[]>(() => {
    const rows: GroupLedgerRow[] = [];
    draftTree.forEach((group, groupIndex) => {
      const groupName = String(group.name || "").trim();
      const tags = group.children || [];
      rows.push({
        kind: "group",
        id: group.id,
        groupIndex,
        group,
        tagCount: tags.filter((tag) => String(tag.name || "").trim()).length,
        nodeCount: groupName ? usageStats.groupCount.get(groupName) || 0 : 0,
        order: groupIndex + 1,
      });
      tags.forEach((tag, tagIndex) => {
        const tagName = String(tag.name || "").trim();
        rows.push({
          kind: "tag",
          id: tag.id,
          groupIndex,
          tagIndex,
          tag,
          groupName,
          nodeCount:
            groupName && tagName
              ? usageStats.tagCount.get(`${groupName}::${tagName}`) || 0
              : 0,
        });
      });
    });
    return rows;
  }, [draftTree, usageStats]);

  const ledgerColumns: ReadonlyArray<AdminDataTableColumn<GroupLedgerRow>> = [
    {
      key: "name",
      label: "名称",
      render: (row) =>
        row.kind === "group" ? (
          <span className="text-sm font-medium text-slate-900 dark:text-neutral-50">
            {String(row.group.name || "").trim() || "未命名分组"}
          </span>
        ) : (
          <span className="pl-5 text-sm text-slate-600 dark:text-neutral-300">
            {String(row.tag.name || "").trim() || "未命名标签"}
          </span>
        ),
    },
    {
      key: "type",
      label: "类型",
      render: (row) =>
        row.kind === "group" ? (
          <Badge variant="outline" className={adminSubtleOutlineBadgeClass}>
            一级分组
          </Badge>
        ) : (
          <Badge variant="secondary" className={adminNeutralBadgeClass}>
            二级标签
          </Badge>
        ),
    },
    {
      key: "tags",
      label: "标签数",
      align: "right",
      mono: true,
      width: "12%",
      render: (row) => (row.kind === "group" ? row.tagCount : "--"),
    },
    {
      key: "nodes",
      label: "节点数",
      align: "right",
      mono: true,
      width: "12%",
      render: (row) => row.nodeCount,
    },
    {
      key: "order",
      label: "排序",
      align: "right",
      mono: true,
      width: "10%",
      render: (row) => (row.kind === "group" ? row.order : "--"),
    },
  ];

  const editingGroupIndex = editingGroupId
    ? draftTree.findIndex((group) => group.id === editingGroupId)
    : -1;
  const editingGroup = editingGroupIndex >= 0 ? draftTree[editingGroupIndex] : null;
  const editingTagGroupIndex = editingTagId
    ? draftTree.findIndex((group) =>
        (group.children || []).some((tag) => tag.id === editingTagId),
      )
    : -1;
  const editingTagGroup =
    editingTagGroupIndex >= 0 ? draftTree[editingTagGroupIndex] : null;
  const editingTagIndex =
    editingTagGroup && editingTagId
      ? (editingTagGroup.children || []).findIndex((tag) => tag.id === editingTagId)
      : -1;
  const editingTag =
    editingTagGroup && editingTagIndex >= 0
      ? editingTagGroup.children[editingTagIndex]
      : null;

  const updateDraftTree = (updater: (current: EditableGroupNode[]) => EditableGroupNode[]) => {
    if (isBusy) {
      return;
    }
    setDraftTree(updater);
  };

  const updateDraftGroup = (
    groupIndex: number,
    updater: (group: EditableGroupNode) => EditableGroupNode,
  ) => {
    updateDraftTree((current) => updateItemAt(current, groupIndex, updater));
  };

  const updateDraftTags = (
    groupIndex: number,
    updater: (children: EditableTagNode[]) => EditableTagNode[],
  ) => {
    updateDraftTree((current) => updateGroupChildren(current, groupIndex, updater));
  };

  const finishSave = (next: SettingsView, fallbackTree: GroupNode[]) => {
    const canonicalTree = Array.isArray(next.group_tree) ? next.group_tree : fallbackTree;
    const nextDraftTree = toEditableTree(canonicalTree);
    setDraftTree(nextDraftTree);
    absorbSourceSignature(serializeEditableTree(nextDraftTree));
    toast.success("分组配置已保存。");
  };

  const updateGroupName = (groupIndex: number, value: string) => {
    updateDraftGroup(groupIndex, (group) => ({
      ...group,
      name: value,
    }));
  };

  const updateTagName = (groupIndex: number, tagIndex: number, value: string) => {
    updateDraftTags(groupIndex, (children) =>
      updateItemAt(children, tagIndex, (tag) => ({
        ...tag,
        name: value,
      })),
    );
  };

  const addGroup = () => {
    const group = createEmptyEditableGroup();
    updateDraftTree((current) => [...current, group]);
    setEditingGroupId(group.id);
    setEditingTagId(null);
  };

  const addTag = (groupIndex: number) => {
    updateDraftTags(groupIndex, (children) => [...children, createEmptyEditableTag()]);
  };

  const removeGroup = (groupIndex: number) => {
    updateDraftTree((current) => removeItemAt(current, groupIndex));
    setEditingGroupId(null);
  };

  const removeTag = (groupIndex: number, tagIndex: number) => {
    updateDraftTags(groupIndex, (children) => removeItemAt(children, tagIndex));
  };

  const moveGroup = (groupIndex: number, offset: -1 | 1) => {
    updateDraftTree((current) => moveItemAt(current, groupIndex, offset));
  };

  const runAction = useAsyncAction();

  const handleSave = () => {
    if (isBusy) {
      return;
    }
    if (validationIssues.length > 0) {
      const firstIssue = validationIssues[0];
      const target = firstIssue.target;
      if (target) {

        const targetGroup = draftTree[target.groupIndex];
        if (targetGroup) {
          const tagIndex = typeof target.tagIndex === "number" ? target.tagIndex : null;
          const targetTag =
            tagIndex !== null ? targetGroup.children?.[tagIndex] : undefined;
          setEditingTagId(targetTag?.id ?? null);
          setEditingGroupId(targetTag ? null : targetGroup.id);
          window.setTimeout(() => {
            const targetID =
              typeof target.tagIndex === "number"
                ? `group-tag-name-${target.groupIndex}-${target.tagIndex}`
                : `group-name-${target.groupIndex}`;
            const element = document.getElementById(targetID);
            if (element instanceof HTMLElement) {
              element.focus();
            }
          }, 250);
        }
      }
      return;
    }

    const nextTree = normalizeGroupTree(draftTree);

    if (nextTree.length === 0 && draftTree.length > 0) {
      toast.error("分组条目无效：请检查空白、重名或保留名（如“全部”）。");
      return;
    }

    void runAction({
      action: () => onSave(nextTree),
      fallbackError: "保存分组失败。",
      onSuccess: (savedSettings) => finishSave(savedSettings, nextTree),
      setBusy: setIsSaving,
    });
  };

  const editingGroupUsage = editingGroup
    ? usageStats.groupCount.get(String(editingGroup.name || "").trim()) || 0
    : 0;
  const editingTagUsage =
    editingTag && editingTagGroup
      ? usageStats.tagCount.get(
          `${String(editingTagGroup.name || "").trim()}::${String(editingTag.name || "").trim()}`,
        ) || 0
      : 0;

  return (
    <div className={adminPageShellClass}>
      <AdminPageHeader
        as="section"
        title="分组管理"
        actions={
          <>
            {isDirty ? (
              <span className={adminDirtyBadgeClass}>有未保存的修改</span>
            ) : null}
            <Button
              variant="outline"
              className={`${adminActionButtonClass} h-9 min-w-[140px] px-4 font-medium`}
              onClick={addGroup}
              disabled={isBusy}
            >
              <Plus className="mr-2 h-4 w-4" />
              新建分组
            </Button>
            <Button
              className={`${adminPrimaryButtonClass} h-9 px-4 font-medium`}
              onClick={handleSave}
              disabled={!isDirty || isBusy}
            >
              {isBusy ? "保存中…" : "保存更改"}
            </Button>
          </>
        }
      />

      <AdminMetricStrip ariaLabel="分组统计" items={metricItems} />

      <AdminPanel
        title="分组列表"
        icon={<FolderTree className="h-4 w-4 text-[var(--label-3)]" />}
      >
        { }
        {generalValidationMessage && draftTree.length > 0 ? (
          <div className="pb-4">
            <div
              className="rounded-[1rem] border border-rose-200 bg-rose-50 px-4 py-2 text-sm font-medium text-rose-600 dark:border-rose-900/60 dark:bg-rose-950/40 dark:text-rose-300"
              aria-live="polite"
            >
              {generalValidationMessage}
            </div>
          </div>
        ) : null}
        <AdminDataTable
          ariaLabel="分组列表"
          columns={ledgerColumns}
          rows={ledgerRows}
          rowKey={(row) => row.id}
          onRowClick={(row) => {
            if (row.kind === "group") {
              setEditingGroupId(row.id);
              setEditingTagId(null);
            } else {
              setEditingTagId(row.id);
              setEditingGroupId(null);
            }
          }}
          emptyLabel="还没有一级分组，点击右上角「新建分组」开始。"
        />
      </AdminPanel>

      {editingGroup && editingGroupIndex >= 0 ? (
        <AdminDrawer
          open
          onOpenChange={(open) => {
            if (!open) {
              setEditingGroupId(null);
            }
          }}
          title={
            String(editingGroup.name || "").trim() || "未命名分组"
          }
          description={`一级分组 · 第 ${editingGroupIndex + 1} 位 / 共 ${draftTree.length} 个分组`}
          footer={
            <div className="flex items-center justify-between gap-2">
              <AlertDialog>
                <AlertDialogTrigger
                  className={adminDangerIconButtonClass}
                  disabled={isBusy}
                  type="button"
                  aria-label="删除一级分组"
                >
                  <Trash2 className="h-4 w-4" />
                </AlertDialogTrigger>
                <AlertDialogContent className={adminDialogContentClass}>
                  <AlertDialogHeader className={adminDialogHeaderClass}>
                    <AlertDialogTitle>确认删除一级分组？</AlertDialogTitle>
                  </AlertDialogHeader>
                  <AlertDialogFooter className={adminDialogFooterClass}>
                    <AlertDialogCancel className={adminDialogCancelClass}>取消</AlertDialogCancel>
                    <AlertDialogAction
                      className={adminDialogDangerActionClass}
                      disabled={isBusy}
                      onClick={() => removeGroup(editingGroupIndex)}
                    >
                      确认删除
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
              <Button
                variant="outline"
                className={adminOutlineButtonClass}
                onClick={() => setEditingGroupId(null)}
                disabled={isBusy}
              >
                关闭
              </Button>
            </div>
          }
        >
          <section>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
              分组信息
            </h3>
            <AdminKVField label="名称" htmlFor={`group-name-${editingGroupIndex}`}>
              <div className="space-y-2">
                <Input
                  id={`group-name-${editingGroupIndex}`}
                  name={`group-name-${editingGroupIndex}`}
                  autoComplete="off"
                  value={editingGroup.name}
                  placeholder="例如：美国、香港、日本…"
                  className={adminWideInputClass}
                  aria-invalid={Boolean(validationLookup.groupErrors[String(editingGroupIndex)])}
                  aria-describedby={
                    validationLookup.groupErrors[String(editingGroupIndex)]
                      ? `group-name-${editingGroupIndex}-error`
                      : undefined
                  }
                  disabled={isBusy}
                  onChange={(event) => updateGroupName(editingGroupIndex, event.target.value)}
                />
                {validationLookup.groupErrors[String(editingGroupIndex)] ? (
                  <p
                    id={`group-name-${editingGroupIndex}-error`}
                    className="text-xs font-medium text-rose-500"
                    aria-live="polite"
                  >
                    {validationLookup.groupErrors[String(editingGroupIndex)]}
                  </p>
                ) : null}
              </div>
            </AdminKVField>
            <AdminKVField label="类型">
              <Badge variant="outline" className={adminSubtleOutlineBadgeClass}>
                一级分组
              </Badge>
            </AdminKVField>
            <AdminKVField label="上级分组">
              <span className="text-sm text-[var(--label-3)]">—（顶级）</span>
            </AdminKVField>
            <AdminKVField label="节点归属">
              <span className="data-text text-sm text-slate-700 dark:text-neutral-200">
                {`${editingGroupUsage} 个节点`}
              </span>
            </AdminKVField>
            <AdminKVField label="排序">
              <div className="flex flex-wrap items-center gap-2">
                <span className="data-text text-sm text-slate-700 dark:text-neutral-200">
                  {`第 ${editingGroupIndex + 1} / ${draftTree.length} 位`}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  className={compactOutlineActionClass}
                  onClick={() => moveGroup(editingGroupIndex, -1)}
                  disabled={isBusy || editingGroupIndex === 0}
                >
                  <ArrowUp className="mr-1 h-4 w-4" />
                  上移
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className={compactOutlineActionClass}
                  onClick={() => moveGroup(editingGroupIndex, 1)}
                  disabled={isBusy || editingGroupIndex === draftTree.length - 1}
                >
                  <ArrowDown className="mr-1 h-4 w-4" />
                  下移
                </Button>
              </div>
            </AdminKVField>
          </section>

          <section>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
              二级标签
            </h3>
            {(editingGroup.children || []).length === 0 ? (
              <p className="text-sm text-[var(--label-3)]">暂无二级标签</p>
            ) : (
              <div className="divide-y divide-[var(--separator)]">
                {(editingGroup.children || []).map((tag, tagIndex) => {
                  const tagName = String(tag.name || "").trim();
                  const tagKey =
                    String(editingGroup.name || "").trim() && tagName
                      ? `${String(editingGroup.name || "").trim()}::${tagName}`
                      : "";
                  const tagUsageCount = tagKey ? usageStats.tagCount.get(tagKey) || 0 : 0;

                  return (
                    <div key={tag.id} className="flex items-center gap-3 py-2 first:pt-0 last:pb-0">
                      <div className="min-w-0 flex-1 space-y-2">
                        <Input
                          id={`group-tag-name-${editingGroupIndex}-${tagIndex}`}
                          name={`group-tag-name-${editingGroupIndex}-${tagIndex}`}
                          autoComplete="off"
                          value={tag.name}
                          placeholder="例如：CN2、BGP、GIA…"
                          className="h-9 w-full rounded-xl border-[var(--cm-control-border)] bg-[var(--cm-control-bg)] text-sm text-slate-900 placeholder:text-slate-500 dark:placeholder:text-neutral-400 dark:text-neutral-100"
                          aria-invalid={Boolean(
                            validationLookup.tagErrors[`${editingGroupIndex}-${tagIndex}`],
                          )}
                          aria-describedby={
                            validationLookup.tagErrors[`${editingGroupIndex}-${tagIndex}`]
                              ? `group-tag-name-${editingGroupIndex}-${tagIndex}-error`
                              : undefined
                          }
                          disabled={isBusy}
                          onChange={(event) =>
                            updateTagName(editingGroupIndex, tagIndex, event.target.value)
                          }
                        />
                        {validationLookup.tagErrors[`${editingGroupIndex}-${tagIndex}`] ? (
                          <p
                            id={`group-tag-name-${editingGroupIndex}-${tagIndex}-error`}
                            className="text-xs font-medium text-rose-500"
                            aria-live="polite"
                          >
                            {validationLookup.tagErrors[`${editingGroupIndex}-${tagIndex}`]}
                          </p>
                        ) : null}
                      </div>

                      <Badge
                        variant="outline"
                        className={`${adminSubtleOutlineBadgeClass} data-text shrink-0`}
                      >
                        {`${tagUsageCount} 个节点`}
                      </Badge>

                      <Button
                        variant="ghost"
                        size="icon"
                        className={`${adminDangerIconButtonClass} h-9 w-9 shrink-0`}
                        onClick={() => removeTag(editingGroupIndex, tagIndex)}
                        disabled={isBusy}
                        aria-label="删除标签"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  );
                })}
              </div>
            )}
            <div>
              <Button
                variant="outline"
                size="sm"
                className={compactOutlineActionClass}
                onClick={() => addTag(editingGroupIndex)}
                disabled={isBusy}
              >
                <Plus className="mr-1 h-4 w-4" />
                添加标签
              </Button>
            </div>
          </section>
        </AdminDrawer>
      ) : null}

      {editingTag && editingTagGroup && editingTagGroupIndex >= 0 && editingTagIndex >= 0 ? (
        <AdminDrawer
          open
          onOpenChange={(open) => {
            if (!open) {
              setEditingTagId(null);
            }
          }}
          title={String(editingTag.name || "").trim() || "未命名标签"}
          description={`二级标签 · 所属分组 ${
            String(editingTagGroup.name || "").trim() || "未命名分组"
          }`}
          footer={
            <div className="flex items-center justify-between gap-2">
              <Button
                variant="ghost"
                size="icon"
                className={adminDangerIconButtonClass}
                disabled={isBusy}
                type="button"
                aria-label="删除标签"
                onClick={() => removeTag(editingTagGroupIndex, editingTagIndex)}
              >
                <Trash2 className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                className={adminOutlineButtonClass}
                onClick={() => setEditingTagId(null)}
                disabled={isBusy}
              >
                关闭
              </Button>
            </div>
          }
        >
          <section>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-neutral-50">
              标签信息
            </h3>
            <AdminKVField label="名称" htmlFor={`group-tag-name-${editingTagGroupIndex}-${editingTagIndex}`}>
              <div className="space-y-2">
                <Input
                  id={`group-tag-name-${editingTagGroupIndex}-${editingTagIndex}`}
                  name={`group-tag-name-${editingTagGroupIndex}-${editingTagIndex}`}
                  autoComplete="off"
                  value={editingTag.name}
                  placeholder="例如：CN2、BGP、GIA…"
                  className={adminWideInputClass}
                  aria-invalid={Boolean(
                    validationLookup.tagErrors[`${editingTagGroupIndex}-${editingTagIndex}`],
                  )}
                  aria-describedby={
                    validationLookup.tagErrors[`${editingTagGroupIndex}-${editingTagIndex}`]
                      ? `group-tag-name-${editingTagGroupIndex}-${editingTagIndex}-error`
                      : undefined
                  }
                  disabled={isBusy}
                  onChange={(event) =>
                    updateTagName(editingTagGroupIndex, editingTagIndex, event.target.value)
                  }
                />
                {validationLookup.tagErrors[`${editingTagGroupIndex}-${editingTagIndex}`] ? (
                  <p
                    id={`group-tag-name-${editingTagGroupIndex}-${editingTagIndex}-error`}
                    className="text-xs font-medium text-rose-500"
                    aria-live="polite"
                  >
                    {validationLookup.tagErrors[`${editingTagGroupIndex}-${editingTagIndex}`]}
                  </p>
                ) : null}
              </div>
            </AdminKVField>
            <AdminKVField label="类型">
              <Badge variant="secondary" className={adminNeutralBadgeClass}>
                二级标签
              </Badge>
            </AdminKVField>
            <AdminKVField label="上级分组">
              <span className="text-sm text-slate-700 dark:text-neutral-200">
                {String(editingTagGroup.name || "").trim() || "未命名分组"}
              </span>
            </AdminKVField>
            <AdminKVField label="节点归属">
              <span className="data-text text-sm text-slate-700 dark:text-neutral-200">
                {`${editingTagUsage} 个节点`}
              </span>
            </AdminKVField>
            <p className={`${adminStatEyebrowClass} text-xs leading-relaxed`}>
              标签的增删与排序请在所属分组的抽屉中完成。
            </p>
          </section>
        </AdminDrawer>
      ) : null}
    </div>
  );
}

const compactOutlineActionClass = `${adminOutlineButtonClass} h-9 px-4`;
