import { useEffect, useMemo, useState } from "react";
import {
  closestCenter,
  DndContext,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  arrayMove,
  SortableContext,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
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
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  AlertTriangle,
  FolderTree,
  GripVertical,
  Plus,
  Tag,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import {
  adminActionButtonClass,
  adminDetailCardClass,
  adminDetailHeaderClass,
  adminDirtyBadgeClass,
  adminDangerIconButtonClass,
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminEmptyStateClass,
  adminInlineEmptyStateClass,
  adminMutedTextClass,
  adminNeutralBadgeClass,
  adminOutlineButtonClass,
  adminPageActionsClass,
  adminPageHeaderClass,
  adminPageShellClass,
  adminPageTitleClass,
  adminPrimaryButtonClass,
  adminSectionHeaderClass,
  adminStatCardClass,
  adminStatCardHeaderClass,
  adminStatEyebrowClass,
  adminStatIconChipClass,
  adminStatIconChipClassByTone,
  adminStatSurfaceClassByTone,
  adminStatValueToneClassByTone,
  adminSubtleOutlineBadgeClass,
  adminSurfaceCardClass,
  adminWideInputClass,
  adminWorkspaceHeaderClass,
} from "@/lib/admin-ui";
import { getErrorMessage, resolveNodeSelections } from "@/lib/admin-format";
import type { GroupNode, NodeView } from "@/lib/admin-types";

export interface GroupManagementProps {
  groupTree: GroupNode[];
  nodes: NodeView[];
  onDirtyChange?: (dirty: boolean) => void;
  saving?: boolean;
  onSave: (groupTree: GroupNode[]) => Promise<void>;
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

const statCardLabelClass = adminStatEyebrowClass;

const panelCardClass = `overflow-hidden ${adminSurfaceCardClass}`;

const panelHeaderClass = adminSectionHeaderClass;

const groupCardClass = `${adminDetailCardClass} !rounded-[1.5rem]`;

const groupCardHeaderClass =
  `${adminDetailHeaderClass} flex flex-col gap-4 px-6 py-5 lg:flex-row lg:items-center lg:justify-between`;

const outlineActionClass = adminActionButtonClass;

const compactOutlineActionClass = `${adminOutlineButtonClass} h-9 px-4`;

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
    } else if (groupName === "全部") {
      const message = "一级分组名称不能使用“全部”。";
      validationIssues.push({
        key: `group-all-${groupIndex}`,
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

      if (tagName === "全部") {
        const message = `${groupLabel} 下的标签不能使用“全部”。`;
        validationIssues.push({
          key: `tag-all-${groupIndex}-${tagIndex}`,
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
  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 8,
      },
    }),
  );

  useEffect(() => {
    setDraftTree(incomingTree);
  }, [incomingSignature]);

  const draftSignature = useMemo(() => serializeEditableTree(draftTree), [draftTree]);
  const isDirty = incomingSignature !== draftSignature;

  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);

  useEffect(() => {
    return () => {
      onDirtyChange?.(false);
    };
  }, [onDirtyChange]);

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

  const statCards = [
    {
      label: "一级分组",
      value: summary.totalGroups,
      icon: FolderTree,
      tone: "neutral",
    },
    {
      label: "二级标签",
      value: summary.totalTags,
      icon: Tag,
      tone: "info",
    },
    {
      label: "节点归属",
      value: usageStats.assignedNodes,
      icon: AlertTriangle,
      tone: usageStats.ungroupedNodes > 0 ? "warning" : "success",
    },
  ] as const;

  const updateGroupName = (groupIndex: number, value: string) => {
    setDraftTree((current) =>
      current.map((group, index) =>
        index === groupIndex
          ? {
              ...group,
              name: value,
            }
          : group,
      ),
    );
  };

  const updateTagName = (groupIndex: number, tagIndex: number, value: string) => {
    setDraftTree((current) =>
      current.map((group, index) => {
        if (index !== groupIndex) {
          return group;
        }

        return {
          ...group,
          children: (group.children || []).map((tag, currentTagIndex) =>
            currentTagIndex === tagIndex
              ? {
                  ...tag,
                  name: value,
                }
              : tag,
          ),
        };
      }),
    );
  };

  const addGroup = () => {
    setDraftTree((current) => [...current, { id: createEditableID("group"), name: "", children: [] }]);
  };

  const addTag = (groupIndex: number) => {
    setDraftTree((current) =>
      current.map((group, index) =>
        index === groupIndex
          ? {
              ...group,
              children: [...(group.children || []), { id: createEditableID("tag"), name: "" }],
            }
          : group,
      ),
    );
  };

  const removeGroup = (groupIndex: number) => {
    setDraftTree((current) => current.filter((_, index) => index !== groupIndex));
  };

  const removeTag = (groupIndex: number, tagIndex: number) => {
    setDraftTree((current) =>
      current.map((group, index) =>
        index === groupIndex
          ? {
              ...group,
              children: (group.children || []).filter((_, currentTagIndex) => currentTagIndex !== tagIndex),
            }
          : group,
      ),
    );
  };

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) {
      return;
    }
    setDraftTree((current) => {
      const oldIndex = current.findIndex((group) => group.id === active.id);
      const newIndex = current.findIndex((group) => group.id === over.id);
      if (oldIndex === -1 || newIndex === -1) {
        return current;
      }
      return arrayMove(current, oldIndex, newIndex);
    });
  };

  const handleSave = async () => {
    if (validationIssues.length > 0) {
      const firstIssue = validationIssues[0];
      if (firstIssue.target) {
        const targetID =
          typeof firstIssue.target.tagIndex === "number"
            ? `group-tag-name-${firstIssue.target.groupIndex}-${firstIssue.target.tagIndex}`
            : `group-name-${firstIssue.target.groupIndex}`;
        const element = document.getElementById(targetID);
        if (element instanceof HTMLElement) {
          element.focus();
        }
      }
      return;
    }

    const nextTree = normalizeGroupTree(draftTree);
    if (nextTree.length === 0) {
      return;
    }

    setIsSaving(true);
    try {
      await onSave(nextTree);
      setDraftTree(toEditableTree(nextTree));
      toast.success("分组配置已保存。");
    } catch (error) {
      toast.error(getErrorMessage(error, "保存分组失败。"));
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className={adminPageShellClass}>
      <section className={adminPageHeaderClass}>
        <div>
          <h1 className={adminPageTitleClass}>分组管理</h1>
        </div>
        <div className={adminPageActionsClass}>
          {isDirty ? (
            <span className={adminDirtyBadgeClass}>有未保存的修改</span>
          ) : null}
          <Button
            variant="outline"
            className={`${adminActionButtonClass} h-11 min-w-[140px] px-5 font-bold`}
            onClick={addGroup}
            disabled={isSaving || saving}
          >
            <Plus className="mr-2 h-4 w-4" />
            新建分组
          </Button>
          <Button
            className={`${adminPrimaryButtonClass} h-11 px-5 font-bold`}
            onClick={handleSave}
            disabled={!isDirty || isSaving || saving}
          >
            {isSaving || saving ? "保存中…" : "保存更改"}
          </Button>
        </div>
      </section>

      <section className="grid auto-rows-fr gap-4 md:grid-cols-3">
        {statCards.map((item) => {
          const Icon = item.icon;
          return (
            <Card
              key={item.label}
              className={`${adminStatCardClass} ${adminStatSurfaceClassByTone[item.tone]}`}
            >
              <CardHeader className={adminStatCardHeaderClass}>
                <div>
                  <CardDescription className={statCardLabelClass}>
                    {item.label}
                  </CardDescription>
                  <CardTitle
                    className={`mt-3 text-4xl ${adminStatValueToneClassByTone[item.tone]}`}
                  >
                    {item.value}
                  </CardTitle>
                </div>
                <div className={`${adminStatIconChipClass} ${adminStatIconChipClassByTone[item.tone]}`}>
                  <Icon className="h-5 w-5" />
                </div>
              </CardHeader>
            </Card>
          );
        })}
      </section>

      <Card className={panelCardClass}>
        <CardHeader className={panelHeaderClass}>
          <CardTitle className="flex items-center gap-3 text-slate-900 dark:text-slate-50">
            <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-sky-100 text-sky-700 dark:bg-sky-900 dark:text-sky-100">
              <FolderTree className="h-5 w-5" />
            </span>
            <span>分组编辑</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5 p-5">
          {generalValidationMessage ? (
            <div
              className="rounded-[1rem] border border-rose-200 bg-rose-50 px-4 py-3 text-sm font-medium text-rose-600 dark:border-rose-900/60 dark:bg-rose-950/40 dark:text-rose-300"
              aria-live="polite"
            >
              {generalValidationMessage}
            </div>
          ) : null}
          {draftTree.length === 0 ? (
            <div className={adminEmptyStateClass}>
              <p className="text-sm font-medium text-slate-700 dark:text-slate-200">还没有一级分组</p>
              <Button
                className={`mt-5 ${outlineActionClass}`}
                variant="outline"
                onClick={addGroup}
                disabled={isSaving || saving}
              >
                <Plus className="mr-2 h-4 w-4" />
                新建分组
              </Button>
            </div>
          ) : null}

          <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
            <SortableContext items={draftTree.map((group) => group.id)} strategy={verticalListSortingStrategy}>
              {draftTree.map((group, groupIndex) => (
                <SortableGroupCard
                  key={group.id}
                  group={group}
                  groupIndex={groupIndex}
                  groupUsageCount={String(group.name || "").trim() ? usageStats.groupCount.get(String(group.name || "").trim()) || 0 : 0}
                  tagUsageStats={usageStats.tagCount}
                  groupCardClass={groupCardClass}
                  groupCardHeaderClass={groupCardHeaderClass}
                  isBusy={isSaving || saving}
                  validationLookup={validationLookup}
                  onAddTag={addTag}
                  onRemoveGroup={removeGroup}
                  onRemoveTag={removeTag}
                  onUpdateGroupName={updateGroupName}
                  onUpdateTagName={updateTagName}
                />
              ))}
            </SortableContext>
          </DndContext>
        </CardContent>
      </Card>
    </div>
  );
}

function SortableGroupCard({
  group,
  groupIndex,
  groupUsageCount,
  tagUsageStats,
  groupCardClass,
  groupCardHeaderClass,
  isBusy,
  validationLookup,
  onAddTag,
  onRemoveGroup,
  onRemoveTag,
  onUpdateGroupName,
  onUpdateTagName,
}: {
  key?: string;
  group: EditableGroupNode;
  groupIndex: number;
  groupUsageCount: number;
  tagUsageStats: Map<string, number>;
  groupCardClass: string;
  groupCardHeaderClass: string;
  isBusy: boolean;
  validationLookup: {
    groupErrors: Record<string, string>;
    tagErrors: Record<string, string>;
  };
  onAddTag: (groupIndex: number) => void;
  onRemoveGroup: (groupIndex: number) => void;
  onRemoveTag: (groupIndex: number, tagIndex: number) => void;
  onUpdateGroupName: (groupIndex: number, value: string) => void;
  onUpdateTagName: (groupIndex: number, tagIndex: number, value: string) => void;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: group.id,
  });
  const groupName = String(group.name || "").trim();
  const tags = group.children || [];
  const effectiveTagCount = tags.filter((tag) => String(tag.name || "").trim()).length;
  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  };
  return (
    <div
      ref={setNodeRef}
      style={style}
      className={`${groupCardClass} ${isDragging ? "opacity-80 shadow-[0_24px_48px_-28px_rgba(14,116,214,0.28)]" : ""}`}
    >
      <div className={groupCardHeaderClass}>
        <div className={`${adminWorkspaceHeaderClass} flex-1`}>
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-400 transition-colors hover:border-sky-200 hover:text-sky-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-500 dark:hover:border-sky-800 dark:hover:text-sky-300"
              aria-label="拖动排序"
              {...attributes}
              {...listeners}
            >
              <GripVertical className="h-4 w-4" />
            </button>
            <div className="rounded-2xl bg-sky-100 p-2.5 text-sky-700 dark:bg-sky-900 dark:text-sky-100">
              <FolderTree className="h-4 w-4" />
            </div>
            <div className="flex-1 space-y-2">
              <p className={statCardLabelClass}>一级分组名称</p>
              <Input
                id={`group-name-${groupIndex}`}
                name={`group-name-${groupIndex}`}
                autoComplete="off"
                value={group.name}
                placeholder="例如：美国、香港、日本…"
                className={adminWideInputClass}
                aria-invalid={Boolean(validationLookup.groupErrors[String(groupIndex)])}
                aria-describedby={
                  validationLookup.groupErrors[String(groupIndex)]
                    ? `group-name-${groupIndex}-error`
                    : undefined
                }
                onChange={(event) => onUpdateGroupName(groupIndex, event.target.value)}
              />
              {validationLookup.groupErrors[String(groupIndex)] ? (
                <p
                  id={`group-name-${groupIndex}-error`}
                  className="text-xs font-medium text-rose-500"
                  aria-live="polite"
                >
                  {validationLookup.groupErrors[String(groupIndex)]}
                </p>
              ) : null}
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                <Badge variant="secondary" className={adminNeutralBadgeClass}>
                  {groupUsageCount} 个节点
                </Badge>
                <Badge variant="outline" className={adminSubtleOutlineBadgeClass}>
                  {effectiveTagCount} 个标签
                </Badge>
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className={compactOutlineActionClass}
            onClick={() => onAddTag(groupIndex)}
            disabled={isBusy}
          >
            <Plus className="mr-1 h-4 w-4" />
            添加标签
          </Button>
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
                  onClick={() => onRemoveGroup(groupIndex)}
                >
                  确认删除
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </div>

      <div className="space-y-4 px-6 py-5">
        <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
          <h4 className="text-sm font-medium text-slate-900 dark:text-slate-100">二级标签</h4>
          <Badge variant="outline" className={`w-fit ${adminSubtleOutlineBadgeClass}`}>
            共 {effectiveTagCount} 个有效标签
          </Badge>
        </div>

        {tags.length === 0 ? (
          <div className={adminInlineEmptyStateClass}>
            暂无二级标签
          </div>
        ) : null}

        {tags.length > 0 ? (
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
            {tags.map((tag, tagIndex) => {
              const tagName = String(tag.name || "").trim();
              const tagKey = groupName && tagName ? `${groupName}::${tagName}` : "";
              const tagUsageCount = tagKey ? tagUsageStats.get(tagKey) || 0 : 0;

              return (
                <div
                  key={tag.id}
                  className="flex items-center gap-3 rounded-[1.15rem] border border-slate-200 bg-white px-3 py-3 dark:border-slate-800 dark:bg-slate-900"
                >
                  <div className="rounded-xl bg-emerald-50 p-2 text-emerald-600 dark:bg-emerald-950 dark:text-emerald-200">
                    <Tag className="h-4 w-4" />
                  </div>

                  <div className="min-w-0 flex-1 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <Badge variant="outline" className={adminSubtleOutlineBadgeClass}>
                        {tagUsageCount} 个节点
                      </Badge>
                    </div>

                    <Input
                      id={`group-tag-name-${groupIndex}-${tagIndex}`}
                      name={`group-tag-name-${groupIndex}-${tagIndex}`}
                      autoComplete="off"
                      value={tag.name}
                      placeholder="例如：CN2、BGP、GIA…"
                      className="h-10 w-full rounded-xl border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                      aria-invalid={Boolean(validationLookup.tagErrors[`${groupIndex}-${tagIndex}`])}
                      aria-describedby={
                        validationLookup.tagErrors[`${groupIndex}-${tagIndex}`]
                          ? `group-tag-name-${groupIndex}-${tagIndex}-error`
                          : undefined
                      }
                      onChange={(event) => onUpdateTagName(groupIndex, tagIndex, event.target.value)}
                    />
                    {validationLookup.tagErrors[`${groupIndex}-${tagIndex}`] ? (
                      <p
                        id={`group-tag-name-${groupIndex}-${tagIndex}-error`}
                        className="text-xs font-medium text-rose-500"
                        aria-live="polite"
                      >
                        {validationLookup.tagErrors[`${groupIndex}-${tagIndex}`]}
                      </p>
                    ) : null}
                  </div>

                  <Button
                    variant="ghost"
                    size="icon"
                    className={`${adminDangerIconButtonClass} h-9 w-9 shrink-0`}
                    onClick={() => onRemoveTag(groupIndex, tagIndex)}
                    disabled={isBusy}
                    aria-label="删除标签"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              );
            })}
          </div>
        ) : null}
      </div>
    </div>
  );
}
