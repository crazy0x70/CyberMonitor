import { useEffect, useMemo, useRef, useState } from "react";
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type CollisionDetection,
  type DragEndEvent,
  type DragOverEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { AdminPageHeader } from "@/components/admin-page-header";
import { AdminPanel } from "@/components/admin-panel";
import { AdminDrawer } from "@/components/admin-drawer";
import { AdminEmptyState } from "@/components/admin-empty-state";
import { AdminKVField } from "@/components/admin-kv-field";
import { AdminSaveBar } from "@/components/admin-save-bar";
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
  ChevronRight,
  FolderTree,
  GripVertical,
  Plus,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import {
  adminActionButtonClass,
  adminCompactActionButtonClass,
  adminDangerIconButtonClass,
  adminDialogCancelClass,
  adminDialogContentClass,
  adminDialogDangerActionClass,
  adminDialogFooterClass,
  adminDialogHeaderClass,
  adminFieldErrorClass,
  adminInputClass,
  adminNeutralBadgeClass,
  adminOutlineButtonClass,
  adminPageShellClass,
  adminPrimaryButtonClass,
  adminSubtleOutlineBadgeClass,
  adminWideInputClass,
} from "@/lib/admin-ui";
import { useAsyncAction, useDirtyNotification, useDraftReconcile } from "@/lib/admin-hooks";
import { resolveNodeSelections } from "@/lib/admin-format";
import type { GroupMove, GroupNode, NodeView, SettingsView } from "@/lib/admin-types";
import { cn } from "@/lib/utils";

export interface GroupManagementProps {
  groupTree: GroupNode[];
  nodes: NodeView[];
  onDirtyChange?: (dirty: boolean) => void;
  saving?: boolean;
  // F1：groupMoves 为保存时按「草稿节点 id → 原始 selection」对比生成的归属迁移
  //（对应后端 SettingsUpdate.GroupMoves）；无迁移时为空数组。
  onSave: (groupTree: GroupNode[], groupMoves?: GroupMove[]) => Promise<SettingsView>;
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

  if (tree.length === 0) {
    validationIssues.push({
      key: "group-empty",
      message: "至少需要保留一个分组。",
    });
  }

  tree.forEach((group, groupIndex) => {
    const groupName = String(group.name || "").trim();
    const groupLabel = groupName || `第 ${groupIndex + 1} 个分组`;

    if (!groupName) {
      const message = `${groupLabel} 名称不能为空。`;
      validationIssues.push({
        key: `group-name-${groupIndex}`,
        message,
        target: { groupIndex },
      });
      groupErrors[String(groupIndex)] = message;
    } else if (RESERVED_GROUP_NAMES.has(groupName)) {
      const message = "分组名称与展示页固定标签冲突，请换一个名称。";
      validationIssues.push({
        key: `group-reserved-${groupIndex}`,
        message,
        target: { groupIndex },
      });
      groupErrors[String(groupIndex)] = message;
    } else if (groupName.includes(":") || groupName.includes("/")) {

      const message = "分组名称不能包含“:”或“/”。";
      validationIssues.push({
        key: `group-separator-${groupIndex}`,
        message,
        target: { groupIndex },
      });
      groupErrors[String(groupIndex)] = message;
    } else if (seenGroups.has(groupName)) {
      const message = `分组“${groupName}”重复，请保留唯一名称。`;
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

// F1 拖拽：落点指示线——渲染在目标行的上沿或下沿（2px --accent 横线）。
type DropIndicator = { rowId: string; edge: "top" | "bottom" };

type LocatedTreeRow =
  | { kind: "group"; groupIndex: number }
  | { kind: "tag"; groupIndex: number; tagIndex: number };

function locateTreeRow(
  tree: EditableGroupNode[],
  rowId: string,
): LocatedTreeRow | null {
  for (let groupIndex = 0; groupIndex < tree.length; groupIndex += 1) {
    const group = tree[groupIndex];
    if (group.id === rowId) {
      return { kind: "group", groupIndex };
    }
    const children = group.children || [];
    for (let tagIndex = 0; tagIndex < children.length; tagIndex += 1) {
      if (children[tagIndex].id === rowId) {
        return { kind: "tag", groupIndex, tagIndex };
      }
    }
  }
  return null;
}

// F1 拖拽：拖动分组时其下标签整体跟随——分组作为整块在同级之间移动。
function moveGroupTo(
  tree: EditableGroupNode[],
  groupID: string,
  overID: string,
  edge: "top" | "bottom",
): EditableGroupNode[] {
  const from = tree.findIndex((group) => group.id === groupID);
  const overLocation = locateTreeRow(tree, overID);
  if (from < 0 || !overLocation) {
    return tree;
  }
  const targetGroupIndex = overLocation.groupIndex;
  if (targetGroupIndex < 0 || targetGroupIndex >= tree.length || targetGroupIndex === from) {
    return tree;
  }
  let insertAt = edge === "top" ? targetGroupIndex : targetGroupIndex + 1;
  if (from < insertAt) {
    insertAt -= 1;
  }
  if (insertAt === from) {
    return tree;
  }
  const next = [...tree];
  const [moved] = next.splice(from, 1);
  next.splice(insertAt, 0, moved);
  return next;
}

// F1 拖拽：标签组内重排或跨组移动；overID 为标签行（插到其上/下方）
// 或分组行（追加到该分组末尾）。
function moveTagTo(
  tree: EditableGroupNode[],
  tagID: string,
  overID: string,
  edge: "top" | "bottom",
): EditableGroupNode[] {
  const source = locateTreeRow(tree, tagID);
  const over = locateTreeRow(tree, overID);
  if (!source || !over || source.kind !== "tag") {
    return tree;
  }
  const toGroupIndex = over.groupIndex;
  let insertAt =
    over.kind === "tag"
      ? edge === "top"
        ? over.tagIndex
        : over.tagIndex + 1
      : (tree[toGroupIndex]?.children || []).length;
  const sourceGroup = tree[source.groupIndex];
  const movedTag = sourceGroup?.children?.[source.tagIndex];
  if (!sourceGroup || !movedTag) {
    return tree;
  }
  if (source.groupIndex === toGroupIndex && source.tagIndex < insertAt) {
    insertAt -= 1;
  }
  const withoutTag = updateGroupChildren(tree, source.groupIndex, (children) =>
    removeItemAt(children, source.tagIndex),
  );
  return updateGroupChildren(withoutTag, toGroupIndex, (children) => {
    const next = [...children];
    next.splice(Math.max(0, Math.min(insertAt, next.length)), 0, movedTag);
    return next;
  });
}

// F1：按草稿节点 id 记录其在服务端当前树中的 selection（"A" / "A:t"）。
// 草稿与服务端树重新对齐（初始加载、重置、保存回写、内容收敛）时重建。
function buildSelectionMap(tree: EditableGroupNode[]): Map<string, string> {
  const map = new Map<string, string>();
  tree.forEach((group) => {
    const groupName = String(group.name || "").trim();
    if (groupName) {
      map.set(group.id, groupName);
    }
    (group.children || []).forEach((tag) => {
      const tagName = String(tag.name || "").trim();
      if (groupName && tagName) {
        map.set(tag.id, `${groupName}:${tagName}`);
      }
    });
  });
  return map;
}

// F1：保存时对比「草稿节点 id 的原始 selection」与「草稿当前 selection」，
// 生成 group_moves 交给后端迁移节点归属（拖拽跨组 / 改名都会体现为 move）。
function collectGroupMoves(
  tree: EditableGroupNode[],
  baseline: Map<string, string>,
): GroupMove[] {
  const moves: GroupMove[] = [];
  const seen = new Set<string>();
  const push = (from: string, to: string) => {
    const key = `${from}\n${to}`;
    if (!seen.has(key)) {
      seen.add(key);
      moves.push({ from, to });
    }
  };

  tree.forEach((group) => {
    const groupName = String(group.name || "").trim();
    const groupFrom = baseline.get(group.id);
    if (groupName && groupFrom && groupFrom !== groupName) {
      push(groupFrom, groupName);
    }
    (group.children || []).forEach((tag) => {
      const tagName = String(tag.name || "").trim();
      if (!groupName || !tagName) {
        return;
      }
      const to = `${groupName}:${tagName}`;
      const from = baseline.get(tag.id);
      if (from && from !== to) {
        push(from, to);
      }
    });
  });

  return moves;
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

  // F1：服务端当前树的「草稿节点 id → 原始 selection」基线，保存时用于生成 group_moves。
  const baselineSelectionsRef = useRef<Map<string, string>>(buildSelectionMap(incomingTree));
  const rebaseSelectionBaseline = (tree: EditableGroupNode[]) => {
    baselineSelectionsRef.current = buildSelectionMap(tree);
  };

  const [editingGroupId, setEditingGroupId] = useState<string | null>(null);
  const [editingTagId, setEditingTagId] = useState<string | null>(null);
  const isBusy = isSaving || saving;

  const draftSignature = useMemo(() => serializeEditableTree(draftTree), [draftTree]);

  // A-03：接收 useDraftReconcile 第三个返回值 discard（保存条「放弃修改」），
  // 其余签名化脏检测逻辑不动。
  const [absorbedSignature, absorbSourceSignature, discard] = useDraftReconcile({
    draftSignature,
    nextSourceSignature: incomingSignature,
    isBusy,
    resetDraft: () => {
      setDraftTree(incomingTree);
      rebaseSelectionBaseline(incomingTree);
    },
    warningText: "服务端分组配置已更新，当前未保存修改已保留。",
  });
  const isDirty = absorbedSignature !== draftSignature;
  useDirtyNotification(onDirtyChange, isDirty);

  // 草稿内容与服务端树一致（初始加载、重置回写、内容收敛）时重建基线，
  // 让后续改名 / 拖拽继续以正确的原始 selection 计算 group_moves。
  useEffect(() => {
    if (!isDirty && absorbedSignature === incomingSignature) {
      rebaseSelectionBaseline(draftTree);
    }
  }, [absorbedSignature, draftTree, incomingSignature, isDirty]);

  const draftTreeAnalysis = useMemo(() => analyzeDraftTree(draftTree), [draftTree]);
  const {
    validationIssues,
    validationLookup,
    generalValidationMessage,
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

  // ===== F1 拖拽树形列表（替代 AdminDataTable）=====
  // 指针 + 键盘（KeyboardSensor：空格拿起、方向键移动、空格放下）双通道。
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const [dropIndicator, setDropIndicator] = useState<DropIndicator | null>(null);

  const rowKindById = useMemo(() => {
    const map = new Map<string, "group" | "tag">();
    ledgerRows.forEach((row) => map.set(row.id, row.kind));
    return map;
  }, [ledgerRows]);

  // 碰撞检测：拖动分组时只有分组行是有效落点（分组整块移动，标签行跟随父分组）；
  // 拖动标签时所有行都可作为落点（组内重排或跨组移动）。
  const treeCollisionDetection = useMemo<CollisionDetection>(() => {
    return (args) => {
      const activeID = String(args.active.id);
      const activeKind = rowKindById.get(activeID);
      const candidates = args.droppableContainers.filter((container) => {
        const id = String(container.id);
        if (id === activeID) {
          return false;
        }
        return activeKind === "group" ? rowKindById.get(id) === "group" : rowKindById.has(id);
      });
      return closestCenter({ ...args, droppableContainers: candidates });
    };
  }, [rowKindById]);

  const applyDropIndicator = (next: DropIndicator | null) => {
    setDropIndicator((current) =>
      current && next && current.rowId === next.rowId && current.edge === next.edge
        ? current
        : next,
    );
  };

  // 被拖项（已跟随指针平移）中心落在目标行中心的上/下半侧 → 落点上沿/下沿。
  const resolveDropEdge = (
    activeRect: { top: number; height: number } | null,
    overRect: { top: number; height: number } | null,
  ): "top" | "bottom" | null => {
    if (!activeRect || !overRect) {
      return null;
    }
    return activeRect.top + activeRect.height / 2 < overRect.top + overRect.height / 2
      ? "top"
      : "bottom";
  };

  // 落在分组行底部 = 追加到该分组末尾，指示线画在该分组最后一个标签行的下沿。
  const lastTagRowIdOfGroup = (groupIndex: number): string | null => {
    const children = draftTree[groupIndex]?.children || [];
    return children.length > 0 ? children[children.length - 1].id : null;
  };

  const handleDragOver = (event: DragOverEvent) => {
    if (isBusy || !event.over) {
      applyDropIndicator(null);
      return;
    }
    const activeID = String(event.active.id);
    const overID = String(event.over.id);
    if (overID === activeID) {
      applyDropIndicator(null);
      return;
    }
    const activeRow = ledgerRows.find((row) => row.id === activeID);
    const overRow = ledgerRows.find((row) => row.id === overID);
    if (!activeRow || !overRow) {
      applyDropIndicator(null);
      return;
    }
    const edge = resolveDropEdge(event.active.rect.current.translated, event.over.rect);
    if (!edge) {
      applyDropIndicator(null);
      return;
    }
    if (activeRow.kind === "group") {
      if (overRow.kind !== "group") {
        applyDropIndicator(null);
        return;
      }
      if (edge === "top") {
        applyDropIndicator({ rowId: overRow.id, edge: "top" });
      } else {
        applyDropIndicator({ rowId: lastTagRowIdOfGroup(overRow.groupIndex) ?? overRow.id, edge: "bottom" });
      }
      return;
    }
    if (overRow.kind === "tag") {
      applyDropIndicator({ rowId: overRow.id, edge });
      return;
    }
    applyDropIndicator({ rowId: lastTagRowIdOfGroup(overRow.groupIndex) ?? overRow.id, edge: "bottom" });
  };

  // 拖拽只改草稿；保存仍走浮动保存条（onSave → group_tree + group_moves）。
  const handleDragEnd = (event: DragEndEvent) => {
    applyDropIndicator(null);
    if (isBusy || !event.over) {
      return;
    }
    const activeID = String(event.active.id);
    const overID = String(event.over.id);
    if (activeID === overID) {
      return;
    }
    const activeKind = rowKindById.get(activeID);
    if (!activeKind || !rowKindById.has(overID)) {
      return;
    }
    const edge = resolveDropEdge(event.active.rect.current.translated, event.over.rect) ?? "bottom";
    updateDraftTree((current) =>
      activeKind === "group"
        ? moveGroupTo(current, activeID, overID, edge)
        : moveTagTo(current, activeID, overID, edge),
    );
  };

  const openLedgerRow = (row: GroupLedgerRow) => {
    if (row.kind === "group") {
      setEditingGroupId(row.id);
      setEditingTagId(null);
    } else {
      setEditingTagId(row.id);
      setEditingGroupId(null);
    }
  };

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
    // 保存成功后，服务端树（含 group_moves 已迁移的归属）成为新的基线。
    baselineSelectionsRef.current = buildSelectionMap(nextDraftTree);
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

  // F1 第 5 条：标签抽屉同样提供上下移动按钮（复用 moveItemAt），
  // 作为键盘与读屏用户在拖拽之外的兜底。
  const moveTag = (groupIndex: number, tagIndex: number, offset: -1 | 1) => {
    updateDraftTags(groupIndex, (children) => moveItemAt(children, tagIndex, offset));
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

    // F1：按草稿节点 id 对比原始 selection，生成 group_moves（改名 / 跨组拖拽）。
    const groupMoves = collectGroupMoves(draftTree, baselineSelectionsRef.current);

    void runAction({
      action: () => onSave(nextTree, groupMoves),
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
            {/* A-12 / 0.1.2：保存入口与「有未保存的修改」徽标移入浮动保存条，页头只留「新建分组」。 */}
            <Button
              variant="outline"
              className={`${adminActionButtonClass} h-9 min-w-[140px] flex-1 gap-1.5 px-4 font-medium sm:flex-none`}
              onClick={addGroup}
              disabled={isBusy}
            >
              <Plus className="h-4 w-4" aria-hidden="true" />
              新建分组
            </Button>
          </>
        }
      />

      {/* A-03 / F1 第 1 条：删除顶部「分组 / 标签 / 节点归属」统计卡。 */}
      <AdminPanel
        title="分组列表"
        icon={<FolderTree className="h-4 w-4 text-[var(--label-3)]" />}
      >
        {generalValidationMessage && draftTree.length > 0 ? (
          <div className="pb-4">
            <div
              className="rounded-xl border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-[13px] font-medium leading-5 text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/40 dark:text-rose-300"
              aria-live="polite"
            >
              {generalValidationMessage}
            </div>
          </div>
        ) : null}
        <DndContext
          sensors={sensors}
          collisionDetection={treeCollisionDetection}
          onDragOver={handleDragOver}
          onDragEnd={handleDragEnd}
          onDragCancel={() => applyDropIndicator(null)}
        >
          <SortableContext items={ledgerRows.map((row) => row.id)} strategy={verticalListSortingStrategy}>
            {/* A-09 第 1 条同款卡片；不加 overflow-hidden，避免拖拽平移时被卡片裁切。 */}
            <div
              role="tree"
              aria-label="分组列表"
              className="rounded-[var(--r-lg)] border border-[var(--hairline)] bg-[var(--surface-raised)] shadow-[var(--shadow-1)]"
            >
              {ledgerRows.length === 0 ? (
                <div className="rounded-[var(--r-lg)] px-5 py-12">
                  {/* E-11 / A-16 / 0.1.2：空态用 AdminEmptyState，主按钮复用页头「新建分组」
                      同一个 onClick（addGroup），不新增逻辑。 */}
                  <AdminEmptyState
                    icon={<FolderTree aria-hidden="true" />}
                    title="还没有分组"
                    description="创建分组后，可在节点管理中为节点指定分组归属，展示页将按分组筛选节点。"
                    action={
                      <Button className={adminPrimaryButtonClass} onClick={addGroup} disabled={isBusy}>
                        <Plus className="h-4 w-4" aria-hidden="true" />
                        新建分组
                      </Button>
                    }
                  />
                </div>
              ) : (
                ledgerRows.map((row) => (
                  <GroupLedgerItem
                    key={row.id}
                    row={row}
                    disabled={isBusy}
                    dropEdge={dropIndicator?.rowId === row.id ? dropIndicator.edge : null}
                    onOpen={openLedgerRow}
                  />
                ))
              )}
            </div>
          </SortableContext>
        </DndContext>
      </AdminPanel>

      {isDirty ? (
        // A-12：保存入口移入浮动保存条；handleSave 的校验、聚焦定位与禁用条件
        // 复用原有逻辑，只改呈现位置。A-03：左侧「放弃修改」带二次确认（D-07）。
        <AdminSaveBar
          saving={isSaving || saving}
          disabled={isBusy}
          onSave={handleSave}
          onDiscard={discard}
        />
      ) : null}

      {editingGroup && editingGroupIndex >= 0 ? (
        <AdminDrawer
          open
          onOpenChange={(open) => {
            if (!open) {
              setEditingGroupId(null);
            }
          }}
          title={
            <span
              data-admin-i18n-skip={String(editingGroup.name || "").trim() ? true : undefined}
            >
              {String(editingGroup.name || "").trim() || "未命名分组"}
            </span>
          }
          description={`分组 · 第 ${editingGroupIndex + 1} 位 / 共 ${draftTree.length} 个`}
          footer={
            <div className="flex items-center justify-between gap-2">
              <AlertDialog>
                <AlertDialogTrigger
                  className={cn(
                    adminDangerIconButtonClass,
                    "focus-visible:border-[var(--primary-border)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)]",
                  )}
                  disabled={isBusy}
                  type="button"
                  aria-label="删除分组"
                >
                  <Trash2 className="h-4 w-4" aria-hidden="true" />
                </AlertDialogTrigger>
                <AlertDialogContent className={adminDialogContentClass}>
                  <AlertDialogHeader className={adminDialogHeaderClass}>
                    <AlertDialogTitle>确认删除分组？</AlertDialogTitle>
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
                className={cn(adminOutlineButtonClass, "min-w-[84px] px-4")}
                onClick={() => setEditingGroupId(null)}
                disabled={isBusy}
              >
                关闭
              </Button>
            </div>
          }
        >
          <section>
            <h3 className="text-sm font-semibold text-[var(--label-1)]">
              分组信息
            </h3>
            <AdminKVField label="名称" htmlFor={`group-name-${editingGroupIndex}`}>
              <div className="space-y-1.5">
                <Input
                  id={`group-name-${editingGroupIndex}`}
                  name={`group-name-${editingGroupIndex}`}
                  autoComplete="off"
                  value={editingGroup.name}
                  placeholder="例如：美国、香港、日本…"
                  className={`${adminWideInputClass} w-full`}
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
                    className={adminFieldErrorClass}
                    aria-live="polite"
                  >
                    {validationLookup.groupErrors[String(editingGroupIndex)]}
                  </p>
                ) : null}
              </div>
            </AdminKVField>
            <AdminKVField label="类型">
              <Badge variant="outline" className={adminSubtleOutlineBadgeClass}>
                分组
              </Badge>
            </AdminKVField>
            <AdminKVField label="上级分组">
              <span className="text-sm text-[var(--label-3)]">—（顶级）</span>
            </AdminKVField>
            <AdminKVField label="节点归属">
              <span className="text-sm tabular-nums text-[var(--label-1)]">
                {`${editingGroupUsage} 个节点`}
              </span>
            </AdminKVField>
            <AdminKVField label="排序">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm tabular-nums text-[var(--label-1)]">
                  {`第 ${editingGroupIndex + 1} / ${draftTree.length} 位`}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  className={compactOutlineActionClass}
                  onClick={() => moveGroup(editingGroupIndex, -1)}
                  disabled={isBusy || editingGroupIndex === 0}
                >
                  <ArrowUp className="h-4 w-4" aria-hidden="true" />
                  上移
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className={compactOutlineActionClass}
                  onClick={() => moveGroup(editingGroupIndex, 1)}
                  disabled={isBusy || editingGroupIndex === draftTree.length - 1}
                >
                  <ArrowDown className="h-4 w-4" aria-hidden="true" />
                  下移
                </Button>
              </div>
            </AdminKVField>
          </section>

          <section>
            <h3 className="text-sm font-semibold text-[var(--label-1)]">
              标签
            </h3>
            {(editingGroup.children || []).length === 0 ? (
              <p className="rounded-xl border border-dashed border-[var(--separator-opaque)] px-4 py-6 text-center text-[13px] leading-relaxed text-[var(--label-2)]">
                暂无标签
              </p>
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
                    <div key={tag.id} className="flex items-start gap-2.5 py-3 first:pt-0 last:pb-0">
                      <div className="min-w-0 flex-1 space-y-1.5">
                        <Input
                          id={`group-tag-name-${editingGroupIndex}-${tagIndex}`}
                          name={`group-tag-name-${editingGroupIndex}-${tagIndex}`}
                          autoComplete="off"
                          value={tag.name}
                          placeholder="例如：CN2、BGP、GIA…"
                          className={`${adminInputClass} w-full`}
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
                            className={adminFieldErrorClass}
                            aria-live="polite"
                          >
                            {validationLookup.tagErrors[`${editingGroupIndex}-${tagIndex}`]}
                          </p>
                        ) : null}
                      </div>

                      <Badge
                        variant="outline"
                        className={`${adminSubtleOutlineBadgeClass} mt-2 shrink-0 tabular-nums`}
                      >
                        {`${tagUsageCount} 个节点`}
                      </Badge>

                      <Button
                        variant="ghost"
                        size="icon"
                        className={adminDangerIconButtonClass}
                        onClick={() => removeTag(editingGroupIndex, tagIndex)}
                        disabled={isBusy}
                        aria-label="删除标签"
                      >
                        <Trash2 className="h-4 w-4" aria-hidden="true" />
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
                <Plus className="h-4 w-4" aria-hidden="true" />
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
          title={
            <span
              data-admin-i18n-skip={String(editingTag.name || "").trim() ? true : undefined}
            >
              {String(editingTag.name || "").trim() || "未命名标签"}
            </span>
          }
          description={`标签 · 所属分组 ${
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
                <Trash2 className="h-4 w-4" aria-hidden="true" />
              </Button>
              <Button
                variant="outline"
                className={cn(adminOutlineButtonClass, "min-w-[84px] px-4")}
                onClick={() => setEditingTagId(null)}
                disabled={isBusy}
              >
                关闭
              </Button>
            </div>
          }
        >
          <section>
            <h3 className="text-sm font-semibold text-[var(--label-1)]">
              标签信息
            </h3>
            <AdminKVField label="名称" htmlFor={`group-tag-name-${editingTagGroupIndex}-${editingTagIndex}`}>
              <div className="space-y-1.5">
                <Input
                  id={`group-tag-name-${editingTagGroupIndex}-${editingTagIndex}`}
                  name={`group-tag-name-${editingTagGroupIndex}-${editingTagIndex}`}
                  autoComplete="off"
                  value={editingTag.name}
                  placeholder="例如：CN2、BGP、GIA…"
                  className={`${adminWideInputClass} w-full`}
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
                    className={adminFieldErrorClass}
                    aria-live="polite"
                  >
                    {validationLookup.tagErrors[`${editingTagGroupIndex}-${editingTagIndex}`]}
                  </p>
                ) : null}
              </div>
            </AdminKVField>
            <AdminKVField label="类型">
              <Badge variant="secondary" className={adminNeutralBadgeClass}>
                标签
              </Badge>
            </AdminKVField>
            <AdminKVField label="上级分组">
              <span
                className="text-sm text-[var(--label-1)]"
                data-admin-i18n-skip={String(editingTagGroup.name || "").trim() ? true : undefined}
              >
                {String(editingTagGroup.name || "").trim() || "未命名分组"}
              </span>
            </AdminKVField>
            <AdminKVField label="节点归属">
              <span className="text-sm tabular-nums text-[var(--label-1)]">
                {`${editingTagUsage} 个节点`}
              </span>
            </AdminKVField>
            <AdminKVField label="排序">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm tabular-nums text-[var(--label-1)]">
                  {`第 ${editingTagIndex + 1} / ${(editingTagGroup.children || []).length} 位`}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  className={compactOutlineActionClass}
                  onClick={() => moveTag(editingTagGroupIndex, editingTagIndex, -1)}
                  disabled={isBusy || editingTagIndex === 0}
                >
                  <ArrowUp className="h-4 w-4" aria-hidden="true" />
                  上移
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className={compactOutlineActionClass}
                  onClick={() => moveTag(editingTagGroupIndex, editingTagIndex, 1)}
                  disabled={isBusy || editingTagIndex === (editingTagGroup.children || []).length - 1}
                >
                  <ArrowDown className="h-4 w-4" aria-hidden="true" />
                  下移
                </Button>
              </div>
            </AdminKVField>
          </section>
        </AdminDrawer>
      ) : null}
    </div>
  );
}

// F1 拖拽树形列表的一行（分组行 / 标签行）：
// - 左侧 GripVertical 拖拽柄（16px，--label-4，悬停 --label-2），PointerSensor 与
//   KeyboardSensor（空格拿起 / 方向键移动 / 空格放下）共用该柄；
// - 分组行：分组名 15px/600 + 右侧「N 个标签 · M 个节点」（13px --label-3）+ ›；
// - 标签行：缩进 28px，名称 14px/400，右侧「M 个节点」+ ›；
// - 点击行主体打开现有编辑抽屉；拖拽中该行 --shadow-3 + scale(1.02)；
//   落点在行上/下沿渲染 2px --accent 横线。
function GroupLedgerItem({
  row,
  disabled,
  dropEdge,
  onOpen,
}: {
  row: GroupLedgerRow;
  disabled: boolean;
  dropEdge: "top" | "bottom" | null;
  onOpen: (row: GroupLedgerRow) => void;
}) {
  const { attributes, listeners, setNodeRef, setActivatorNodeRef, transform, isDragging } =
    useSortable({ id: row.id, disabled });
  const isGroup = row.kind === "group";
  const rawName = isGroup
    ? String(row.group.name || "").trim()
    : String(row.tag.name || "").trim();

  return (
    <div
      ref={setNodeRef}
      role="treeitem"
      aria-level={isGroup ? 1 : 2}
      style={
        isDragging && transform
          ? { transform: `translate3d(${transform.x}px, ${transform.y}px, 0) scale(1.02)`, zIndex: 20 }
          : undefined
      }
      className={cn(
        "group/row relative flex select-none items-center border-b border-[var(--hairline)] pr-3 last:border-b-0",
        isGroup ? "pl-2" : "pl-7",
        isDragging &&
          "rounded-[var(--r-lg)] bg-[var(--surface-raised)] shadow-[var(--shadow-3)]",
      )}
    >
      {dropEdge ? (
        <span
          aria-hidden="true"
          className={cn(
            "pointer-events-none absolute inset-x-0 z-30 h-0.5 bg-[var(--accent)]",
            dropEdge === "top" ? "top-0" : "bottom-0",
          )}
        />
      ) : null}
      <button
        ref={setActivatorNodeRef}
        type="button"
        {...attributes}
        {...listeners}
        aria-label="拖拽排序"
        onClick={(event) => event.stopPropagation()}
        className={cn(
          "flex size-6 shrink-0 cursor-grab touch-none items-center justify-center rounded-md text-[var(--label-4)] outline-none transition-colors duration-150 hover:text-[var(--label-2)] focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)]",
          isDragging && "cursor-grabbing text-[var(--label-2)]",
        )}
      >
        <GripVertical className="size-4" aria-hidden="true" />
      </button>
      <div
        role="button"
        tabIndex={0}
        onClick={() => onOpen(row)}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onOpen(row);
          }
        }}
        className={cn(
          "flex min-w-0 flex-1 cursor-pointer items-center gap-2 rounded-md py-2 pr-1 pl-2 outline-none",
          "hover:bg-[rgba(0,0,0,0.025)] hover:dark:bg-[rgba(255,255,255,0.05)]",
          "focus-visible:ring-2 focus-visible:ring-[var(--primary-ring)]",
        )}
      >
        <span
          className={cn(
            "min-w-0 truncate",
            isGroup
              ? "text-[15px] font-semibold text-[var(--label-1)]"
              : "text-sm font-normal text-[var(--label-2)]",
          )}
          data-admin-i18n-skip={rawName ? true : undefined}
        >
          {rawName || (isGroup ? "未命名分组" : "未命名标签")}
        </span>
        <span className="ml-auto flex shrink-0 items-center gap-1.5 pl-3 text-[13px] tabular-nums text-[var(--label-3)]">
          {isGroup
            ? `${row.tagCount} 个标签 · ${row.nodeCount} 个节点`
            : `${row.nodeCount} 个节点`}
        </span>
        <ChevronRight
          aria-hidden="true"
          className="h-4 w-4 shrink-0 text-[var(--label-4)] transition-all duration-150 group-hover/row:translate-x-0.5 group-hover/row:text-[var(--label-2)]"
        />
      </div>
    </div>
  );
}

const compactOutlineActionClass = `${adminCompactActionButtonClass} gap-1.5 text-[13px]`;
