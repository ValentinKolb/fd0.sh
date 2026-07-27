import type { PassField } from "../../../shared/contracts";

const MAX_PASS_DEPTH = 4;

export type PassFieldDropLane = "field" | "section" | "mixed";

export function updatePassFieldTree(fields: PassField[], path: number[], next: PassField | null): PassField[] {
  const [index, ...rest] = path;
  if (index === undefined || index < 0 || index >= fields.length) return fields;
  if (rest.length === 0) {
    if (next === null) return fields.filter((_, current) => current !== index);
    return fields.map((field, current) => current === index ? next : field);
  }
  return fields.map((field, current) => {
    if (current !== index || field.type !== "section") return field;
    return { ...field, fields: updatePassFieldTree(field.fields ?? [], rest, next) };
  });
}

export function countPassFields(fields: PassField[]): number {
  return fields.reduce((count, field) => count + 1 + (field.type === "section" ? countPassFields(field.fields ?? []) : 0), 0);
}

export function canMovePassFieldTree(fields: PassField[], sourcePath: number[], targetParentPath: number[], targetIndex: number): boolean {
  const source = passFieldAt(fields, sourcePath);
  const sourceParentPath = sourcePath.slice(0, -1);
  const sourceIndex = sourcePath.at(-1);
  const target = passFieldListAt(fields, targetParentPath);
  if (!source || sourceIndex === undefined || !target) return false;
  if (pathStartsWith(targetParentPath, sourcePath)) return false;
  if (targetIndex < 0 || targetIndex > target.length) return false;
  if (samePath(sourceParentPath, targetParentPath) && (targetIndex === sourceIndex || targetIndex === sourceIndex + 1)) return false;
  if (targetParentPath.length + sectionHeight(source) > MAX_PASS_DEPTH) return false;

  const duplicate = target.some((field, index) => {
    if (samePath(sourceParentPath, targetParentPath) && index === sourceIndex) return false;
    return field.name === source.name;
  });
  return !duplicate;
}

/**
 * Drag-and-drop only reorders siblings. Root fields and root sections render
 * in separate visual lanes, while children of a section share one mixed lane.
 */
export function canReorderPassFieldTree(
  fields: PassField[],
  sourcePath: number[],
  targetParentPath: number[],
  targetIndex: number,
  lane: PassFieldDropLane,
): boolean {
  if (!samePath(sourcePath.slice(0, -1), targetParentPath)) return false;
  const source = passFieldAt(fields, sourcePath);
  if (!source) return false;
  if (lane === "field" && source.type === "section") return false;
  if (lane === "section" && source.type !== "section") return false;
  return canMovePassFieldTree(fields, sourcePath, targetParentPath, targetIndex);
}

export function movePassFieldTree(fields: PassField[], sourcePath: number[], targetParentPath: number[], targetIndex: number): PassField[] {
  if (!canMovePassFieldTree(fields, sourcePath, targetParentPath, targetIndex)) return fields;
  const source = passFieldAt(fields, sourcePath)!;
  const sourceParentPath = sourcePath.slice(0, -1);
  const sourceIndex = sourcePath.at(-1)!;
  const sourceList = passFieldListAt(fields, sourceParentPath)!;
  const withoutSource = replacePassFieldList(fields, sourceParentPath, sourceList.filter((_, index) => index !== sourceIndex));

  const adjustedParentPath = adjustPathAfterRemoval(targetParentPath, sourceParentPath, sourceIndex);
  const adjustedTargetIndex = samePath(sourceParentPath, targetParentPath) && targetIndex > sourceIndex
    ? targetIndex - 1
    : targetIndex;
  const targetList = passFieldListAt(withoutSource, adjustedParentPath);
  if (!targetList) return fields;

  const insertionIndex = Math.min(Math.max(adjustedTargetIndex, 0), targetList.length);
  const nextTarget = [...targetList];
  nextTarget.splice(insertionIndex, 0, source);
  return replacePassFieldList(withoutSource, adjustedParentPath, nextTarget);
}

/** Explicit hierarchy changes append the field to the chosen destination. */
export function movePassFieldTreeToParent(fields: PassField[], sourcePath: number[], targetParentPath: number[]): PassField[] {
  const target = passFieldListAt(fields, targetParentPath);
  if (!target) return fields;
  return movePassFieldTree(fields, sourcePath, targetParentPath, target.length);
}

function passFieldAt(fields: PassField[], path: number[]): PassField | null {
  if (path.length === 0) return null;
  const parent = passFieldListAt(fields, path.slice(0, -1));
  return parent?.[path.at(-1)!] ?? null;
}

function passFieldListAt(fields: PassField[], parentPath: number[]): PassField[] | null {
  let current = fields;
  for (const index of parentPath) {
    const section = current[index];
    if (!section || section.type !== "section") return null;
    current = section.fields ?? [];
  }
  return current;
}

function replacePassFieldList(fields: PassField[], parentPath: number[], nextList: PassField[]): PassField[] {
  const [index, ...rest] = parentPath;
  if (index === undefined) return nextList;
  return fields.map((field, current) => {
    if (current !== index || field.type !== "section") return field;
    return { ...field, fields: replacePassFieldList(field.fields ?? [], rest, nextList) };
  });
}

function adjustPathAfterRemoval(path: number[], sourceParentPath: number[], sourceIndex: number): number[] {
  if (!pathStartsWith(path, sourceParentPath) || path.length === sourceParentPath.length) return path;
  const branchIndex = path[sourceParentPath.length]!;
  if (branchIndex <= sourceIndex) return path;
  const adjusted = [...path];
  adjusted[sourceParentPath.length] = branchIndex - 1;
  return adjusted;
}

function sectionHeight(field: PassField): number {
  if (field.type !== "section") return 0;
  return 1 + Math.max(0, ...(field.fields ?? []).map(sectionHeight));
}

function pathStartsWith(path: number[], prefix: number[]): boolean {
  return prefix.length <= path.length && prefix.every((part, index) => path[index] === part);
}

function samePath(left: number[], right: number[]): boolean {
  return left.length === right.length && left.every((part, index) => right[index] === part);
}
