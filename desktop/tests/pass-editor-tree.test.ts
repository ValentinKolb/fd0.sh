import { describe, expect, test } from "bun:test";
import type { PassField } from "../src/shared/contracts";
import {
  canMovePassFieldTree,
  canReorderPassFieldTree,
  movePassFieldTree,
  movePassFieldTreeToParent,
} from "../src/renderer/src/components/passEditorTree";

const text = (name: string): PassField => ({ type: "text", name, value: name });
const section = (name: string, fields: PassField[] = []): PassField => ({ type: "section", name, fields });

describe("password editor field moves", () => {
  test("reorders fields in the same list", () => {
    const fields = [text("a"), text("b"), text("c")];
    expect(movePassFieldTree(fields, [0], [], 3).map((field) => field.name)).toEqual(["b", "c", "a"]);
  });

  test("moves a root field into a later section after indices shift", () => {
    const fields = [text("token"), section("Operations"), text("owner")];
    const moved = movePassFieldTree(fields, [0], [1], 0);
    expect(moved.map((field) => field.name)).toEqual(["Operations", "owner"]);
    expect(moved[0]!.fields?.map((field) => field.name)).toEqual(["token"]);
  });

  test("moves a nested field back to the root", () => {
    const fields = [section("Operations", [text("token")]), text("owner")];
    const moved = movePassFieldTree(fields, [0, 0], [], 2);
    expect(moved.map((field) => field.name)).toEqual(["Operations", "owner", "token"]);
    expect(moved[0]!.fields).toEqual([]);
  });

  test("explicit hierarchy moves append to the chosen parent", () => {
    const fields = [section("Operations", [text("token")]), text("owner"), section("Archive")];
    const movedToRoot = movePassFieldTreeToParent(fields, [0, 0], []);
    expect(movedToRoot.map((field) => field.name)).toEqual(["Operations", "owner", "Archive", "token"]);

    const movedToArchive = movePassFieldTreeToParent(movedToRoot, [3], [2]);
    expect(movedToArchive.map((field) => field.name)).toEqual(["Operations", "owner", "Archive"]);
    expect(movedToArchive[2]!.fields?.map((field) => field.name)).toEqual(["token"]);
  });

  test("moves a section as one subtree", () => {
    const operations = section("Operations", [text("token")]);
    const fields = [text("owner"), operations, text("region")];
    const moved = movePassFieldTree(fields, [1], [], 0);
    expect(moved.map((field) => field.name)).toEqual(["Operations", "owner", "region"]);
    expect(moved[0]).toBe(operations);
  });

  test("moves a section into another section without losing its subtree", () => {
    const source = section("Source", [text("token")]);
    const fields = [source, text("owner"), section("Target")];
    const moved = movePassFieldTree(fields, [0], [2], 0);
    expect(moved.map((field) => field.name)).toEqual(["owner", "Target"]);
    expect(moved[1]!.fields).toEqual([source]);
    expect(moved[1]!.fields?.[0]!.fields?.map((field) => field.name)).toEqual(["token"]);
  });

  test("rejects self, descendant, duplicate-name, and excessive-depth moves", () => {
    const nested = section("A", [section("B", [section("C", [section("D")])])]);
    const fields = [nested, section("Target", [text("token")]), text("token")];
    expect(canMovePassFieldTree(fields, [0], [0, 0], 0)).toBe(false);
    expect(canMovePassFieldTree(fields, [2], [1], 1)).toBe(false);
    expect(canMovePassFieldTree(fields, [1], [0, 0, 0, 0], 0)).toBe(false);
    expect(movePassFieldTree(fields, [0], [0, 0], 0)).toBe(fields);
  });

  test("drag reorder accepts siblings only and respects root lanes", () => {
    const fields = [text("owner"), section("Operations", [text("token"), section("Nested")]), section("Archive")];
    expect(canReorderPassFieldTree(fields, [0], [], 3, "field")).toBe(true);
    expect(canReorderPassFieldTree(fields, [0], [1], 0, "mixed")).toBe(false);
    expect(canReorderPassFieldTree(fields, [1], [], 3, "field")).toBe(false);
    expect(canReorderPassFieldTree(fields, [1], [], 3, "section")).toBe(true);
    expect(canReorderPassFieldTree(fields, [1, 0], [1], 2, "mixed")).toBe(true);
  });
});
