import { describe, expect, it } from "vitest";
import { isContained } from "./paths.js";
import { posix, win32 } from "path";

// Windows path semantics injected on any platform: the containment logic must
// use the separator of the semantics that produced the relative path, or
// `..\escape` slips past a hard-coded "../" test.
const windowsSemantics = {
  relative: win32.relative,
  isAbsolute: win32.isAbsolute,
  sep: win32.sep,
};

describe("isContained (posix semantics, active platform default)", () => {
  it("accepts strictly interior targets", () => {
    expect(isContained("/a/skill", "/a/skill/lib/x.ts")).toBe(true);
    expect(isContained("/a/skill", "/a/skill/a/b/c.md")).toBe(true);
  });

  it("rejects sibling directories that share a string prefix", () => {
    expect(isContained("/a/skill", "/a/skill-evil/x.ts")).toBe(false);
    expect(isContained("/a/skill", "/a/skillet/x.ts")).toBe(false);
  });

  it("rejects the root itself, the parent, and everything above", () => {
    expect(isContained("/a/skill", "/a/skill")).toBe(false); // strictly interior only
    expect(isContained("/a/skill", "/a")).toBe(false); // parent exactly ("..")
    expect(isContained("/a/skill", "/")).toBe(false);
    expect(isContained("/a/skill", "/etc/passwd")).toBe(false);
  });
});

describe("isContained (win32 semantics — the ..\\ blind spot)", () => {
  it("accepts strictly interior targets", () => {
    expect(isContained("C:\\skills\\a", "C:\\skills\\a\\lib\\x.ts", windowsSemantics)).toBe(true);
  });

  it("rejects backslash parent escapes that never start with ../", () => {
    // win32.relative("C:\\skills\\a", "C:\\skills\\a-evil\\x.ts") === "..\\a-evil\\x.ts"
    expect(isContained("C:\\skills\\a", "C:\\skills\\a-evil\\x.ts", windowsSemantics)).toBe(false);
    expect(isContained("C:\\skills\\a", "C:\\skills\\other\\x.ts", windowsSemantics)).toBe(false);
    expect(isContained("C:\\skills\\a", "C:\\skills", windowsSemantics)).toBe(false);
    expect(isContained("C:\\skills\\a", "C:\\", windowsSemantics)).toBe(false);
  });

  it("rejects the root itself and same-drive parents", () => {
    expect(isContained("C:\\skills\\a", "C:\\skills\\a", windowsSemantics)).toBe(false);
    expect(isContained("C:\\skills\\a", "C:\\skills\\a\\..", windowsSemantics)).toBe(false);
  });

  it("rejects different-drive targets (absolute relative-result)", () => {
    // win32.relative across drives returns an absolute path
    expect(isContained("C:\\skills\\a", "D:\\steal\\x.ts", windowsSemantics)).toBe(false);
  });
});
