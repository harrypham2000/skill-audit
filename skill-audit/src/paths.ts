/**
 * Path containment must be segment-aware: a sibling like `/root-other`
 * must never pass a check against `/root`. String-prefix matching is
 * unsafe; use normalized relative containment.
 *
 * The parent-escape prefix is built from the ACTIVE path module's separator:
 * on Windows, relative() emits `..\outside`, which a hard-coded "../" test
 * would let through. Path semantics are injectable so Windows behavior is
 * testable on any platform.
 */
import path from "path";

export interface PathSemantics {
  relative(from: string, to: string): string;
  isAbsolute(p: string): boolean;
  sep: string;
}

export function isContained(root: string, target: string, paths: PathSemantics = path): boolean {
  const rel = paths.relative(root, target);
  return (
    rel !== "" &&
    rel !== ".." &&
    !rel.startsWith(`..${paths.sep}`) &&
    !paths.isAbsolute(rel)
  );
}
