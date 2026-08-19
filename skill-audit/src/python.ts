/**
 * Python AST analysis (Phase 5, slice 3).
 *
 * Uses the reference `python3` interpreter's ast module when available to
 * parse skill Python files — parse only, the file is never executed. The
 * static collector script emits JSON records; capability mapping and taint
 * analysis happen in TypeScript against the shared ObservedCapability model.
 * When python3 is unavailable the analyzer reports skipped.
 */
import { execFileSync } from "child_process";
import { CapabilityKind } from "./context.js";
import { SourceLocation } from "./types.js";

export interface PythonCapability {
  capability: CapabilityKind;
  level: "observed";
  evidence: string;
  file: string;
  line: number;
  scope?: { server?: string; tool?: string };
  location?: SourceLocation;
}

export interface PythonTaintPath {
  kind: "env-to-network" | "file-to-network" | "input-to-exec" | "context-to-output";
  evidence: string;
  file: string;
  line: number;
  location?: SourceLocation;
}

export interface PythonAnalyzerResult {
  capabilities: PythonCapability[];
  taintPaths: PythonTaintPath[];
  status: "completed" | "skipped" | "not_applicable" | "partial";
  detail?: string;
  filesAnalyzed: number;
  /** Candidates in scope when the analyzer could not run. */
  filesInScope?: number;
}

const PY_FILES = /\.py$/i;

/**
 * Position fields emitted by the collector. Python ast offsets are 0-based;
 * `end_col` is exclusive (one past the last character). Fields may be null
 * on interpreters older than 3.8, which lack end positions.
 */
interface PyPosition {
  col?: number | null;
  end_line?: number | null;
  end_col?: number | null;
}

interface PyCallRecord extends PyPosition {
  name: string;
  module: string | null;
  line: number;
  args: string;
}
interface PyAssignRecord extends PyPosition {
  target: string;
  source: "env" | "file" | "argv" | "context";
  line: number;
}
interface PyEnvRecord extends PyPosition { name: string; line: number; }
interface PyOpenRecord extends PyPosition { mode: string; line: number; }

interface PyFileReport {
  calls: PyCallRecord[];
  assigns: PyAssignRecord[];
  envReads: PyEnvRecord[];
  opens: PyOpenRecord[];
}

// Parses the file and prints JSON records. Never executes the target file.
const COLLECTOR = String.raw`
import ast, json, sys
records = {"calls": [], "assigns": [], "envReads": [], "opens": []}

def arg_text(a):
    try:
        return ast.unparse(a)[:160]
    except Exception:
        return "?"

def pos(node):
    return {
        "col": getattr(node, "col_offset", None),
        "end_line": getattr(node, "end_lineno", None),
        "end_col": getattr(node, "end_col_offset", None),
    }

class V(ast.NodeVisitor):
    def call_name(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id, None
        if isinstance(node.func, ast.Attribute):
            mod = None
            if isinstance(node.func.value, ast.Name):
                mod = node.func.value.id
            return node.func.attr, mod
        return None, None

    def visit_Call(self, node):
        name, mod = self.call_name(node)
        if name:
            parts = [arg_text(a) for a in node.args[:3]]
            parts.extend(f"{kw.arg}={arg_text(kw.value)}" for kw in node.keywords[:3])
            records["calls"].append({
                "name": name, "module": mod, "line": node.lineno,
                "args": ", ".join(parts), **pos(node),
            })
            if name == "open":
                mode = "r"
                for kw in node.keywords:
                    if kw.arg == "mode":
                        try:
                            mode = ast.literal_eval(kw.value)
                        except Exception:
                            mode = "?"
                if len(node.args) >= 2:
                    try:
                        mode = ast.literal_eval(node.args[1])
                    except Exception:
                        pass
                records["opens"].append({"mode": str(mode), "line": node.lineno, **pos(node)})
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if (isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name)
                and node.value.attr == "environ" and node.value.value.id == "os"):
            records["envReads"].append({"name": node.attr, "line": node.lineno, **pos(node)})
        self.generic_visit(node)

    def visit_Assign(self, node):
        if not node.targets or not isinstance(node.targets[0], ast.Name):
            return
        target = node.targets[0].id
        v = node.value
        kind = None
        name, mod = self.call_name(v) if isinstance(v, ast.Call) else (None, None)
        if name == "getenv" and mod in ("os", None):
            kind = "env"
        elif name == "environ" or (name == "get" and isinstance(v, ast.Attribute)
                and isinstance(v.value, ast.Attribute) and v.value.attr == "environ"):
            kind = "env"
        elif name == "open":
            kind = "file"
        elif name == "read" or name == "readlines":
            kind = "file"
        elif isinstance(v, ast.Subscript) or name == "argv":
            src = ast.unparse(v) if hasattr(ast, "unparse") else ""
            if "argv" in src:
                kind = "argv"
        if kind:
            records["assigns"].append({"target": target, "source": kind, "line": node.lineno, **pos(node)})
        self.generic_visit(node)

with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
    tree = ast.parse(fh.read(), filename=sys.argv[1])
V().visit(tree)
print(json.dumps(records))
`;

function pythonAvailable(): boolean {
  try {
    execFileSync("python3", ["--version"], { stdio: "ignore", timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

const EXEC_CALLS: Record<string, Set<string>> = {
  system: new Set(["os"]), popen: new Set(["os"]),
  run: new Set(["subprocess"]), Popen: new Set(["subprocess"]),
  check_output: new Set(["subprocess"]), check_call: new Set(["subprocess"]),
  exec: new Set([""]), eval: new Set([""]),
};
const NETWORK_CALLS: Record<string, Set<string>> = {
  urlopen: new Set(["urllib", "urllib_request"]),
  request: new Set(["requests"]), get: new Set(["requests"]), post: new Set(["requests"]),
  put: new Set(["requests"]), delete: new Set(["requests"]), head: new Set(["requests"]),
  create_connection: new Set(["socket"]),
};
const NETWORK_MODULES = new Set(["requests", "httpx", "aiohttp", "urllib3"]);
const HTTP_VERBS = new Set(["get", "post", "put", "delete", "head", "request", "patch"]);

function classifyCall(rec: PyCallRecord): CapabilityKind | null {
  const mod = rec.module ?? "";
  if (/^(callTool|use_mcp_tool|invoke_tool|list_tools)$/.test(rec.name)) return "mcp.invoke";
  if ((rec.name === "getenv" || rec.name === "environ") && mod === "os") return "env.read";
  if (EXEC_CALLS[rec.name]?.has(mod)) return "process.exec";
  if (NETWORK_CALLS[rec.name]?.has(mod)) return "network.request";
  if (NETWORK_MODULES.has(mod) && HTTP_VERBS.has(rec.name)) return "network.request";
  return null;
}

/**
 * Build a SourceLocation from the collector's position fields.
 * Python offsets are 0-based; end_col_offset is exclusive, so the 1-based
 * exclusive end column is end_col + 1. When end positions are missing
 * (python3 < 3.8) the location degrades honestly to line-only.
 */
function locationOf(file: string, rec: { line: number } & PyPosition): SourceLocation {
  if (rec.col == null || rec.end_line == null || rec.end_col == null) {
    return {
      file,
      startLine: rec.line,
      startColumn: 1,
      endLine: rec.line,
      endColumn: 1,
      precision: "line-only",
    };
  }
  return {
    file,
    startLine: rec.line,
    startColumn: rec.col + 1,
    endLine: rec.end_line,
    endColumn: rec.end_col + 1, // python end_col_offset is 0-based exclusive
    precision: "exact",
  };
}

export interface PythonAnalyzerOptions {
  /** Test override: force the "python3 unavailable" path. */
  pythonAvailable?: boolean;
}

export function analyzePython(files: Array<{ path: string; absolutePath?: string; content?: string }>, options: PythonAnalyzerOptions = {}): PythonAnalyzerResult {
  const candidates = files.filter(f => PY_FILES.test(f.path) && f.content !== undefined);
  if (candidates.length === 0) {
    return { capabilities: [], taintPaths: [], status: "not_applicable", detail: "no Python files in scope", filesAnalyzed: 0 };
  }
  const canRun = options.pythonAvailable === undefined ? pythonAvailable() : options.pythonAvailable;
  if (!canRun) {
    return {
      capabilities: [], taintPaths: [], status: "skipped",
      detail: `python3 not available; ${candidates.length} Python file(s) in scope left unanalyzed`,
      filesInScope: candidates.length,
      filesAnalyzed: 0,
    };
  }

  const capabilities: PythonCapability[] = [];
  const taintPaths: PythonTaintPath[] = [];
  const seen = new Set<string>();
  let failed = 0;

  for (const file of candidates) {
    let report: PyFileReport;
    try {
      const out = execFileSync("python3", ["-c", COLLECTOR, file.absolutePath ?? file.path], {
        encoding: "utf-8",
        timeout: 10_000,
        maxBuffer: 8 * 1024 * 1024,
      });
      report = JSON.parse(out) as PyFileReport;
    } catch {
      failed++;
      continue;
    }

    const push = (capability: CapabilityKind, evidence: string, line: number, location: SourceLocation, scope?: { server?: string; tool?: string }) => {
      const key = `${capability}:${file.path}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      capabilities.push({ capability, level: "observed", evidence: evidence.slice(0, 160), file: file.path, line, location, scope });
    };

    for (const rec of report.calls) {
      const kind = classifyCall(rec);
      if (!kind) continue;
      const scope = kind === "mcp.invoke"
        ? {
            server: rec.args.match(/server(?:Name)?\s*=\s*['"]([^'"]+)['"]/)?.[1],
            tool: rec.args.match(/(?:toolName|tool_name|name)\s*=\s*['"]([^'"]+)['"]/)?.[1],
          }
        : undefined;
      push(kind, `${rec.name}(${rec.args})`, rec.line, locationOf(file.path, rec), scope);
    }
    for (const env of report.envReads) push("env.read", `os.environ.${env.name}`, env.line, locationOf(file.path, env));
    for (const open of report.opens) {
      push(/^[wax]/.test(open.mode) ? "fs.write" : "fs.read", `open(mode="${open.mode}")`, open.line, locationOf(file.path, open));
    }

    // ---- Intra-file taint (Phase 5, slice 4) ----
    const tainted = new Map<string, PyAssignRecord["source"]>();
    for (const a of report.assigns) tainted.set(a.target, a.source);
    for (const rec of report.calls) {
      const kind = classifyCall(rec);
      if (kind !== "network.request" && kind !== "process.exec") continue;
      const location = locationOf(file.path, rec);
      for (const [varName, source] of tainted) {
        if (!new RegExp(`\\b${varName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(rec.args)) continue;
        if (source === "env" && kind === "network.request") {
          taintPaths.push({ kind: "env-to-network", evidence: `${varName} → ${rec.name}(${rec.args})`, file: file.path, line: rec.line, location });
        } else if (source === "file" && kind === "network.request") {
          taintPaths.push({ kind: "file-to-network", evidence: `${varName} → ${rec.name}(${rec.args})`, file: file.path, line: rec.line, location });
        } else if (source === "argv" && kind === "process.exec") {
          taintPaths.push({ kind: "input-to-exec", evidence: `${varName} → ${rec.name}(${rec.args})`, file: file.path, line: rec.line, location });
        }
      }
    }
  }

  const status = failed === candidates.length ? "partial" : failed > 0 ? "partial" : "completed";
  return {
    capabilities,
    taintPaths,
    status,
    detail: failed > 0 ? `${failed}/${candidates.length} file(s) failed to parse` : undefined,
    filesAnalyzed: candidates.length - failed,
  };
}
