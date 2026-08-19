/**
 * Structural code analysis (Phase 5, slice 1: TypeScript/JavaScript AST).
 *
 * Uses the TypeScript compiler API when the `typescript` package is
 * resolvable at runtime (dev environments, skills that ship it); otherwise
 * the analyzer reports skipped and regex-grade observation remains the only
 * source. Every detection emits the shared ObservedCapability model — no
 * language-specific policy — so preflight comparison stays uniform.
 */
import { createRequire } from "module";
import { CapabilityKind } from "./context.js";
import { SourceLocation } from "./types.js";

export interface AstCapability {
  capability: CapabilityKind;
  level: "observed";
  evidence: string;
  file: string;
  line: number;
  scope?: { server?: string; tool?: string };
  location?: SourceLocation;
}

export interface AstTaintPath {
  kind: "env-to-network" | "file-to-network" | "input-to-exec" | "context-to-output";
  evidence: string;
  file: string;
  line: number;
  location?: SourceLocation;
}

export interface AstAnalyzerResult {
  capabilities: AstCapability[];
  taintPaths: AstTaintPath[];
  status: "completed" | "partial" | "skipped" | "not_applicable";
  detail?: string;
  filesAnalyzed: number;
  /** Candidates in scope when the analyzer could not run. */
  filesInScope?: number;
}

const TS_FILES = /\.(ts|tsx|js|jsx|mjs|cjs)$/i;

/** Call targets mapped to capability kinds. */
const CALL_PATTERNS: Array<{ match: RegExp; capability: CapabilityKind }> = [
  { match: /^(?:execSync|execFileSync|spawnSync|exec|execFile|spawn|fork)$/, capability: "process.exec" },
  { match: /^(?:fetch)$/, capability: "network.request" },
  { match: /^(?:request|get|post|put|delete|connect)$/, capability: "network.request" },
  { match: /^(?:readFile|readFileSync|readdir|readdirSync|readlink|readlinkSync)$/, capability: "fs.read" },
  { match: /^(?:writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync)$/, capability: "fs.write" },
];

const NETWORK_MODULES = /^(?:https?|net|tls|undici|axios|node-fetch|got|superagent)$/;

interface TsModule {
  createSourceFile: (
    fileName: string,
    text: string,
    languageVersion: number,
    setParentNodes?: boolean
  ) => TsSourceFileLike;
  ScriptTarget: { ES2022: number };
  SyntaxKind: { [key: string]: number };
  forEachChild: (node: unknown, cb: (node: unknown) => void) => void;
  isCallExpression: (node: unknown) => boolean;
  isPropertyAccessExpression: (node: unknown) => boolean;
  isIdentifier: (node: unknown) => boolean;
  isVariableDeclaration: (node: unknown) => boolean;
}

/** The subset of ts.SourceFile the analyzer relies on. */
interface TsSourceFileLike {
  getLineAndCharacterOfPosition(pos: number): { line: number; character: number };
  /**
   * Parser diagnostics populated because we call createSourceFile directly
   * (no Program). Non-empty when the file had syntax errors; the parser
   * still recovers, so partially-parsed nodes remain walkable.
   */
  parseDiagnostics?: ReadonlyArray<{
    messageText: string | { messageText?: string };
    start?: number;
  }>;
}

let tsModule: TsModule | null | undefined;

function loadTypescript(): TsModule | null {
  if (tsModule !== undefined) return tsModule;
  try {
    const require = createRequire(import.meta.url);
    tsModule = require("typescript") as TsModule;
  } catch {
    tsModule = null;
  }
  return tsModule;
}

interface TsNode {
  getStart(): number;
  /** Exclusive end offset (one past the last character of the node). */
  getEnd(): number;
  getSourceFile(): { getLineAndCharacterOfPosition?(pos: number): { line: number; character: number } };
  expression?: TsNode;
  name?: TsNode;
  getText(): string;
  parent?: TsNode;
}

function calleeName(node: TsNode): string | null {
  const expr = node.expression;
  if (!expr) return null;
  // directCall() or module.call()
  const text = expr.getText();
  const lastSegment = text.includes(".") ? text.split(".").pop()! : text;
  return lastSegment || null;
}

function importModuleOfCall(node: TsNode): string | null {
  // Walk up property access: `child_process.execSync(...)` → module text.
  const expr = node.expression;
  if (expr && expr.getText().includes(".")) {
    const text = expr.getText();
    const modulePart = text.slice(0, text.lastIndexOf("."));
    if (/^[A-Za-z_$][\w$]*$/.test(modulePart)) return modulePart;
  }
  return null;
}

export interface AstAnalyzerOptions {
  /** Test override: force the "typescript unresolvable" path. */
  typescriptAvailable?: boolean;
}

export function analyzeTypeScript(files: Array<{ path: string; content?: string }>, options: AstAnalyzerOptions = {}): AstAnalyzerResult {
  const candidates = files.filter(f => TS_FILES.test(f.path) && f.content !== undefined);
  if (candidates.length === 0) {
    return { capabilities: [], taintPaths: [], status: "not_applicable", detail: "no TypeScript/JavaScript files in scope", filesAnalyzed: 0 };
  }

  const ts = options.typescriptAvailable === false ? null : loadTypescript();
  if (!ts) {
    return {
      capabilities: [],
      taintPaths: [],
      status: "skipped",
      detail: `typescript package not resolvable; ${candidates.length} TypeScript/JavaScript file(s) in scope left unanalyzed`,
      filesInScope: candidates.length,
      filesAnalyzed: 0,
    };
  }

  const capabilities: AstCapability[] = [];
  const allTaint: AstTaintPath[] = [];
  const seen = new Set<string>();
  let parseErrors = 0;
  let filesWithParseErrors = 0;

  const push = (capability: CapabilityKind, evidence: string, file: string, line: number, location?: SourceLocation, scope?: { server?: string; tool?: string }) => {
    const key = `${capability}:${file}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    capabilities.push({ capability, level: "observed", evidence: evidence.slice(0, 120), file, line, location, scope });
  };

  for (const file of candidates) {
    const source = ts.createSourceFile(file.path, file.content!, ts.ScriptTarget.ES2022, true);
    const diagnostics = source.parseDiagnostics ?? [];
    if (diagnostics.length > 0) {
      parseErrors += diagnostics.length;
      filesWithParseErrors++;
    }

    // Exact 1-based range from TS offsets (both 0-based; end exclusive).
    const locationOf = (node: TsNode): SourceLocation => {
      const start = source.getLineAndCharacterOfPosition(node.getStart());
      const end = source.getLineAndCharacterOfPosition(node.getEnd());
      return {
        file: file.path,
        startLine: start.line + 1,
        startColumn: start.character + 1,
        endLine: end.line + 1,
        endColumn: end.character + 1, // exclusive: end offset sits one past the last char
        precision: "exact",
      };
    };

    const tainted = new Map<string, "env" | "file" | "argv" | "context">();

    const recordTaint = (node: TsNode) => {
      // const x = <initializer> — classify the initializer's taint source.
      const init = (node as TsNode & { initializer?: TsNode }).initializer;
      const nameNode = (node as TsNode & { name?: TsNode }).name;
      if (!init || !nameNode) return;
      const varName = nameNode.getText();
      const initText = init.getText();
      let source: "env" | "file" | "argv" | "context" | null = null;
      if (initText.includes("process.env.")) source = "env";
      else if (/readFile|readdir|createReadStream/.test(initText)) source = "file";
      else if (initText.includes("process.argv") || initText.includes("readline")
        || initText.includes("process.stdin")) source = "argv";
      else if (/context|session|conversation|history|transcript/i.test(varName)) source = "context";
      if (source && !tainted.has(varName)) tainted.set(varName, source);
    };

    const taintPaths: AstTaintPath[] = [];
    const checkTaintSink = (node: TsNode, capability: CapabilityKind) => {
      const text = node.getText();
      const location = locationOf(node);
      const line = location.startLine;
      for (const [varName, source] of tainted) {
        const re = new RegExp(`\\b${varName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);
        if (!re.test(text)) continue;
        if (source === "env" && capability === "network.request") {
          taintPaths.push({ kind: "env-to-network", evidence: `${varName} → ${text.slice(0, 100)}`, file: file.path, line, location });
        } else if (source === "file" && capability === "network.request") {
          taintPaths.push({ kind: "file-to-network", evidence: `${varName} → ${text.slice(0, 100)}`, file: file.path, line, location });
        } else if (source === "argv" && capability === "process.exec") {
          taintPaths.push({ kind: "input-to-exec", evidence: `${varName} → ${text.slice(0, 100)}`, file: file.path, line, location });
        } else if (source === "context"
          && (capability === "network.request" || /console\.(log|info|error)|logger|log\(/.test(text))) {
          taintPaths.push({ kind: "context-to-output", evidence: `${varName} → ${text.slice(0, 100)}`, file: file.path, line, location });
        }
      }
    };

    const visit = (node: unknown) => {
      const n = node as TsNode;
      if (ts.isVariableDeclaration(node)) {
        recordTaint(n);
      }
      if (ts.isCallExpression(node)) {
        const name = calleeName(n);
        const module = importModuleOfCall(n);
        let matched: CapabilityKind | null = null;
        if (name) {
          for (const { match, capability } of CALL_PATTERNS) {
            if (match.test(name)) {
              // Only attribute module-ambiguous short names when the call
              // site references a known network module; `fetch` is unambiguous.
              if (capability === "network.request" && !module && name !== "fetch") continue;
              matched = capability;
              const location = locationOf(n);
              push(capability, n.getText(), file.path, location.startLine, location);
              break;
            }
          }
        }
        if (module && NETWORK_MODULES.test(module)) {
          matched = "network.request";
          const location = locationOf(n);
          push("network.request", n.getText(), file.path, location.startLine, location);
        }
        if (name && /^(callTool|use_mcp_tool|invoke_tool|listTools)$/.test(name)) {
          const text = n.getText();
          const server = text.match(/server(?:Name)?\s*[:=]\s*['"]([^'"]+)['"]/)?.[1];
          const tool = text.match(/(?:toolName|tool_name|name)\s*[:=]\s*['"]([^'"]+)['"]/)?.[1];
          const location = locationOf(n);
          push("mcp.invoke", text, file.path, location.startLine, location, { server, tool });
        }
        if (matched) checkTaintSink(n, matched);
      }
      if (ts.isPropertyAccessExpression(node) || ts.isIdentifier(node)) {
        const text = n.getText();
        if (text.startsWith("process.env.")) {
          const location = locationOf(n);
          push("env.read", text, file.path, location.startLine, location);
        }
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(source, visit);
    allTaint.push(...taintPaths);
  }

  // Structural parse failures downgrade the run to partial — the capabilities
  // above were collected from the parser's recovered (parseable) portions only,
  // so consumers must not treat the file set as fully analyzed.
  if (filesWithParseErrors > 0) {
    return {
      capabilities,
      taintPaths: allTaint,
      status: "partial",
      detail: `${parseErrors} parse error(s) in ${filesWithParseErrors} file(s)`,
      filesAnalyzed: candidates.length,
    };
  }
  return { capabilities, taintPaths: allTaint, status: "completed", filesAnalyzed: candidates.length };
}
