/**
 * Canonical scan kernel (Phase 1 of the improvement plan).
 *
 * Processing order:
 *   snapshot → analyzers → capabilities → policy decision → canonical report
 *
 * The report is renderer-agnostic: the CLI (or any caller) selects a renderer
 * only after the policy decision has been computed. Exit contract:
 *   0 = scan completed, policy allowed
 *   1 = scan completed, policy rejected
 *   2 = invalid input, required analyzer failure, or insufficient inspection
 */
import { createHash } from "crypto";
import { lstatSync, readdirSync, readFileSync, statSync, existsSync, realpathSync, openSync, readSync, closeSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { isContained } from "./paths.js";
import { join, relative, resolve, basename } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import { Finding } from "./types.js";
import { auditSecurity } from "./security.js";
import { validateSkillSpec } from "./spec.js";
import { scanDependenciesDetailed } from "./deps.js";
import { observeProcessExec, parseContextContract, evaluatePreflight, PreflightDecision, ObservedCapability } from "./context.js";
import { findingFingerprint, loadSuppressions, applySuppressions } from "./suppress.js";
import { analyzeTypeScript } from "./ast.js";
import { analyzeShell } from "./shell.js";
import { analyzePython } from "./python.js";
import { MCP_CONFIG_FILES, parseMcpConfig, analyzeMcpConfig, diffMcpConfigs } from "./mcp.js";
import { getIgnorePatterns, filterIgnoredFiles, resolveSkillPath } from "./discover.js";

// ============================================================
// Limits and snapshot model
// ============================================================

export interface ScanLimits {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  maxDepth: number;
  followSymlinks: boolean;
  timeoutMs: number;
}

export const DEFAULT_SCAN_LIMITS: ScanLimits = {
  maxFiles: 2000,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: 50 * 1024 * 1024,
  maxDepth: 8,
  followSymlinks: false,
  timeoutMs: 10_000,
};

export interface SnapshotFile {
  /** Path relative to the skill root, normalized with forward slashes. */
  path: string;
  absolutePath: string;
  size: number;
  sha256: string;
  executable: boolean;
  type: "text" | "binary" | "unknown";
  /** Text content when read (possibly truncated to maxFileBytes). */
  content?: string;
  truncated: boolean;
  readError?: string;
}

export interface ScopeExclusion {
  path: string;
  reason:
    | "default-exclude"
    | "ignore-pattern"
    | "symlink-escape"
    | "symlink-disabled"
    | "symlink-cycle"
    | "depth-exceeded"
    | "file-count-exceeded"
    | "total-bytes-exceeded"
    | "unreadable"
    | "timeout";
}

export interface SkillSnapshot {
  root: string;
  files: SnapshotFile[];
  exclusions: ScopeExclusion[];
  limitsExceeded: boolean;
  timedOut: boolean;
  digest: string;
  totalBytes: number;
}

const DEFAULT_EXCLUDED_DIRS = new Set(["node_modules", ".git", "dist", ".cache"]);

function sha256(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Stream a file with bounded memory: hash the COMPLETE file with SHA-256
 * while retaining at most maxBytes for analysis content. Bytes past the
 * retained prefix still change the digest; the analysis buffer never
 * exceeds maxBytes plus one chunk.
 */
function hashAndRetain(fullPath: string, maxBytes: number): {
  content: Buffer;
  sha256: string;
  truncated: boolean;
  actualBytes: number;
} {
  const fd = openSync(fullPath, "r");
  try {
    const hash = createHash("sha256");
    const chunk = Buffer.allocUnsafe(64 * 1024);
    const retained: Buffer[] = [];
    let retainedBytes = 0;
    let total = 0;
    let read: number;
    while ((read = readSync(fd, chunk, 0, chunk.length, null)) > 0) {
      const data = chunk.subarray(0, read);
      hash.update(data);
      total += read;
      if (retainedBytes < maxBytes) {
        const take = Math.min(read, maxBytes - retainedBytes);
        retained.push(Buffer.from(data.subarray(0, take)));
        retainedBytes += take;
      }
    }
    return {
      content: Buffer.concat(retained),
      sha256: hash.digest("hex"),
      truncated: total > maxBytes,
      actualBytes: total,
    };
  } finally {
    closeSync(fd);
  }
}

function isBinary(buf: Buffer): boolean {
  const probe = buf.subarray(0, 8192);
  return probe.includes(0);
}

export function buildSnapshot(rootInput: string, limits: ScanLimits = DEFAULT_SCAN_LIMITS): SkillSnapshot {
  const inputPath = resolveSkillPath(rootInput);
  const inputStat = statSync(inputPath);
  // A single-file input is scoped to that file within its parent directory.
  const root = inputStat.isFile() ? resolve(inputPath, "..") : inputPath;
  const onlyFile = inputStat.isFile() ? basename(inputPath) : undefined;
  const startedAt = Date.now();
  const files: SnapshotFile[] = [];
  const exclusions: ScopeExclusion[] = [];
  const rel = (p: string) => relative(root, p).split(/[\\/]/).join("/");

  let limitsExceeded = false;
  let timedOut = false;
  let totalBytes = 0;

  // Real paths of directories already walked. A followed symlink resolving
  // here is a cycle (or an alias revisit): it must be recorded as an
  // exclusion, never recursed into — otherwise cycles masquerade as
  // depth/limit failures and duplicate subtrees in the snapshot.
  const walkedDirs = new Set<string>();

  const walk = (dir: string, depth: number) => {
    if (timedOut) return;
    let realDir: string;
    try {
      realDir = realpathSync(dir);
    } catch {
      exclusions.push({ path: rel(dir), reason: "unreadable" });
      return;
    }
    if (walkedDirs.has(realDir)) {
      exclusions.push({ path: rel(dir), reason: "symlink-cycle" });
      return;
    }
    walkedDirs.add(realDir);
    if (Date.now() - startedAt > limits.timeoutMs) {
      timedOut = true;
      limitsExceeded = true;
      exclusions.push({ path: rel(dir), reason: "timeout" });
      return;
    }
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch (e) {
      exclusions.push({ path: rel(dir), reason: "unreadable" });
      return;
    }
    for (const entry of entries) {
      if (timedOut) return;
      const fullPath = join(dir, entry);
      let lst: ReturnType<typeof lstatSync>;
      try {
        lst = lstatSync(fullPath);
      } catch {
        exclusions.push({ path: rel(fullPath), reason: "unreadable" });
        continue;
      }

      if (lst.isSymbolicLink()) {
        let target: string;
        try {
          target = realpathSync(fullPath);
        } catch {
          exclusions.push({ path: rel(fullPath), reason: "symlink-disabled" });
          continue;
        }
        const escapes = !isContained(root, resolve(target));
        if (escapes || !limits.followSymlinks) {
          exclusions.push({
            path: rel(fullPath),
            reason: escapes ? "symlink-escape" : "symlink-disabled",
          });
          continue;
        }
        // Follow the contained symlink by TARGET type: lst is the link's own
        // stat, so directories behind links would otherwise never be walked.
        // The target can vanish between realpath and stat: that must exclude
        // the entry, never crash the whole scan.
        let targetStat: ReturnType<typeof statSync>;
        try {
          targetStat = statSync(target);
        } catch {
          exclusions.push({ path: rel(fullPath), reason: "unreadable" });
          continue;
        }
        if (targetStat.isDirectory()) {
          if (depth + 1 > limits.maxDepth) {
            exclusions.push({ path: rel(fullPath), reason: "depth-exceeded" });
            limitsExceeded = true;
            continue;
          }
          // Walk the SYMLINK PATH (not the resolved target) so recorded
          // paths stay in the skill's own namespace; readdir follows the link.
          walk(fullPath, depth + 1);
          continue;
        }
        if (!targetStat.isFile()) continue;
        // Fall through as a file using the target's stat for size decisions.
        lst = targetStat;
      }

      if (lst.isDirectory()) {
        if (DEFAULT_EXCLUDED_DIRS.has(entry) || entry.startsWith(".")) {
          exclusions.push({ path: rel(fullPath), reason: "default-exclude" });
          continue;
        }
        if (depth + 1 > limits.maxDepth) {
          exclusions.push({ path: rel(fullPath), reason: "depth-exceeded" });
          limitsExceeded = true;
          continue;
        }
        walk(fullPath, depth + 1);
        continue;
      }

      if (!lst.isFile()) continue;

      if (files.length >= limits.maxFiles) {
        exclusions.push({ path: rel(fullPath), reason: "file-count-exceeded" });
        limitsExceeded = true;
        continue;
      }
      if (totalBytes + lst.size > limits.maxTotalBytes) {
        exclusions.push({ path: rel(fullPath), reason: "total-bytes-exceeded" });
        limitsExceeded = true;
        continue;
      }

      let read: ReturnType<typeof hashAndRetain>;
      try {
        read = hashAndRetain(fullPath, limits.maxFileBytes);
      } catch (e) {
        files.push({
          path: rel(fullPath),
          absolutePath: fullPath,
          size: lst.size,
          sha256: "",
          executable: (lst.mode & 0o111) !== 0,
          type: "unknown",
          truncated: false,
          readError: String(e),
        });
        continue;
      }

      const binary = isBinary(read.content);
      // size reflects the actual bytes hashed, not the retained prefix.
      totalBytes += read.actualBytes;

      files.push({
        path: rel(fullPath),
        absolutePath: fullPath,
        size: read.actualBytes,
        sha256: read.sha256,
        executable: (lst.mode & 0o111) !== 0,
        type: binary ? "binary" : "text",
        content: binary ? undefined : read.content.toString("utf-8"),
        truncated: read.truncated,
      });
    }
  };

  walk(root, 0);

  if (onlyFile !== undefined) {
    for (let i = files.length - 1; i >= 0; i--) {
      if (files[i].path !== onlyFile) files.splice(i, 1);
    }
    for (let i = exclusions.length - 1; i >= 0; i--) {
      if (exclusions[i].path !== onlyFile) exclusions.splice(i, 1);
    }
  }

  const ignorePatterns = getIgnorePatterns(root);
  let finalFiles = files;
  if (ignorePatterns.length > 0) {
    const kept = new Set(
      filterIgnoredFiles(files.map(f => f.absolutePath), ignorePatterns, root)
    );
    finalFiles = files.filter(f => {
      if (kept.has(f.absolutePath)) return true;
      exclusions.push({ path: f.path, reason: "ignore-pattern" });
      return false;
    });
  }

  finalFiles.sort((a, b) => a.path.localeCompare(b.path));
  const digest = sha256(finalFiles.map(f => `${f.path}:${f.sha256 || f.readError || "err"}`).join("\n"));

  return { root, files: finalFiles, exclusions, limitsExceeded, timedOut, digest, totalBytes };
}

// ============================================================
// Analyzer ledger, diagnostics, policy, report
// ============================================================

export type AnalyzerStatus = "completed" | "partial" | "skipped" | "failed" | "not_applicable";

export interface AnalyzerRun {
  analyzer: string;
  status: AnalyzerStatus;
  detail?: string;
  findings: number;
  durationMs: number;
  /** Candidates in scope when the analyzer was skipped (gating input). */
  filesInScope?: number;
}

export interface Diagnostic {
  source: string;
  message: string;
}

export interface PolicyDecision {
  outcome: "allow" | "reject" | "indeterminate";
  rule: string;
  reason: string;
  exitCode: 0 | 1 | 2;
}

export interface ScanReport {
  schemaVersion: "1";
  scanner: { name: string; version: string };
  input: {
    skill: string;
    path: string;
    fileCount: number;
    totalBytes: number;
    snapshotDigest: string;
    /** Remote acquisition provenance when the skill came from --remote. */
    remote?: { kind: string; source: string; digest: string };
  };
  findings: Finding[];
  capabilities: ObservedCapability[];
  analyzerRuns: AnalyzerRun[];
  diagnostics: Diagnostic[];
  exclusions: ScopeExclusion[];
  scanStatus: "complete" | "partial" | "failed";
  decision: PolicyDecision;
  /** Findings currently suppressed by a governed baseline. */
  suppressedCount: number;
  /** Declared-vs-observed comparison outcome (Phase 3). */
  preflight?: PreflightDecision;
  /** Opt-in semantic analysis outcome (Phase 8). */
  semantic?: {
    requested: boolean;
    available: boolean;
    status: string;
    provider?: string;
    model?: string;
    promptVersion: string;
    disclosure?: string;
    detail?: string;
  };
  /** Secondary prioritization signal only; never an authorization. */
  riskScore: number;
}

export interface ScanOptions {
  limits?: Partial<ScanLimits>;
  /** Enable dependency scanning. Default false in the kernel; CLI decides. */
  deps?: boolean;
  /** Allow network-dependent routes (OSV API). Default false: local scanners only. */
  network?: boolean;
  /** Score threshold for the score.threshold policy rule. */
  threshold?: number;
  /** Analyzer names that must succeed for the scan to be complete. */
  requiredAnalyzers?: string[];
  /** Invocation facts: confirmation approvals granted for this skill. */
  approvals?: string[];
  /** Environment state: trusted-baseline drift detected. */
  environmentDrift?: boolean;
  /** Path to a governed suppression baseline (JSON, version 1). */
  suppressionsPath?: string;
  /** Origin metadata from remote acquisition (fetchRemoteSource). */
  remoteProvenance?: { kind: string; source: string; digest: string };
  /** Prebuilt canonical snapshot; scanSkill will not rebuild one. */
  snapshot?: SkillSnapshot;
  /** Previous MCP config for version-to-version comparison (mcp-diff). */
  mcpBaselinePath?: string;
}

export function getScannerVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf-8"));
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const TEXT_SUFFIXES = /\.(md|txt|json|ya?ml|toml|ts|tsx|js|jsx|mjs|cjs|py|sh|bash|zsh|rb|go|rs|java|php|pl|lua|sql|html|css|xml|csv|env|ini|cfg|conf)$/i;

function decide(
  findings: Finding[],
  context: {
    inputInvalid: boolean;
    invalidManifest: boolean;
    inspectionInsufficient: boolean;
    requiredAnalyzerFailed: boolean;
  },
  preflight?: PreflightDecision
): PolicyDecision {
  if (context.inputInvalid) {
    return {
      outcome: "indeterminate",
      rule: "input.invalid",
      reason: "Skill path is missing or is not a file/directory",
      exitCode: 2,
    };
  }
  if (context.requiredAnalyzerFailed) {
    return {
      outcome: "indeterminate",
      rule: "analyzer.required_failed",
      reason: "A required analyzer failed; results cannot be trusted",
      exitCode: 2,
    };
  }
  if (context.invalidManifest) {
    return {
      outcome: "indeterminate",
      rule: "input.invalid_manifest",
      reason: "SKILL.md is missing or its frontmatter cannot be parsed",
      exitCode: 2,
    };
  }
  if (context.inspectionInsufficient) {
    return {
      outcome: "indeterminate",
      rule: "inspection.insufficient",
      reason: "Inspection incomplete (limits exceeded, missing, unreadable, degraded required analysis, or truncated required files)",
      exitCode: 2,
    };
  }
  const critical = findings.find(f => f.severity === "critical");
  if (critical) {
    return {
      outcome: "reject",
      rule: "findings.critical",
      reason: `Critical finding ${critical.id}: ${critical.message}`,
      exitCode: 1,
    };
  }
  // Context preflight feeds the canonical decision at exactly one seam.
  if (preflight?.outcome === "reject") {
    const rule = preflight.violations[0]?.rule ?? "reject";
    return {
      outcome: "reject",
      rule: `preflight.${rule}`,
      reason: preflight.reasons[0] ?? "Context comparison rejected this invocation",
      exitCode: 1,
    };
  }
  if (preflight?.outcome === "confirmation_required") {
    return {
      outcome: "reject",
      rule: "preflight.confirmation.required",
      reason: preflight.reasons[0] ?? "Required confirmation cannot pass without approval",
      exitCode: 1,
    };
  }
  if (preflight?.outcome === "indeterminate") {
    return {
      outcome: "indeterminate",
      rule: "preflight.indeterminate",
      reason: preflight.reasons[0] ?? "Context comparison was indeterminate",
      exitCode: 2,
    };
  }
  return { outcome: "allow", rule: "policy.default", reason: "No blocking findings or gates", exitCode: 0 };
}

/**
 * Programmatic single-skill scan. Builds an immutable snapshot, runs the
 * existing analyzers under an inspection ledger, computes the policy decision,
 * and returns the canonical versioned report.
 */
export function scanSkill(skillPath: string, skillName: string, options: ScanOptions = {}): ScanReport {
  const limits = { ...DEFAULT_SCAN_LIMITS, ...options.limits };
  // The canonical pipeline's deterministic analyzers are required: a
  // degraded (partial) run of any of them is incomplete inspection.
  // "dependencies" is excluded: its coverage legitimately depends on
  // installed scanners (route "none" is skipped, not degraded).
  const required = new Set(options.requiredAnalyzers ?? [
    "spec", "security-patterns", "ast-typescript", "shell-structural", "python-ast",
  ]);
  const analyzerRuns: AnalyzerRun[] = [];
  const diagnostics: Diagnostic[] = [];
  const specFindings: Finding[] = [];
  const secFindings: Finding[] = [];
  const depFindings: Finding[] = [];

  const pathExists = existsSync(skillPath);
  const stat = pathExists ? statSync(skillPath) : undefined;
  const inputInvalid = !stat || !(stat.isFile() || stat.isDirectory());

  let snapshot: SkillSnapshot | undefined;
  if (!inputInvalid) {
    if (options.snapshot) {
      snapshot = options.snapshot; // the canonical snapshot, built once by the caller
    } else {
      try {
        snapshot = buildSnapshot(skillPath, limits);
      } catch (e) {
        diagnostics.push({ source: "snapshot", message: String(e) });
      }
    }
  }

  // Materialize the immutable snapshot so every analyzer consumes exactly the
  // hashed content: no TOCTOU, exclusions and truncation cannot be bypassed,
  // and findings always match recorded digests.
  let materializedRoot: string | undefined;
  let materializedCleanup: (() => void) | undefined;
  if (snapshot) {
    const tempRoot = mkdtempSync(join(tmpdir(), "skill-audit-mat-"));
    const matDir = join(tempRoot, skillName);
    mkdirSync(matDir, { recursive: true });
    for (const f of snapshot.files) {
      if (f.readError || f.content === undefined) continue;
      const dest = join(matDir, f.path);
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, f.content);
    }
    materializedRoot = matDir;
    materializedCleanup = () => rmSync(tempRoot, { recursive: true, force: true });
  }
  const analyzerRoot = materializedRoot ?? skillPath;

  let report!: ScanReport;
  try {
  // Snapshot-level facts about the manifest file, used to distinguish
  // genuine input invalidity from artifacts of bounded inspection.
  const skillMdFile = snapshot?.files.find(f => f.path === "SKILL.md");
  const manifestTruncated = skillMdFile?.truncated === true;

  // ---- Analyzer: spec validation ----
  const specStart = Date.now();
  let manifest: import("./types.js").SkillManifest | undefined;
  let invalidManifest = false;
  if (inputInvalid || !snapshot) {
    analyzerRuns.push({ analyzer: "spec", status: "skipped", detail: "no snapshot", findings: 0, durationMs: 0 });
  } else {
    try {
      const specResult = validateSkillSpec(analyzerRoot, skillName);
      manifest = specResult.manifest;
      specFindings.push(...specResult.findings);
      // SPEC-01..04 are manifest-validity failures (missing/unparsable
      // SKILL.md, missing name/description) — invalid input, not a verdict.
      invalidManifest = specResult.findings.some(
        f => /^SPEC-0[1-4]$/.test(f.id) && f.severity === "critical"
      ) && !manifestTruncated; // truncated manifests are inspection failures
      analyzerRuns.push({
        analyzer: "spec",
        status: invalidManifest ? "partial" : "completed",
        detail: invalidManifest ? "invalid or unparsable SKILL.md frontmatter" : undefined,
        findings: specResult.findings.length,
        durationMs: Date.now() - specStart,
      });
      if (invalidManifest) {
        diagnostics.push({ source: "spec", message: "SKILL.md frontmatter missing or unparsable" });
      }
    } catch (e) {
      analyzerRuns.push({ analyzer: "spec", status: "failed", detail: String(e), findings: 0, durationMs: Date.now() - specStart });
      diagnostics.push({ source: "spec", message: `spec analyzer threw: ${String(e)}` });
    }
  }

  // ---- Analyzer: security patterns (includes CTX + provenance) ----
  const secStart = Date.now();
  if (inputInvalid || !snapshot) {
    analyzerRuns.push({ analyzer: "security-patterns", status: "skipped", detail: "no snapshot", findings: 0, durationMs: 0 });
  } else {
    try {
      const skill = {
        name: skillName,
        path: analyzerRoot,
        scope: "global" as const,
        agents: [] as string[],
      };
      const result = auditSecurity(skill, manifest);
      // Scanner failures are diagnostics and completeness outcomes — never findings.
      const scannerFailures = result.findings.filter(f => /^SCAN-/.test(f.id));
      for (const sf of scannerFailures) {
        diagnostics.push({ source: "security-patterns", message: `${sf.id}: ${sf.message}` });
      }
      secFindings.push(...result.findings.filter(f => !/^SCAN-/.test(f.id)));
      const partial = result.unreadableFiles.length > 0 || scannerFailures.length > 0;
      analyzerRuns.push({
        analyzer: "security-patterns",
        status: partial ? "partial" : "completed",
        detail: partial ? `${result.unreadableFiles.length} unreadable file(s), ${scannerFailures.length} scanner failure(s)` : undefined,
        findings: result.findings.length - scannerFailures.length,
        durationMs: Date.now() - secStart,
      });
    } catch (e) {
      analyzerRuns.push({ analyzer: "security-patterns", status: "failed", detail: String(e), findings: 0, durationMs: Date.now() - secStart });
      diagnostics.push({ source: "security-patterns", message: `analyzer threw: ${String(e)}` });
    }
  }

  // ---- Analyzer: dependency scanning ----
  const depsStart = Date.now();
  if (options.deps) {
    try {
      const depResult = scanDependenciesDetailed(analyzerRoot, {
        allowNetwork: options.network === true,
      });
      depFindings.push(...depResult.findings);
      for (const d of depResult.diagnostics) {
        diagnostics.push({ source: `dependencies:${d.source}`, message: d.message });
      }
      const routeError = depResult.diagnostics.some(d => d.message.includes("scan error"));
      analyzerRuns.push({
        analyzer: "dependencies",
        // route "none" is a capability gap (skipped); route errors are
        // degraded coverage (partial).
        status: depResult.route === "none" ? "skipped" : routeError ? "partial" : "completed",
        detail: depResult.route === "none"
          ? "no vulnerability route available for this run"
          : routeError
            ? `route ${depResult.route} reported errors; coverage degraded`
            : `route: ${depResult.route}`,
        findings: depResult.findings.length,
        durationMs: Date.now() - depsStart,
      });
    } catch (e) {
      analyzerRuns.push({ analyzer: "dependencies", status: "failed", detail: String(e), findings: 0, durationMs: Date.now() - depsStart });
      diagnostics.push({ source: "dependencies", message: `analyzer threw: ${String(e)}` });
    }
  } else {
    analyzerRuns.push({ analyzer: "dependencies", status: "skipped", detail: "deps disabled for this run", findings: 0, durationMs: 0 });
  }

  // ---- Analyzer: TypeScript/JavaScript AST (Phase 5, slice 1) ----
  const astStart = Date.now();
  const astResult = snapshot
    ? analyzeTypeScript(
        snapshot.files
          .filter(f => !f.readError && f.content !== undefined)
          .map(f => ({ path: f.path, content: f.content as string }))
      )
    : { capabilities: [], taintPaths: [], status: "skipped" as const, detail: "no snapshot", filesAnalyzed: 0 };
  analyzerRuns.push({
    analyzer: "ast-typescript",
    status: astResult.status,
    detail: astResult.detail ?? (astResult.status === "completed" ? `${astResult.filesAnalyzed} file(s) analyzed` : undefined),
    findings: 0,
    durationMs: Date.now() - astStart,
    filesInScope: astResult.filesInScope,
  });

  // ---- Analyzer: shell structural analysis (Phase 5, slice 2) ----
  const shellStart = Date.now();
  const shellResult = snapshot
    ? analyzeShell(
        snapshot.files
          .filter(f => !f.readError && f.content !== undefined)
          .map(f => ({ path: f.path, content: f.content as string }))
      )
    : { capabilities: [], status: "skipped" as const, detail: "no snapshot", filesAnalyzed: 0 };
  analyzerRuns.push({
    analyzer: "shell-structural",
    status: shellResult.status,
    detail: shellResult.detail ?? (shellResult.status === "completed" ? `${shellResult.filesAnalyzed} file(s) analyzed` : undefined),
    findings: 0,
    durationMs: Date.now() - shellStart,
  });

  // ---- Analyzer: Python AST (Phase 5, slice 3) ----
  const pyStart = Date.now();
  const pyResult = snapshot
    ? analyzePython(
        snapshot.files
          .filter(f => !f.readError && f.content !== undefined)
          .map(f => ({ path: f.path, absolutePath: join(analyzerRoot, f.path), content: f.content as string }))
      )
    : { capabilities: [], taintPaths: [], status: "skipped" as const, detail: "no snapshot", filesAnalyzed: 0 };
  analyzerRuns.push({
    analyzer: "python-ast",
    status: pyResult.status,
    detail: pyResult.detail ?? (pyResult.status === "completed" ? `${pyResult.filesAnalyzed} file(s) analyzed` : undefined),
    findings: 0,
    durationMs: Date.now() - pyStart,
    filesInScope: pyResult.filesInScope,
  });

  // ---- Shared observed-capability assembly (used by MCP + preflight) ----
  let capabilities: ObservedCapability[] = [];
  if (snapshot && !inputInvalid && !invalidManifest) {
    const regexCaps = observeProcessExec(
      snapshot.files
        .filter(f => !f.readError && f.content !== undefined)
        .map(f => ({ path: f.path, content: f.content, executable: f.executable }))
    );
    // Dedup by capability:file:line; when a structural analyzer observed the
    // same line, its exact location replaces the regex line-only observation.
    const byKey = new Map<string, ObservedCapability>();
    const add = (cap: ObservedCapability, preferExact: boolean) => {
      const key = `${cap.capability}:${cap.file}:${cap.line}`;
      const existing = byKey.get(key);
      if (!existing) {
        byKey.set(key, cap);
        return;
      }
      if (preferExact && existing.location?.precision !== "exact" && cap.location?.precision === "exact") {
        byKey.set(key, cap);
      }
    };
    regexCaps.forEach(c => add(c, false));
    astResult.capabilities.forEach(c => add(c, true));
    shellResult.capabilities.forEach(c => add(c, true));
    pyResult.capabilities.forEach(c => add(c, true));
    capabilities = [...byKey.values()];
  }

  // ---- Analyzer: MCP config (Phase 6) ----
  const mcpStart = Date.now();
  let mcpFindings: Finding[] = [];
  let mcpStatus: "completed" | "not_applicable" | "partial" = "not_applicable";
  let mcpDetail: string | undefined = snapshot ? "no MCP config in scope" : "no snapshot";
  let mcpConfigPresent = false;
  if (snapshot) {
    const configFile = snapshot.files.find(f => MCP_CONFIG_FILES.includes(f.path) && f.content !== undefined);
    mcpConfigPresent = configFile !== undefined;
    if (configFile) {
      const parsedMcp = parseMcpConfig(configFile.content as string);
      if (parsedMcp.error || !parsedMcp.config) {
        mcpStatus = "partial";
        mcpDetail = parsedMcp.error ?? "unparsable MCP config";
        diagnostics.push({ source: "mcp-config", message: parsedMcp.error ?? "unparsable MCP config" });
      } else {
        const mcpEvidence: import("./mcp.js").McpInvocationEvidence[] = capabilities
          .filter(c => c.capability === "mcp.invoke")
          .map(c => ({
            server: c.scope?.server,
            tool: c.scope?.tool,
            source: "observed-capability",
            file: c.file,
            line: c.line,
          }));
        mcpFindings = analyzeMcpConfig(parsedMcp.config, configFile.path, manifest?.content ?? "", mcpEvidence);
        // Version-to-version expansion rides the same analyzer + policy seam.
        if (options.mcpBaselinePath) {
          try {
            const baselineRaw = readFileSync(options.mcpBaselinePath, "utf-8");
            const baseline = parseMcpConfig(baselineRaw);
            if (baseline.config) {
              mcpFindings.push(...diffMcpConfigs(baseline.config, parsedMcp.config, configFile.path));
            } else {
              mcpStatus = "partial";
              mcpDetail = `baseline MCP config unparsable: ${baseline.error ?? "unknown"}`;
              diagnostics.push({ source: "mcp-config", message: baseline.error ?? "unparsable baseline MCP config" });
            }
          } catch (e) {
            mcpStatus = "partial";
            mcpDetail = `could not read MCP baseline: ${String(e).slice(0, 120)}`;
            diagnostics.push({ source: "mcp-config", message: `could not read MCP baseline: ${String(e)}` });
          }
        }
        if (mcpStatus !== "partial") {
          mcpStatus = "completed";
          mcpDetail = `${Object.keys(parsedMcp.config.servers).length} server(s) analyzed`
            + (options.mcpBaselinePath ? " (+ version diff)" : "");
        }
      }
    } else if (capabilities.some(c => c.capability === "mcp.invoke")) {
      // MCP invocation observed with no config in scope: every observed
      // server is undeclared by absence, and the analysis is degraded.
      const invoked = capabilities.filter(c => c.capability === "mcp.invoke");
      for (const inv of invoked) {
        mcpFindings.push(inv.scope?.server
          ? {
              id: "MCP-003", category: "ENV", asi: "ASI09", severity: "high",
              file: inv.file, line: inv.line,
              message: `Observed MCP invocation of undeclared server "${inv.scope.server}" (no MCP config in scope)`,
              evidence: inv.evidence, recommendation: "Add an mcp.json declaring the servers this skill invokes.",
              confidence: "high",
            }
          : {
              id: "MCP-009", category: "ENV", asi: "ASI09", severity: "medium",
              file: inv.file, line: inv.line,
              message: "Dynamic MCP usage cannot be verified against declared servers (no MCP config in scope)",
              evidence: inv.evidence,
              recommendation: "Declare the full server set this skill may invoke.",
              confidence: "low",
            });
      }
      mcpStatus = "partial";
      mcpDetail = `MCP invocation observed (${invoked.length} site(s)) but no mcp.json in scope`;
    }
  }
  analyzerRuns.push({
    analyzer: "mcp-config",
    status: mcpStatus,
    detail: mcpDetail,
    findings: mcpFindings.length,
    durationMs: Date.now() - mcpStart,
  });

  // ---- Taint paths (Phase 5, slice 4) → TAINT-* findings ----
  const TAINT_RULES: Record<string, { id: string; category: "TM" | "CE"; asi: string; severity: "high" | "critical" }> = {
    "env-to-network": { id: "TAINT-001", category: "TM", asi: "ASI02", severity: "high" },
    "file-to-network": { id: "TAINT-002", category: "TM", asi: "ASI02", severity: "high" },
    "input-to-exec": { id: "TAINT-003", category: "CE", asi: "ASI05", severity: "critical" },
    "context-to-output": { id: "TAINT-004", category: "TM", asi: "ASI02", severity: "high" },
  };
  const taintFindings: Finding[] = [...astResult.taintPaths, ...pyResult.taintPaths].map(tp => {
    const rule = TAINT_RULES[tp.kind] ?? TAINT_RULES["env-to-network"];
    return {
      id: rule.id,
      category: rule.category,
      asi: rule.asi,
      severity: rule.severity,
      file: tp.file,
      line: tp.line,
      location: tp.location,
      message: `Taint path ${tp.kind.replace(/-/g, " → ")} observed in implementation`,
      evidence: tp.evidence,
      confidence: "medium" as const,
    };
  });
  analyzerRuns.push({
    analyzer: "taint-analysis",
    status: taintFindings.length > 0 ? "completed" : "not_applicable",
    detail: taintFindings.length > 0 ? `${taintFindings.length} taint path(s)` : "no taint paths observed",
    findings: taintFindings.length,
    durationMs: 0,
  });

  // Findings produced against the materialized copy must reference the
  // original skill paths; otherwise fingerprints would not be reproducible.
  const normalizePath = (f: Finding): Finding =>
    materializedRoot && f.file.startsWith(materializedRoot) && snapshot
      ? { ...f, file: snapshot.root + f.file.slice(materializedRoot.length) }
      : f;
  for (let i = 0; i < specFindings.length; i++) specFindings[i] = normalizePath(specFindings[i]);
  for (let i = 0; i < secFindings.length; i++) secFindings[i] = normalizePath(secFindings[i]);
  for (let i = 0; i < depFindings.length; i++) depFindings[i] = normalizePath(depFindings[i]);

  // ---- Fingerprints and governed suppressions (Phase 4) ----
  const scannerVersion = getScannerVersion();
  const sourceDigestFor = (file: string): string => {
    if (!snapshot) return "";
    const match = snapshot.files.find(f => f.absolutePath === file || file.endsWith(f.path) || f.path.endsWith(file));
    return match?.sha256 ?? "";
  };
  const fingerprintGroup = (group: Finding[], analyzer: string): Finding[] =>
    group.map(f => ({
      ...f,
      fingerprint: findingFingerprint({
        scannerVersion,
        analyzer,
        ruleId: f.id,
        path: f.file,
        sourceDigest: sourceDigestFor(f.file),
        evidence: f.evidence ?? f.message,
        location: f.location,
      }),
    }));

  let findings: Finding[] = [
    ...fingerprintGroup(specFindings, "spec"),
    ...fingerprintGroup(secFindings, "security-patterns"),
    ...fingerprintGroup(depFindings, "dependencies"),
    ...fingerprintGroup(taintFindings, "taint"),
    ...fingerprintGroup(mcpFindings, "mcp-config"),
  ];

  let suppressedCount = 0;
  if (options.suppressionsPath) {
    const parsedSuppressions = loadSuppressions(options.suppressionsPath);
    for (const err of parsedSuppressions.errors) {
      diagnostics.push({ source: "suppressions", message: err });
    }
    if (parsedSuppressions.entries.length > 0) {
      const outcome = applySuppressions(findings, parsedSuppressions.entries);
      findings = outcome.findings;
      suppressedCount = outcome.suppressedCount;
      diagnostics.push(...outcome.diagnostics);
    }
  }
  // Suppressed findings stay visible in reports but cannot affect policy or score.
  const activeFindings = findings.filter(f => !f.suppressed);

  // ---- Inspection completeness ----
  // MCP analysis is required when MCP inputs or observed MCP capabilities
  // exist; otherwise a missing analysis is honestly not applicable.
  const mcpRelevant = mcpConfigPresent || capabilities.some(c => c.capability === "mcp.invoke");
  const effectiveRequired = new Set(required);
  if (mcpRelevant) effectiveRequired.add("mcp-config");

  // A REQUIRED analyzer that ran degraded (partial) is incomplete inspection,
  // and so is a REQUIRED analyzer that was SKIPPED while it had material in
  // scope (e.g. python3 or typescript unavailable with analyzable files).
  // The scan can never appear safe while required inspection has gaps.
  const requiredAnalyzerDegraded = analyzerRuns.some(
    a => effectiveRequired.has(a.analyzer)
      && (a.status === "partial"
        || (a.status === "skipped" && (a.filesInScope ?? 0) > 0))
  );
  const skillMd = skillMdFile;
  const requiredUnreadable = snapshot?.files.some(
    f => f.readError && (f.path === "SKILL.md" || TEXT_SUFFIXES.test(f.path))
  ) ?? false;
  const requiredTruncated = snapshot?.files.some(f => f.truncated && TEXT_SUFFIXES.test(f.path)) ?? false;
  const inspectionInsufficient =
    !snapshot ||
    snapshot.files.length === 0 ||
    snapshot.limitsExceeded ||
    !skillMd ||
    !!skillMd.readError ||
    skillMd.truncated ||
    requiredUnreadable ||
    requiredTruncated ||
    requiredAnalyzerDegraded;

  if (snapshot?.limitsExceeded) {
    diagnostics.push({ source: "snapshot", message: "scan limits exceeded; scope was bounded" });
  }

  const requiredAnalyzerFailed = analyzerRuns.some(a => a.status === "failed" && effectiveRequired.has(a.analyzer));

  // ---- Score (secondary signal, suppressions excluded) ----
  const severityScores: Record<string, number> = { critical: 5, high: 3, medium: 1.5, low: 0.5, info: 0.1 };
  const rawScore = activeFindings.reduce((sum, f) => sum + (severityScores[f.severity] ?? 1), 0);
  const riskScore = Math.round(Math.min(rawScore, 10) * 10) / 10;

  // ---- Declared-vs-observed comparison (single policy seam) ----
  let preflight: PreflightDecision | undefined;
  if (snapshot && !inputInvalid && !invalidManifest) {
    const contractParse = parseContextContract(manifest?.context);
    preflight = evaluatePreflight({
      contract: contractParse.contract,
      allowedTools: manifest?.allowedTools,
      capabilities,
      approvals: options.approvals,
      skillName,
      environmentDrift: options.environmentDrift,
      hasRiskFindings: activeFindings.some(f => f.severity === "critical" || f.severity === "high"),
    });
    if (contractParse.errors.length > 0 && preflight.outcome === "allow") {
      // Invalid contract values block preflight trust even without exec use.
      preflight = {
        outcome: "indeterminate",
        reasons: ["Context contract failed schema validation", ...preflight.reasons],
        violations: preflight.violations,
      };
    }
  }

  const decision = decide(activeFindings, {
    inputInvalid,
    invalidManifest,
    inspectionInsufficient,
    requiredAnalyzerFailed,
  }, preflight);

  const scanStatus: ScanReport["scanStatus"] = inputInvalid || invalidManifest || requiredAnalyzerFailed
    ? "failed"
    : inspectionInsufficient || analyzerRuns.some(a => a.status === "partial")
      ? "partial"
      : "complete";

  report = {
    schemaVersion: "1",
    scanner: { name: "skill-audit", version: getScannerVersion() },
    input: {
      skill: skillName,
      path: skillPath,
      fileCount: snapshot?.files.length ?? 0,
      totalBytes: snapshot?.totalBytes ?? 0,
      snapshotDigest: snapshot?.digest ?? "",
      remote: options.remoteProvenance,
    },
    findings,
    capabilities,
    analyzerRuns,
    diagnostics,
    exclusions: snapshot?.exclusions ?? [],
    scanStatus,
    decision,
    suppressedCount,
    preflight,
    riskScore,
  };
  } finally {
    materializedCleanup?.();
  }
  return report;
}

/**
 * Snapshot-derived input for opt-in semantic analysis: the skill content is
 * taken from a freshly built immutable snapshot, never reread live, and the
 * digests let callers detect drift and bind fingerprints to source identity.
 */
export interface SemanticSourceInput {
  skillName: string;
  content: string;
  declaredPurpose: string;
  snapshotDigest: string;
  skillMdDigest: string;
  error?: string;
}

export function semanticInputFromSnapshot(snapshot: SkillSnapshot, skillName: string): SemanticSourceInput {
  const skillMd = snapshot.files.find(f => f.path === "SKILL.md");
  const content = skillMd?.content ?? "";
  const declaredPurpose = content.match(/^---\n[\s\S]*?\ndescription:\s*(.+)$/m)?.[1]?.trim() ?? "";
  return {
    skillName,
    content,
    declaredPurpose,
    snapshotDigest: snapshot.digest,
    skillMdDigest: skillMd?.sha256 ?? "",
  };
}

/**
 * Integrate post-scan findings (e.g. semantic analysis) through the same
 * canonical sequence as initial findings: fingerprint → suppress → score →
 * policy. Exit-2 gates are never cleared; preflight remains the single
 * context seam; score never authorizes.
 */
export function withExtraFindings(
  report: ScanReport,
  extraFindings: Finding[],
  analyzer: string,
  opts: {
    suppressionsPath?: string;
    durationMs?: number;
    sourceDigest?: string;
    /** Honest ledger status for the appended analyzer run (default completed). */
    analyzerStatus?: AnalyzerStatus;
    analyzerDetail?: string;
  } = {}
): ScanReport {
  const fingerprinted = extraFindings.map(f => ({
    ...f,
    fingerprint: findingFingerprint({
      scannerVersion: report.scanner.version,
      analyzer,
      ruleId: f.id,
      path: f.file,
      sourceDigest: opts.sourceDigest ?? "",
      evidence: f.evidence ?? f.message,
      location: f.location,
    }),
  }));

  let findings = [...report.findings, ...fingerprinted];
  let suppressedCount = report.suppressedCount;
  if (opts.suppressionsPath) {
    const parsed = loadSuppressions(opts.suppressionsPath);
    if (parsed.entries.length > 0) {
      const outcome = applySuppressions(findings, parsed.entries);
      findings = outcome.findings;
      suppressedCount = outcome.suppressedCount;
    }
  }
  const active = findings.filter(f => !f.suppressed);

  const severityScores: Record<string, number> = { critical: 5, high: 3, medium: 1.5, low: 0.5, info: 0.1 };
  const rawScore = active.reduce((sum, f) => sum + (severityScores[f.severity] ?? 1), 0);
  const riskScore = Math.round(Math.min(rawScore, 10) * 10) / 10;

  let decision = report.decision;
  if (decision.exitCode !== 2) {
    const critical = active.find(f => f.severity === "critical");
    if (critical) {
      decision = { outcome: "reject", rule: "findings.critical", reason: `Critical finding ${critical.id}: ${critical.message}`, exitCode: 1 };
    } else {
      // Preserve the preflight seam: context results keep driving policy.
      const pf = report.preflight;
      if (pf?.outcome === "reject" || pf?.outcome === "confirmation_required") {
        decision = { outcome: "reject", rule: `preflight.${pf.violations[0]?.rule ?? pf.outcome}`, reason: pf.reasons[0] ?? "Context comparison rejected this invocation", exitCode: 1 };
      } else if (pf?.outcome === "indeterminate") {
        decision = { outcome: "indeterminate", rule: "preflight.indeterminate", reason: pf.reasons[0] ?? "Context comparison was indeterminate", exitCode: 2 };
      } else {
        decision = { outcome: "allow", rule: "policy.default", reason: "No blocking findings or gates", exitCode: 0 };
      }
    }
  }

  const analyzerRuns = [...report.analyzerRuns, {
    analyzer,
    status: opts.analyzerStatus ?? ("completed" as const),
    detail: opts.analyzerDetail,
    findings: extraFindings.length,
    durationMs: opts.durationMs ?? 0,
  }];

  return { ...report, findings, suppressedCount, analyzerRuns, decision, riskScore };
}

/**
 * Shared severity policy for adapters that only have findings (no snapshot
 * pipeline of their own): critical findings reject; everything else allows.
 * Score never authorizes. Used by legacy audit and mcp-diff so every
 * adapter exits through the same policy semantics.
 */
export function decideFindingsPolicy(findings: Finding[]): PolicyDecision {
  const critical = findings.find(f => f.severity === "critical");
  if (critical) {
    return {
      outcome: "reject",
      rule: "findings.critical",
      reason: `Critical finding ${critical.id}: ${critical.message}`,
      exitCode: 1,
    };
  }
  return { outcome: "allow", rule: "policy.default", reason: "No blocking findings", exitCode: 0 };
}

/** Worst-case aggregation across reports: failure beats rejection beats allow. */
export function aggregateDecision(reports: ScanReport[]): PolicyDecision {
  if (reports.length === 0) {
    return { outcome: "indeterminate", rule: "input.invalid", reason: "No skills to scan", exitCode: 2 };
  }
  const worst = reports.find(r => r.decision.exitCode === 2) ?? reports.find(r => r.decision.exitCode === 1) ?? reports[0];
  return worst.decision;
}
