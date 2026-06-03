import { constants, existsSync, mkdirSync, readFileSync, statSync, writeFileSync, accessSync } from "fs";
import { homedir } from "os";
import { basename, delimiter, dirname, join, resolve } from "path";
import { createHash } from "crypto";
import { Finding } from "./types.js";

export interface EnvironmentDoctorResult {
  generated: string;
  summary: {
    shellFiles: number;
    agentConfigFiles: number;
    instructionFiles: number;
    pathEntries: number;
    packageFiles: number;
  };
  findings: Finding[];
  riskScore: number;
  riskLevel: "safe" | "risky" | "dangerous" | "malicious";
  files: EnvironmentFileFingerprint[];
}

export interface EnvironmentDoctorOptions {
  home?: string;
  cwd?: string;
  path?: string;
  baselinePath?: string;
}

export interface EnvironmentFileFingerprint {
  path: string;
  sha256: string;
}

export interface EnvironmentBaseline {
  created: string;
  result: EnvironmentDoctorResult;
}

export interface EnvironmentDiffResult {
  baselinePath: string;
  hasBaseline: boolean;
  baseline?: EnvironmentBaseline;
  current: EnvironmentDoctorResult;
  addedFiles: string[];
  removedFiles: string[];
  changedFiles: string[];
  addedFindings: Finding[];
  resolvedFindings: Finding[];
  drift: boolean;
}

export interface EnvironmentCommandAssessment {
  command: string;
  sensitive: boolean;
  reasons: string[];
  environment?: EnvironmentDiffResult;
}

const DEFAULT_HOME = homedir();

const SENSITIVE_BINARIES = ["node", "npm", "npx", "bun", "pnpm", "git", "ssh", "curl", "wget", "python", "bash", "sh"];

type PatternRule = {
  id: string;
  severity: Finding["severity"];
  asixx: string;
  message: string;
  pattern: RegExp;
  recommendation?: string;
};

const SHELL_RULES: PatternRule[] = [
  { id: "ENV-SHELL-001", severity: "critical", asixx: "ASI05", message: "Shell startup fetches remote script into an interpreter", pattern: /(curl|wget)[^\n|]*\|\s*(sh|bash|python|perl)/i, recommendation: "Remove remote shell execution from startup files." },
  { id: "ENV-SHELL-002", severity: "critical", asixx: "ASI05", message: "Reverse shell pattern in shell startup file", pattern: /(bash\s+-i\s+.*\/dev\/tcp|nc\s+-[elv]|netcat\s+-[elv])/i },
  { id: "ENV-SHELL-003", severity: "high", asixx: "ASI05", message: "Shell alias overrides a sensitive command", pattern: /alias\s+(npm|npx|node|git|ssh|curl|wget|python|bash|sh)=/i, recommendation: "Review aliases that shadow common development and network tools." },
  { id: "ENV-SHELL-004", severity: "medium", asixx: "ASI04", message: "Shell startup exports a likely secret", pattern: /export\s+\w*(TOKEN|SECRET|PASSWORD|API_KEY)\w*=/i, recommendation: "Avoid storing credentials directly in shell startup files." },
];

const AGENT_CONFIG_RULES: PatternRule[] = [
  { id: "ENV-HOOK-001", severity: "high", asixx: "ASI05", message: "Agent hook executes a shell command", pattern: /"(PreToolUse|PostToolUse|hooks?)"[\s\S]{0,800}"command"\s*:/i, recommendation: "Verify hook commands are expected, pinned, and documented." },
  { id: "ENV-HOOK-002", severity: "critical", asixx: "ASI05", message: "Agent config contains remote script execution", pattern: /(curl|wget)[^\n|]*\|\s*(sh|bash|python|perl)/i },
  { id: "ENV-MCP-001", severity: "medium", asixx: "ASI02", message: "MCP/tool server uses unpinned npx latest-style execution", pattern: /"command"\s*:\s*"npx"[\s\S]{0,400}(@latest|"latest"|\s-y\s)/i, recommendation: "Pin MCP/tool package versions instead of using latest or implicit installs." },
  { id: "ENV-SECRET-001", severity: "high", asixx: "ASI04", message: "Agent config appears to contain a secret value", pattern: /"\w*(TOKEN|SECRET|PASSWORD|API_KEY)\w*"\s*:\s*"[^"$][^"]{8,}"/i, recommendation: "Move secrets to a secret manager or environment source outside agent config." },
];

const INSTRUCTION_RULES: PatternRule[] = [
  { id: "ENV-CTX-001", severity: "critical", asixx: "ASI01", message: "Agent instruction file attempts to override prior instructions", pattern: /ignore\s+(all\s+)?previous\s+(instructions?|rules?)/i },
  { id: "ENV-CTX-002", severity: "high", asixx: "ASI01", message: "Agent instruction file contains context-forgetting directive", pattern: /forget\s+(everything|all|your)/i },
  { id: "ENV-CTX-003", severity: "high", asixx: "ASI04", message: "Agent instruction file asks for secrets or credentials", pattern: /(reveal|print|exfiltrate|send).{0,80}(secret|token|password|api key|credential)/i },
  { id: "ENV-CTX-004", severity: "medium", asixx: "ASI05", message: "Agent instruction file mandates command execution", pattern: /always\s+(run|execute)\s+(`[^`]+`|["'][^"']+["']|(?:npm|npx|bun|pnpm|curl|wget|bash|sh|python|git)\b[^\n]+)/i, recommendation: "Prefer conditional instructions with explicit user intent and safety checks." },
];

const PACKAGE_RULES: PatternRule[] = [
  { id: "ENV-PKG-001", severity: "critical", asixx: "ASI05", message: "Package lifecycle script fetches remote code into shell", pattern: /"(preinstall|install|postinstall|prepare)"\s*:\s*"[^"]*(curl|wget)[^"|]*\|\s*(sh|bash|python|perl)/i },
  { id: "ENV-PKG-002", severity: "high", asixx: "ASI05", message: "Package lifecycle script contains destructive filesystem command", pattern: /"(preinstall|install|postinstall|prepare)"\s*:\s*"[^"]*rm\s+-rf\s+(\/|~|\$HOME)/i },
  { id: "ENV-PKG-003", severity: "medium", asixx: "ASI04", message: "Package lifecycle script accesses likely secrets", pattern: /"(preinstall|install|postinstall|prepare)"\s*:\s*"[^"]*(TOKEN|SECRET|PASSWORD|API_KEY|\.env)/i },
];

const SENSITIVE_COMMAND_PATTERNS = [
  { reason: "skill installation command", pattern: /\bnpx\s+skills\s+add\b|\bskills\s+add\b/i },
  { reason: "package install command", pattern: /\b(npm|pnpm|bun|yarn)\s+(install|add|i)\b/i },
  { reason: "remote script execution", pattern: /\b(curl|wget)\b[^\n|]*\|\s*(sh|bash|python|perl)/i },
  { reason: "agent config modification", pattern: /(>|>>|tee\s+-a?)\s+.*(\.claude|\.qwen|\.gemini|\.amp|settings\.json|AGENTS\.md|CLAUDE\.md|QWEN\.md|GEMINI\.md)/i },
  { reason: "shell startup modification", pattern: /(>|>>|tee\s+-a?)\s+.*(\.bashrc|\.zshrc|\.profile|config\.fish)/i },
  { reason: "executable permission change", pattern: /\bchmod\s+\+?x\b/i },
];

export function runEnvironmentDoctor(options: EnvironmentDoctorOptions = {}): EnvironmentDoctorResult {
  const home = options.home || DEFAULT_HOME;
  const cwd = options.cwd || process.cwd();
  const shellFiles = buildShellFiles(home);
  const agentConfigFiles = buildAgentConfigFiles(home);
  const instructionFiles = buildWorkspaceInstructionFiles(cwd);
  const packageFiles = buildWorkspacePackageFiles(cwd);
  const pathValue = options.path ?? process.env.PATH ?? "";
  const findings: Finding[] = [];
  const summary = {
    shellFiles: 0,
    agentConfigFiles: 0,
    instructionFiles: 0,
    pathEntries: pathValue.split(delimiter).filter(Boolean).length,
    packageFiles: 0,
  };

  summary.shellFiles = scanFiles(shellFiles, SHELL_RULES, findings);
  summary.agentConfigFiles = scanFiles(agentConfigFiles, AGENT_CONFIG_RULES, findings);
  summary.instructionFiles = scanFiles(instructionFiles, INSTRUCTION_RULES, findings);
  summary.packageFiles = scanFiles(packageFiles, PACKAGE_RULES, findings);
  scanPath(findings, cwd, pathValue);
  const files = fingerprintFiles([...shellFiles, ...agentConfigFiles, ...instructionFiles, ...packageFiles]);

  const riskScore = scoreFindings(findings);
  return {
    generated: new Date().toISOString(),
    summary,
    findings,
    riskScore,
    riskLevel: riskLevel(riskScore),
    files,
  };
}

export function writeEnvironmentBaseline(options: EnvironmentDoctorOptions = {}): EnvironmentBaseline {
  const baselinePath = getBaselinePath(options);
  const baseline: EnvironmentBaseline = {
    created: new Date().toISOString(),
    result: runEnvironmentDoctor(options),
  };
  mkdirSync(dirname(baselinePath), { recursive: true });
  writeFileSync(baselinePath, JSON.stringify(baseline, null, 2));
  return baseline;
}

export function diffEnvironmentBaseline(options: EnvironmentDoctorOptions = {}): EnvironmentDiffResult {
  const baselinePath = getBaselinePath(options);
  const current = runEnvironmentDoctor(options);
  if (!existsSync(baselinePath)) {
    return {
      baselinePath,
      hasBaseline: false,
      current,
      addedFiles: [],
      removedFiles: [],
      changedFiles: [],
      addedFindings: current.findings,
      resolvedFindings: [],
      drift: current.findings.length > 0,
    };
  }

  const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as EnvironmentBaseline;
  const baselineFiles = new Map(baseline.result.files.map(file => [file.path, file.sha256]));
  const currentFiles = new Map(current.files.map(file => [file.path, file.sha256]));
  const addedFiles = current.files.filter(file => !baselineFiles.has(file.path)).map(file => file.path);
  const removedFiles = baseline.result.files.filter(file => !currentFiles.has(file.path)).map(file => file.path);
  const changedFiles = current.files
    .filter(file => baselineFiles.has(file.path) && baselineFiles.get(file.path) !== file.sha256)
    .map(file => file.path);
  const baselineFindings = new Set(baseline.result.findings.map(findingKey));
  const currentFindings = new Set(current.findings.map(findingKey));
  const addedFindings = current.findings.filter(finding => !baselineFindings.has(findingKey(finding)));
  const resolvedFindings = baseline.result.findings.filter(finding => !currentFindings.has(findingKey(finding)));

  return {
    baselinePath,
    hasBaseline: true,
    baseline,
    current,
    addedFiles,
    removedFiles,
    changedFiles,
    addedFindings,
    resolvedFindings,
    drift: addedFiles.length > 0 || removedFiles.length > 0 || changedFiles.length > 0 || addedFindings.length > 0 || resolvedFindings.length > 0,
  };
}

export function assessShellCommand(command: string, options: EnvironmentDoctorOptions = {}): EnvironmentCommandAssessment {
  const reasons = SENSITIVE_COMMAND_PATTERNS
    .filter(rule => rule.pattern.test(command))
    .map(rule => rule.reason);
  const sensitive = reasons.length > 0;
  return {
    command,
    sensitive,
    reasons,
    environment: sensitive ? diffEnvironmentBaseline(options) : undefined,
  };
}

export function reportCommandAssessment(assessment: EnvironmentCommandAssessment, options: { json?: boolean; verbose?: boolean; block?: boolean; threshold?: number }): void {
  if (options.json) {
    console.log(JSON.stringify(assessment, null, 2));
    return;
  }

  console.log("\n🧭 Shell Command Environment Check\n");
  console.log(`   Sensitive: ${assessment.sensitive ? "⚠️ yes" : "✅ no"}`);
  if (assessment.reasons.length > 0) {
    console.log(`   Reasons: ${assessment.reasons.join(", ")}`);
  }
  if (!assessment.environment) {
    console.log("");
    return;
  }
  console.log(`   Environment drift: ${assessment.environment.drift ? "⚠️ yes" : "✅ no"}`);
  console.log(`   Environment risk: ${assessment.environment.current.riskLevel} (${assessment.environment.current.riskScore.toFixed(1)}/10)`);
  if (!assessment.environment.hasBaseline) {
    console.log("   No environment baseline found. Run: skill-audit trust env");
  }
  if (options.verbose && assessment.environment.addedFindings.length > 0) {
    for (const finding of assessment.environment.addedFindings) {
      console.log(`   + finding [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`);
    }
  }
  console.log("");
}

export function getEnvironmentBaselinePath(options: EnvironmentDoctorOptions = {}): string {
  return options.baselinePath || join(options.home || DEFAULT_HOME, ".skill-audit", "baselines", "environment.json");
}

function getBaselinePath(options: EnvironmentDoctorOptions): string {
  return getEnvironmentBaselinePath(options);
}

function findingKey(finding: Finding): string {
  return `${finding.id}:${finding.file}:${finding.line || 0}:${finding.message}`;
}

function fingerprintFiles(paths: string[]): EnvironmentFileFingerprint[] {
  const files: EnvironmentFileFingerprint[] = [];
  for (const path of paths) {
    if (!existsSync(path)) continue;
    const stat = statSync(path);
    if (stat.isDirectory()) continue;
    const content = readFileSync(path);
    files.push({
      path,
      sha256: createHash("sha256").update(content).digest("hex"),
    });
  }
  return files;
}

function buildShellFiles(home: string): string[] {
  return [
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    join(".config", "fish", "config.fish"),
  ].map(path => join(home, path));
}

function buildAgentConfigFiles(home: string): string[] {
  return [
    ".claude.json",
    join(".claude", "settings.json"),
    join(".config", "claude", "mcp.json"),
    join(".qwen", "settings.json"),
    join(".gemini", "settings.json"),
    join(".amp", "settings.json"),
  ].map(path => join(home, path));
}

function buildWorkspaceInstructionFiles(cwd: string): string[] {
  return [
    "AGENTS.md",
    "CLAUDE.md",
    "QWEN.md",
    "GEMINI.md",
    join(".cursor", "rules"),
  ].map(path => join(cwd, path));
}

function buildWorkspacePackageFiles(cwd: string): string[] {
  return [
    "package.json",
    "bun.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
  ].map(path => join(cwd, path));
}

function scanFiles(paths: string[], rules: PatternRule[], findings: Finding[]): number {
  let checked = 0;
  for (const path of paths) {
    if (!existsSync(path)) continue;
    const stat = statSync(path);
    if (stat.isDirectory()) continue;
    checked++;
    const content = readFileSync(path, "utf8");
    for (const rule of rules) {
      const match = rule.pattern.exec(content);
      if (!match) continue;
      findings.push({
        id: rule.id,
        category: "ENV",
        asixx: rule.asixx,
        severity: rule.severity,
        file: path,
        line: lineOf(content, match.index),
        message: rule.message,
        evidence: rule.id.includes("SECRET") ? redactSecretEvidence(match[0]) : trimEvidence(match[0]),
        recommendation: rule.recommendation,
      });
    }
  }
  return checked;
}

function scanPath(findings: Finding[], cwd: string, pathValue: string): void {
  for (const entry of pathValue.split(delimiter).filter(Boolean)) {
    if (isWorldWritable(entry)) {
      findings.push({
        id: "ENV-PATH-001",
        category: "ENV",
        asixx: "ASI05",
        severity: "high",
        file: entry,
        message: "PATH contains a world-writable directory",
        recommendation: "Remove world-writable directories from PATH or move them after trusted system paths.",
      });
    }
  }

  for (const bin of SENSITIVE_BINARIES) {
    for (const resolvedPath of whichAll(bin, pathValue)) {
      if (isWorldWritable(resolvedPath)) {
        findings.push({
          id: "ENV-PATH-002",
          category: "ENV",
          asixx: "ASI05",
          severity: "high",
          file: resolvedPath,
          message: `${bin} resolves to a world-writable executable path`,
          recommendation: "Use trusted, non-writable tool binaries for agent shell execution.",
        });
      }
      if (resolve(resolvedPath).startsWith(resolve(cwd))) {
        findings.push({
          id: "ENV-PATH-003",
          category: "ENV",
          asixx: "ASI05",
          severity: "medium",
          file: resolvedPath,
          message: `${bin} resolves inside the current workspace`,
          recommendation: "Check for PATH hijacking before running agent shell commands.",
        });
      }
    }
  }
}

function whichAll(command: string, pathValue: string): string[] {
  const matches: string[] = [];
  for (const entry of pathValue.split(delimiter).filter(Boolean)) {
    const candidate = join(entry, command);
    try {
      accessSync(candidate, constants.X_OK);
      matches.push(candidate);
    } catch {
      // Not executable or not present.
    }
  }
  return matches;
}

function isWorldWritable(path: string): boolean {
  try {
    return (statSync(path).mode & 0o002) !== 0;
  } catch {
    return false;
  }
}

function lineOf(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

function trimEvidence(evidence: string): string {
  return evidence.replace(/\s+/g, " ").slice(0, 160);
}

function redactSecretEvidence(evidence: string): string {
  return trimEvidence(evidence).replace(/:\s*"[^"]+"/, ': "[REDACTED]"');
}

function scoreFindings(findings: Finding[]): number {
  const weights: Record<Finding["severity"], number> = { critical: 4, high: 2.5, medium: 1.2, low: 0.5, info: 0.1 };
  return Math.min(10, findings.reduce((sum, finding) => sum + weights[finding.severity], 0));
}

function riskLevel(score: number): EnvironmentDoctorResult["riskLevel"] {
  if (score > 7) return "malicious";
  if (score > 5) return "dangerous";
  if (score > 3) return "risky";
  return "safe";
}

export function reportEnvironmentDoctor(result: EnvironmentDoctorResult, options: { json?: boolean; verbose?: boolean; output?: string }): void {
  if (options.output) {
    writeFileSync(options.output, JSON.stringify(result, null, 2));
    if (!options.json) console.log(`\n📄 Environment report saved to: ${options.output}`);
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const icon = result.riskLevel === "safe" ? "✅" : result.riskLevel === "risky" ? "⚠️" : result.riskLevel === "dangerous" ? "🔴" : "☠️";
  console.log("\n🩺 Agent Environment Doctor\n");
  console.log(`   Shell startup files: ${result.summary.shellFiles}`);
  console.log(`   Agent config files:  ${result.summary.agentConfigFiles}`);
  console.log(`   Instruction files:   ${result.summary.instructionFiles}`);
  console.log(`   PATH entries:        ${result.summary.pathEntries}`);
  console.log(`   Package files:       ${result.summary.packageFiles}`);
  console.log(`\n${icon} Environment risk: ${result.riskLevel} (${result.riskScore.toFixed(1)}/10)`);
  console.log(`   Findings: ${result.findings.length}\n`);

  const shown = options.verbose ? result.findings : result.findings.slice(0, 5);
  for (const finding of shown) {
    console.log(`   [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`);
    console.log(`      ${displayPath(finding.file)}${finding.line ? `:${finding.line}` : ""}`);
    if (options.verbose && finding.recommendation) {
      console.log(`      Recommendation: ${finding.recommendation}`);
    }
  }

  if (!options.verbose && result.findings.length > shown.length) {
    console.log(`   ... and ${result.findings.length - shown.length} more findings. Re-run with --verbose for details.`);
  }
}

export function reportEnvironmentBaseline(baseline: EnvironmentBaseline, baselinePath: string, options: { json?: boolean }): void {
  if (options.json) {
    console.log(JSON.stringify({ baselinePath, baseline }, null, 2));
    return;
  }

  console.log("\n🛡️  Environment baseline saved\n");
  console.log(`   Path: ${displayPath(baselinePath)}`);
  console.log(`   Risk: ${baseline.result.riskLevel} (${baseline.result.riskScore.toFixed(1)}/10)`);
  console.log(`   Files fingerprinted: ${baseline.result.files.length}`);
  console.log(`   Findings recorded: ${baseline.result.findings.length}\n`);
}

export function reportEnvironmentDiff(diff: EnvironmentDiffResult, options: { json?: boolean; verbose?: boolean; block?: boolean; threshold?: number }): void {
  if (options.json) {
    console.log(JSON.stringify(diff, null, 2));
    return;
  }

  console.log("\n🔎 Agent Environment Drift\n");
  console.log(`   Baseline: ${displayPath(diff.baselinePath)}`);
  if (!diff.hasBaseline) {
    console.log("   Status: no baseline found");
    console.log("   Run: skill-audit trust env\n");
    return;
  }

  console.log(`   Drift: ${diff.drift ? "⚠️ yes" : "✅ no"}`);
  console.log(`   Current risk: ${diff.current.riskLevel} (${diff.current.riskScore.toFixed(1)}/10)`);
  console.log(`   Added files: ${diff.addedFiles.length} | Removed files: ${diff.removedFiles.length} | Changed files: ${diff.changedFiles.length}`);
  console.log(`   Added findings: ${diff.addedFindings.length} | Resolved findings: ${diff.resolvedFindings.length}\n`);

  if (!options.verbose) {
    if (diff.drift) console.log("   Re-run with --verbose for changed files and findings.\n");
    return;
  }

  for (const file of diff.addedFiles) console.log(`   + file ${displayPath(file)}`);
  for (const file of diff.removedFiles) console.log(`   - file ${displayPath(file)}`);
  for (const file of diff.changedFiles) console.log(`   ~ file ${displayPath(file)}`);
  for (const finding of diff.addedFindings) console.log(`   + finding [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`);
  for (const finding of diff.resolvedFindings) console.log(`   - finding [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`);
  if (diff.drift) console.log("");
}

function displayPath(path: string): string {
  const home = DEFAULT_HOME;
  if (path.startsWith(home)) return `~/${path.slice(home.length + 1)}`;
  return basename(path) === path ? path : path;
}
