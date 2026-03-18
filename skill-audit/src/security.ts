import { readFileSync } from "fs";
import { basename, extname } from "path";
import { SkillInfo, SkillManifest, Finding } from "./types.js";
import { resolveSkillPath, getSkillFiles } from "./discover.js";
import { loadAndCompile, hasPatternsFile, getPatternMetadata, CompiledPattern } from "./patterns.js";

/**
 * Phase 1 - Layer 2: Security Auditor
 *
 * Detects dangerous behavior in skill content and bundled files.
 * This runs AFTER spec validation - security findings may be warnings.
 *
 * Security categories (OWASP Agentic Top 10):
 * - ASI01: Prompt Injection
 * - ASI02: Tool Misuse / Exfiltration
 * - ASI04: Secrets / Supply Chain
 * - ASI05: Code Execution
 * - ASI09: Behavioral Manipulation
 *
 * Pattern sources:
 * 1. External patterns file (rules/default-patterns.json) - preferred
 * 2. Hardcoded fallback patterns - used if external file missing
 */

// ============================================================
// Pattern Loading
// ============================================================

let compiledPatterns: Map<string, CompiledPattern[]> | null = null;
let patternMetadata = { version: "unknown", updated: "unknown" };

/**
 * Initialize patterns (load from file or use hardcoded fallback)
 */
function initPatterns(): Map<string, CompiledPattern[]> {
  if (compiledPatterns) {
    return compiledPatterns;
  }
  
  try {
    if (hasPatternsFile()) {
      compiledPatterns = loadAndCompile();
      patternMetadata = getPatternMetadata();
      return compiledPatterns;
    }
  } catch (error) {
    console.warn("Failed to load external patterns, using hardcoded fallback:", error);
  }
  
  // Fallback to hardcoded patterns (original implementation)
  compiledPatterns = new Map();
  return compiledPatterns;
}

// ============================================================
// PROMPT INJECTION PATTERNS (ASI01 - Goal Hijacking)
// ============================================================

const PROMPT_INJECTION_PATTERNS = [
  // Critical - Block immediately
  { pattern: /ignore\s+(all\s+)?previous\s+(instructions?|rules?)/i, id: "PI01", severity: "critical", message: "Instruction override - ignore previous instructions" },
  { pattern: /you\s+(are\s+)?now\s+(a|an|i am)\s+\w+/i, id: "PI02", severity: "critical", message: "Roleplay bypass - role impersonation" },
  { pattern: /forget\s+(everything|all|your)/i, id: "PI03", severity: "critical", message: "Context forgetting attempt" },
  { pattern: /system\s+prompt\s+override/i, id: "PI04", severity: "critical", message: "System prompt override attempt" },
  { pattern: /act\s+as\s+if\s+(you\s+)?(have|no)\s+(restrictions|limits)/i, id: "PI05", severity: "critical", message: "Restriction removal attempt" },
  { pattern: /\[SYSTEM\]|\[ADMIN\]|\[ROOT\]/i, id: "PI06", severity: "critical", message: "Fake role tags injection" },

  // High - Flag for review
  { pattern: /end\s+of\s+system\s+prompt|---END---/i, id: "PI07", severity: "high", message: "Prompt termination marker" },
  { pattern: /debug\s+mode\s*:\s*enabled|safety\s+mode\s*:\s*off/i, id: "PI08", severity: "high", message: "Safety toggle disable" },
  { pattern: /<!--[\s\S]*?-->/g, id: "PI09", severity: "high", message: "Hidden instructions in HTML comments" },
  { pattern: /note\s+to\s+AI:|AI\s+instruction:/i, id: "PI10", severity: "high", message: "AI directive injection" },

  // Medium - Evaluate context
  { pattern: /(?:you\s+must|you\s+should)\s+(not|never)/i, id: "PI11", severity: "medium", message: "Command to override restrictions" },
  { pattern: /bypass\s+(restriction|rule|limit|safety)/i, id: "PI12", severity: "medium", message: "Bypass attempt" },
  { pattern: /disregard\s+(all|your|the)\s+(previous|system)/i, id: "PI13", severity: "medium", message: "Disregard instruction pattern" },
  { pattern: /i.*am\s+the\s+developer.*trust\s+me/i, id: "PI14", severity: "medium", message: "Social engineering - developer trust exploitation" },
];

// ============================================================
// CREDENTIAL LEAKS (ASI04 - Supply Chain)
// ============================================================

// Only scan code files for credential patterns
const CREDENTIAL_PATTERNS_CODE = [
  { pattern: /~\/\.ssh|\/\.ssh\//, id: "CL01", severity: "critical", message: "SSH credential path reference" },
  { pattern: /~\/\.aws|\/\.aws\//, id: "CL02", severity: "critical", message: "AWS credential path reference" },
  { pattern: /~\/\.env|mkdir.*\.env/, id: "CL03", severity: "critical", message: ".env file reference (potential secret exposure)" },
  { pattern: /curl\s+(?!.*(-fsSL|-f\s|-L)).*\|\s*(sh|bash|perl|python)/, id: "CL04", severity: "critical", message: "Pipe to shell - code execution risk" },
  { pattern: /wget\s+(?!.*(-q|-O)).*\|\s*(sh|bash)/, id: "CL05", severity: "critical", message: "Pipe to shell - code execution risk" },
  { pattern: /nc\s+-[elv]\s+|netcat\s+-[elv]/, id: "CL06", severity: "critical", message: "Netcat reverse shell pattern" },
  { pattern: /bash\s+-i\s+.*\&\s*\/dev\/tcp/, id: "CL07", severity: "critical", message: "Bash reverse shell pattern" },
];

const CREDENTIAL_PATTERNS_MD = [
  { pattern: /bash\s+-i\s+.*\&\s*\/dev\/tcp/, id: "CL07", severity: "critical", message: "Bash reverse shell pattern" },
];

// ============================================================
// NETWORK EXFILTRATION (ASI02 - Tool Misuse)
// ============================================================

const EXFILTRATION_PATTERNS = [
  { pattern: /https?:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, id: "EX01", severity: "critical", message: "Raw IP address in URL - potential exfiltration" },
  { pattern: /fetch\s*\(\s*["'`][^"']+\?(key|token|secret|password)/i, id: "EX03", severity: "critical", message: "API key in URL query string - exfiltration risk" },
  { pattern: /\.send\(.*(http|https|external)/i, id: "EX04", severity: "critical", message: "Data send to external server" },
  { pattern: /dns\.resolve|dns\.query|new\s+DNS/i, id: "EX05", severity: "critical", message: "DNS resolution - potential DNS tunneling" },
  { pattern: /new\s+WebSocket\s*\(\s*["'`][^'"`]+["'`]\s*\)/, id: "EX06", severity: "high", message: "WebSocket connection - check target" },
  { pattern: /readFile.*send|fetch.*readFile|read_file.*fetch/i, id: "EX07", severity: "critical", message: "File read + send exfiltration chain" },
];

// ============================================================
// DANGEROUS CODE EXECUTION (ASI05)
// ============================================================

const DANGEROUS_PATTERNS = [
  { pattern: /rm\s+-rf\s+\/\s*$/, id: "CE01", severity: "critical", message: "Destructive rm -rf / command (root)" },
  { pattern: /rm\s+-rf\s+\$HOME|rm\s+-rf\s+~\s*$|rm\s+-rf\s+\/home\s*$|rm\s+-rf\s+\/tmp\s*$/, id: "CE02", severity: "high", message: "Recursive delete in user directory" },
  { pattern: /exec\s+\$\(/, id: "CE03", severity: "high", message: "Dynamic command execution" },
  { pattern: /eval\s+\$/, id: "CE04", severity: "high", message: "Eval with variable interpolation" },
  { pattern: /subprocess.*shell\s*=\s*true/i, id: "CE05", severity: "medium", message: "Subprocess with shell=True" },
  { pattern: /os\.system\s*\(/, id: "CE06", severity: "high", message: "os.system() call - shell injection risk" },
  { pattern: /child_process.*exec\s*\(/, id: "CE07", severity: "medium", message: "child_process.exec - verify input sanitization" },
  { pattern: /chmod\s+[47]777/, id: "CE08", severity: "high", message: "World-writable permissions" },
  { pattern: /process\.fork\s*\(|child_process\.spawn\s*\(|subprocess\.spawn\s*\(/i, id: "CE09", severity: "high", message: "Process fork/spawn - potential crypto miner" },
];

// ============================================================
// SECRET PATTERNS (ASI04 - Supply Chain)
// ============================================================

const SECRET_PATTERNS = [
  { pattern: /sk-[a-zA-Z0-9]{20,}/, id: "SC01", severity: "critical", message: "OpenAI API key pattern" },
  { pattern: /github_pat_[a-zA-Z0-9_]{20,}/, id: "SC02", severity: "critical", message: "GitHub PAT pattern" },
  { pattern: /ghp_[a-zA-Z0-9]{36}/, id: "SC03", severity: "critical", message: "GitHub OAuth token pattern" },
  { pattern: /xox[baprs]-[a-zA-Z0-9]{10,}/, id: "SC04", severity: "critical", message: "Slack token pattern" },
  { pattern: /AKIA[0-9A-Z]{16}/, id: "SC05", severity: "critical", message: "AWS access key pattern" },
];

// ============================================================
// TOOL MISUSE PATTERNS (ASI02)
// ============================================================

const TOOL_MISUSE_PATTERNS = [
  { pattern: /upload.*(file|data).*(external|remote|server)/i, id: "TM01", severity: "high", message: "Potential data exfiltration pattern" },
  { pattern: /export\s+(API|TOKEN|KEY|SECRET|PASSWORD|CREENTIAL)/i, id: "TM02", severity: "high", message: "Exporting sensitive environment variable" },
  { pattern: /setenv.*(PASSWORD|TOKEN|KEY|SECRET|CREDS)/i, id: "TM03", severity: "high", message: "Setting sensitive environment variable" },
  { pattern: /process\.env\[.*(KEY|SECRET|TOKEN|PASSWORD)/i, id: "TM04", severity: "medium", message: "Accessing sensitive env vars" },
];

// ============================================================
// BEHAVIORAL/MANIPULATION (ASI09)
// ============================================================

const BEHAVIORAL_PATTERNS = [
  { pattern: /^(always|never)\s+(say|do|follow|use|assume|accept|must|should)/im, id: "BM01", severity: "medium", message: "Absolute command pattern - may override safety" },
  { pattern: /^(never|always)\s+(question|verify|check|ask)/im, id: "BM02", severity: "medium", message: "Verification suppression" },
  { pattern: /^trust\s+(me|this| blindly)/im, id: "BM03", severity: "medium", message: "Blind trust request" },
  { pattern: /^don.*t\s+(need|require).*(permission|approval|confirm)/im, id: "BM04", severity: "medium", message: "Permission bypass encouragement" },
  { pattern: /^keep.*(this|secret|hidden).*(from|between)/im, id: "BM05", severity: "medium", message: "Secret keeping instruction" },
];

// ============================================================
// PROVENANCE CHECKS (ASI04)
// ============================================================

const TRUSTED_DOMAINS = [
  'github.com',
  'raw.githubusercontent.com',
  'vercel.com',
  'www.github.com'
];

const TRUSTED_PROTOCOLS = ['https:', 'git:'];

// ============================================================
// Helper Functions
// ============================================================

function isCodeFile(filename: string): boolean {
  const codeExtensions = [".sh", ".bash", ".py", ".js", ".ts", ".tsx", ".jsx", ".rb", ".go", ".rs", ".java", ".c", ".cpp", ".cs", ".php", ".yaml", ".yml"];
  return codeExtensions.includes(extname(filename).toLowerCase());
}

function getCategoryFromId(id: string): string {
  if (id.startsWith("PI")) return "PI";
  if (id.startsWith("CL")) return "SC";
  if (id.startsWith("EX")) return "TM";
  if (id.startsWith("CE")) return "CE";
  if (id.startsWith("SC")) return "SC";
  if (id.startsWith("TM")) return "TM";
  if (id.startsWith("BM")) return "BM";
  if (id.startsWith("PROV")) return "PROV";
  return "SC";
}

function getASIXXFromId(id: string): string {
  if (id.startsWith("PI")) return "ASI01";
  if (id.startsWith("CL")) return "ASI04";
  if (id.startsWith("EX")) return "ASI02";
  if (id.startsWith("CE")) return "ASI05";
  if (id.startsWith("SC")) return "ASI04";
  if (id.startsWith("TM")) return "ASI02";
  if (id.startsWith("BM")) return "ASI09";
  if (id.startsWith("PROV")) return "ASI04";
  return "ASI04";
}

interface PatternDef {
  pattern: RegExp;
  id: string;
  severity?: string;
  message: string;
}

interface CompiledPatternDef {
  regex: RegExp;
  id: string;
  severity: string;
  message: string;
  category: string;
}

function scanContent(content: string, file: string, patterns: PatternDef[] | CompiledPatternDef[]): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (const patternDef of patterns) {
    const regex = 'regex' in patternDef ? patternDef.regex : patternDef.pattern;
    const id = patternDef.id;
    const severity = 'severity' in patternDef ? patternDef.severity : (patternDef as PatternDef).severity || "medium";
    const message = patternDef.message;
    const category = 'category' in patternDef ? patternDef.category : getCategoryFromId(id);
    const asixx = 'category' in patternDef ? mapCategoryToASIXX(category) : getASIXXFromId(id);

    for (let i = 0; i < lines.length; i++) {
      if (regex.test(lines[i])) {
        findings.push({
          id,
          category: category as any,
          asixx,
          severity: severity as any,
          file,
          line: i + 1,
          message,
          evidence: lines[i].substring(0, 100)
        });
      }
    }
  }
  return findings;
}

function mapCategoryToASIXX(category: string): string {
  const map: Record<string, string> = {
    "promptInjection": "ASI01",
    "credentialLeaks": "ASI04",
    "shellInjection": "ASI05",
    "exfiltration": "ASI02",
    "secrets": "ASI04",
    "toolMisuse": "ASI02",
    "behavioral": "ASI09"
  };
  return map[category] || "ASI04";
}

function scanCodeBlocksInMarkdown(content: string, file: string): Finding[] {
  const findings: Finding[] = [];
  const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
  let match;

  while ((match = codeBlockRegex.exec(content)) !== null) {
    const code = match[2];
    findings.push(...scanContent(code, file + " (code block)", CREDENTIAL_PATTERNS_CODE));
    findings.push(...scanContent(code, file + " (code block)", EXFILTRATION_PATTERNS));
    findings.push(...scanContent(code, file + " (code block)", DANGEROUS_PATTERNS));
    findings.push(...scanContent(code, file + " (code block)", SECRET_PATTERNS));
  }

  return findings;
}

function checkProvenance(origin: string, skillPath: string): Finding[] {
  const findings: Finding[] = [];

  try {
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      findings.push({
        id: "PROV-01",
        category: "PROV",
        asixx: "ASI04",
        severity: "medium",
        file: skillPath,
        message: "Origin is not a URL - cannot verify provenance",
        evidence: origin
      });
      return findings;
    }

    if (!TRUSTED_PROTOCOLS.includes(url.protocol)) {
      findings.push({
        id: "PROV-02",
        category: "PROV",
        asixx: "ASI04",
        severity: "critical",
        file: skillPath,
        message: "Untrusted protocol - only https and git allowed",
        evidence: origin
      });
    }

    const hostname = url.hostname.toLowerCase();
    const isTrusted = TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));

    if (!isTrusted) {
      findings.push({
        id: "PROV-03",
        category: "PROV",
        asixx: "ASI04",
        severity: "high",
        file: skillPath,
        message: "Origin domain is not in trusted list",
        evidence: origin
      });
    }

    const isPinned = /[a-f0-9]{7,40}|v\d+\.\d+|release/.test(origin);
    if (!isPinned && url.pathname.includes('/blob/')) {
      findings.push({
        id: "PROV-04",
        category: "PROV",
        asixx: "ASI04",
        severity: "medium",
        file: skillPath,
        message: "Origin does not use pinned ref (commit SHA or tag)",
        evidence: origin
      });
    }
  } catch (e) {
    findings.push({
      id: "PROV-ERR-01",
      category: "PROV",
      asixx: "ASI04",
      severity: "low",
      file: skillPath,
      message: "Provenance check failed",
      evidence: String(e).slice(0, 100)
    });
  }

  return findings;
}

// ============================================================
// Main Security Audit Function
// ============================================================

export interface SecurityAuditResult {
  findings: Finding[];
  unreadableFiles: string[];
}

export function auditSecurity(skill: SkillInfo, manifest?: SkillManifest): SecurityAuditResult {
  let resolvedPath: string;
  try {
    resolvedPath = resolveSkillPath(skill.path);
  } catch (e) {
    return {
      findings: [{
        id: "SCAN-ERR-01",
        category: "SC",
        asixx: "ASI04",
        severity: "medium",
        file: skill.path,
        message: "Could not resolve skill path",
        evidence: String(e)
      }],
      unreadableFiles: []
    };
  }

  // Initialize patterns (load from file or use hardcoded fallback)
  const patterns = initPatterns();
  const hasExternalPatterns = patterns.size > 0;

  const files = getSkillFiles(resolvedPath);
  const findings: Finding[] = [];
  const unreadableFiles: string[] = [];

  for (const file of files) {
    const filename = basename(file);

    try {
      const content = readFileSync(file, "utf-8");

      if (filename === "SKILL.md" || filename === "SKILL.md") {
        // Use external patterns if available, otherwise use hardcoded
        if (hasExternalPatterns) {
          const piPatterns = patterns.get("promptInjection") || [];
          const clPatterns = patterns.get("credentialLeaks") || [];
          const exPatterns = patterns.get("exfiltration") || [];
          const bmPatterns = patterns.get("behavioral") || [];
          const cePatterns = patterns.get("shellInjection") || [];
          
          findings.push(...scanContent(content, file, piPatterns));
          findings.push(...scanContent(content, file, clPatterns));
          findings.push(...scanContent(content, file, exPatterns));
          findings.push(...scanContent(content, file, bmPatterns));
          findings.push(...scanContent(content, file, cePatterns));
        } else {
          findings.push(...scanContent(content, file, PROMPT_INJECTION_PATTERNS));
          findings.push(...scanContent(content, file, CREDENTIAL_PATTERNS_MD));
          findings.push(...scanContent(content, file, EXFILTRATION_PATTERNS));
          findings.push(...scanContent(content, file, BEHAVIORAL_PATTERNS));
          findings.push(...scanContent(content, file, DANGEROUS_PATTERNS));
        }
        findings.push(...scanCodeBlocksInMarkdown(content, file));
      } else if (isCodeFile(file)) {
        if (hasExternalPatterns) {
          const clPatterns = patterns.get("credentialLeaks") || [];
          const exPatterns = patterns.get("exfiltration") || [];
          const cePatterns = patterns.get("shellInjection") || [];
          const scPatterns = patterns.get("secrets") || [];
          const tmPatterns = patterns.get("toolMisuse") || [];
          
          findings.push(...scanContent(content, file, clPatterns));
          findings.push(...scanContent(content, file, exPatterns));
          findings.push(...scanContent(content, file, cePatterns));
          findings.push(...scanContent(content, file, scPatterns));
          findings.push(...scanContent(content, file, tmPatterns));
        } else {
          findings.push(...scanContent(content, file, CREDENTIAL_PATTERNS_CODE));
          findings.push(...scanContent(content, file, EXFILTRATION_PATTERNS));
          findings.push(...scanContent(content, file, DANGEROUS_PATTERNS));
          findings.push(...scanContent(content, file, SECRET_PATTERNS));
          findings.push(...scanContent(content, file, TOOL_MISUSE_PATTERNS));
        }
      }
    } catch (e) {
      unreadableFiles.push(file);
    }
  }

  // Add findings for unreadable files
  if (unreadableFiles.length > 0) {
    findings.push({
      id: "SCAN-ERR-02",
      category: "SC",
      asixx: "ASI04",
      severity: "medium",
      file: resolvedPath,
      message: `Could not read ${unreadableFiles.length} file(s) - security scan incomplete`,
      evidence: unreadableFiles.join(", ")
    });
  }

  if (files.length === 0) {
    findings.push({
      id: "SCAN-ERR-03",
      category: "SC",
      asixx: "ASI04",
      severity: "medium",
      file: resolvedPath,
      message: "No files found in skill directory",
      evidence: resolvedPath
    });
  }

  // Provenance checks (origin is optional metadata, not spec-required)
  if (manifest?.origin) {
    findings.push(...checkProvenance(manifest.origin, resolvedPath));
  }

  return { findings, unreadableFiles };
}