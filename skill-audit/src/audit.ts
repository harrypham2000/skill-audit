import { readFileSync } from "fs";
import { basename, extname } from "path";
import matter from "gray-matter";
import { SkillInfo, SkillManifest, Finding, GroupedAuditResult } from "./types.js";
import { resolveSkillPath, getSkillFiles } from "./discover.js";
import { checkCompliance, complianceToFindings, getComplianceSummary, ComplianceReport } from "./compliance.js";

// ============================================================
// PROMPT INJECTION PATTERNS (ASI01 - Goal Hijacking)
// Based on openclaw-skills-security approach
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
// Based on openclaw-skills-security approach
// ============================================================

// Only scan code files for credential patterns (not markdown docs)
const CREDENTIAL_PATTERNS_CODE = [
  // Critical - Block immediately
  { pattern: /~\/\.ssh|\/\.ssh\//, id: "CL01", severity: "critical", message: "SSH credential path reference" },
  { pattern: /~\/\.aws|\/\.aws\//, id: "CL02", severity: "critical", message: "AWS credential path reference" },
  { pattern: /~\/\.env|mkdir.*\.env/, id: "CL03", severity: "critical", message: ".env file reference (potential secret exposure)" },
  // Pipe to shell - only flag suspicious patterns (not known install scripts)
  { pattern: /curl\s+(?!.*(-fsSL|-f\s|-L)).*\|\s*(sh|bash|perl|python)/, id: "CL04", severity: "critical", message: "Pipe to shell - code execution risk (unsupported curl flags)" },
  { pattern: /wget\s+(?!.*(-q|-O)).*\|\s*(sh|bash)/, id: "CL05", severity: "critical", message: "Pipe to shell - code execution risk (unsupported wget flags)" },
  { pattern: /nc\s+-[elv]\s+|netcat\s+-[elv]/, id: "CL06", severity: "critical", message: "Netcat reverse shell pattern" },
  { pattern: /bash\s+-i\s+.*\&\s*\/dev\/tcp/, id: "CL07", severity: "critical", message: "Bash reverse shell pattern" },
];

// Markdown-only patterns (less aggressive for docs showing examples)
const CREDENTIAL_PATTERNS_MD = [
  { pattern: /bash\s+-i\s+.*\&\s*\/dev\/tcp/, id: "CL07", severity: "critical", message: "Bash reverse shell pattern" },
];

// ============================================================
// NETWORK EXFILTRATION (ASI02 - Tool Misuse)
// Based on openclaw-skills-security approach
// ============================================================

const EXFILTRATION_PATTERNS = [
  // Critical red flags
  { pattern: /https?:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, id: "EX01", severity: "critical", message: "Raw IP address in URL - potential exfiltration" },
  { pattern: /fetch\s*\(\s*["'`][^"']+\?(key|token|secret|password)/i, id: "EX03", severity: "critical", message: "API key in URL query string - exfiltration risk" },
  { pattern: /\.send\(.*(http|https|external)/i, id: "EX04", severity: "critical", message: "Data send to external server" },
  { pattern: /dns\.resolve|dns\.query|new\s+DNS/i, id: "EX05", severity: "critical", message: "DNS resolution - potential DNS tunneling" },

  // WebSocket patterns
  { pattern: /new\s+WebSocket\s*\(\s*["'`][^'"`]+["'`]\s*\)/, id: "EX06", severity: "high", message: "WebSocket connection - check target" },

  // Exfiltration chains
  { pattern: /readFile.*send|fetch.*readFile|read_file.*fetch/i, id: "EX07", severity: "critical", message: "File read + send exfiltration chain" },
];

// ============================================================
// DANGEROUS CODE EXECUTION (ASI05)
// ============================================================

const DANGEROUS_PATTERNS = [
  // Only match actual root deletion, not cleanup in subdirs
  { pattern: /rm\s+-rf\s+\/\s*$/, id: "CE01", severity: "critical", message: "Destructive rm -rf / command (root)" },
  { pattern: /rm\s+-rf\s+\$HOME|rm\s+-rf\s+~\s*$|rm\s+-rf\s+\/home\s*$|rm\s+-rf\s+\/tmp\s*$/, id: "CE02", severity: "high", message: "Recursive delete in user directory" },
  { pattern: /exec\s+\$\(/, id: "CE03", severity: "high", message: "Dynamic command execution" },
  { pattern: /eval\s+\$/, id: "CE04", severity: "high", message: "Eval with variable interpolation" },
  { pattern: /subprocess.*shell\s*=\s*true/i, id: "CE05", severity: "medium", message: "Subprocess with shell=True" },
  { pattern: /os\.system\s*\(/, id: "CE06", severity: "high", message: "os.system() call - shell injection risk" },
  { pattern: /child_process.*exec\s*\(/, id: "CE07", severity: "medium", message: "child_process.exec - verify input sanitization" },
  { pattern: /chmod\s+[47]777/, id: "CE08", severity: "high", message: "World-writable permissions" },
  // Only match actual process.fork() or child_process.spawn with shell path, not "git fork" in docs
  { pattern: /process\.fork\s*\(|child_process\.spawn\s*\(|subprocess\.spawn\s*\(/i, id: "CE09", severity: "high", message: "Process fork/spawn - potential crypto miner" },
];

// ============================================================
// SECRET PATTERNS (ASI04 - Supply Chain)
// Only for code files, not documentation
// ============================================================

const SECRET_PATTERNS = [
  { pattern: /sk-[a-zA-Z0-9]{20,}/, id: "SC01", message: "OpenAI API key pattern" },
  { pattern: /github_pat_[a-zA-Z0-9_]{20,}/, id: "SC02", message: "GitHub PAT pattern" },
  { pattern: /ghp_[a-zA-Z0-9]{36}/, id: "SC03", message: "GitHub OAuth token pattern" },
  { pattern: /xox[baprs]-[a-zA-Z0-9]{10,}/, id: "SC04", message: "Slack token pattern" },
  { pattern: /AKIA[0-9A-Z]{16}/, id: "SC05", message: "AWS access key pattern" },
];

// ============================================================
// TOOL MISUSE PATTERNS (ASI02)
// ============================================================

const TOOL_MISUSE_PATTERNS = [
  { pattern: /upload.*(file|data).*(external|remote|server)/i, id: "TM01", message: "Potential data exfiltration pattern" },
  { pattern: /export\s+(API|TOKEN|KEY|SECRET|PASSWORD|CREENTIAL)/i, id: "TM02", message: "Exporting sensitive environment variable" },
  { pattern: /setenv.*(PASSWORD|TOKEN|KEY|SECRET|CREDS)/i, id: "TM03", message: "Setting sensitive environment variable" },
  { pattern: /process\.env\[.*(KEY|SECRET|TOKEN|PASSWORD)/i, id: "TM04", message: "Accessing sensitive env vars" },
];

// ============================================================
// BEHAVIORAL/MANIPULATION (ASI09)
// ============================================================

const BEHAVIORAL_PATTERNS = [
  // More specific - only match imperative commands at start of line (not "always returns" in technical docs)
  { pattern: /^(always|never)\s+(say|do|follow|use|assume|accept|must|should)/im, id: "BM01", severity: "medium", message: "Absolute command pattern - may override safety" },
  { pattern: /^(never|always)\s+(question|verify|check|ask)/im, id: "BM02", severity: "medium", message: "Verification suppression" },
  { pattern: /^trust\s+(me|this| blindly)/im, id: "BM03", severity: "medium", message: "Blind trust request" },
  { pattern: /^don.*t\s+(need|require).*(permission|approval|confirm)/im, id: "BM04", severity: "medium", message: "Permission bypass encouragement" },
  { pattern: /^keep.*(this|secret|hidden).*(from|between)/im, id: "BM05", severity: "medium", message: "Secret keeping instruction" },
];

function isCodeFile(filename: string): boolean {
  const codeExtensions = [".sh", ".bash", ".py", ".js", ".ts", ".tsx", ".jsx", ".rb", ".go", ".rs", ".java", ".c", ".cpp", ".cs", ".php", ".yaml", ".yml"];
  return codeExtensions.includes(extname(filename).toLowerCase());
}

function scanContent(content: string, file: string, patterns: Array<{pattern: RegExp, id: string, severity?: string, message: string}>): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (const { pattern, id, severity = "medium", message } of patterns) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        findings.push({
          id,
          category: getCategoryFromId(id),
          asixx: getASIXXFromId(id),
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

function getCategoryFromId(id: string): "PI" | "BM" | "SC" | "CE" | "TM" | "MC" | "HT" | "RA" {
  if (id.startsWith("PI")) return "PI";
  if (id.startsWith("CL")) return "SC";
  if (id.startsWith("EX")) return "TM";
  if (id.startsWith("CE")) return "CE";
  if (id.startsWith("SC")) return "SC";
  if (id.startsWith("TM")) return "TM";
  if (id.startsWith("BM")) return "BM";
  return "SC";
}

function getASIXXFromId(id: string): string {
  if (id.startsWith("PI")) return "ASI01";  // Prompt injection
  if (id.startsWith("CL")) return "ASI04";  // Credential leaks
  if (id.startsWith("EX")) return "ASI02";  // Exfiltration
  if (id.startsWith("CE")) return "ASI05";  // Code execution
  if (id.startsWith("SC")) return "ASI04";  // Secrets
  if (id.startsWith("TM")) return "ASI02";  // Tool misuse
  if (id.startsWith("BM")) return "ASI09";  // Behavioral
  return "ASI04";
}

export function auditSkill(skill: SkillInfo): { manifest?: SkillManifest; findings: Finding[]; complianceReports?: ComplianceReport[] } {
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
      }]
    };
  }

  const files = getSkillFiles(resolvedPath);
  const findings: Finding[] = [];
  const unreadableFiles: string[] = [];
  let manifest: SkillManifest | undefined;

  for (const file of files) {
    const filename = basename(file);

    try {
      const content = readFileSync(file, "utf-8");

      if (filename === "SKILL.md" || filename === "AGENTS.md") {
        // Parse frontmatter
        if (filename === "SKILL.md") {
          const parsed = matter(content);
          manifest = {
            name: parsed.data.name || skill.name,
            description: parsed.data.description || "",
            origin: parsed.data.origin,
            license: parsed.data.license,
            compatibility: parsed.data.compatibility,
            metadata: parsed.data.metadata,
            allowedTools: parsed.data['allowed-tools'],
            content: parsed.content,
            files
          };
        }

        // Scan markdown for pattern categories (use MD-specific for credentials)
        findings.push(...scanContent(content, file, PROMPT_INJECTION_PATTERNS));
        findings.push(...scanContent(content, file, CREDENTIAL_PATTERNS_MD));
        findings.push(...scanContent(content, file, EXFILTRATION_PATTERNS));
        findings.push(...scanContent(content, file, BEHAVIORAL_PATTERNS));
        findings.push(...scanContent(content, file, DANGEROUS_PATTERNS));

        // Also scan fenced code blocks in markdown (use code patterns)
        const codeBlockFindings = scanCodeBlocksInMarkdown(content, file);
        findings.push(...codeBlockFindings);
      } else if (isCodeFile(file)) {
        // Full scan for code files (use CODE-specific patterns for credentials)
        findings.push(...scanContent(content, file, CREDENTIAL_PATTERNS_CODE));
        findings.push(...scanContent(content, file, EXFILTRATION_PATTERNS));
        findings.push(...scanContent(content, file, DANGEROUS_PATTERNS));
        findings.push(...scanContent(content, file, SECRET_PATTERNS));
        findings.push(...scanContent(content, file, TOOL_MISUSE_PATTERNS));
      }
    } catch (e) {
      unreadableFiles.push(file);
    }
  }

  // Add findings for unreadable files (fail-safe)
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
      message: "No files found in skill directory - possible empty or inaccessible skill",
      evidence: resolvedPath
    });
  }

  // Provenance checks (if manifest exists with origin)
  if (manifest?.origin) {
    findings.push(...checkProvenance(manifest.origin, resolvedPath));
  }

  // Spec validation (Agent Skills format)
  if (manifest) {
    findings.push(...validateSkillSpec(manifest, resolvedPath, basename(resolvedPath)));
  }

  // NEW: Compliance checks
  const complianceReports = checkCompliance(resolvedPath, manifest);
  const complianceFindings = complianceToFindings(complianceReports, resolvedPath);
  findings.push(...complianceFindings);

  return { manifest, findings, complianceReports };
}

// Validate skill against Agent Skills specification
function validateSkillSpec(manifest: SkillManifest, skillPath: string, dirName: string): Finding[] {
  const findings: Finding[] = [];

  // Required: name field
  if (!manifest.name) {
    findings.push({
      id: "SPEC-01",
      category: "SC",
      asixx: "ASI04",
      severity: "critical",
      file: skillPath,
      message: "SKILL.md frontmatter missing required 'name' field"
    });
  } else {
    // Validate name format
    if (manifest.name.length > 64) {
      findings.push({
        id: "SPEC-02",
        category: "SC",
        asixx: "ASI04",
        severity: "high",
        file: skillPath,
        message: "name field exceeds 64 character limit: " + manifest.name.length + " chars"
      });
    }
    if (!/^[a-z0-9-]+$/.test(manifest.name)) {
      findings.push({
        id: "SPEC-03",
        category: "SC",
        asixx: "ASI04",
        severity: "high",
        message: "name field must only contain lowercase letters, numbers, and hyphens",
        file: skillPath
      });
    }
    if (manifest.name.startsWith('-') || manifest.name.endsWith('-')) {
      findings.push({
        id: "SPEC-04",
        category: "SC",
        asixx: "ASI04",
        severity: "high",
        file: skillPath,
        message: "name field cannot start or end with a hyphen"
      });
    }
    if (manifest.name.includes('--')) {
      findings.push({
        id: "SPEC-05",
        category: "SC",
        asixx: "ASI04",
        severity: "high",
        file: skillPath,
        message: "name field cannot contain consecutive hyphens"
      });
    }
    // Validate name matches directory
    if (manifest.name !== dirName) {
      findings.push({
        id: "SPEC-06",
        category: "SC",
        asixx: "ASI04",
        severity: "medium",
        file: skillPath,
        message: "name field must match directory name: expected '" + dirName + "', got '" + manifest.name + "'"
      });
    }
  }

  // Required: description field
  if (!manifest.description) {
    findings.push({
      id: "SPEC-07",
      category: "SC",
      asixx: "ASI04",
      severity: "critical",
      file: skillPath,
      message: "SKILL.md frontmatter missing required 'description' field"
    });
  } else if (manifest.description.length > 1024) {
    findings.push({
      id: "SPEC-08",
      category: "SC",
      asixx: "ASI04",
      severity: "high",
      file: skillPath,
      message: "description field exceeds 1024 character limit: " + manifest.description.length + " chars"
    });
  }

  // Optional: compatibility field
  if (manifest.compatibility && manifest.compatibility.length > 500) {
    findings.push({
      id: "SPEC-09",
      category: "SC",
      asixx: "ASI04",
      severity: "medium",
      file: skillPath,
      message: "compatibility field exceeds 500 character limit"
    });
  }

  return findings;
}

// Trusted domains/hosts for skill origins
const TRUSTED_DOMAINS = [
  'github.com',
  'raw.githubusercontent.com',
  'vercel.com',
  'www.github.com'
];

const TRUSTED_PROTOCOLS = ['https:', 'git:'];

// Check provenance of skill origin
function checkProvenance(origin: string, skillPath: string): Finding[] {
  const findings: Finding[] = [];

  try {
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      // Not a URL - could be a git ref or local path
      findings.push({
        id: "PROV-01",
        category: "SC",
        asixx: "ASI04",
        severity: "medium",
        file: skillPath,
        message: "Origin is not a URL - cannot verify provenance: " + origin,
        evidence: origin
      });
      return findings;
    }

    // Check protocol
    if (!TRUSTED_PROTOCOLS.includes(url.protocol)) {
      findings.push({
        id: "PROV-02",
        category: "SC",
        asixx: "ASI04",
        severity: "critical",
        file: skillPath,
        message: "Untrusted protocol in origin - only https and git are allowed: " + url.protocol,
        evidence: origin
      });
    }

    // Check domain
    const hostname = url.hostname.toLowerCase();
    const isTrusted = TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
    
    if (!isTrusted) {
      findings.push({
        id: "PROV-03",
        category: "SC",
        asixx: "ASI04",
        severity: "high",
        file: skillPath,
        message: "Origin domain is not in trusted list: " + hostname,
        evidence: origin
      });
    }

    // Check for pinned refs (commit SHA, tag, branch)
    const isPinned = /[a-f0-9]{7,40}|v\d+\.\d+|release/.test(origin);
    
    if (!isPinned && url.pathname.includes('/blob/')) {
      findings.push({
        id: "PROV-04",
        category: "SC",
        asixx: "ASI04",
        severity: "medium",
        file: skillPath,
        message: "Origin does not appear to use a pinned ref (commit SHA or tag) - consider pinning for reproducibility",
        evidence: origin
      });
    }

  } catch (e) {
    findings.push({
      id: "PROV-ERR-01",
      category: "SC",
      asixx: "ASI04",
      severity: "low",
      file: skillPath,
      message: "Provenance check failed: " + String(e).slice(0, 100),
      evidence: String(e)
    });
  }

  return findings;
}

function scanCodeBlocksInMarkdown(content: string, file: string): Finding[] {
  const findings: Finding[] = [];
  const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
  let match;

  while ((match = codeBlockRegex.exec(content)) !== null) {
    const code = match[2];

    // Scan code blocks for dangerous patterns (use code patterns)
    findings.push(...scanContent(code, file + " (code block)", CREDENTIAL_PATTERNS_CODE));
    findings.push(...scanContent(code, file + " (code block)", EXFILTRATION_PATTERNS));
    findings.push(...scanContent(code, file + " (code block)", DANGEROUS_PATTERNS));
    findings.push(...scanContent(code, file + " (code block)", SECRET_PATTERNS));
  }

  return findings;
}