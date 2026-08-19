export interface SkillInfo {
  name: string;
  path: string;
  scope: 'global' | 'project';
  agents: string[];
}

export interface SkillManifest {
  name: string;
  description: string;
  origin?: string;
  license?: string;
  compatibility?: string;
  metadata?: Record<string, string>;
  allowedTools?: string;
  context?: unknown;
  content: string;
  files: string[];
}

export type FindingCategory = 
  | 'PI'   // Prompt Injection
  | 'BM'   // Behavioral Manipulation
  | 'SC'   // Secrets/Credentials
  | 'CE'   // Code Execution
  | 'TM'   // Tool Misuse
  | 'PII'  // PII Detection (NEW)
  | 'COMP' // Compliance (NEW)
  | 'MC'   // Malicious Content
  | 'HT'   // Harmful Techniques
  | 'RA'   // Resource Abuse
  | 'SPEC' // Specification
  | 'PROV' // Provenance
  | 'INTEL' // Intelligence
  | 'ENV';  // Agent environment risks

/**
 * Source range of a piece of evidence, 1-based everywhere.
 *
 * Column convention: `startColumn` is inclusive, `endColumn` is EXCLUSIVE
 * (i.e. the range covers `startColumn .. endColumn - 1` on `endLine`).
 * This matches the TypeScript compiler's exclusive `getEnd()` offsets and
 * Python's exclusive `end_col_offset`. Converters to inclusive consumers
 * (e.g. SARIF regions) must subtract 1 from `endColumn`.
 *
 * `precision` states what the analyzer actually knows:
 * - "exact": the range was derived from parsed syntax offsets.
 * - "line-only": only the line is known; columns span the whole line.
 *   Never fabricate "exact" when only line knowledge exists.
 */
export interface SourceLocation {
  file: string;            // relative path (or the report file path for findings)
  startLine: number;       // 1-based
  startColumn: number;     // 1-based, inclusive
  endLine: number;         // 1-based
  endColumn: number;       // 1-based, EXCLUSIVE
  precision: "exact" | "line-only";
}

export interface Finding {
  id: string;
  category: FindingCategory;
  asi: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  file: string;
  /** Legacy 1-based line number; kept populated alongside `location`. */
  line?: number;
  /** Exact or line-only source range when the analyzer knows it. */
  location?: SourceLocation;
  message: string;
  evidence?: string;
  recommendation?: string; // NEW: for compliance recommendations
  confidence?: 'high' | 'medium' | 'low';
  cwe?: string;
  /** Stable digest (scanner+analyzer+rule+path+source+evidence) for suppression baselines. */
  fingerprint?: string;
  /** Present when a suppression baseline matched this finding. */
  suppressed?: boolean;
  suppression?: {
    reason: string;
    approver?: string;
    ticket?: string;
    created?: string;
    expires?: string;
  };
}

/**
 * Grouped audit results for layered output
 */
export interface GroupedAuditResult {
  skill: SkillInfo;
  manifest?: SkillManifest;
  specFindings: Finding[];
  securityFindings: Finding[];
  piiFindings: Finding[];  // NEW: PII detection findings
  complianceFindings: Finding[];  // NEW: Compliance findings
  intelFindings: Finding[];
  riskScore: number;
  riskLevel: 'safe' | 'risky' | 'dangerous' | 'malicious';
  complianceScore?: number;  // Only set when compliance checks actually ran
  complianceRiskLevel?: 'minimal' | 'limited' | 'high' | 'unacceptable';
  complianceStatus?: 'not_run' | 'experimental';
}

export interface AuditResult {
  skill: SkillInfo;
  manifest?: SkillManifest;
  findings: Finding[];
  riskScore: number;
  riskLevel: 'safe' | 'risky' | 'dangerous' | 'malicious';
}
