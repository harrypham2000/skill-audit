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
  | 'INTEL'; // Intelligence

export interface Finding {
  id: string;
  category: FindingCategory;
  asixx: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  file: string;
  line?: number;
  message: string;
  evidence?: string;
  recommendation?: string; // NEW: for compliance recommendations
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
  complianceScore?: number;  // NEW: Overall compliance score (0-100)
  complianceRiskLevel?: 'minimal' | 'limited' | 'high' | 'unacceptable';  // NEW
}

export interface AuditResult {
  skill: SkillInfo;
  manifest?: SkillManifest;
  findings: Finding[];
  riskScore: number;
  riskLevel: 'safe' | 'risky' | 'dangerous' | 'malicious';
}
