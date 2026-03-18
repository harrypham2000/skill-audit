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

export interface Finding {
  id: string;
  category: 'PI' | 'BM' | 'SC' | 'CE' | 'TM' | 'MC' | 'HT' | 'RA' | 'SPEC' | 'PROV' | 'INTEL';
  asixx: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  file: string;
  line?: number;
  message: string;
  evidence?: string;
}

/**
 * Grouped audit results for layered output
 */
export interface GroupedAuditResult {
  skill: SkillInfo;
  manifest?: SkillManifest;
  specFindings: Finding[];
  securityFindings: Finding[];
  intelFindings: Finding[];
  riskScore: number;
  riskLevel: 'safe' | 'risky' | 'dangerous' | 'malicious';
}

export interface AuditResult {
  skill: SkillInfo;
  manifest?: SkillManifest;
  findings: Finding[];
  riskScore: number;
  riskLevel: 'safe' | 'risky' | 'dangerous' | 'malicious';
}
