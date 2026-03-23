/**
 * Compliance Validation Module
 *
 * Validates skills against regulatory frameworks:
 * - Vietnam AI Law 2026
 * - EU AI Act
 * - GDPR
 *
 * Inspired by AgentVeil's compliance checking approach.
 */

import { readFileSync } from "fs";
import { basename } from "path";
import { Finding, SkillManifest } from "./types.js";

// ============================================================
// Types
// ============================================================

export type ComplianceFramework = 'VN_AI_LAW_2026' | 'EU_AI_ACT' | 'GDPR';

export type RiskLevel = 'minimal' | 'limited' | 'high' | 'unacceptable';

export interface ComplianceRequirement {
  id: string;
  name: string;
  description: string;
  required: boolean;
  check: (content: string, manifest?: SkillManifest) => ComplianceCheckResult;
}

export interface ComplianceCheckResult {
  passed: boolean;
  evidence?: string;
  recommendation?: string;
}

export interface ComplianceFinding {
  framework: ComplianceFramework;
  requirement: string;
  passed: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  evidence?: string;
  recommendation?: string;
}

export interface ComplianceReport {
  framework: ComplianceFramework;
  score: number; // 0-100
  riskLevel: RiskLevel;
  findings: ComplianceFinding[];
  passed: number;
  failed: number;
  total: number;
}

// ============================================================
// Vietnam AI Law 2026 Requirements
// ============================================================

const VN_AI_LAW_REQUIREMENTS: ComplianceRequirement[] = [
  {
    id: 'VN-AI-001',
    name: 'Data Localization',
    description: 'Vietnamese citizens\' data must be stored within Vietnam',
    required: true,
    check: (content, manifest) => {
      // Check for external data endpoints outside Vietnam
      const hasExternalStorage = /(?:aws\.com|azure\.com|gcp\.google|us-east|us-west|eu-west|ap-southeast)/i.test(content);
      const hasVNStorage = /(?:vn-|vietnam|hanoi|ho chi minh|fpt|viettel)/i.test(content);
      
      if (hasExternalStorage && !hasVNStorage) {
        return {
          passed: false,
          evidence: 'External storage endpoints detected without Vietnam localization',
          recommendation: 'Ensure Vietnamese user data is stored in Vietnam-based infrastructure'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'VN-AI-002',
    name: 'User Consent',
    description: 'Explicit user consent required for AI processing',
    required: true,
    check: (content) => {
      const hasConsentMechanism = /consent|agree|accept|permission|xác nhận|đồng ý/i.test(content);
      
      if (!hasConsentMechanism) {
        return {
          passed: false,
          evidence: 'No consent mechanism detected',
          recommendation: 'Add explicit user consent before AI processing'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'VN-AI-003',
    name: 'Transparency',
    description: 'Users must be informed they are interacting with AI',
    required: true,
    check: (content) => {
      const hasTransparency = /AI|artificial intelligence|machine learning|bot|assistant|trí tuệ nhân tạo/i.test(content);
      
      if (!hasTransparency) {
        return {
          passed: false,
          evidence: 'No AI disclosure detected',
          recommendation: 'Clearly disclose AI nature of the system to users'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'VN-AI-004',
    name: 'Human Oversight',
    description: 'Human oversight mechanism for high-risk decisions',
    required: true,
    check: (content) => {
      const hasHumanOversight = /human|review|approve|oversight|supervisor|người duyệt|xét duyệt/i.test(content);
      
      if (!hasHumanOversight) {
        return {
          passed: false,
          evidence: 'No human oversight mechanism detected',
          recommendation: 'Implement human review for high-risk AI decisions'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'VN-AI-005',
    name: 'Data Minimization',
    description: 'Collect only necessary data for AI functionality',
    required: true,
    check: (content) => {
      const hasExcessiveCollection = /collect.*all|store.*all|save.*everything|lưu tất cả|thu thập tất cả/i.test(content);
      
      if (hasExcessiveCollection) {
        return {
          passed: false,
          evidence: 'Potential excessive data collection detected',
          recommendation: 'Implement data minimization - collect only what is necessary'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'VN-AI-006',
    name: 'Right to Explanation',
    description: 'Users can request explanation of AI decisions',
    required: true,
    check: (content) => {
      const hasExplanationMechanism = /explain|reason|why|decision|tại sao|giải thích|lý do/i.test(content);
      
      if (!hasExplanationMechanism) {
        return {
          passed: false,
          evidence: 'No explanation mechanism detected',
          recommendation: 'Provide users with ability to understand AI decisions'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'VN-AI-007',
    name: 'Bias Prevention',
    description: 'Measures to prevent discriminatory outcomes',
    required: false,
    check: (content) => {
      const hasBiasPrevention = /bias|fair|discriminat|equality|công bằng|phân biệt đối xử/i.test(content);
      
      if (!hasBiasPrevention) {
        return {
          passed: false,
          evidence: 'No bias prevention measures detected',
          recommendation: 'Implement bias detection and mitigation measures'
        };
      }
      return { passed: true };
    }
  }
];

// ============================================================
// EU AI Act Requirements
// ============================================================

const EU_AI_ACT_REQUIREMENTS: ComplianceRequirement[] = [
  {
    id: 'EU-AI-001',
    name: 'Risk Assessment',
    description: 'Conduct and document risk assessment for AI system',
    required: true,
    check: (content) => {
      const hasRiskAssessment = /risk|assessment|hazard|danger|đánh giá rủi ro/i.test(content);
      
      if (!hasRiskAssessment) {
        return {
          passed: false,
          evidence: 'No risk assessment documentation detected',
          recommendation: 'Document AI system risk assessment'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'EU-AI-002',
    name: 'Data Governance',
    description: 'Data quality and governance measures in place',
    required: true,
    check: (content) => {
      const hasDataGovernance = /data quality|governance|validation|verify|kiểm tra|chất lượng dữ liệu/i.test(content);
      
      if (!hasDataGovernance) {
        return {
          passed: false,
          evidence: 'No data governance measures detected',
          recommendation: 'Implement data quality and governance controls'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'EU-AI-003',
    name: 'Technical Documentation',
    description: 'Maintain technical documentation for AI system',
    required: true,
    check: (content, manifest) => {
      const hasDocumentation = manifest?.metadata?.documentation || 
        /documentation|readme|docs|hướng dẫn|tài liệu/i.test(content);
      
      if (!hasDocumentation) {
        return {
          passed: false,
          evidence: 'No technical documentation detected',
          recommendation: 'Create and maintain technical documentation'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'EU-AI-004',
    name: 'Record Keeping',
    description: 'Automatic logging of AI system operations',
    required: true,
    check: (content) => {
      const hasLogging = /log|record|audit trail|history|nhật ký|ghi nhận/i.test(content);
      
      if (!hasLogging) {
        return {
          passed: false,
          evidence: 'No logging mechanism detected',
          recommendation: 'Implement automatic logging of AI operations'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'EU-AI-005',
    name: 'Transparency Obligations',
    description: 'Inform users about AI interaction and content',
    required: true,
    check: (content) => {
      const hasTransparency = /AI-generated|artificial|automated|tự động|AI tạo ra/i.test(content);
      
      if (!hasTransparency) {
        return {
          passed: false,
          evidence: 'No AI transparency disclosure detected',
          recommendation: 'Disclose AI-generated content to users'
        };
      }
      return { passed: true };
    }
  }
];

// ============================================================
// GDPR Requirements
// ============================================================

const GDPR_REQUIREMENTS: ComplianceRequirement[] = [
  {
    id: 'GDPR-001',
    name: 'Lawful Basis',
    description: 'Processing must have a lawful basis',
    required: true,
    check: (content) => {
      const hasLawfulBasis = /consent|contract|legal obligation|vital interest|public interest|legitimate interest/i.test(content);
      
      if (!hasLawfulBasis) {
        return {
          passed: false,
          evidence: 'No lawful basis for processing detected',
          recommendation: 'Document lawful basis for data processing (consent, contract, etc.)'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'GDPR-002',
    name: 'Data Subject Rights',
    description: 'Mechanism for users to exercise their rights',
    required: true,
    check: (content) => {
      const hasRightsMechanism = /right to access|right to delete|right to rectif|right to erasure|right to be forgotten|quyền xóa|quyền truy cập/i.test(content);
      
      if (!hasRightsMechanism) {
        return {
          passed: false,
          evidence: 'No data subject rights mechanism detected',
          recommendation: 'Implement user rights (access, deletion, rectification)'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'GDPR-003',
    name: 'Privacy by Design',
    description: 'Privacy considerations built into the system',
    required: true,
    check: (content) => {
      const hasPrivacyByDesign = /privacy by design|data protection|encryption|anonymiz|pseudonymiz/i.test(content);
      
      if (!hasPrivacyByDesign) {
        return {
          passed: false,
          evidence: 'No privacy by design measures detected',
          recommendation: 'Implement privacy-preserving techniques (encryption, anonymization)'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'GDPR-004',
    name: 'Data Protection Impact Assessment',
    description: 'DPIA for high-risk processing',
    required: false,
    check: (content) => {
      const hasDPIA = /DPIA|impact assessment|risk assessment|đánh giá tác động/i.test(content);
      
      if (!hasDPIA) {
        return {
          passed: false,
          evidence: 'No Data Protection Impact Assessment detected',
          recommendation: 'Conduct DPIA for high-risk data processing activities'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'GDPR-005',
    name: 'Data Breach Notification',
    description: 'Procedure for breach notification within 72 hours',
    required: true,
    check: (content) => {
      const hasBreachProcedure = /breach|notification|72 hours|incident response|sự cố|thông báo/i.test(content);
      
      if (!hasBreachProcedure) {
        return {
          passed: false,
          evidence: 'No data breach notification procedure detected',
          recommendation: 'Implement breach notification procedure (72-hour requirement)'
        };
      }
      return { passed: true };
    }
  },
  {
    id: 'GDPR-006',
    name: 'International Transfers',
    description: 'Safeguards for international data transfers',
    required: false,
    check: (content) => {
      const hasInternationalTransfer = /transfer|international|cross-border|SCC|standard contractual|adequacy/i.test(content);
      const hasExternalAPI = /api\.(openai|anthropic|google|aws)/i.test(content);
      
      if (hasExternalAPI && !hasInternationalTransfer) {
        return {
          passed: false,
          evidence: 'External API usage without international transfer safeguards',
          recommendation: 'Implement safeguards for international data transfers (SCCs, adequacy decisions)'
        };
      }
      return { passed: true };
    }
  }
];

// ============================================================
// Main Compliance Check Function
// ============================================================

export function checkCompliance(
  skillPath: string,
  manifest?: SkillManifest
): ComplianceReport[] {
  const reports: ComplianceReport[] = [];
  
  // Read skill content
  let content = '';
  try {
    const files = [skillPath];
    if (manifest?.files) {
      files.push(...manifest.files);
    }
    
    for (const file of files) {
      try {
        const fileContent = readFileSync(file, 'utf-8');
        content += '\n' + fileContent;
      } catch {
        // Skip unreadable files
      }
    }
  } catch {
    // If no content, still run checks with empty string
  }
  
  // Check each framework
  reports.push(runFrameworkCheck('VN_AI_LAW_2026', VN_AI_LAW_REQUIREMENTS, content, manifest));
  reports.push(runFrameworkCheck('EU_AI_ACT', EU_AI_ACT_REQUIREMENTS, content, manifest));
  reports.push(runFrameworkCheck('GDPR', GDPR_REQUIREMENTS, content, manifest));
  
  return reports;
}

function runFrameworkCheck(
  framework: ComplianceFramework,
  requirements: ComplianceRequirement[],
  content: string,
  manifest?: SkillManifest
): ComplianceReport {
  const findings: ComplianceFinding[] = [];
  let passed = 0;
  let failed = 0;
  
  for (const req of requirements) {
    const result = req.check(content, manifest);
    
    if (!result.passed) {
      failed++;
      findings.push({
        framework,
        requirement: req.id,
        passed: false,
        severity: req.required ? 'high' : 'medium',
        message: `${req.name}: ${req.description}`,
        evidence: result.evidence,
        recommendation: result.recommendation
      });
    } else {
      passed++;
    }
  }
  
  // Calculate score (percentage of passed requirements)
  const total = requirements.length;
  const score = Math.round((passed / total) * 100);
  
  // Determine risk level based on score and framework
  const riskLevel = determineRiskLevel(framework, score, findings);
  
  return {
    framework,
    score,
    riskLevel,
    findings,
    passed,
    failed,
    total
  };
}

function determineRiskLevel(
  framework: ComplianceFramework,
  score: number,
  findings: ComplianceFinding[]
): RiskLevel {
  const criticalFailures = findings.filter(f => f.severity === 'critical').length;
  const highFailures = findings.filter(f => f.severity === 'high').length;
  
  // Vietnam AI Law 2026 has specific risk categories
  if (framework === 'VN_AI_LAW_2026') {
    if (criticalFailures > 0 || score < 40) return 'unacceptable';
    if (highFailures > 2 || score < 60) return 'high';
    if (highFailures > 0 || score < 80) return 'limited';
    return 'minimal';
  }
  
  // EU AI Act risk levels
  if (framework === 'EU_AI_ACT') {
    if (criticalFailures > 0 || score < 40) return 'unacceptable';
    if (highFailures > 1 || score < 60) return 'high';
    if (score < 80) return 'limited';
    return 'minimal';
  }
  
  // GDPR - more lenient but still strict
  if (criticalFailures > 0 || score < 50) return 'high';
  if (highFailures > 1 || score < 70) return 'limited';
  if (score < 90) return 'minimal';
  return 'minimal';
}

// ============================================================
// Convert Compliance Findings to Security Findings
// ============================================================

export function complianceToFindings(
  reports: ComplianceReport[],
  skillPath: string
): Finding[] {
  const findings: Finding[] = [];
  
  for (const report of reports) {
    for (const finding of report.findings) {
      findings.push({
        id: finding.requirement,
        category: 'COMP',
        asixx: 'ASI04',
        severity: finding.severity,
        file: skillPath,
        message: `[${report.framework}] ${finding.message}`,
        evidence: finding.evidence,
        recommendation: finding.recommendation
      });
    }
  }
  
  return findings;
}

// ============================================================
// Summary Report
// ============================================================

export function getComplianceSummary(reports: ComplianceReport[]): {
  overallScore: number;
  overallRiskLevel: RiskLevel;
  frameworksPassed: number;
  frameworksFailed: number;
} {
  const avgScore = Math.round(
    reports.reduce((sum, r) => sum + r.score, 0) / reports.length
  );
  
  const riskLevels: RiskLevel[] = ['minimal', 'limited', 'high', 'unacceptable'];
  const worstRiskLevel = reports.reduce((worst, r) => {
    const worstIdx = riskLevels.indexOf(worst);
    const currentIdx = riskLevels.indexOf(r.riskLevel);
    return currentIdx > worstIdx ? r.riskLevel : worst;
  }, 'minimal' as RiskLevel);
  
  const frameworksPassed = reports.filter(r => r.score >= 80).length;
  const frameworksFailed = reports.filter(r => r.score < 60).length;
  
  return {
    overallScore: avgScore,
    overallRiskLevel: worstRiskLevel,
    frameworksPassed,
    frameworksFailed
  };
}