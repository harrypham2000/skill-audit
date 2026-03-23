import { Finding, SkillInfo, SkillManifest, AuditResult, GroupedAuditResult } from "./types.js";

const SEVERITY_SCORES: Record<string, number> = {
  critical: 5.0,
  high: 3.0,
  medium: 1.5,
  low: 0.5,
  info: 0.1
};

const CATEGORY_WEIGHTS: Record<string, number> = {
  SC: 2.0,
  CE: 1.5,
  PI: 1.2,
  BM: 1.0,
  TM: 1.0,
  PII: 2.5,      // NEW: PII detection - high weight
  COMP: 1.0,     // NEW: Compliance - medium weight
  SPEC: 0.5,    // Spec errors are less severe than security
  PROV: 0.8,    // Provenance issues
  INTEL: 1.0    // Intelligence findings
};

export interface RiskScore {
  total: number;
  breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  categories: Record<string, number>;
  asixx: Record<string, number>;
}

export function calculateRiskScore(findings: Finding[]): RiskScore {
  const breakdown = { critical: 0, high: 0, medium: 0, low: 0 };
  const categories: Record<string, number> = {};
  const asixx: Record<string, number> = {};
  
  for (const finding of findings) {
    const severityScore = SEVERITY_SCORES[finding.severity] || 1.0;
    const categoryWeight = CATEGORY_WEIGHTS[finding.category] || 1.0;
    
    if (finding.severity in breakdown) {
      breakdown[finding.severity as keyof typeof breakdown]++;
    }
    
    categories[finding.category] = (categories[finding.category] || 0) + 1;
    
    if (finding.asixx) {
      asixx[finding.asixx] = (asixx[finding.asixx] || 0) + 1;
    }
  }
  
  let total = 0;
  for (const finding of findings) {
    const severityScore = SEVERITY_SCORES[finding.severity] || 1.0;
    const categoryWeight = CATEGORY_WEIGHTS[finding.category] || 1.0;
    total += severityScore * categoryWeight;
  }
  
  total = Math.min(total, 10.0);
  
  return {
    total: Math.round(total * 10) / 10,
    breakdown,
    categories,
    asixx
  };
}

export function getRiskLevel(score: number): { label: string; icon: string; color: string } {
  if (score === 0) {
    return { label: "Safe", icon: "✅", color: "green" };
  } else if (score <= 3.0) {
    return { label: "Risky", icon: "⚠️", color: "yellow" };
  } else if (score <= 7.0) {
    return { label: "Dangerous", icon: "🔴", color: "red" };
  } else {
    return { label: "Malicious", icon: "☠️", color: "black" };
  }
}

export function getOWASPDescription(asixx: string): string {
  const descriptions: Record<string, string> = {
    ASI01: "Goal Hijacking - Prompt Injection",
    ASI02: "Tool Misuse and Exploitation",
    ASI03: "Planning Strategy Manipulation",
    ASI04: "Supply Chain Vulnerabilities",
    ASI05: "Unexpected Code Execution",
    ASI06: "Agentic Prompt Leakage",
    ASI07: "Insecure Agent Output Handling",
    ASI08: "Insufficient Human Oversight",
    ASI09: "Trust Boundary Violation",
    ASI10: "Agent Model Denial of Service"
  };
  return descriptions[asixx] || asixx;
}

export function createAuditResult(
  skill: SkillInfo,
  manifest: SkillManifest | undefined,
  findings: Finding[],
  depFindings: Finding[]
): AuditResult {
  const allFindings = [...findings, ...depFindings];
  const riskScore = calculateRiskScore(allFindings);
  const riskLevelInfo = getRiskLevel(riskScore.total);
  
  // Map label to enum value
  const riskLevel: "safe" | "risky" | "dangerous" | "malicious" = 
    riskLevelInfo.label === "Safe" ? "safe" :
    riskLevelInfo.label === "Risky" ? "risky" :
    riskLevelInfo.label === "Dangerous" ? "dangerous" : "malicious";
  
  return {
    skill,
    manifest,
    findings: allFindings,
    riskScore: riskScore.total,
    riskLevel
  };
}

/**
 * Create grouped audit result for layered output
 * Spec findings drive the decision to block, security/intel are warnings
 */
export function createGroupedAuditResult(
  skill: SkillInfo,
  manifest: SkillManifest | undefined,
  specFindings: Finding[],
  securityFindings: Finding[],
  piiFindings: Finding[],
  complianceFindings: Finding[],
  intelFindings: Finding[]
): GroupedAuditResult {
  // Spec findings get lower weight - they're blockers but not security-critical
  const specScore = calculateRiskScore(specFindings);
  const securityScore = calculateRiskScore(securityFindings);
  const piiScore = calculateRiskScore(piiFindings);
  const complianceScore = calculateRiskScore(complianceFindings);
  const intelScore = calculateRiskScore(intelFindings);

  // Combined score with weights
  const totalScore = specScore.total * 0.2 + securityScore.total * 0.35 + piiScore.total * 0.25 + complianceScore.total * 0.1 + intelScore.total * 0.1;
  const finalScore = Math.min(totalScore, 10.0);
  const riskLevelInfo = getRiskLevel(finalScore);

  const riskLevel: "safe" | "risky" | "dangerous" | "malicious" =
    riskLevelInfo.label === "Safe" ? "safe" :
    riskLevelInfo.label === "Risky" ? "risky" :
    riskLevelInfo.label === "Dangerous" ? "dangerous" : "malicious";

  // Calculate compliance score (percentage)
  const complianceTotal = complianceFindings.length;
  const compliancePassed = complianceTotal === 0 ? 100 : Math.max(0, 100 - complianceTotal * 10);

  return {
    skill,
    manifest,
    specFindings,
    securityFindings,
    piiFindings,
    complianceFindings,
    intelFindings,
    riskScore: Math.round(finalScore * 10) / 10,
    riskLevel,
    complianceScore: compliancePassed,
    complianceRiskLevel: compliancePassed >= 80 ? 'minimal' : compliancePassed >= 60 ? 'limited' : compliancePassed >= 40 ? 'high' : 'unacceptable'
  };
}

/**
 * Check if spec errors should block (critical or high severity)
 */
export function hasBlockingSpecErrors(findings: Finding[]): boolean {
  return findings.some(f => f.severity === "critical" && f.category === "SPEC");
}

/**
 * Check if security findings should block (critical severity)
 */
export function hasBlockingSecurityFindings(findings: Finding[]): boolean {
  return findings.some(f => f.severity === "critical");
}
