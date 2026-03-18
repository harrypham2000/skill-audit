const SEVERITY_SCORES = {
    critical: 5.0,
    high: 3.0,
    medium: 1.5,
    low: 0.5,
    info: 0.1
};
const CATEGORY_WEIGHTS = {
    SC: 2.0,
    CE: 1.5,
    PI: 1.2,
    BM: 1.0,
    TM: 1.0,
    SPEC: 0.5, // Spec errors are less severe than security
    PROV: 0.8, // Provenance issues
    INTEL: 1.0 // Intelligence findings
};
export function calculateRiskScore(findings) {
    const breakdown = { critical: 0, high: 0, medium: 0, low: 0 };
    const categories = {};
    const asixx = {};
    for (const finding of findings) {
        const severityScore = SEVERITY_SCORES[finding.severity] || 1.0;
        const categoryWeight = CATEGORY_WEIGHTS[finding.category] || 1.0;
        if (finding.severity in breakdown) {
            breakdown[finding.severity]++;
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
export function getRiskLevel(score) {
    if (score === 0) {
        return { label: "Safe", icon: "✅", color: "green" };
    }
    else if (score <= 3.0) {
        return { label: "Risky", icon: "⚠️", color: "yellow" };
    }
    else if (score <= 7.0) {
        return { label: "Dangerous", icon: "🔴", color: "red" };
    }
    else {
        return { label: "Malicious", icon: "☠️", color: "black" };
    }
}
export function getOWASPDescription(asixx) {
    const descriptions = {
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
export function createAuditResult(skill, manifest, findings, depFindings) {
    const allFindings = [...findings, ...depFindings];
    const riskScore = calculateRiskScore(allFindings);
    const riskLevelInfo = getRiskLevel(riskScore.total);
    // Map label to enum value
    const riskLevel = riskLevelInfo.label === "Safe" ? "safe" :
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
export function createGroupedAuditResult(skill, manifest, specFindings, securityFindings, intelFindings) {
    // Spec findings get lower weight - they're blockers but not security-critical
    const specScore = calculateRiskScore(specFindings);
    const securityScore = calculateRiskScore(securityFindings);
    const intelScore = calculateRiskScore(intelFindings);
    // Combined score with weights
    const totalScore = specScore.total * 0.3 + securityScore.total * 0.5 + intelScore.total * 0.2;
    const finalScore = Math.min(totalScore, 10.0);
    const riskLevelInfo = getRiskLevel(finalScore);
    const riskLevel = riskLevelInfo.label === "Safe" ? "safe" :
        riskLevelInfo.label === "Risky" ? "risky" :
            riskLevelInfo.label === "Dangerous" ? "dangerous" : "malicious";
    return {
        skill,
        manifest,
        specFindings,
        securityFindings,
        intelFindings,
        riskScore: Math.round(finalScore * 10) / 10,
        riskLevel
    };
}
/**
 * Check if spec errors should block (critical or high severity)
 */
export function hasBlockingSpecErrors(findings) {
    return findings.some(f => f.severity === "critical" && f.category === "SPEC");
}
/**
 * Check if security findings should block (critical severity)
 */
export function hasBlockingSecurityFindings(findings) {
    return findings.some(f => f.severity === "critical");
}
