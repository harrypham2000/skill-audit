import { AuditResult, Finding, FindingCategory } from "./types.js";
import { ComplianceReport } from "./compliance.js";

const LEVEL_ICONS: Record<string, string> = {
  "safe": "✅",
  "risky": "⚠️",
  "dangerous": "🔴",
  "malicious": "☠️",
};

const COMPLIANCE_ICONS: Record<string, string> = {
  "minimal": "✅",
  "limited": "⚠️",
  "high": "🔴",
  "unacceptable": "☠️",
};

const SEVERITY_COLORS: Record<string, string> = {
  "critical": "\x1b[31m",
  "high": "\x1b[33m",
  "medium": "\x1b[35m",
  "low": "\x1b[36m",
  "info": "\x1b[90m",
};

const CATEGORY_COLORS: Record<FindingCategory, string> = {
  "PI": "\x1b[31m",   // Prompt Injection - Red
  "BM": "\x1b[33m",   // Behavioral - Yellow
  "SC": "\x1b[35m",   // Secrets - Magenta
  "CE": "\x1b[31m",   // Code Execution - Red
  "TM": "\x1b[33m",   // Tool Misuse - Yellow
  "PII": "\x1b[36m",  // PII - Cyan (NEW)
  "COMP": "\x1b[34m", // Compliance - Blue (NEW)
  "MC": "\x1b[31m",   // Malicious Content - Red
  "HT": "\x1b[31m",   // Harmful Techniques - Red
  "RA": "\x1b[33m",   // Resource Abuse - Yellow
  "SPEC": "\x1b[90m", // Specification - Gray
  "PROV": "\x1b[33m", // Provenance - Yellow
  "INTEL": "\x1b[90m", // Intelligence - Gray
};

const RESET = "\x1b[0m";

function padEnd(str: string, len: number): string {
  while (str.length < len) str += " ";
  return str;
}

// NEW: Categorize findings by type
function categorizeFindings(findings: Finding[]): {
  security: Finding[];
  pii: Finding[];
  compliance: Finding[];
} {
  return {
    security: findings.filter(f => !['PII', 'COMP'].includes(f.category)),
    pii: findings.filter(f => f.category === 'PII'),
    compliance: findings.filter(f => f.category === 'COMP'),
  };
}

// NEW: Format compliance report
function formatComplianceReport(reports: ComplianceReport[]): string {
  const lines: string[] = [];
  
  for (const report of reports) {
    const icon = COMPLIANCE_ICONS[report.riskLevel] || "❓";
    lines.push(`      ${icon} ${report.framework}: ${report.score}% (${report.passed}/${report.total} passed)`);
  }
  
  return lines.join("\n");
}

export function reportResults(results: AuditResult[], options: any, complianceReports?: Map<string, ComplianceReport[]>): void {
  if (options.json) {
    const output = {
      skills: results,
      compliance: complianceReports ? Object.fromEntries(complianceReports) : undefined,
    };
    console.log(JSON.stringify(output, null, 2));
    return;
  }

  const byAgent = new Map<string, AuditResult[]>();
  for (const result of results) {
    for (const agent of result.skill.agents) {
      if (!byAgent.has(agent)) byAgent.set(agent, []);
      byAgent.get(agent)!.push(result);
    }
  }

  const uniqueSkills = new Map<string, AuditResult>();
  for (const result of results) {
    uniqueSkills.set(result.skill.name, result);
  }

  const uniqueResults = Array.from(uniqueSkills.values());

  console.log("\n🔍 Auditing installed skills...\n");
  console.log("Total: " + uniqueResults.length + " skills scanned");

  const safe = uniqueResults.filter(r => r.riskLevel === "safe").length;
  const risky = uniqueResults.filter(r => r.riskLevel === "risky").length;
  const dangerous = uniqueResults.filter(r => r.riskLevel === "dangerous").length;
  const malicious = uniqueResults.filter(r => r.riskLevel === "malicious").length;

  console.log("✅ Safe: " + safe + " | ⚠️ Risky: " + risky + " | 🔴 Dangerous: " + dangerous + " | ☠️ Malicious: " + malicious + "\n");

  // NEW: Count PII and compliance findings
  const piiFindings = uniqueResults.flatMap(r => r.findings.filter(f => f.category === 'PII'));
  const complianceFindings = uniqueResults.flatMap(r => r.findings.filter(f => f.category === 'COMP'));
  
  if (piiFindings.length > 0) {
    console.log("🔐 PII Findings: " + piiFindings.length + " potential PII exposures detected");
  }
  if (complianceFindings.length > 0) {
    console.log("📋 Compliance Findings: " + complianceFindings.length + " compliance issues detected");
  }
  console.log("");

  for (const [agent, agentResults] of byAgent) {
    const uniqueAgentSkills = new Map<string, AuditResult>();
    for (const r of agentResults) {
      uniqueAgentSkills.set(r.skill.name, r);
    }

    console.log("📂 " + agent + " (" + uniqueAgentSkills.size + " skills)");

    for (const result of uniqueAgentSkills.values()) {
      const icon = LEVEL_ICONS[result.riskLevel];
      const score = result.riskScore.toFixed(1);

      console.log("  " + icon + " " + padEnd(result.skill.name, 40) + " " + score);

      if (options.verbose && result.findings.length > 0) {
        const categorized = categorizeFindings(result.findings);
        
        // Security findings
        if (categorized.security.length > 0) {
          for (const f of categorized.security.slice(0, 3)) {
            const color = SEVERITY_COLORS[f.severity] || "";
            const catColor = CATEGORY_COLORS[f.category] || "";
            console.log("      " + color + f.severity.toUpperCase() + RESET + ": " + catColor + "[" + f.category + "]" + RESET + " " + f.message);
          }
          if (categorized.security.length > 3) {
            console.log("      ... and " + (categorized.security.length - 3) + " more security findings");
          }
        }
        
        // PII findings (NEW)
        if (categorized.pii.length > 0) {
          console.log("      🔐 PII Detection:");
          for (const f of categorized.pii.slice(0, 3)) {
            const color = SEVERITY_COLORS[f.severity] || "";
            console.log("        " + color + f.severity.toUpperCase() + RESET + ": " + f.message);
          }
          if (categorized.pii.length > 3) {
            console.log("        ... and " + (categorized.pii.length - 3) + " more PII findings");
          }
        }
        
        // Compliance findings (NEW)
        if (categorized.compliance.length > 0) {
          console.log("      📋 Compliance:");
          for (const f of categorized.compliance.slice(0, 3)) {
            const color = SEVERITY_COLORS[f.severity] || "";
            console.log("        " + color + f.severity.toUpperCase() + RESET + ": " + f.message);
          }
          if (categorized.compliance.length > 3) {
            console.log("        ... and " + (categorized.compliance.length - 3) + " more compliance issues");
          }
        }
      }
    }
    console.log("");
  }

  // NEW: Show compliance summary if available
  if (complianceReports && complianceReports.size > 0) {
    console.log("📋 Compliance Summary:");
    for (const [skillName, reports] of complianceReports) {
      const avgScore = Math.round(reports.reduce((sum, r) => sum + r.score, 0) / reports.length);
      const worstRisk = reports.reduce((worst, r) => {
        const levels = ['minimal', 'limited', 'high', 'unacceptable'];
        return levels.indexOf(r.riskLevel) > levels.indexOf(worst) ? r.riskLevel : worst;
      }, 'minimal');
      
      const icon = COMPLIANCE_ICONS[worstRisk];
      console.log("  " + icon + " " + padEnd(skillName, 40) + " " + avgScore + "%");
    }
    console.log("");
  }

  if (options.threshold !== undefined) {
    const failed = uniqueResults.filter(r => r.riskScore > options.threshold);
    if (failed.length > 0) {
      console.log("❌ " + failed.length + " skills exceed threshold (" + options.threshold + ")");
      process.exit(1);
    } else {
      console.log("✅ All skills within acceptable risk threshold");
    }
  }
}
