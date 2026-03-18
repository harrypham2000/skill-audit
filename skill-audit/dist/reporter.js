const LEVEL_ICONS = {
    "safe": "✅",
    "risky": "⚠️",
    "dangerous": "🔴",
    "malicious": "☠️",
};
const SEVERITY_COLORS = {
    "critical": "\x1b[31m",
    "high": "\x1b[33m",
    "medium": "\x1b[35m",
    "low": "\x1b[36m",
    "info": "\x1b[90m",
};
const RESET = "\x1b[0m";
function padEnd(str, len) {
    while (str.length < len)
        str += " ";
    return str;
}
export function reportResults(results, options) {
    if (options.json) {
        console.log(JSON.stringify(results, null, 2));
        return;
    }
    const byAgent = new Map();
    for (const result of results) {
        for (const agent of result.skill.agents) {
            if (!byAgent.has(agent))
                byAgent.set(agent, []);
            byAgent.get(agent).push(result);
        }
    }
    const uniqueSkills = new Map();
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
    for (const [agent, agentResults] of byAgent) {
        const uniqueAgentSkills = new Map();
        for (const r of agentResults) {
            uniqueAgentSkills.set(r.skill.name, r);
        }
        console.log("📂 " + agent + " (" + uniqueAgentSkills.size + " skills)");
        for (const result of uniqueAgentSkills.values()) {
            const icon = LEVEL_ICONS[result.riskLevel];
            const score = result.riskScore.toFixed(1);
            console.log("  " + icon + " " + padEnd(result.skill.name, 40) + " " + score);
            if (options.verbose && result.findings.length > 0) {
                for (const f of result.findings.slice(0, 5)) {
                    const color = SEVERITY_COLORS[f.severity] || "";
                    console.log("      " + color + f.severity.toUpperCase() + RESET + ": [" + f.asixx + "] " + f.message);
                }
                if (result.findings.length > 5) {
                    console.log("      ... and " + (result.findings.length - 5) + " more");
                }
            }
        }
        console.log("");
    }
    if (options.threshold !== undefined) {
        const failed = uniqueResults.filter(r => r.riskScore > options.threshold);
        if (failed.length > 0) {
            console.log("❌ " + failed.length + " skills exceed threshold (" + options.threshold + ")");
            process.exit(1);
        }
        else {
            console.log("✅ All skills within acceptable risk threshold");
        }
    }
}
