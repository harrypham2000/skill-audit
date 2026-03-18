#!/usr/bin/env node
import { Command } from "commander";
import { discoverSkills } from "./discover.js";
import { auditSecurity } from "./security.js";
import { validateSkillSpec } from "./spec.js";
import { createGroupedAuditResult } from "./scoring.js";
import { scanDependencies } from "./deps.js";
import { getKEV, getEPSS } from "./intel.js";
import { writeFileSync } from "fs";
// Build CLI - no subcommands, just options + action
const program = new Command();
program
    .name("skills-audit")
    .description("Security auditing CLI for AI agent skills")
    .version("0.1.0")
    .option("-g, --global", "Audit global skills only (default: true)")
    .option("-p, --project", "Audit project-level skills only")
    .option("-a, --agent <agents...>", "Filter by specific agents")
    .option("-j, --json", "Output as JSON")
    .option("-o, --output <file>", "Save report to file (JSON format)")
    .option("-v, --verbose", "Show detailed findings")
    .option("-t, --threshold <score>", "Fail if risk score exceeds threshold", parseFloat)
    .option("--no-deps", "Skip dependency scanning (faster)")
    .option("--mode <mode>", "Audit mode: 'lint' (spec only) or 'audit' (full)", "audit")
    .option("--update-db", "Update advisory intelligence feeds")
    .option("--source <sources...>", "Sources for update-db: kev, epss, all", ["all"])
    .option("--strict", "Fail if feeds are stale");
program.parse(process.argv);
const options = program.opts();
// Handle update-db action
if (options.updateDb) {
    await updateAdvisoryDB({ source: options.source, strict: options.strict });
    process.exit(0);
}
// Default to global skills
const scope = options.project ? "project" : "global";
const mode = options.mode || "audit";
if (!options.json) {
    console.log(mode === "lint"
        ? "📋 Linting skills (spec validation)..."
        : "🔍 Auditing skills (full security + intelligence)...");
}
const skills = await discoverSkills(scope);
// Filter by agents if specified
let filteredSkills = skills;
if (options.agent && options.agent.length > 0) {
    filteredSkills = skills.filter(s => s.agents.some(a => options.agent.includes(a)));
}
if (!options.json) {
    console.log("Found " + filteredSkills.length + " skills\n");
}
const results = [];
for (const skill of filteredSkills) {
    // Step 1: Spec validation (always runs first)
    const specResult = validateSkillSpec(skill.path, skill.name);
    // Step 2: Security audit (full or lite based on mode)
    let securityResult = { findings: [], unreadableFiles: [] };
    let depFindings = [];
    if (mode === "audit") {
        securityResult = auditSecurity(skill, specResult.manifest);
        if (options.deps !== false) {
            depFindings = scanDependencies(skill.path);
        }
    }
    const allSecurityFindings = [...securityResult.findings, ...depFindings];
    const result = createGroupedAuditResult(skill, specResult.manifest, specResult.findings, allSecurityFindings, []);
    results.push(result);
}
reportGroupedResults(results, {
    json: options.json,
    output: options.output,
    verbose: options.verbose,
    threshold: options.threshold,
    mode
});
async function updateAdvisoryDB(opts) {
    const sources = opts.source.includes("all") ? ["kev", "epss"] : opts.source;
    console.log("📥 Updating advisory intelligence feeds...\n");
    for (const source of sources) {
        console.log(`Fetching ${source.toUpperCase()}...`);
        try {
            if (source === "kev") {
                const result = await getKEV();
                console.log(`   ✓ CISA KEV: ${result.findings.length} vulnerabilities cached (stale: ${result.stale})`);
            }
            else if (source === "epss") {
                const result = await getEPSS();
                console.log(`   ✓ EPSS: ${result.findings.length} scores cached (stale: ${result.stale})`);
            }
        }
        catch (e) {
            console.error(`   ✗ Failed to fetch ${source}:`, e);
        }
    }
    console.log("\n✅ Advisory DB updated");
}
function reportGroupedResults(results, options) {
    const { json, output, verbose, threshold, mode } = options;
    // Export to file if specified
    if (output) {
        const report = {
            generated: new Date().toISOString(),
            mode,
            summary: {
                total: results.length,
                safe: results.filter(r => r.riskLevel === "safe").length,
                risky: results.filter(r => r.riskLevel === "risky").length,
                dangerous: results.filter(r => r.riskLevel === "dangerous").length,
                malicious: results.filter(r => r.riskLevel === "malicious").length,
                specIssues: results.filter(r => r.specFindings.length > 0).length,
                securityIssues: results.filter(r => r.securityFindings.length > 0).length
            },
            results
        };
        writeFileSync(output, JSON.stringify(report, null, 2));
        console.log(`\n📄 Report saved to: ${output}`);
        return;
    }
    if (json) {
        console.log(JSON.stringify(results, null, 2));
        return;
    }
    let safeCount = 0, riskyCount = 0, dangerousCount = 0, maliciousCount = 0;
    let specErrors = 0, securityIssues = 0;
    for (const r of results) {
        if (r.riskLevel === "safe")
            safeCount++;
        else if (r.riskLevel === "risky")
            riskyCount++;
        else if (r.riskLevel === "dangerous")
            dangerousCount++;
        else
            maliciousCount++;
        if (r.specFindings.length > 0)
            specErrors++;
        if (r.securityFindings.length > 0)
            securityIssues++;
    }
    console.log(`\n📊 Summary (${mode} mode):`);
    console.log(`   Safe: ${safeCount} | Risky: ${riskyCount} | Dangerous: ${dangerousCount} | Malicious: ${maliciousCount}`);
    console.log(`   Skills with spec issues: ${specErrors} | Security issues: ${securityIssues}`);
    if (threshold !== undefined) {
        const failing = results.filter(r => r.riskScore > threshold);
        if (failing.length > 0) {
            console.log(`\n❌ ${failing.length} skills exceed threshold ${threshold}`);
            for (const f of failing) {
                console.log(`   - ${f.skill.name}: ${f.riskScore}`);
            }
        }
        else {
            console.log(`\n✅ All skills pass threshold ${threshold}`);
        }
    }
    if (verbose) {
        for (const r of results) {
            console.log(`\n--- ${r.skill.name} ---`);
            if (r.specFindings.length > 0) {
                console.log(`\n📋 Spec Issues (${r.specFindings.length}):`);
                for (const f of r.specFindings) {
                    console.log(`   [${f.severity.toUpperCase()}] ${f.id}: ${f.message}`);
                }
            }
            if (r.securityFindings.length > 0) {
                console.log(`\n🔒 Security Issues (${r.securityFindings.length}):`);
                for (const f of r.securityFindings) {
                    console.log(`   [${f.severity.toUpperCase()}] ${f.id}: ${f.message}`);
                }
            }
        }
    }
}
