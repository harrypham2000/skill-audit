#!/usr/bin/env node

import { Command } from "commander";
import { discoverSkills } from "./discover.js";
import { auditSecurity, SecurityAuditResult } from "./security.js";
import { validateSkillSpec, SpecValidationResult } from "./spec.js";
import { createGroupedAuditResult } from "./scoring.js";
import { scanDependencies } from "./deps.js";
import { getKEV, getEPSS, getNVD, isCacheStale, downloadOfflineDB } from "./intel.js";
import { installHook, uninstallHook, getHookStatus, getDefaultHookConfig } from "./hooks.js";
import { writeFileSync } from "fs";
import { Finding, GroupedAuditResult } from "./types.js";

// Build CLI - no subcommands, just options + action
const program = new Command();

program
  .name("skill-audit")
  .description("Security auditing CLI for AI agent skills")
  .version("0.3.0")
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
  .option("--source <sources...>", "Sources for update-db: kev, epss, nvd, all", ["all"])
  .option("--strict", "Fail if feeds are stale")
  .option("--quiet", "Suppress non-error output")
  .option("--download-offline-db <dir>", "Download offline vulnerability databases to directory")
  .option("--install-hook", "Install PreToolUse hook for automatic skill auditing")
  .option("--uninstall-hook", "Remove the PreToolUse hook")
  .option("--hook-threshold <score>", "Risk threshold for hook (default: 3.0)", parseFloat)
  .option("--hook-status", "Show current hook status")
  .option("--block", "Exit with code 1 if threshold exceeded (for hooks)");

program.parse(process.argv);

const options = program.opts();

// Handle download-offline-db action
if (options.downloadOfflineDb) {
  await downloadOfflineDB(options.downloadOfflineDb);
  process.exit(0);
}

// Handle update-db action
if (options.updateDb) {
  await updateAdvisoryDB({ source: options.source, strict: options.strict });
  process.exit(0);
}

// Handle hook-status action
if (options.hookStatus) {
  const status = getHookStatus();
  console.log("\n🪝 skill-audit Hook Status\n");
  console.log(`   Installed: ${status.installed ? "✅ Yes" : "❌ No"}`);
  if (status.installed && status.config) {
    console.log(`   Threshold: ${status.config.threshold}`);
    console.log(`   Block on failure: ${status.config.blockOnFailure ? "Yes" : "No"}`);
  }
  console.log(`   Settings file: ${status.settingsPath}\n`);
  process.exit(0);
}

// Handle install-hook action
if (options.installHook) {
  const config = getDefaultHookConfig();
  if (options.hookThreshold) {
    config.threshold = options.hookThreshold;
  }
  config.blockOnFailure = true;

  console.log("\n🪝 Installing skill-audit hook...\n");
  const result = installHook(config);
  
  if (result.success) {
    console.log(`✅ ${result.message}`);
    console.log(`   Settings file: ${getHookStatus().settingsPath}`);
    console.log("\n   Skills will now be audited before installation.");
    console.log("   Run 'skill-audit --uninstall-hook' to remove.\n");
  } else {
    console.error(`❌ ${result.message}`);
    process.exit(1);
  }
  process.exit(0);
}

// Handle uninstall-hook action
if (options.uninstallHook) {
  console.log("\n🪝 Removing skill-audit hook...\n");
  const result = uninstallHook();
  
  if (result.success) {
    console.log(`✅ ${result.message}\n`);
  } else {
    console.error(`❌ ${result.message}`);
    process.exit(1);
  }
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
  filteredSkills = skills.filter(s =>
    s.agents.some(a => options.agent.includes(a))
  );
}

if (!options.json) {
  console.log("Found " + filteredSkills.length + " skills\n");
}

const results: GroupedAuditResult[] = [];

for (const skill of filteredSkills) {
  // Step 1: Spec validation (always runs first)
  const specResult: SpecValidationResult = validateSkillSpec(skill.path, skill.name);

  // Step 2: Security audit (full or lite based on mode)
  let securityResult: SecurityAuditResult = { findings: [], unreadableFiles: [] };
  let depFindings: Finding[] = [];

  if (mode === "audit") {
    securityResult = auditSecurity(skill, specResult.manifest);
    
    if (options.deps !== false) {
      depFindings = scanDependencies(skill.path);
    }
  }

  const allSecurityFindings = [...securityResult.findings, ...depFindings];
  
  // NEW: Separate PII and compliance findings
  const piiFindings = allSecurityFindings.filter(f => f.category === 'PII');
  const complianceFindings = allSecurityFindings.filter(f => f.category === 'COMP');
  const otherSecurityFindings = allSecurityFindings.filter(f => !['PII', 'COMP'].includes(f.category));

  const result = createGroupedAuditResult(
    skill,
    specResult.manifest,
    specResult.findings,
    otherSecurityFindings,
    piiFindings,
    complianceFindings,
    []
  );
  results.push(result);
}

reportGroupedResults(results, {
  json: options.json,
  output: options.output,
  verbose: options.verbose,
  threshold: options.threshold,
  mode,
  block: options.block
});

async function updateAdvisoryDB(opts: { source: string[]; strict: boolean }) {
  const sources = opts.source.includes("all") ? ["kev", "epss", "nvd"] : opts.source;
  const quiet = program.opts().quiet;

  if (!quiet) {
    console.log("📥 Updating advisory intelligence feeds...\n");
  }

  let hasErrors = false;

  for (const source of sources) {
    if (!quiet) {
      console.log(`Fetching ${source.toUpperCase()}...`);
    }

    try {
      if (source === "kev") {
        const result = await getKEV();
        if (!quiet) {
          console.log(`   ✓ CISA KEV: ${result.findings.length} vulnerabilities cached (stale: ${result.stale})`);
        }
      } else if (source === "epss") {
        const result = await getEPSS();
        if (!quiet) {
          console.log(`   ✓ EPSS: ${result.findings.length} scores cached (stale: ${result.stale})`);
        }
      } else if (source === "nvd") {
        const result = await getNVD();
        if (!quiet) {
          console.log(`   ✓ NVD: ${result.findings.length} CVEs cached (stale: ${result.stale})`);
        }
      }
    } catch (e) {
      console.error(`   ✗ Failed to fetch ${source}:`, e);
      hasErrors = true;
    }
  }

  if (!quiet) {
    console.log("\n✅ Advisory DB updated");
  }

  if (opts.strict && hasErrors) {
    process.exit(1);
  }
}

interface ReportOptions {
  json: boolean;
  output?: string;
  verbose: boolean;
  threshold?: number;
  mode: string;
  block?: boolean;
}

function reportGroupedResults(results: GroupedAuditResult[], options: ReportOptions): void {
  const { json, output, verbose, threshold, mode, block } = options;

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
    if (r.riskLevel === "safe") safeCount++;
    else if (r.riskLevel === "risky") riskyCount++;
    else if (r.riskLevel === "dangerous") dangerousCount++;
    else maliciousCount++;

    if (r.specFindings.length > 0) specErrors++;
    if (r.securityFindings.length > 0) securityIssues++;
  }

  console.log(`\n📊 Summary (${mode} mode):`);
  console.log(`   Safe: ${safeCount} | Risky: ${riskyCount} | Dangerous: ${dangerousCount} | Malicious: ${maliciousCount}`);
  console.log(`   Skills with spec issues: ${specErrors} | Security issues: ${securityIssues}`);

  // Check cache freshness and warn if stale
  const kevStale = isCacheStale("kev");
  const epssStale = isCacheStale("epss");
  const nvdStale = isCacheStale("nvd");
  if (!options.json && (kevStale.warn || epssStale.warn || nvdStale.warn)) {
    const ages = [];
    if (kevStale.age) ages.push(`${kevStale.age.toFixed(1)} days for KEV`);
    if (epssStale.age) ages.push(`${epssStale.age.toFixed(1)} days for EPSS`);
    if (nvdStale.age) ages.push(`${nvdStale.age.toFixed(1)} days for NVD`);
    console.log(`\n⚠️  Vulnerability DB is stale (${ages.join(", ")})`);
    console.log(`   Run: npx skill-audit --update-db`);
  }

  if (threshold !== undefined) {
    const failing = results.filter(r => r.riskScore > threshold);
    if (failing.length > 0) {
      console.log(`\n❌ ${failing.length} skills exceed threshold ${threshold}`);
      for (const f of failing) {
        console.log(`   - ${f.skill.name}: ${f.riskScore}`);
      }
      // Exit with error code if block flag is set
      if (block) {
        process.exit(1);
      }
    } else {
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