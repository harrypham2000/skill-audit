#!/usr/bin/env node

import { Command } from "commander";
import { discoverSkills, getGlobalConfig } from "./discover.js";
import { SecurityAuditResult } from "./security.js";
import { validateSkillSpec, SpecValidationResult } from "./spec.js";
import { createGroupedAuditResult } from "./scoring.js";
import { getKEV, getEPSS, getNVD, isCacheStale, downloadOfflineDB } from "./intel.js";
import { installHook, uninstallHook, getHookStatus, getDefaultHookConfig } from "./hooks.js";
import { assessShellCommand, diffEnvironmentBaseline, getEnvironmentBaselinePath, reportCommandAssessment, reportEnvironmentBaseline, reportEnvironmentDiff, reportEnvironmentDoctor, runEnvironmentDoctor, writeEnvironmentBaseline } from "./environment.js";
import { getFeatureStatuses, deriveRuntimeFeatureStates } from "./features.js";
import { scanSkill, aggregateDecision } from "./scan.js";
import { preflightExitCode } from "./context.js";
import { toSarif } from "./sarif.js";
import { parseMcpConfig, diffMcpConfigs } from "./mcp.js";
import { fetchRemoteSource } from "./remote.js";
import { runSemanticAnalysis, defaultProviderFromEnv, explainSemanticProviderEnv } from "./semantic.js";
import { loadGatewayConfig, enforceCommand, attestExecution } from "./gateway.js";
import { withExtraFindings, decideFindingsPolicy, buildSnapshot, semanticInputFromSnapshot, DEFAULT_SCAN_LIMITS } from "./scan.js";
import type { SkillSnapshot } from "./scan.js";

// Build the canonical snapshot, tolerating invalid input: classification of
// missing/unreadable paths belongs to scanSkill (exit 2), not a crash here.
function tryBuildSnapshot(path: string, limits: Partial<import("./scan.js").ScanLimits>): SkillSnapshot | undefined {
  try {
    return buildSnapshot(path, { ...DEFAULT_SCAN_LIMITS, ...limits });
  } catch {
    return undefined;
  }
}
import { readFileSync, writeFileSync, existsSync } from "fs";
import { fileURLToPath } from "url";
import { basename, dirname, join } from "path";
import { Finding, GroupedAuditResult } from "./types.js";

/**
 * Exit AFTER stdout/stderr drain: pipes flush asynchronously, and a bare
 * process.exit truncates large JSON reports mid-write once they exceed the
 * pipe buffer (~64KB). The empty writes queue behind all pending output;
 * their callbacks fire only when everything before them has been flushed.
 */
async function exitFlushed(code: number): Promise<never> {
  await new Promise<void>(resolve => process.stdout.write("", () => resolve()));
  await new Promise<void>(resolve => process.stderr.write("", () => resolve()));
  process.exit(code);
}

function getVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"));
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

// Build CLI - no subcommands, just options + action
const program = new Command();

if (process.argv[2] === "doctor") {
  process.argv.splice(2, 1, "--mode", "doctor");
}
if (process.argv[2] === "diff-env") {
  process.argv.splice(2, 1, "--mode", "diff-env");
}
if (process.argv[2] === "trust" && process.argv[3] === "env") {
  process.argv.splice(2, 2, "--mode", "trust-env");
}

program
  .name("skill-audit")
  .description("Security auditing CLI for AI agent skills")
  .version(getVersion())
  .option("-g, --global", "Audit global skills only (default: true)")
  .option("-p, --project", "Audit project-level skills only")
  .option("-a, --agent <agents...>", "Filter by specific agents")
  .option("-x, --exclude-skill <names...>", "Skills to exclude from audit (by name)")
  .option("-j, --json", "Output as JSON")
  .option("-o, --output <file>", "Save report to file (JSON format)")
  .option("-v, --verbose", "Show detailed findings")
  .option("-t, --threshold <score>", "Fail if risk score exceeds threshold", parseFloat)
  .option("--no-deps", "Skip dependency scanning (faster)")
  .option("--mode <mode>", "Mode: 'scan' (default, canonical), 'lint', 'preflight', 'mcp-diff', 'gateway', 'doctor', 'trust-env', or 'diff-env'", "scan")
  .option("--skill-path <path>", "Scan a single skill directory or SKILL.md (canonical scan mode)")
  .option("--max-files <n>", "Scan limit: maximum files per skill", v => parseInt(v, 10))
  .option("--max-file-bytes <n>", "Scan limit: maximum bytes per file", v => parseInt(v, 10))
  .option("--max-total-bytes <n>", "Scan limit: maximum aggregate bytes per skill", v => parseInt(v, 10))
  .option("--max-depth <n>", "Scan limit: maximum directory depth", v => parseInt(v, 10))
  .option("--scan-timeout <ms>", "Scan limit: wall-clock timeout in milliseconds", v => parseInt(v, 10))
  .option("--update-db", "Update advisory intelligence feeds")
  .option("--source <sources...>", "Sources for update-db: kev, epss, nvd, all", ["all"])
  .option("--strict", "Fail if feeds are stale")
  .option("--quiet", "Suppress non-error output")
  .option("--download-offline-db <dir>", "Download offline vulnerability databases to directory")
  .option("--check-command <command>", "Assess whether a shell command should trigger environment safety checks")
  .option("--install-hook", "Install PreToolUse hook for automatic skill auditing")
  .option("--uninstall-hook", "Remove the PreToolUse hook")
  .option("--hook-threshold <score>", "Risk threshold for hook (default: 3.0)", parseFloat)
  .option("--hook-status", "Show current hook status")
  .option("--block", "Exit with code 1 if threshold exceeded (for hooks)")
  .option("--network", "Allow network operations (OSV API dependency route, background feed refresh)")
  .option("--approve <skills...>", "Record invocation approvals for preflight confirmation checks")
  .option("--no-drift-check", "Skip environment drift check in preflight mode")
  .option("--suppressions <file>", "Governed suppression baseline (JSON v1) for scan mode")
  .option("--sarif <file>", "Write a SARIF 2.1.0 report (scan mode)")
  .option("--baseline-config <file>", "Previous MCP config for version-to-version diff (mcp-diff mode)")
  .option("--remote <source>", "Scan a remote source: local .zip archive (remote HTTPS and git acquisition disabled pending security review)")
  .option("--allow-host <hosts...>", "HTTPS host allowlist for remote artifact downloads")
  .option("--semantic", "Opt in to LLM semantic analysis (requires a provider and --network)")
  .option("--gateway-config <file>", "Gateway config JSON (default ~/.skill-audit/gateway.json)")
  .option("--attest", "Gateway mode: read an execution attestation from stdin instead of a request");

program.parse(process.argv);

const options = program.opts();

// Legacy audit was removed: it bypassed the canonical pipeline.
if (options.mode === "audit") {
  console.error("❌ --mode audit was removed: it bypassed the canonical scan pipeline. Use the default scan mode (or --mode lint for spec-only checks).");
  process.exit(2);
}

// Load global config (~/.skill-audit/config.json) and merge with CLI options
const globalConfig = getGlobalConfig();

// Merge excludeSkills from config with CLI options
const excludeSkillsFromConfig = globalConfig.excludeSkills || [];
const excludeSkillsFromCLI = options.excludeSkill || [];
const allExcludeSkills = [...new Set([...excludeSkillsFromConfig, ...excludeSkillsFromCLI])];

// Handle download-offline-db action
if (options.downloadOfflineDb) {
  await downloadOfflineDB(options.downloadOfflineDb);
  process.exit(0);
}

// Handle hook-friendly shell command assessment
if (options.checkCommand) {
  const assessment = assessShellCommand(options.checkCommand);
  reportCommandAssessment(assessment, {
    json: options.json,
    verbose: options.verbose,
    block: options.block,
    threshold: options.threshold,
  });
  if (options.block && assessment.environment?.drift) {
    process.exit(1);
  }
  if (options.block && options.threshold !== undefined && (assessment.environment?.current.riskScore || 0) > options.threshold) {
    process.exit(1);
  }
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

if (mode === "doctor") {
  const result = runEnvironmentDoctor();
  reportEnvironmentDoctor(result, {
    json: options.json,
    verbose: options.verbose,
    output: options.output,
  });
  if (options.block && options.threshold !== undefined && result.riskScore > options.threshold) {
    process.exit(1);
  }
  process.exit(0);
}

if (mode === "trust-env") {
  const baseline = writeEnvironmentBaseline();
  reportEnvironmentBaseline(baseline, getEnvironmentBaselinePath(), { json: options.json });
  process.exit(0);
}

if (mode === "diff-env") {
  const diff = diffEnvironmentBaseline();
  reportEnvironmentDiff(diff, {
    json: options.json,
    verbose: options.verbose,
    block: options.block,
    threshold: options.threshold,
  });
  if (options.block && diff.drift) {
    process.exit(1);
  }
  if (options.block && options.threshold !== undefined && diff.current.riskScore > options.threshold) {
    process.exit(1);
  }
  process.exit(0);
}

// Runtime enforcement gateway (Phase 9): decision service for tool wrappers.
// Reads one JSON request from stdin, prints the decision, logs it, exits
// 0 allow / 1 deny-or-confirm / 2 invalid input. The gateway never executes
// the command itself — containment belongs to the calling wrapper.
if (mode === "gateway") {
  const config = loadGatewayConfig(options.gatewayConfig);
  let raw = "";
  process.stdin.setEncoding("utf-8");
  for await (const chunk of process.stdin) raw += chunk;

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw);
  } catch {
    console.error("gateway input is not valid JSON");
    process.exit(2);
  }

  if (options.attest) {
    const ok = attestExecution(config.logPath, {
      command: String(parsed.command ?? ""),
      skill: parsed.skill ? String(parsed.skill) : undefined,
      exitCode: Number(parsed.exitCode ?? -1),
      durationMs: Number(parsed.durationMs ?? 0),
    });
    if (!ok) {
      console.error("could not write attestation to the gateway ledger");
      process.exit(2);
    }
    if (options.json) console.log(JSON.stringify({ attested: true, logPath: config.logPath }));
    else console.log(`📝 Attestation recorded in ${config.logPath}`);
    process.exit(0);
  }

  const decision = enforceCommand(
    {
      tool: parsed.tool ? String(parsed.tool) : undefined,
      command: parsed.command ? String(parsed.command) : undefined,
      skill: parsed.skill ? String(parsed.skill) : undefined,
      cwd: parsed.cwd ? String(parsed.cwd) : undefined,
      approved: parsed.approved === true,
      environmentDrift: parsed.environmentDrift === true,
    },
    config
  );

  if (options.json) {
    console.log(JSON.stringify(decision));
  } else {
    const icon = decision.action === "allow" ? "✅" : decision.action === "confirm" ? "⚠️" : "⛔";
    console.log(`${icon} ${decision.action.toUpperCase()} (${decision.rule})`);
    console.log(`   ${decision.reason}`);
    if (!decision.logged) console.log("   ⚠️ decision could not be written to the ledger");
  }
  process.exit(decision.action === "allow" ? 0 : decision.action === "confirm" ? 1 : 1);
}

// MCP version diff: a canonical scan with a previous-config baseline. The
// decision, ledger, suppressions, and exit contract all come from the one
// canonical pipeline — no independent policy.
if (mode === "mcp-diff") {
  if (!options.skillPath || !options.baselineConfig) {
    console.error("mcp-diff mode requires --skill-path <dir> and --baseline-config <previous mcp.json>");
    process.exit(2);
  }
  const name = basename(options.skillPath) === "SKILL.md"
    ? basename(dirname(options.skillPath))
    : basename(options.skillPath);
  const report = scanSkill(options.skillPath, name, {
    deps: false,
    suppressionsPath: options.suppressions,
    mcpBaselinePath: options.baselineConfig,
  });
  const expansion = report.findings.filter(f => f.id === "MCP-008");
  if (options.json) {
    console.log(JSON.stringify({
      features: deriveRuntimeFeatureStates(getFeatureStatuses({ mode, depsEnabled: false }), [report]),
      decision: report.decision,
      mcpExpansion: expansion,
      reports: [report],
    }, null, 2));
  } else {
    console.log(`\n🛰️  MCP diff: ${expansion.length} expansion finding(s)`);
    for (const f of expansion) {
      console.log(`   [${f.severity.toUpperCase()}] ${f.id}: ${f.message}${f.evidence ? ` — ${f.evidence}` : ""}`);
    }
    console.log(`\nDecision: ${report.decision.outcome} (rule ${report.decision.rule}, exit ${report.decision.exitCode})`);
  }
  await exitFlushed(report.decision.exitCode);
}

// Preflight mode (Phase 3): declared contract vs observed capabilities vs
// invocation approvals vs environment drift, for one skill about to be invoked.
if (mode === "preflight") {
  if (!options.skillPath) {
    console.error("preflight mode requires --skill-path <path>");
    process.exit(2);
  }
  const name = basename(options.skillPath) === "SKILL.md"
    ? basename(dirname(options.skillPath))
    : basename(options.skillPath);

  let environmentDrift = false;
  if (options.driftCheck !== false) {
    try {
      environmentDrift = diffEnvironmentBaseline().drift;
    } catch {
      // No trusted baseline yet: no drift fact can be established.
    }
  }

  const report = scanSkill(options.skillPath, name, {
    deps: false,
    approvals: options.approve,
    environmentDrift,
  });
  const pf = report.preflight;
  const pfExit = pf ? preflightExitCode(pf.outcome) : 2;
  const exit = Math.max(report.decision.exitCode, pfExit) as 0 | 1 | 2;

  if (options.json) {
    console.log(JSON.stringify({
      skill: name,
      preflight: pf ?? { outcome: "indeterminate", reasons: ["preflight unavailable"], violations: [] },
      capabilities: report.capabilities,
      findings: report.findings,
      scanStatus: report.scanStatus,
      exitCode: exit,
    }, null, 2));
  } else {
    const icon = exit === 0 ? "✅" : exit === 1 ? "🔴" : "⚠️";
    console.log(`\n${icon} Preflight for ${name}: ${pf?.outcome ?? "indeterminate"} (exit ${exit})`);
    for (const reason of pf?.reasons ?? ["preflight unavailable"]) {
      console.log(`   ${reason}`);
    }
    for (const v of pf?.violations ?? []) {
      const loc = v.file ? ` (${v.file}${v.line !== undefined ? ":" + v.line : ""})` : "";
      console.log(`   · ${v.rule}: ${v.message}${loc}`);
    }
    for (const c of report.capabilities) {
      console.log(`   observed ${c.capability} at ${c.file}:${c.line} — ${c.evidence}`);
    }
  }
  await exitFlushed(exit);
}

// Canonical scan mode (Phase 1 kernel): snapshot → analyzers → policy → report.
// Exit contract: 0 allowed, 1 rejected, 2 invalid input / failed analyzer / insufficient inspection.
if (mode === "scan") {
  const limits: Partial<import("./scan.js").ScanLimits> = {};
  if (options.maxFiles) limits.maxFiles = options.maxFiles;
  if (options.maxFileBytes) limits.maxFileBytes = options.maxFileBytes;
  if (options.maxTotalBytes) limits.maxTotalBytes = options.maxTotalBytes;
  if (options.maxDepth) limits.maxDepth = options.maxDepth;
  if (options.scanTimeout) limits.timeoutMs = options.scanTimeout;

  let reports: import("./scan.js").ScanReport[];
  // The canonical snapshot per report index: built once, shared by scan and
  // semantic analysis so no consumer ever rereads live sources.
  const canonicalSnapshots = new Map<number, SkillSnapshot>();
  let remoteSource: Awaited<ReturnType<typeof fetchRemoteSource>> | undefined;
  if (options.remote) {
    try {
      remoteSource = await fetchRemoteSource(options.remote, { allowHosts: options.allowHost });
      if (!options.quiet && !options.json) {
        console.log(`📥 Fetched ${options.remote} (${remoteSource.origin.kind}) → ${remoteSource.localPath}`);
      }
    } catch (e) {
      console.error(`❌ Remote fetch failed: ${String(e)}`);
      process.exit(2);
    }
  }
  if (remoteSource) {
    const name = remoteSource.origin.kind === "git"
      ? (options.remote!.match(/([\w.-]+)(?:\.git)?\/?$/) ?? [])[1] ?? "remote-skill"
      : "remote-skill";
    try {
      const snap = tryBuildSnapshot(remoteSource.localPath, limits);
      reports = [scanSkill(remoteSource.localPath, name, {
        limits,
        deps: options.deps !== false,
        network: options.network === true,
        threshold: options.threshold,
        suppressionsPath: options.suppressions,
        ...(snap ? { snapshot: snap } : {}),
        remoteProvenance: {
          kind: remoteSource.origin.kind,
          source: remoteSource.origin.source,
          digest: remoteSource.digest,
        },
      })];
      if (snap) canonicalSnapshots.set(0, snap);
    } finally {
      remoteSource.cleanup();
    }
  } else if (options.skillPath) {
    const name = basename(options.skillPath) === "SKILL.md"
      ? basename(dirname(options.skillPath))
      : basename(options.skillPath);
    const snap = tryBuildSnapshot(options.skillPath, limits);
    reports = [scanSkill(options.skillPath, name, {
      limits,
      deps: options.deps !== false,
      network: options.network === true,
      threshold: options.threshold,
      suppressionsPath: options.suppressions,
      ...(snap ? { snapshot: snap } : {}),
    })];
    if (snap) canonicalSnapshots.set(0, snap);
  } else {
    const skills = await discoverSkills(scope);
    const filtered = (options.agent && options.agent.length > 0
      ? skills.filter(s => s.agents.some(a => options.agent.includes(a)))
      : skills
    ).filter(s => !allExcludeSkills.includes(s.name));
    const scanned: import("./scan.js").ScanReport[] = [];
    for (const s of filtered) {
      const snap = tryBuildSnapshot(s.path, limits);
      scanned.push(scanSkill(s.path, s.name, {
        limits,
        deps: options.deps !== false,
        network: options.network === true,
        threshold: options.threshold,
        suppressionsPath: options.suppressions,
        ...(snap ? { snapshot: snap } : {}),
      }));
      if (snap) canonicalSnapshots.set(scanned.length - 1, snap);
    }
    reports = scanned;
  }

  // Opt-in semantic analysis (Phase 8): provider from env, egress needs --network.
  if (options.semantic) {
    if (!options.network) {
      console.error("❌ --semantic requires --network (skill content would egress to the provider)");
      process.exit(2);
    }
    const provider = defaultProviderFromEnv();
    // Policy rejections (host/model allowlists) surface as an explicit
    // reason instead of a silent "not configured".
    const providerUnavailableReason = explainSemanticProviderEnv() ?? undefined;
    for (let i = 0; i < reports.length; i++) {
      const report = reports[i];
      // Semantic input comes from THE canonical snapshot object of this scan —
      // never a second snapshot, never a live reread.
      const snapshot = canonicalSnapshots.get(i);
      const source = snapshot
        ? semanticInputFromSnapshot(snapshot, report.input.skill)
        : {
            skillName: report.input.skill, content: "", declaredPurpose: "",
            snapshotDigest: "", skillMdDigest: "",
            error: "canonical snapshot unavailable for semantic analysis",
          };
      const semanticStart = Date.now();
      let result: Awaited<ReturnType<typeof runSemanticAnalysis>>;
      if (source.error) {
        result = {
          requested: true, available: true, status: "degraded", promptVersion: "sem-v1",
          provider: provider?.name, model: provider?.model, findings: [],
          detail: source.error,
        };
      } else {
        result = await runSemanticAnalysis({
          optIn: true,
          skillName: report.input.skill,
          content: source.content,
          declaredPurpose: source.declaredPurpose,
          observedCapabilities: [...new Set(report.capabilities.map(c => c.capability))],
          provider,
        });
      }
      const semanticDuration = Date.now() - semanticStart;
      reports[i] = withExtraFindings(report, result.findings, "semantic", {
        suppressionsPath: options.suppressions,
        durationMs: semanticDuration,
        sourceDigest: source.skillMdDigest || report.input.snapshotDigest,
        // The ledger must not claim a completed run when the provider failed.
        analyzerStatus: result.status === "successful" ? "completed"
          : result.status === "partial" ? "partial"
          : result.status === "degraded" ? "failed"
          : "skipped",
        analyzerDetail: result.detail,
      });
      reports[i].semantic = {
        requested: result.requested,
        available: result.available,
        status: result.status,
        provider: result.provider,
        model: result.model,
        promptVersion: result.promptVersion,
        disclosure: result.disclosure,
        detail: result.detail,
      };
    }
  }

  const decision = aggregateDecision(reports);
  const featureStatuses = deriveRuntimeFeatureStates(
    getFeatureStatuses({
      mode,
      depsEnabled: options.deps !== false,
      semanticProviderConfigured: options.semantic === true,
    }),
    reports
  );

  if (options.output) {
    writeFileSync(options.output, JSON.stringify({
      generated: new Date().toISOString(),
      mode: "scan",
      schemaVersion: "1",
      features: featureStatuses,
      decision,
      reports,
    }, null, 2));
    if (!options.quiet && !options.json) console.log(`\n📄 Report saved to: ${options.output}`);
  } else if (options.json) {
    console.log(JSON.stringify({
      features: featureStatuses,
      decision,
      reports,
    }, null, 2));
  } else if (!options.quiet) {
    for (const r of reports) {
      const icon = r.decision.exitCode === 0 ? "✅" : r.decision.exitCode === 1 ? "🔴" : "⚠️";
      const suppressedNote = r.suppressedCount > 0 ? `, ${r.suppressedCount} suppressed` : "";
      console.log(`${icon} ${r.input.skill} — ${r.scanStatus}, ${r.findings.length} finding(s)${suppressedNote}, score ${r.riskScore}`);
      if (options.verbose) {
        for (const f of r.findings) {
          const flag = f.suppressed ? " [SUPPRESSED]" : "";
          console.log(`   [${f.severity.toUpperCase()}] ${f.id}: ${f.message} (${f.file})${flag}`);
        }
        for (const a of r.analyzerRuns) {
          console.log(`   · analyzer ${a.analyzer}: ${a.status}`);
        }
        for (const d of r.diagnostics) {
          console.log(`   · diagnostic ${d.source}: ${d.message}`);
        }
      }
    }
    console.log(`\nDecision: ${decision.outcome} (rule ${decision.rule}, exit ${decision.exitCode})`);
    console.log(`   ${decision.reason}`);
  }

  if (options.sarif) {
    writeFileSync(options.sarif, JSON.stringify(toSarif(reports), null, 2));
    if (!options.quiet && !options.json && !options.output) console.log(`\n📄 SARIF report saved to: ${options.sarif}`);
  }

  await exitFlushed(decision.exitCode);
}

// Background feed refresh is opt-in network I/O (Phase 2: explicit network operations)
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

// Filter by excluded skills (from config + CLI)
if (allExcludeSkills.length > 0) {
  filteredSkills = filteredSkills.filter(s =>
    !allExcludeSkills.includes(s.name)
  );
}

if (!options.json) {
  console.log("Found " + filteredSkills.length + " skills\n");
}

const results: GroupedAuditResult[] = [];

for (const skill of filteredSkills) {
  // Step 1: Spec validation (always runs first)
  const specResult: SpecValidationResult = validateSkillSpec(skill.path, skill.name);

  // Step 2: lint mode runs spec validation only; full analysis lives in the
  // canonical scan pipeline (src/scan.ts).
  const securityResult: SecurityAuditResult = { findings: [], unreadableFiles: [] };
  const depFindings: Finding[] = [];

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

const lintPolicy = reportGroupedResults(results, {
  json: options.json,
  output: options.output,
  verbose: options.verbose,
  threshold: options.threshold,
  mode,
  features: getFeatureStatuses({ mode, depsEnabled: options.deps !== false }),
});
// One policy decision, independent of renderer: --block exits on the shared
// severity gate whether output went to terminal, JSON, or a file.
if (options.block && lintPolicy.exitCode === 1) {
  console.error(`❌ ${lintPolicy.reason}`);
  await exitFlushed(1);
}

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
  features?: import("./features.js").FeatureStatus[];
}

function reportGroupedResults(results: GroupedAuditResult[], options: ReportOptions): import("./scan.js").PolicyDecision {
  const { json, output, verbose, threshold, mode, features } = options;

  // The shared severity policy (not the score) decides the exit; the renderer
  // only reports it, so every output format produces the same exit behavior.
  const policyFindings = results.flatMap(r => [...r.specFindings, ...r.securityFindings, ...r.piiFindings, ...r.complianceFindings, ...r.intelFindings]);
  const policy = decideFindingsPolicy(policyFindings);

  // Export to file if specified
  if (output) {
    const report = {
      generated: new Date().toISOString(),
      mode,
      features: features ?? [],
      decision: policy,
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
    return policy;
  }

  if (json) {
    console.log(JSON.stringify({ features: features ?? [], results, decision: policy }, null, 2));
    return policy;
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
  // Renderer parity: the terminal carries the same decision the JSON and
  // file renderers do, so gate behavior never depends on output format.
  console.log(`\nDecision: ${policy.outcome} (rule ${policy.rule}, exit ${policy.exitCode})`);

  if (features && features.length > 0) {
    console.log(`\n🧭 Feature status:`);
    for (const f of features) {
      console.log(`   ${f.state.padEnd(21)} ${f.feature}${f.state === "stable" ? "" : ` — ${f.detail}`}`);
    }
  }

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
    } else {
      console.log(`\n✅ All skills pass threshold ${threshold}`);
    }
    console.log(`   (advisory: scores prioritize; the blocking decision uses the shared severity policy)`);
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
  return policy;
}
