/**
 * Feature status reporting.
 *
 * Every feature surfaced in reports must state whether it actually ran and
 * how far its implementation goes. Labels:
 * - stable:               connected to the audit pipeline and deterministic
 * - experimental:         connected, but accuracy or scope is still limited
 * - initial slice:        first working implementation of a planned larger area
 * - partially integrated: implemented but only partly wired into the pipeline
 * - unavailable:          cannot run in this environment (missing tool/provider)
 * - not run:              available but skipped for this run (mode or flag)
 * - planned:              documented but not implemented
 */
export type FeatureState =
  | "stable"
  | "experimental"
  | "initial slice"
  | "partially integrated"
  | "unavailable"
  | "not run"
  | "planned";

export interface FeatureStatus {
  feature: string;
  state: FeatureState;
  detail: string;
}

export interface FeatureStatusOptions {
  /** "scan" | "lint" | "mcp-diff" | other modes */
  mode: string;
  /** false when --no-deps, lint mode, or mcp-diff */
  depsEnabled: boolean;
  /** Environment probe for the semantic provider (injected for tests). */
  semanticProviderConfigured?: boolean;
}

export function getFeatureStatuses(options: FeatureStatusOptions): FeatureStatus[] {
  // Only the canonical scan (and mcp-diff, which reuses it without deps)
  // performs full analysis; every other mode is a subset. States below are
  // defaults — runtime derivation from analyzer outcomes corrects them
  // after each scan.
  const auditMode = options.mode === "scan" || options.mode === "mcp-diff";
  const depsRan = auditMode && options.depsEnabled;

  return [
    {
      feature: "spec-validation",
      state: "stable",
      detail: "Agent Skills frontmatter and structure validation",
    },
    {
      feature: "canonical-scan-kernel",
      state: "stable",
      detail: "Versioned report, inspection ledger, policy decision, 0/1/2 exit contract (--mode scan)",
    },
    {
      feature: "pattern-detection",
      state: auditMode ? "stable" : "not run",
      detail: auditMode
        ? "Regex security patterns (PI, SC, CE, PII, ENV, CTX); regex-only, no AST"
        : "Skipped: not exercised in this mode",
    },
    {
      feature: "dependency-scanning",
      state: depsRan ? "stable" : "not run",
      detail: depsRan
        ? "One authoritative route per run: osv-scanner > trivy > OSV API (only with --network)"
        : "Skipped: not exercised in this mode (--no-deps or non-scan)",
    },
    {
      feature: "environment-doctor",
      state: "stable",
      detail: "Agent hooks, shell startup, PATH, and MCP/tool config inspection (doctor mode)",
    },
    {
      feature: "fingerprints-and-suppressions",
      state: "stable",
      detail: "Governed baselines with reasons, approvers, expirations; automatic reactivation",
    },
    {
      feature: "sarif-output",
      state: "stable",
      detail: "SARIF 2.1.0 with partial fingerprints; decisions agree with JSON",
    },
    {
      feature: "session-context-contracts",
      state: auditMode ? "experimental" : "not run",
      detail: auditMode
        ? "Partial: preflight governs process.exec, network hosts, and MCP servers; fs/env/secrets capabilities remain ungoverned"
        : "Skipped: not exercised in this mode",
    },
    {
      feature: "vulnerability-intel-enrichment",
      state: "experimental",
      detail: "Local KEV/EPSS caches enrich dependency findings when present; refresh with --update-db",
    },
    {
      feature: "structural-analysis",
      state: auditMode ? "initial slice" : "not run",
      detail: auditMode
        ? "First slices: TypeScript/JavaScript AST, shell structural parsing, Python AST (needs python3), intra-file taint paths"
        : "Skipped: not exercised in this mode",
    },
    {
      feature: "mcp-security-analysis",
      state: auditMode ? "partially integrated" : "not run",
      detail: auditMode
        ? "Config checks (poisoning, unpinned refs, wildcards, version diff) fully wired; capability comparison consumes observed mcp.invoke evidence"
        : "Skipped: not exercised in this mode",
    },
    {
      feature: "remote-input",
      state: "initial slice",
      detail: "Local ZIP only (--remote); HTTPS and git acquisition are disabled pending security review (DNS SSRF, archive limits, SSH transport)",
    },
    {
      feature: "compliance-frameworks",
      state: "unavailable",
      detail: "VN AI Law 2026 / EU AI Act / GDPR checklists exist as library code but are not wired into scans",
    },
    {
      feature: "semantic-analysis",
      state: options.semanticProviderConfigured ? "experimental" : "unavailable",
      detail: options.semanticProviderConfigured
        ? "Opt-in LLM intent analysis via the configured provider (--semantic + --network)"
        : "Opt-in, but unavailable: no provider configured (SKILL_AUDIT_SEMANTIC_URL/KEY/MODEL)",
    },
    {
      feature: "policy-decision-adapter",
      state: "initial slice",
      detail: "Gateway mode: process.exec policy decision and attestation adapter. It does not own execution and provides no containment",
    },
  ];
}

import { AnalyzerRun, ScanReport } from "./scan.js";

/**
 * Ground feature status in actual analyzer outcomes from a completed scan
 * instead of only the selected CLI mode. Analyzer-observable features get
 * their state and detail rewritten from the inspection ledger.
 */
export function deriveRuntimeFeatureStates(
  base: FeatureStatus[],
  reports: ScanReport[]
): FeatureStatus[] {
  if (reports.length === 0) return base;

  const runsOf = (analyzer: string): AnalyzerRun[] =>
    reports.flatMap(r => r.analyzerRuns.filter(a => a.analyzer === analyzer));

  const summarize = (analyzer: string): string => {
    const states = runsOf(analyzer).map(a => a.status);
    if (states.length === 0) return "absent";
    const counts = states.reduce<Record<string, number>>((acc, s) => {
      acc[s] = (acc[s] ?? 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts).map(([s, n]) => `${n} ${s}`).join(", ");
  };

  // Outcome-derived state for a feature backed by one analyzer family.
  // Mirrors the kernel's own completeness gating (scan.ts): a skipped
  // analyzer with material in scope is degraded inspection, and a feature
  // whose analyzers were all not_applicable never exercised.
  const deriveFrom = (
    runs: AnalyzerRun[],
    whenRan: FeatureState,
    whenDegraded: FeatureState,
    whenSkipped: FeatureState = "not run"
  ): FeatureState | undefined => {
    if (runs.length === 0) return undefined;
    const states = runs.map(a => a.status);
    if (states.some(s => s === "failed")) return "unavailable";
    if (runs.some(a => a.status === "skipped" && (a.filesInScope ?? 0) > 0)) return "unavailable";
    if (states.some(s => s === "partial")) return whenDegraded;
    if (states.some(s => s === "completed")) return whenRan;
    if (states.some(s => s === "skipped")) return whenSkipped;
    // Only not_applicable remains: the feature never exercised.
    return "not run";
  };

  return base.map(f => {
    if (f.feature === "structural-analysis") {
      const runs = [
        ...runsOf("ast-typescript"),
        ...runsOf("shell-structural"),
        ...runsOf("python-ast"),
      ];
      const parts = [
        `ast-typescript (${summarize("ast-typescript")})`,
        `shell-structural (${summarize("shell-structural")})`,
        `python-ast (${summarize("python-ast")})`,
      ].join("; ");
      const state = deriveFrom(runs, "initial slice", "partially integrated", "unavailable");
      if (!state) return f;
      return { ...f, state, detail: `Analyzer outcomes — ${parts}` };
    }
    if (f.feature === "mcp-security-analysis") {
      const state = deriveFrom(runsOf("mcp-config"), "partially integrated", "partially integrated");
      if (!state) return f;
      return { ...f, state, detail: `Analyzer outcomes — ${summarize("mcp-config")}` };
    }
    if (f.feature === "dependency-scanning") {
      // Route errors (scanner present but failing) are an environment
      // failure, not partial integration; route "none" stays "not run".
      const state = deriveFrom(runsOf("dependencies"), "stable", "unavailable");
      if (!state) return f;
      return { ...f, state, detail: `Analyzer outcomes — ${summarize("dependencies")}` };
    }
    if (f.feature === "pattern-detection") {
      const state = deriveFrom(runsOf("security-patterns"), "stable", "partially integrated");
      if (!state) return f;
      return { ...f, state, detail: `Analyzer outcomes — ${summarize("security-patterns")}` };
    }
    if (f.feature === "semantic-analysis") {
      const withSemantic = reports.filter(r => r.semantic);
      if (withSemantic.length === 0) return f;
      const statuses = withSemantic.map(r => r.semantic!.status);
      // Worst run across skills: a failed provider call delivered nothing,
      // so the feature was unavailable for this run regardless of opt-in.
      const state: FeatureState =
        statuses.some(s => s === "requested_unavailable" || s === "degraded") ? "unavailable"
        : statuses.some(s => s === "successful" || s === "partial") ? "experimental"
        : f.state;
      return { ...f, state, detail: `Run status: ${[...new Set(statuses)].join(", ")}` };
    }
    return f;
  });
}
