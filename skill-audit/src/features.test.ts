import { describe, expect, it } from "vitest";
import { getFeatureStatuses, deriveRuntimeFeatureStates } from "./features.js";

function stateOf(feature: string, mode: string, depsEnabled: boolean): string | undefined {
  return getFeatureStatuses({ mode, depsEnabled })
    .find(f => f.feature === feature)?.state;
}

describe("getFeatureStatuses", () => {
  it("marks vulnerability intel enrichment as experimental (local caches)", () => {
    expect(stateOf("vulnerability-intel-enrichment", "audit", true)).toBe("experimental");
  });

  it("marks compliance frameworks as unavailable until wired into scans", () => {
    expect(stateOf("compliance-frameworks", "audit", true)).toBe("unavailable");
  });

  it("marks dependency scanning stable in canonical scan mode", () => {
    expect(stateOf("dependency-scanning", "scan", true)).toBe("stable");
  });

  it("marks dependency scanning not run with --no-deps", () => {
    expect(stateOf("dependency-scanning", "audit", false)).toBe("not run");
  });

  it("marks pattern detection not run in lint mode", () => {
    expect(stateOf("pattern-detection", "lint", true)).toBe("not run");
    expect(stateOf("dependency-scanning", "lint", true)).toBe("not run");
    expect(stateOf("session-context-contracts", "lint", true)).toBe("not run");
  });

  it("marks context contracts experimental in canonical scan mode", () => {
    expect(stateOf("session-context-contracts", "scan", true)).toBe("experimental");
  });

  it("classifies newer features as initial slices or partially integrated, never done", () => {
    expect(stateOf("structural-analysis", "scan", true)).toBe("initial slice");
    expect(stateOf("remote-input", "scan", true)).toBe("initial slice");
    expect(stateOf("mcp-security-analysis", "scan", true)).toBe("partially integrated");
  });

  it("describes the gateway as a decision/attestation adapter without containment", () => {
    const gateway = getFeatureStatuses({ mode: "audit", depsEnabled: true })
      .find(f => f.feature === "policy-decision-adapter")!;
    expect(gateway.state).toBe("initial slice");
    expect(gateway.detail).toContain("does not own execution");
    expect(gateway.detail.toLowerCase()).not.toContain("enforcement");
  });

  it("marks semantic analysis unavailable without a provider, experimental with one", () => {
    expect(getFeatureStatuses({ mode: "audit", depsEnabled: true, semanticProviderConfigured: false })
      .find(f => f.feature === "semantic-analysis")!.state).toBe("unavailable");
    expect(getFeatureStatuses({ mode: "audit", depsEnabled: true, semanticProviderConfigured: true })
      .find(f => f.feature === "semantic-analysis")!.state).toBe("experimental");
  });

  it("only uses documented feature states", () => {
    const allowed = new Set(["stable", "experimental", "initial slice", "partially integrated", "unavailable", "not run", "planned"]);
    for (const f of getFeatureStatuses({ mode: "audit", depsEnabled: true })) {
      expect(allowed.has(f.state), `${f.feature}: ${f.state}`).toBe(true);
      expect(f.detail.length).toBeGreaterThan(0);
    }
  });
});

describe("deriveRuntimeFeatureStates", () => {
  const report = (analyzerRuns: Array<{ analyzer: string; status: import("./scan.js").AnalyzerStatus }>) => ({
    schemaVersion: "1" as const,
    scanner: { name: "skill-audit", version: "0" },
    input: { skill: "s", path: "/s", fileCount: 1, totalBytes: 1, snapshotDigest: "d" },
    findings: [],
    capabilities: [],
    analyzerRuns: analyzerRuns.map(a => ({ ...a, findings: 0, durationMs: 0 })),
    diagnostics: [],
    exclusions: [],
    scanStatus: "complete" as const,
    decision: { outcome: "allow" as const, rule: "policy.default", reason: "", exitCode: 0 as const },
    suppressedCount: 0,
    riskScore: 0,
  });

  it("grounds structural analysis state in analyzer outcomes", () => {
    const base = getFeatureStatuses({ mode: "scan", depsEnabled: true });
    const ran = deriveRuntimeFeatureStates(base, [
      report([
        { analyzer: "ast-typescript", status: "completed" },
        { analyzer: "shell-structural", status: "completed" },
        { analyzer: "python-ast", status: "skipped" },
      ]),
    ]);
    const structural = ran.find(f => f.feature === "structural-analysis")!;
    expect(structural.state).toBe("initial slice");
    expect(structural.detail).toContain("python-ast (1 skipped)");

    const unavailable = deriveRuntimeFeatureStates(base, [
      report([
        { analyzer: "ast-typescript", status: "skipped" },
        { analyzer: "shell-structural", status: "skipped" },
        { analyzer: "python-ast", status: "skipped" },
      ]),
    ]);
    expect(unavailable.find(f => f.feature === "structural-analysis")!.state).toBe("unavailable");
  });

  it("marks MCP analysis not run when no config was in scope", () => {
    const base = getFeatureStatuses({ mode: "scan", depsEnabled: true });
    const derived = deriveRuntimeFeatureStates(base, [
      report([{ analyzer: "mcp-config", status: "not_applicable" }]),
    ]);
    expect(derived.find(f => f.feature === "mcp-security-analysis")!.state).toBe("not run");
  });
});

describe("gate 5: outcome-derived feature status", () => {
  const report = (analyzerRuns: Array<{ analyzer: string; status: import("./scan.js").AnalyzerStatus }>) => ({
    schemaVersion: "1" as const,
    scanner: { name: "skill-audit", version: "0" },
    input: { skill: "s", path: "/s", fileCount: 1, totalBytes: 1, snapshotDigest: "d" },
    findings: [],
    capabilities: [],
    analyzerRuns: analyzerRuns.map(a => ({ ...a, findings: 0, durationMs: 0 })),
    diagnostics: [],
    exclusions: [],
    scanStatus: "complete" as const,
    decision: { outcome: "allow" as const, rule: "policy.default", reason: "", exitCode: 0 as const },
    suppressedCount: 0,
    riskScore: 0,
  });

  it("derives dependency scanning state from analyzer outcomes, not flags", () => {
    const base = getFeatureStatuses({ mode: "scan", depsEnabled: true });
    const completed = deriveRuntimeFeatureStates(base, [
      report([{ analyzer: "dependencies", status: "completed" }]),
    ]);
    expect(completed.find(f => f.feature === "dependency-scanning")!.state).toBe("stable");

    const degraded = deriveRuntimeFeatureStates(base, [
      report([{ analyzer: "dependencies", status: "partial" }]),
    ]);
    const depFeature = degraded.find(f => f.feature === "dependency-scanning")!;
    // Route errors (scanner present but failing) are an environment failure.
    expect(depFeature.state).toBe("unavailable");
    expect(depFeature.detail).toContain("1 partial");
  });

  it("remote-input claims local ZIP only with HTTPS/git disabled", () => {
    const remote = getFeatureStatuses({ mode: "scan", depsEnabled: true })
      .find(f => f.feature === "remote-input")!;
    expect(remote.detail).toContain("disabled");
    expect(remote.detail).not.toContain("HTTPS artifact, and git");
  });
});

describe("gates 3+5 (round 2): audit removed, outcome-derived statuses", () => {
  const report = (analyzerRuns: Array<{ analyzer: string; status: import("./scan.js").AnalyzerStatus }>) => ({
    schemaVersion: "1" as const,
    scanner: { name: "skill-audit", version: "0" },
    input: { skill: "s", path: "/s", fileCount: 1, totalBytes: 1, snapshotDigest: "d" },
    findings: [],
    capabilities: [],
    analyzerRuns: analyzerRuns.map(a => ({ ...a, findings: 0, durationMs: 0 })),
    diagnostics: [],
    exclusions: [],
    scanStatus: "complete" as const,
    decision: { outcome: "allow" as const, rule: "policy.default", reason: "", exitCode: 0 as const },
    suppressedCount: 0,
    riskScore: 0,
  });

  it("only the canonical scan marks full-analysis features as run", () => {
    expect(stateOf("pattern-detection", "scan", true)).toBe("stable");
    expect(stateOf("pattern-detection", "lint", true)).toBe("not run");
    expect(stateOf("structural-analysis", "preflight", true)).toBe("not run");
  });

  it("pattern detection derives partial from analyzer outcomes", () => {
    const base = getFeatureStatuses({ mode: "scan", depsEnabled: true });
    const derived = deriveRuntimeFeatureStates(base, [
      report([{ analyzer: "security-patterns", status: "partial" }]),
    ]);
    const pattern = derived.find(f => f.feature === "pattern-detection")!;
    expect(pattern.state).toBe("partially integrated");
    expect(pattern.detail).toContain("1 partial");
  });
});

describe("gate 5 (round 3): failed analyzers surface in feature status", () => {
  const report = (analyzerRuns: Array<{ analyzer: string; status: import("./scan.js").AnalyzerStatus; filesInScope?: number }>) => ({
    schemaVersion: "1" as const,
    scanner: { name: "skill-audit", version: "0" },
    input: { skill: "s", path: "/s", fileCount: 1, totalBytes: 1, snapshotDigest: "d" },
    findings: [],
    capabilities: [],
    analyzerRuns: analyzerRuns.map(a => ({ findings: 0, durationMs: 0, ...a })),
    diagnostics: [],
    exclusions: [],
    scanStatus: "complete" as const,
    decision: { outcome: "allow" as const, rule: "policy.default", reason: "", exitCode: 0 as const },
    suppressedCount: 0,
    riskScore: 0,
    semantic: undefined as undefined | import("./scan.js").ScanReport["semantic"],
  });

  it("a failed analyzer marks its feature unavailable, not stable", () => {
    const base = getFeatureStatuses({ mode: "scan", depsEnabled: true });
    const derived = deriveRuntimeFeatureStates(base, [
      report([
        { analyzer: "security-patterns", status: "failed" },
        { analyzer: "dependencies", status: "failed" },
        { analyzer: "ast-typescript", status: "failed" },
      ]),
    ]);
    expect(derived.find(f => f.feature === "pattern-detection")!.state).toBe("unavailable");
    expect(derived.find(f => f.feature === "dependency-scanning")!.state).toBe("unavailable");
    expect(derived.find(f => f.feature === "structural-analysis")!.state).toBe("unavailable");
  });

  it("skipped with files in scope is unavailable (mirrors the kernel's exit-2 gate)", () => {
    const base = getFeatureStatuses({ mode: "scan", depsEnabled: true });
    const derived = deriveRuntimeFeatureStates(base, [
      report([
        { analyzer: "ast-typescript", status: "completed" },
        { analyzer: "shell-structural", status: "completed" },
        { analyzer: "python-ast", status: "skipped", filesInScope: 3 },
      ]),
    ]);
    expect(derived.find(f => f.feature === "structural-analysis")!.state).toBe("unavailable");
  });

  it("all not_applicable reads as not run, never as ran", () => {
    const base = getFeatureStatuses({ mode: "scan", depsEnabled: true });
    const derived = deriveRuntimeFeatureStates(base, [
      report([
        { analyzer: "ast-typescript", status: "not_applicable" },
        { analyzer: "shell-structural", status: "not_applicable" },
        { analyzer: "python-ast", status: "not_applicable" },
      ]),
    ]);
    const structural = derived.find(f => f.feature === "structural-analysis")!;
    expect(structural.state).toBe("not run");
  });

  it("semantic degraded and requested_unavailable are unavailable, not experimental", () => {
    const base = getFeatureStatuses({ mode: "scan", depsEnabled: true, semanticProviderConfigured: true });
    const degraded = deriveRuntimeFeatureStates(base, [
      report([{ analyzer: "spec", status: "completed" }]),
    ]);
    // attach semantic outcomes directly, as scan reports do
    const withSemantic = (status: string) => [{
      ...report([{ analyzer: "spec", status: "completed" }]),
      semantic: { requested: true, available: true, status, promptVersion: "sem-v1" },
    }];
    expect(deriveRuntimeFeatureStates(base, withSemantic("degraded"))
      .find(f => f.feature === "semantic-analysis")!.state).toBe("unavailable");
    expect(deriveRuntimeFeatureStates(base, withSemantic("requested_unavailable"))
      .find(f => f.feature === "semantic-analysis")!.state).toBe("unavailable");
    expect(deriveRuntimeFeatureStates(base, withSemantic("successful"))
      .find(f => f.feature === "semantic-analysis")!.state).toBe("experimental");
    expect(deriveRuntimeFeatureStates(base, withSemantic("partial"))
      .find(f => f.feature === "semantic-analysis")!.state).toBe("experimental");
    // worst status across multiple skills wins
    expect(deriveRuntimeFeatureStates(base, [
      ...withSemantic("successful"),
      ...withSemantic("degraded"),
    ]).find(f => f.feature === "semantic-analysis")!.state).toBe("unavailable");
    expect(degraded.find(f => f.feature === "semantic-analysis")!.state).toBe("experimental");
  });

  it("mcp-diff mode claims analyzer-backed features from actual outcomes", () => {
    const base = getFeatureStatuses({ mode: "mcp-diff", depsEnabled: false });
    const derived = deriveRuntimeFeatureStates(base, [
      report([{ analyzer: "mcp-config", status: "completed" }]),
    ]);
    expect(derived.find(f => f.feature === "mcp-security-analysis")!.state).toBe("partially integrated");
  });
});
