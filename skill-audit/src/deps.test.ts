import { describe, expect, it, afterEach } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { enrichDependencyFindings, scanDependenciesDetailed, selectDependencyRoute } from "./deps.js";
import { AdvisoryRecord } from "./intel.js";
import { Finding } from "./types.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots) {
    rmSync(root, { recursive: true, force: true });
  }
  roots.length = 0;
});

function makeSkill(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "skill-audit-deps-"));
  roots.push(root);
  for (const [path, content] of Object.entries(files)) {
    writeFileSync(join(root, path), content);
  }
  return root;
}

function vulnFinding(id: string, severity: Finding["severity"] = "medium"): Finding {
  return {
    id,
    category: "SC",
    asi: "ASI04",
    severity,
    file: "package-lock.json",
    message: "[Trivy] Dependency vulnerability in foo: bar",
    evidence: id.replace("VULN-", ""),
  };
}

function advisory(id: string, aliases: string[] = [], extra: Partial<AdvisoryRecord> = {}): AdvisoryRecord {
  return { id, aliases, source: "KEV", references: [], ...extra };
}

describe("enrichDependencyFindings", () => {
  it("marks KEV-listed advisories as known-exploited and escalates severity", () => {
    const kev = [advisory("GHSA-aaaa-bbbb-cccc", ["CVE-2026-1234"], { cwe: ["CWE-502"] })];
    const out = enrichDependencyFindings([vulnFinding("VULN-GHSA-aaaa-bbbb-cccc", "medium")], kev, []);
    expect(out[0].severity).toBe("high");
    expect(out[0].confidence).toBe("high");
    expect(out[0].cwe).toBe("CWE-502");
    expect(out[0].message).toContain("KEV known-exploited");
  });

  it("matches KEV entries through aliases", () => {
    const kev = [advisory("GHSA-xxxx", ["CVE-2026-9999"])];
    const out = enrichDependencyFindings([vulnFinding("VULN-CVE-2026-9999", "low")], kev, []);
    expect(out[0].severity).toBe("high");
    expect(out[0].message).toContain("KEV known-exploited");
  });

  it("does not downgrade critical severity for KEV entries", () => {
    const kev = [advisory("GHSA-crit")];
    const out = enrichDependencyFindings([vulnFinding("VULN-GHSA-crit", "critical")], kev, []);
    expect(out[0].severity).toBe("critical");
  });

  it("appends EPSS scores without changing severity", () => {
    const epss = [advisory("GHSA-epss", [], { source: "EPSS", epss: 0.87 })];
    const out = enrichDependencyFindings([vulnFinding("VULN-GHSA-epss", "medium")], [], epss);
    expect(out[0].severity).toBe("medium");
    expect(out[0].message).toContain("EPSS 0.87");
    expect(out[0].confidence).toBe("medium");
  });

  it("leaves non-VULN and unmatched findings untouched", () => {
    const kev = [advisory("GHSA-other")];
    const f1 = vulnFinding("VULN-GHSA-unmatched");
    const f2: Finding = { ...vulnFinding("SC-001"), id: "SC-001" };
    const out = enrichDependencyFindings([f1, f2], kev, []);
    expect(out[0].message).not.toContain("KEV");
    expect(out[1]).toEqual(f2);
  });
});

describe("selectDependencyRoute (pure, deterministic)", () => {
  it("prefers osv-scanner over trivy and the network route", () => {
    const both = selectDependencyRoute(() => true, false);
    expect(both.route).toBe("osv-scanner");
    expect(both.diagnostic).toBeUndefined();
  });

  it("falls back to trivy with an explicit diagnostic", () => {
    const trivyOnly = selectDependencyRoute((name) => name === "trivy", false);
    expect(trivyOnly.route).toBe("trivy");
    expect(trivyOnly.diagnostic?.message).toContain("using trivy");
  });

  it("uses the OSV API route only with network consent", () => {
    expect(selectDependencyRoute(() => false, false).route).toBe("none");
    expect(selectDependencyRoute(() => false, true).route).toBe("osv-api");
  });
});

describe("scanDependenciesDetailed with no real scanners", () => {
  it("records route none offline and never emits findings", () => {
    const dir = makeSkill({ "package.json": "{}" });
    const result = scanDependenciesDetailed(dir, { scannerAvailable: () => false });
    expect(result.route).toBe("none");
    expect(result.findings).toEqual([]);
    expect(result.diagnostics.some(d => d.message.includes("no local vulnerability scanner"))).toBe(true);
  });

  it("uses the OSV API route only when network is allowed", () => {
    const dir = makeSkill({ "package.json": "{}" });
    const offline = scanDependenciesDetailed(dir, { scannerAvailable: () => false });
    expect(offline.route).toBe("none");
    expect(offline.findings).toEqual([]);
    expect(offline.diagnostics.some(d => d.message.includes("no local vulnerability scanner"))).toBe(true);

    const online = scanDependenciesDetailed(dir, {
      scannerAvailable: () => false,
      allowNetwork: true,
    });
    expect(online.route).toBe("osv-api");
  });

  it("emits no error-findings when the path does not exist", () => {
    const result = scanDependenciesDetailed(join(tmpdir(), "skill-audit-no-such-path"));
    expect(result.route).toBe("none");
    expect(result.findings).toEqual([]);
    expect(result.diagnostics.length).toBeGreaterThan(0);
  });
});
