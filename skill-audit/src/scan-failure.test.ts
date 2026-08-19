import { describe, expect, it, vi, afterEach } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

// Force the spec analyzer to throw so the kernel's failure path is exercised.
vi.mock("./spec.js", () => ({
  validateSkillSpec: () => {
    throw new Error("forced analyzer crash");
  },
}));

const { scanSkill } = await import("./scan.js");

const roots: string[] = [];

afterEach(() => {
  for (const root of roots) {
    rmSync(root, { recursive: true, force: true });
  }
  roots.length = 0;
});

describe("scanSkill required analyzer failure", () => {
  it("records the analyzer as failed and returns exit 2", () => {
    const root = mkdtempSync(join(tmpdir(), "skill-audit-fail-"));
    roots.push(root);
    const skillDir = join(root, "crash-skill");
    mkdirSync(skillDir, { recursive: true });
    writeFileSync(join(skillDir, "SKILL.md"), "---\nname: crash-skill\ndescription: x\n---\n");

    const report = scanSkill(skillDir, "crash-skill");
    const spec = report.analyzerRuns.find(a => a.analyzer === "spec")!;
    expect(spec.status).toBe("failed");
    expect(report.diagnostics.some(d => d.source === "spec")).toBe(true);
    expect(report.decision.exitCode).toBe(2);
    expect(report.decision.rule).toBe("analyzer.required_failed");
    expect(report.scanStatus).toBe("failed");
  });
});
