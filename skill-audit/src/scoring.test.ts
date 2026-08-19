import { describe, expect, it } from "vitest";
import { createGroupedAuditResult } from "./scoring.js";
import { Finding, SkillInfo } from "./types.js";

const skill: SkillInfo = { name: "t", path: "/tmp/t", scope: "global", agents: ["claude"] };

function compFinding(): Finding {
  return {
    id: "COMP-001",
    category: "COMP",
    asi: "ASI03",
    severity: "medium",
    file: "/tmp/t/SKILL.md",
    message: "checklist gap",
  };
}

describe("createGroupedAuditResult compliance honesty", () => {
  it("does not emit a compliance score when checks did not run", () => {
    const result = createGroupedAuditResult(skill, undefined, [], [], [], [], []);
    expect(result.complianceScore).toBeUndefined();
    expect(result.complianceRiskLevel).toBeUndefined();
    expect(result.complianceStatus).toBe("not_run");
  });

  it("does not emit a perfect score from COMP findings when checks did not run", () => {
    const result = createGroupedAuditResult(skill, undefined, [], [], [], [compFinding()], []);
    expect(result.complianceScore).toBeUndefined();
    expect(result.complianceStatus).toBe("not_run");
  });

  it("computes a score only when compliance checks ran", () => {
    const result = createGroupedAuditResult(skill, undefined, [], [], [], [compFinding(), compFinding()], [], {
      complianceChecksRan: true,
    });
    expect(result.complianceScore).toBe(80);
    expect(result.complianceRiskLevel).toBe("minimal");
    expect(result.complianceStatus).toBe("experimental");
  });

  it("reports 100 only when checks ran and nothing failed", () => {
    const result = createGroupedAuditResult(skill, undefined, [], [], [], [], [], {
      complianceChecksRan: true,
    });
    expect(result.complianceScore).toBe(100);
    expect(result.complianceStatus).toBe("experimental");
  });
});
