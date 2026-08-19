import { describe, expect, it } from "vitest";
import {
  parseContextContract,
  observeProcessExec,
  evaluatePreflight,
  preflightExitCode,
  violationToFinding,
  hasBroadReads,
} from "./context.js";

describe("parseContextContract schema validation", () => {
  it("parses a valid contract", () => {
    const { contract, errors } = parseContextContract({
      version: 1,
      reads: ["user_goal"],
      requires: ["explicit_user_intent"],
      writes: ["commands_run"],
      confirmation: "on-risk",
    });
    expect(errors).toEqual([]);
    expect(contract?.confirmation).toBe("on-risk");
    expect(contract?.reads).toEqual(["user_goal"]);
  });

  it("treats a missing version as v1", () => {
    const { contract, errors } = parseContextContract({ reads: ["user_goal"] });
    expect(errors).toEqual([]);
    expect(contract?.version).toBeUndefined();
  });

  it("rejects an unsupported version", () => {
    const { errors } = parseContextContract({ version: 2 });
    expect(errors.some(e => e.includes("version"))).toBe(true);
  });

  it("rejects invalid confirmation values", () => {
    const { errors } = parseContextContract({ confirmation: "sometimes" });
    expect(errors.some(e => e.includes("confirmation"))).toBe(true);
  });

  it("rejects non-string-array fields", () => {
    const { errors } = parseContextContract({ reads: "everything", requires: [1, 2] });
    expect(errors.some(e => e.includes("reads"))).toBe(true);
    expect(errors.some(e => e.includes("requires"))).toBe(true);
  });

  it("rejects non-mapping context", () => {
    expect(parseContextContract(["list"]).errors.length).toBeGreaterThan(0);
    expect(parseContextContract("nope").errors.length).toBeGreaterThan(0);
  });

  it("flags overbroad reads", () => {
    const { contract } = parseContextContract({ reads: ["full_conversation"] });
    expect(hasBroadReads(contract!)).toBe(true);
  });
});

describe("observeProcessExec", () => {
  it("detects fenced shell blocks with exact file and line evidence", () => {
    const caps = observeProcessExec([{
      path: "SKILL.md",
      content: "---\nname: x\n---\n\n# Title\n\n```bash\nnpm install something\n```\n",
    }]);
    expect(caps.length).toBe(1);
    expect(caps[0].capability).toBe("process.exec");
    expect(caps[0].file).toBe("SKILL.md");
    expect(caps[0].line).toBe(7);
    expect(caps[0].evidence).toContain("npm install");
  });

  it("detects shebangs and exec calls", () => {
    const caps = observeProcessExec([
      { path: "scripts/run.sh", content: "#!/bin/bash\necho hi\n" },
      { path: "tool.js", content: "const out = execSync('ls');\n" },
    ]);
    expect(caps.some(c => c.file === "scripts/run.sh" && c.line === 1)).toBe(true);
    expect(caps.some(c => c.file === "tool.js" && c.evidence.includes("execSync"))).toBe(true);
  });

  it("ignores plain prose without shell evidence", () => {
    const caps = observeProcessExec([{ path: "SKILL.md", content: "# Docs\n\nJust text.\n" }]);
    expect(caps).toEqual([]);
  });
});

function execCap(file = "SKILL.md", line = 5) {
  return {
    capability: "process.exec" as const,
    level: "observed" as const,
    evidence: "npm install",
    file,
    line,
  };
}

describe("evaluatePreflight", () => {
  it("rejects undeclared shell execution", () => {
    const d = evaluatePreflight({
      allowedTools: undefined,
      capabilities: [execCap()],
    });
    expect(d.outcome).toBe("reject");
    expect(d.violations[0].rule).toBe("exec.undeclared");
    expect(d.violations[0].file).toBe("SKILL.md");
    expect(d.violations[0].line).toBe(5);
  });

  it("allows declared execution without confirmation requirement", () => {
    const d = evaluatePreflight({
      allowedTools: "Bash, Read",
      capabilities: [execCap()],
      contract: { version: 1, confirmation: "never" },
    });
    expect(d.outcome).toBe("allow");
  });

  it("requires confirmation when the contract says always and no approval exists", () => {
    const d = evaluatePreflight({
      allowedTools: "Bash",
      capabilities: [execCap()],
      contract: { version: 1, confirmation: "always" },
      skillName: "my-skill",
      approvals: [],
    });
    expect(d.outcome).toBe("confirmation_required");
    expect(d.violations[0].rule).toBe("confirmation.required");
  });

  it("an approval for this skill satisfies the confirmation requirement", () => {
    const d = evaluatePreflight({
      allowedTools: "Bash",
      capabilities: [execCap()],
      contract: { version: 1, confirmation: "always" },
      skillName: "my-skill",
      approvals: ["MY-SKILL"],
    });
    expect(d.outcome).toBe("allow");
  });

  it("an approval for a different skill does not satisfy confirmation", () => {
    const d = evaluatePreflight({
      allowedTools: "Bash",
      capabilities: [execCap()],
      contract: { version: 1, confirmation: "always" },
      skillName: "my-skill",
      approvals: ["other-skill"],
    });
    expect(d.outcome).toBe("confirmation_required");
  });

  it("on-risk confirmation triggers only with risk findings", () => {
    const base = {
      allowedTools: "Bash",
      capabilities: [execCap()],
      contract: { version: 1 as const, confirmation: "on-risk" as const },
      skillName: "my-skill",
    };
    expect(evaluatePreflight({ ...base, hasRiskFindings: false }).outcome).toBe("allow");
    expect(evaluatePreflight({ ...base, hasRiskFindings: true }).outcome).toBe("confirmation_required");
  });

  it("environment drift changes the decision to indeterminate", () => {
    const d = evaluatePreflight({
      allowedTools: "Bash",
      capabilities: [execCap()],
      contract: { version: 1, confirmation: "never" },
      environmentDrift: true,
    });
    expect(d.outcome).toBe("indeterminate");
    expect(d.violations.some(v => v.rule === "environment.drift")).toBe(true);
  });

  it("undeclared execution wins over other outcomes", () => {
    const d = evaluatePreflight({
      allowedTools: undefined,
      capabilities: [execCap()],
      environmentDrift: true,
    });
    expect(d.outcome).toBe("reject");
  });
});

describe("exit mapping and finding conversion", () => {
  it("maps outcomes onto the 0/1/2 exit contract", () => {
    expect(preflightExitCode("allow")).toBe(0);
    expect(preflightExitCode("confirmation_required")).toBe(1);
    expect(preflightExitCode("reject")).toBe(1);
    expect(preflightExitCode("indeterminate")).toBe(2);
  });

  it("renders violations as findings with evidence and location", () => {
    const f = violationToFinding({
      rule: "exec.undeclared",
      capability: "process.exec",
      message: "undeclared",
      evidence: "npm install",
      file: "SKILL.md",
      line: 9,
    }, "/tmp/SKILL.md");
    expect(f.id).toBe("CTX-PRE-EXEC-UNDECLARED");
    expect(f.severity).toBe("critical");
    expect(f.file).toBe("SKILL.md");
    expect(f.line).toBe(9);
  });
});
