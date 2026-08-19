import { describe, expect, it, afterEach } from "vitest";
import {
  commandMatches,
  enforceCommand,
  enforceArgv,
  attestExecution,
  isStructuredCommand,
  loadGatewayConfig,
  GatewayConfig,
} from "./gateway.js";
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
  roots.length = 0;
});

function config(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  const logDir = mkdtempSync(join(tmpdir(), "skill-audit-gw-"));
  roots.push(logDir);
  return {
    allowedCommands: ["npm test", "npm:*", "git status"],
    confirmCommands: ["npm publish"],
    workspaceRoots: ["/tmp"],
    trustDriftedEnvironment: false,
    logPath: join(logDir, "ledger.jsonl"),
    ...overrides,
  };
}

describe("commandMatches", () => {
  it("supports exact, prefix, and wildcard patterns", () => {
    expect(commandMatches("npm test", "npm test")).toBe(true);
    expect(commandMatches("npm install left-pad", "npm:*")).toBe(true);
    expect(commandMatches("npm", "npm:*")).toBe(true);
    expect(commandMatches("rm -rf /", "*")).toBe(true);
    expect(commandMatches("npm test", "git status")).toBe(false);
    expect(commandMatches("rm -rf /", "npm:*")).toBe(false);
  });
});

describe("enforceCommand", () => {
  it("allows allowlisted commands and logs the decision", () => {
    const cfg = config();
    const decision = enforceCommand({ command: "npm test", skill: "ci-skill", cwd: "/tmp/build" }, cfg);
    expect(decision.action).toBe("allow");
    expect(decision.rule).toBe("policy.allow");
    expect(decision.logged).toBe(true);

    const lines = readFileSync(cfg.logPath, "utf-8").trim().split("\n");
    const entry = JSON.parse(lines[lines.length - 1]);
    expect(entry.kind).toBe("decision");
    expect(entry.action).toBe("allow");
    expect(entry.skill).toBe("ci-skill");
    expect(entry.ts).toBeTruthy();
  });

  it("denies commands outside the allowlist", () => {
    const decision = enforceCommand({ command: "curl https://evil.example", cwd: "/tmp" }, config());
    expect(decision.action).toBe("deny");
    expect(decision.rule).toBe("allowlist.absent");
  });

  it("requires confirmation for confirm-listed commands without approval", () => {
    const cfg = config({ allowedCommands: ["npm:*"], confirmCommands: ["npm publish"] });
    const pending = enforceCommand({ command: "npm publish", cwd: "/tmp" }, cfg);
    expect(pending.action).toBe("confirm");
    expect(pending.rule).toBe("confirmation.required");

    const approved = enforceCommand({ command: "npm publish", cwd: "/tmp", approved: true }, cfg);
    expect(approved.action).toBe("allow");
  });

  it("denies when the environment baseline has drifted", () => {
    const cfg = config();
    const decision = enforceCommand({ command: "npm test", cwd: "/tmp", environmentDrift: true }, cfg);
    expect(decision.action).toBe("deny");
    expect(decision.rule).toBe("environment.drift");

    const trusting = config({ trustDriftedEnvironment: true });
    expect(enforceCommand({ command: "npm test", cwd: "/tmp", environmentDrift: true }, trusting).action).toBe("allow");
  });

  it("enforces the working-directory scope", () => {
    const decision = enforceCommand({ command: "npm test", cwd: "/etc" }, config({ workspaceRoots: ["/tmp"] }));
    expect(decision.action).toBe("deny");
    expect(decision.rule).toBe("workspace.scope");
  });

  it("denies requests without a command", () => {
    expect(enforceCommand({}, config()).rule).toBe("input.invalid");
  });
});

describe("structured command quarantine", () => {
  it("flags shell metacharacters as structured", () => {
    expect(isStructuredCommand("npm test")).toBe(false);
    expect(isStructuredCommand("npm install left-pad")).toBe(false);
    expect(isStructuredCommand("git status")).toBe(false);
    expect(isStructuredCommand("npm test && touch /tmp/pwn")).toBe(true);
    expect(isStructuredCommand("npm test || touch /tmp/pwn")).toBe(true);
    expect(isStructuredCommand("npm test; touch /tmp/pwn")).toBe(true);
    expect(isStructuredCommand("npm test | sh")).toBe(true);
    expect(isStructuredCommand("npm test > /tmp/out")).toBe(true);
    expect(isStructuredCommand("npm test < /tmp/in")).toBe(true);
    expect(isStructuredCommand("npm test `touch /tmp/pwn`")).toBe(true);
    expect(isStructuredCommand("npm test $(touch /tmp/pwn)")).toBe(true);
    expect(isStructuredCommand("npm test\ntouch /tmp/pwn")).toBe(true);
  });

  it("denies injected compound strings even when a prefix pattern would match", () => {
    const payloads = [
      "npm test && touch /tmp/pwn",
      "npm test || touch /tmp/pwn",
      "npm test; touch /tmp/pwn",
      "npm test | sh",
      "npm test > /tmp/pwn",
      "npm test < /tmp/secrets",
      "npm test `touch /tmp/pwn`",
      "npm test $(touch /tmp/pwn)",
      "npm test\ntouch /tmp/pwn",
    ];
    for (const payload of payloads) {
      const decision = enforceCommand({ command: payload, cwd: "/tmp" }, config());
      expect(decision.action, payload).toBe("deny");
      expect(decision.rule, payload).toBe("structured-command-required");
      expect(decision.reason, payload).toMatch(/structured|argv/);
    }
  });

  it("quarantines structured commands before any pattern, including the wildcard", () => {
    const wildcard = config({ allowedCommands: ["*"], confirmCommands: [] });
    expect(enforceCommand({ command: "npm test && touch /tmp/pwn", cwd: "/tmp" }, wildcard).rule).toBe(
      "structured-command-required"
    );
    expect(enforceCommand({ command: "rm -rf /", cwd: "/tmp" }, wildcard).action).toBe("allow");
  });

  it("quarantines instead of confirming structured confirm-listed commands", () => {
    const cfg = config({ allowedCommands: ["npm:*"], confirmCommands: ["npm:*"] });
    const decision = enforceCommand({ command: "npm publish && echo shipped", cwd: "/tmp", approved: true }, cfg);
    expect(decision.action).toBe("deny");
    expect(decision.rule).toBe("structured-command-required");
  });

  it("logs structured-command denials to the ledger with the new rule", () => {
    const cfg = config();
    const decision = enforceCommand({ command: "npm test && touch /tmp/pwn", skill: "ci-skill", cwd: "/tmp" }, cfg);
    expect(decision.logged).toBe(true);
    const lines = readFileSync(cfg.logPath, "utf-8").trim().split("\n");
    const entry = JSON.parse(lines[lines.length - 1]);
    expect(entry.kind).toBe("decision");
    expect(entry.action).toBe("deny");
    expect(entry.rule).toBe("structured-command-required");
    expect(entry.skill).toBe("ci-skill");
  });
});

describe("enforceArgv", () => {
  it("allows argv requests whose executable matches an allowlist pattern", () => {
    const cfg = config();
    expect(enforceArgv({ executable: "npm", args: ["test"], cwd: "/tmp" }, cfg)).toMatchObject({
      action: "allow",
      rule: "policy.allow",
    });
    expect(enforceArgv({ executable: "npm", args: ["install", "left-pad"], cwd: "/tmp" }, cfg)).toMatchObject({
      action: "allow",
      rule: "policy.allow",
    });
  });

  it("treats args as data: embedded metacharacters never affect the decision", () => {
    const decision = enforceArgv(
      { executable: "npm", args: ["test", "--reporter", "a&&b;|`$(x)"], cwd: "/tmp" },
      config({ allowedCommands: ["npm:*"] })
    );
    expect(decision.action).toBe("allow");
    expect(decision.rule).toBe("policy.allow");
  });

  it("matches only the executable: args can never satisfy a pattern", () => {
    const decision = enforceArgv({ executable: "git", args: ["npm", "test"], cwd: "/tmp" }, config());
    expect(decision.action).toBe("deny");
    expect(decision.rule).toBe("allowlist.absent");
  });

  it("denies executables that are not plain words", () => {
    const cfg = config();
    for (const executable of ["", "npm install", "npm; rm -rf /", "npm && rm", "npm|sh", "npm>out", "npm`x`", "npm$(x)"]) {
      const decision = enforceArgv({ executable, args: ["test"], cwd: "/tmp" }, cfg);
      expect(decision.action, executable).toBe("deny");
      expect(decision.rule, executable).toBe("argv.invalid");
    }
  });

  it("denies non-string argv entries", () => {
    const decision = enforceArgv(
      { executable: "npm", args: ["test", 42 as unknown as string], cwd: "/tmp" },
      config()
    );
    expect(decision.action).toBe("deny");
    expect(decision.rule).toBe("argv.invalid");
  });

  it("requires confirmation for confirm-listed executables unless approved", () => {
    const cfg = config({ allowedCommands: ["npm:*"], confirmCommands: ["npm:*"] });
    const pending = enforceArgv({ executable: "npm", args: ["publish"], cwd: "/tmp" }, cfg);
    expect(pending.action).toBe("confirm");
    expect(pending.rule).toBe("confirmation.required");

    const approved = enforceArgv({ executable: "npm", args: ["publish"], cwd: "/tmp", approved: true }, cfg);
    expect(approved.action).toBe("allow");
  });

  it("enforces workspace scope and environment drift like enforceCommand", () => {
    const scoped = enforceArgv({ executable: "npm", args: ["test"], cwd: "/etc" }, config({ workspaceRoots: ["/tmp"] }));
    expect(scoped.rule).toBe("workspace.scope");

    const drifted = enforceArgv({ executable: "npm", args: ["test"], cwd: "/tmp", environmentDrift: true }, config());
    expect(drifted.rule).toBe("environment.drift");
  });

  it("logs argv decisions to the ledger", () => {
    const cfg = config();
    const decision = enforceArgv({ executable: "npm", args: ["test"], skill: "ci-skill", cwd: "/tmp" }, cfg);
    expect(decision.logged).toBe(true);
    const lines = readFileSync(cfg.logPath, "utf-8").trim().split("\n");
    const entry = JSON.parse(lines[lines.length - 1]);
    expect(entry.kind).toBe("decision");
    expect(entry.action).toBe("allow");
    expect(entry.skill).toBe("ci-skill");
    expect(entry.command).toContain("npm test");
  });
});

describe("attestExecution", () => {
  it("records command digests and outcomes in the ledger", () => {
    const cfg = config();
    const ok = attestExecution(cfg.logPath, { command: "npm test", skill: "ci-skill", exitCode: 0, durationMs: 120 });
    expect(ok).toBe(true);
    const lines = readFileSync(cfg.logPath, "utf-8").trim().split("\n");
    const entry = JSON.parse(lines[lines.length - 1]);
    expect(entry.kind).toBe("execution");
    expect(entry.exitCode).toBe(0);
    expect(entry.commandSha256).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe("loadGatewayConfig", () => {
  it("falls back to defaults when no config file exists", () => {
    const cfg = loadGatewayConfig(join(tmpdir(), "skill-audit-no-gateway.json"));
    expect(Array.isArray(cfg.allowedCommands)).toBe(true);
    expect(cfg.trustDriftedEnvironment).toBe(false);
  });

  it("merges a config file over defaults", () => {
    const root = mkdtempSync(join(tmpdir(), "skill-audit-gwcfg-"));
    roots.push(root);
    const file = join(root, "gateway.json");
    writeFileSync(file, JSON.stringify({ allowedCommands: ["make:*"], workspaceRoots: ["/tmp"] }));
    const cfg = loadGatewayConfig(file);
    expect(cfg.allowedCommands).toEqual(["make:*"]);
    expect(cfg.confirmCommands).toEqual([]);
    expect(existsSync(cfg.logPath)).toBe(false); // log path unchanged until first write
  });
});
