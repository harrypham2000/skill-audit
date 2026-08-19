/**
 * Typed context contracts and capability comparison (Phase 3).
 *
 * Trust levels keep evidence sources separate:
 * - declared:    what the skill's frontmatter contract says
 * - observed:    what static analysis of the implementation finds
 * - invocation:  facts about this invocation (approvals, user intent)
 * - environment: state of the agent execution environment (drift)
 *
 * The first observed capability is process.exec. Comparison of declared vs
 * observed produces a preflight decision: allow, confirmation_required,
 * reject, or indeterminate.
 */
import { Finding, SourceLocation } from "./types.js";

// ============================================================
// Versioned context contract schema
// ============================================================

export type ConfirmationBoundary = "never" | "on-risk" | "always";

export interface ContractCapabilityDeclarations {
  /** Allowed network host suffixes, or ["*"] for any host. Absent = none declared. */
  network?: string[];
  /** Allowed MCP server names, or ["*"] for any server. Absent = none declared. */
  mcp?: string[];
}

export interface ContextContractV1 {
  /** Schema version. Absent means 1. */
  version?: 1;
  reads?: string[];
  requires?: string[];
  writes?: string[];
  confirmation?: ConfirmationBoundary;
  /** Capability scope the skill declares for itself. */
  capabilities?: ContractCapabilityDeclarations;
}

export interface ContractParseResult {
  contract?: ContextContractV1;
  /** Schema validation errors; invalid values must fail validation. */
  errors: string[];
}

const CONFIRMATION_VALUES: ReadonlySet<string> = new Set(["never", "on-risk", "always"]);
const BROAD_READ_PATTERN = /full[_ -]?conversation|all[_ -]?context|all[_ -]?files/i;

export function parseContextContract(raw: unknown): ContractParseResult {
  if (raw === undefined || raw === null) return { errors: [] };
  const errors: string[] = [];

  if (typeof raw !== "object" || Array.isArray(raw)) {
    return { errors: ["context must be a mapping"] };
  }
  const obj = raw as Record<string, unknown>;

  if (obj.version !== undefined && obj.version !== 1) {
    errors.push(`context.version must be 1 (got ${JSON.stringify(obj.version)})`);
  }

  const stringArray = (key: string): string[] | undefined => {
    const value = obj[key];
    if (value === undefined) return undefined;
    if (!Array.isArray(value) || value.some(v => typeof v !== "string" || v.trim() === "")) {
      errors.push(`context.${key} must be an array of non-empty strings`);
      return undefined;
    }
    return value as string[];
  };

  const capabilities: ContractCapabilityDeclarations = {};
  if (obj.capabilities !== undefined) {
    if (typeof obj.capabilities !== "object" || obj.capabilities === null || Array.isArray(obj.capabilities)) {
      errors.push("context.capabilities must be a mapping");
    } else {
      const caps = obj.capabilities as Record<string, unknown>;
      for (const key of ["network", "mcp"] as const) {
        if (caps[key] === undefined) continue;
        if (!Array.isArray(caps[key]) || caps[key].some(v => typeof v !== "string" || v.trim() === "")) {
          errors.push(`context.capabilities.${key} must be an array of non-empty strings`);
        } else {
          capabilities[key] = caps[key] as string[];
        }
      }
    }
  }

  const contract: ContextContractV1 = {
    reads: stringArray("reads"),
    requires: stringArray("requires"),
    writes: stringArray("writes"),
  };
  if (capabilities.network !== undefined || capabilities.mcp !== undefined) {
    contract.capabilities = capabilities;
  }

  if (obj.confirmation !== undefined) {
    if (typeof obj.confirmation !== "string" || !CONFIRMATION_VALUES.has(obj.confirmation)) {
      errors.push(`context.confirmation must be one of never, on-risk, always (got ${JSON.stringify(obj.confirmation)})`);
    } else {
      contract.confirmation = obj.confirmation as ConfirmationBoundary;
    }
  }

  if (errors.length > 0) return { errors };
  return { contract, errors: [] };
}

/** True when the contract asks for overbroad session context (CTX-006). */
export function hasBroadReads(contract: ContextContractV1): boolean {
  return (contract.reads ?? []).some(r => BROAD_READ_PATTERN.test(r));
}

// ============================================================
// Observed capabilities: process.exec (static, v1)
// ============================================================

export interface CapabilityFile {
  path: string;
  content?: string;
  executable?: boolean;
}

export type CapabilityKind = "process.exec" | "network.request" | "fs.read" | "fs.write" | "env.read" | "mcp.invoke";

export interface ObservedCapability {
  capability: CapabilityKind;
  /** Trust level of this evidence. */
  level: "observed";
  evidence: string;
  file: string;
  line: number;
  /** For mcp.invoke: statically resolved server/tool scope when determinable. */
  scope?: { server?: string; tool?: string };
  /** Source range when the observer knows it (regex observation is line-only). */
  location?: SourceLocation;
}

const SHEBANG_RE = /^#![^\n]*\b(?:ba|z|da|k)?sh\b/;
const FENCED_BLOCK_RE = /```(?:bash|sh|shell|zsh)\n([^`]*)```/g;
const EXEC_CALL_RE = /\b(?:execSync|execFileSync|spawnSync|child_process\.exec|subprocess\.(?:run|call|check_output)|os\.system)\s*\(/;

/** Regex observation knows only the line: span it with line-only precision. */
function lineOnlyLocation(file: string, line: number, lineText: string): SourceLocation {
  return {
    file,
    startLine: line,
    startColumn: 1,
    endLine: line,
    endColumn: lineText.length + 1,
    precision: "line-only",
  };
}

/** Static observation of shell/process execution in skill files. */
export function observeProcessExec(files: CapabilityFile[]): ObservedCapability[] {
  const capabilities: ObservedCapability[] = [];

  for (const file of files) {
    if (!file.content) continue;

    const lines = file.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (SHEBANG_RE.test(line)) {
        capabilities.push({
          capability: "process.exec",
          level: "observed",
          evidence: line.trim().slice(0, 120),
          file: file.path,
          line: i + 1,
          location: lineOnlyLocation(file.path, i + 1, line),
        });
        break; // one shebang evidence per file
      }
    }

    for (const match of file.content.matchAll(FENCED_BLOCK_RE)) {
      const before = file.content.slice(0, match.index ?? 0);
      const line = before.split("\n").length;
      const firstCommand = match[1].split("\n").find(l => l.trim() !== "")?.trim().slice(0, 120) ?? "";
      if (firstCommand) {
        capabilities.push({
          capability: "process.exec",
          level: "observed",
          evidence: firstCommand,
          file: file.path,
          line,
          // The reported line is the opening fence of the block.
          location: lineOnlyLocation(file.path, line, lines[line - 1] ?? ""),
        });
        // Classify fence commands by word so network use in examples is
        // visible to the preflight comparison.
        const firstWord = firstCommand.split(/\s+/)[0];
        if (/^(curl|wget|nc|ncat|socat|ssh|scp|ftp|telnet)$/.test(firstWord)) {
          capabilities.push({
            capability: "network.request",
            level: "observed",
            evidence: firstCommand,
            file: file.path,
            line,
            location: lineOnlyLocation(file.path, line, lines[line - 1] ?? ""),
          });
        }
      }
    }

    if (EXEC_CALL_RE.test(file.content)) {
      for (let i = 0; i < lines.length; i++) {
        if (EXEC_CALL_RE.test(lines[i])) {
          capabilities.push({
            capability: "process.exec",
            level: "observed",
            evidence: lines[i].trim().slice(0, 120),
            file: file.path,
            line: i + 1,
            location: lineOnlyLocation(file.path, i + 1, lines[i]),
          });
          break;
        }
      }
    }
  }

  return capabilities;
}

/** Declared execution intent: allowedTools naming shell-ish tools. */
export function declaresProcessExec(allowedTools: string | undefined, contract?: ContextContractV1): boolean {
  if (allowedTools && /bash|shell|terminal|run_shell_command|execute|script/i.test(allowedTools)) {
    return true;
  }
  return false;
}

// ============================================================
// Preflight comparison
// ============================================================

export type PreflightOutcome = "allow" | "confirmation_required" | "reject" | "indeterminate";

export interface ContractViolation {
  rule: string;
  capability: string;
  message: string;
  evidence?: string;
  file?: string;
  line?: number;
}

export interface PreflightInput {
  /** Declared contract (parsed, valid). */
  contract?: ContextContractV1;
  /** Declared allowedTools frontmatter. */
  allowedTools?: string;
  /** Statically observed capabilities. */
  capabilities: ObservedCapability[];
  /** Invocation facts: confirmation approvals granted for this skill. */
  approvals?: string[];
  /** Skill identity used to match approvals. */
  skillName?: string;
  /** Environment state: baseline drift detected. */
  environmentDrift?: boolean;
  /** Risk signal for on-risk confirmation: any high/critical finding. */
  hasRiskFindings?: boolean;
}

export interface PreflightDecision {
  outcome: PreflightOutcome;
  reasons: string[];
  violations: ContractViolation[];
}

export function evaluatePreflight(input: PreflightInput): PreflightDecision {
  const violations: ContractViolation[] = [];
  const reasons: string[] = [];
  const approved = (input.approvals ?? []).map(a => a.toLowerCase());
  const skillApproved = input.skillName !== undefined && approved.includes(input.skillName.toLowerCase());

  const execObserved = input.capabilities.filter(c => c.capability === "process.exec");
  const execDeclared = declaresProcessExec(input.allowedTools, input.contract);

  if (execObserved.length > 0 && !execDeclared) {
    violations.push({
      rule: "exec.undeclared",
      capability: "process.exec",
      message: `Shell execution observed in ${execObserved.length} location(s) but not declared in allowedTools`,
      evidence: execObserved[0].evidence,
      file: execObserved[0].file,
      line: execObserved[0].line,
    });
    reasons.push("Undeclared shell execution is a direct reject");
  }

  if (execObserved.length > 0 && execDeclared) {
    const confirmation = input.contract?.confirmation;
    const needsConfirmation =
      confirmation === "always" ||
      (confirmation === "on-risk" && input.hasRiskFindings === true) ||
      (confirmation === "on-risk" && input.environmentDrift === true);
    if (needsConfirmation && !skillApproved) {
      violations.push({
        rule: "confirmation.required",
        capability: "process.exec",
        message: `Contract requires confirmation (${confirmation}) and no approval was recorded for this invocation`,
      });
      reasons.push("Required confirmation cannot pass without approval");
    }
  }

  // ---- Network capability comparison ----
  const netObserved = input.capabilities.filter(c => c.capability === "network.request");
  if (netObserved.length > 0) {
    const declaredHosts = input.contract?.capabilities?.network;
    if (!declaredHosts || declaredHosts.length === 0) {
      violations.push({
        rule: "net.undeclared",
        capability: "network.request",
        message: `Network access observed in ${netObserved.length} location(s) but not declared in context.capabilities.network`,
        evidence: netObserved[0].evidence,
        file: netObserved[0].file,
        line: netObserved[0].line,
      });
      reasons.push("Undeclared network access is a direct reject");
    } else if (!declaredHosts.includes("*")) {
      const hostOf = (evidence: string): string | null =>
        evidence.match(/https?:\/\/([A-Za-z0-9.-]+)/)?.[1] ?? null;
      const outOfScope = netObserved.find(c => {
        const host = hostOf(c.evidence);
        if (!host) return true; // unverifiable destination → out of scope
        return !declaredHosts.some(d => d === "*" || host === d || host.endsWith(`.${d}`));
      });
      if (outOfScope) {
        violations.push({
          rule: "net.out-of-scope",
          capability: "network.request",
          message: "Network destination is outside the declared capability scope",
          evidence: outOfScope.evidence,
          file: outOfScope.file,
          line: outOfScope.line,
        });
        reasons.push("Out-of-scope network destination is a direct reject");
      }
    }
  }

  // ---- MCP capability comparison ----
  const mcpObserved = input.capabilities.filter(c => c.capability === "mcp.invoke");
  if (mcpObserved.length > 0) {
    const declaredServers = input.contract?.capabilities?.mcp;
    if (!declaredServers || declaredServers.length === 0) {
      violations.push({
        rule: "mcp.undeclared",
        capability: "mcp.invoke",
        message: `MCP invocation observed in ${mcpObserved.length} location(s) but not declared in context.capabilities.mcp`,
        evidence: mcpObserved[0].evidence,
        file: mcpObserved[0].file,
        line: mcpObserved[0].line,
      });
      reasons.push("Undeclared MCP invocation is a direct reject");
    } else {
      const outOfScope = mcpObserved.find(c => {
        if (c.scope?.server === undefined) return false; // dynamic handled by the MCP analyzer
        return !declaredServers.some(d => d === "*" || d === c.scope?.server);
      });
      if (outOfScope) {
        violations.push({
          rule: "mcp.out-of-scope",
          capability: "mcp.invoke",
          message: `MCP server "${outOfScope.scope?.server}" is outside the declared capability scope`,
          evidence: outOfScope.evidence,
          file: outOfScope.file,
          line: outOfScope.line,
        });
        reasons.push("Out-of-scope MCP server is a direct reject");
      }
    }
  }

  if (input.environmentDrift) {
    violations.push({
      rule: "environment.drift",
      capability: "environment",
      message: "Trusted environment baseline has drifted; preflight cannot trust the execution environment",
    });
    reasons.push("Environment drift changes the preflight decision");
  }

  const capabilityReject = violations.some(v =>
    v.rule === "exec.undeclared" || v.rule === "net.undeclared" ||
    v.rule === "net.out-of-scope" || v.rule === "mcp.undeclared" || v.rule === "mcp.out-of-scope"
  );
  if (capabilityReject) {
    return { outcome: "reject", reasons, violations };
  }
  if (violations.some(v => v.rule === "environment.drift")) {
    return { outcome: "indeterminate", reasons, violations };
  }
  if (violations.some(v => v.rule === "confirmation.required")) {
    return { outcome: "confirmation_required", reasons, violations };
  }
  return { outcome: "allow", reasons: ["No violations between declared contract and observed capabilities"], violations: [] };
}

/** Map preflight outcome to the CLI exit contract. */
export function preflightExitCode(outcome: PreflightOutcome): 0 | 1 | 2 {
  if (outcome === "allow") return 0;
  if (outcome === "indeterminate") return 2;
  return 1;
}

/** Render a preflight violation as a Finding for report integration. */
export function violationToFinding(v: ContractViolation, skillFile: string): Finding {
  const severity = v.rule === "exec.undeclared" ? "critical" : v.rule === "environment.drift" ? "high" : "medium";
  return {
    id: `CTX-PRE-${v.rule.replace(/\./g, "-").toUpperCase()}`,
    category: "ENV",
    asi: v.rule === "environment.drift" ? "ASI09" : "ASI05",
    severity,
    file: v.file ?? skillFile,
    line: v.line,
    message: v.message,
    evidence: v.evidence,
  };
}
