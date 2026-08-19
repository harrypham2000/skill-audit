/**
 * Runtime contract enforcement gateway (Phase 9, initial slice: process.exec).
 *
 * This is a decision service for an agent tool wrapper/hook: it evaluates a
 * shell-command request against the skill's allowlist, confirmation rules,
 * environment trust, and working-directory scope, logs every decision to an
 * append-only JSONL ledger, and records post-execution attestations.
 *
 * The CLI does not claim containment: it never executes the command itself.
 * Containment belongs to whatever runtime wraps the execution boundary and
 * honors this gateway's decision.
 */
import { appendFileSync, existsSync, readFileSync, mkdirSync } from "fs";
import { dirname, isAbsolute, resolve } from "path";
import { homedir } from "os";
import { createHash } from "crypto";

export interface GatewayConfig {
  /** Allowed commands: exact ("npm test"), prefix ("npm:*"), or "*" (explicit). */
  allowedCommands: string[];
  /** Patterns that additionally require a per-invocation approval. */
  confirmCommands: string[];
  /** Working-directory scope: cwd must fall under one root. */
  workspaceRoots: string[];
  /** When false (default), environment baseline drift denies execution. */
  trustDriftedEnvironment: boolean;
  /** Append-only decision ledger. */
  logPath: string;
}

export function defaultGatewayConfigPath(): string {
  return resolve(homedir(), ".skill-audit", "gateway.json");
}

export function defaultGatewayLogPath(): string {
  return resolve(homedir(), ".skill-audit", "gateway-log.jsonl");
}

export function loadGatewayConfig(path?: string): GatewayConfig {
  const file = path ?? defaultGatewayConfigPath();
  const defaults: GatewayConfig = {
    allowedCommands: [],
    confirmCommands: [],
    workspaceRoots: [process.cwd()],
    trustDriftedEnvironment: false,
    logPath: defaultGatewayLogPath(),
  };
  if (!existsSync(file)) return defaults;
  try {
    const parsed = JSON.parse(readFileSync(file, "utf-8")) as Partial<GatewayConfig>;
    return { ...defaults, ...parsed, logPath: parsed.logPath ?? defaults.logPath };
  } catch {
    return defaults;
  }
}

export interface GatewayRequest {
  tool?: string;
  command?: string;
  skill?: string;
  cwd?: string;
  /** Invocation approval recorded upstream (e.g. user confirmed). */
  approved?: boolean;
  /** Environment baseline drift detected by diff-env. */
  environmentDrift?: boolean;
}

export interface GatewayDecision {
  action: "allow" | "deny" | "confirm";
  rule: string;
  reason: string;
  logged: boolean;
}

/**
 * Match a command against "exact", "prefix:*", or "*" patterns.
 *
 * This is a pure pattern matcher with no shell-safety awareness: a compound
 * string like "npm test && touch /tmp/pwn" still matches "npm:*". Callers
 * must quarantine structured commands first (see isStructuredCommand /
 * enforceCommand) before trusting a match.
 */
export function commandMatches(command: string, pattern: string): boolean {
  const trimmed = command.trim();
  if (pattern === "*") return true;
  if (pattern.endsWith(":*")) {
    const prefix = pattern.slice(0, -2);
    return trimmed === prefix || trimmed.startsWith(`${prefix} `);
  }
  return trimmed === pattern;
}

/**
 * Shell metacharacters that make a raw command string compound or otherwise
 * unsafe to authorize as a single word-spawned command: `&&`, `||`, `;`, `|`,
 * `>`, `<`, backticks, `$(...)`, and line breaks.
 */
const STRUCTURED_SHELL_PATTERN = /&&|\|\||;|\||>|<|`|\$\(|[\r\n]/;

/**
 * True when a raw command string embeds shell metacharacters, i.e. it is a
 * structured (compound/substituted) shell string rather than a single simple
 * command. Prefix and wildcard policies must never authorize these directly.
 */
export function isStructuredCommand(command: string): boolean {
  return STRUCTURED_SHELL_PATTERN.test(command);
}

/** An executable must be a plain word: non-empty, no whitespace, no shell metacharacters. */
const NON_WORD_CHARACTERS = /[\s`"'\\;|&<>()$*?[\]{}~]/;

function isPlainExecutableWord(executable: string): boolean {
  return executable.length > 0 && !NON_WORD_CHARACTERS.test(executable);
}

function withinRoots(cwd: string, roots: string[]): boolean {
  const resolved = resolve(cwd);
  return roots.some(root => {
    const base = resolve(root);
    return resolved === base || resolved.startsWith(base + "/");
  });
}

export interface GatewayLogEntry {
  ts?: string;  // set by appendGatewayLog
  kind: "decision" | "execution";
  action?: string;
  rule?: string;
  skill?: string;
  command?: string;
  cwd?: string;
  reason?: string;
  exitCode?: number;
  durationMs?: number;
  commandSha256?: string;
}

export function appendGatewayLog(logPath: string, entry: GatewayLogEntry): boolean {
  try {
    mkdirSync(dirname(logPath), { recursive: true });
    appendFileSync(logPath, JSON.stringify({ ...entry, ts: new Date().toISOString() }) + "\n");
    return true;
  } catch {
    return false;
  }
}

/**
 * Build a decision recorder that logs to the ledger before returning.
 */
function decisionFinisher(
  config: GatewayConfig,
  context: { skill?: string; command?: string; cwd: string }
): (action: GatewayDecision["action"], rule: string, reason: string) => GatewayDecision {
  return (action, rule, reason) => {
    const logged = appendGatewayLog(config.logPath, {
      kind: "decision",
      action,
      rule,
      skill: context.skill,
      command: context.command,
      cwd: context.cwd,
      reason,
    });
    return { action, rule, reason, logged };
  };
}

/**
 * Enforce a process.exec request. Rule order: invalid input → structured
 * command quarantine → workspace scope → environment trust → allowlist →
 * confirmation → allow.
 *
 * Raw compound shell strings (anything containing `&&`, `||`, `;`, `|`, `>`,
 * `<`, backticks, `$(...)`, or line breaks) are quarantined: a prefix or
 * wildcard pattern must never authorize injected shell syntax. Callers that
 * genuinely need compound commands must submit them as structured
 * executable/argv values via enforceArgv.
 */
export function enforceCommand(request: GatewayRequest, config: GatewayConfig): GatewayDecision {
  const command = (request.command ?? "").trim();
  const cwd = request.cwd ?? process.cwd();
  const finish = decisionFinisher(config, { skill: request.skill, command: command || undefined, cwd });

  if (!command) {
    return finish("deny", "input.invalid", "gateway request carries no command");
  }
  if (isStructuredCommand(command)) {
    return finish(
      "deny",
      "structured-command-required",
      "raw compound shell strings are not authorized by prefix policies; submit the command as structured executable/argv values (enforceArgv)"
    );
  }
  if (config.workspaceRoots.length > 0 && !withinRoots(cwd, config.workspaceRoots)) {
    return finish("deny", "workspace.scope", `cwd ${cwd} is outside the configured workspace roots`);
  }
  if (request.environmentDrift && !config.trustDriftedEnvironment) {
    return finish("deny", "environment.drift", "trusted environment baseline has drifted; re-trust with `skill-audit trust env`");
  }
  const allowed = config.allowedCommands.some(pattern => commandMatches(command, pattern));
  if (!allowed) {
    return finish("deny", "allowlist.absent", `command is not in the allowlist: ${command.split(/\s+/)[0]}`);
  }
  const needsConfirmation = config.confirmCommands.some(pattern => commandMatches(command, pattern));
  if (needsConfirmation && request.approved !== true) {
    return finish("confirm", "confirmation.required", "command requires an explicit approval for this invocation");
  }
  return finish("allow", "policy.allow", "command within declared contract");
}

export interface GatewayArgvRequest {
  tool?: string;
  /** Executable to run; must be a plain word (no whitespace, no shell metacharacters). */
  executable?: string;
  /** Argument values. Data only: never matched against command patterns. */
  args?: string[];
  skill?: string;
  cwd?: string;
  /** Invocation approval recorded upstream (e.g. user confirmed). */
  approved?: boolean;
  /** Environment baseline drift detected by diff-env. */
  environmentDrift?: boolean;
}

/**
 * Enforce a structured executable + argv request — the safe alternative to
 * raw compound shell strings. Only the executable is matched against the
 * allowlist/confirmation patterns (exact, `prefix:*`, or `*`); args are data
 * and never participate in matching, so metacharacters inside an arg value
 * cannot change the decision. Rule order: invalid argv (executable must be a
 * plain word, entries must be strings) → workspace scope → environment trust
 * → allowlist → confirmation → allow.
 */
export function enforceArgv(request: GatewayArgvRequest, config: GatewayConfig): GatewayDecision {
  const executable = typeof request.executable === "string" ? request.executable.trim() : "";
  const args = Array.isArray(request.args) ? request.args : [];
  const cwd = request.cwd ?? process.cwd();
  const display = [executable, ...args.filter(arg => typeof arg === "string")].join(" ").trim();
  const finish = decisionFinisher(config, { skill: request.skill, command: display || undefined, cwd });

  if (!isPlainExecutableWord(executable)) {
    return finish(
      "deny",
      "argv.invalid",
      "structured requests need a plain-word executable: non-empty, no whitespace, no shell metacharacters"
    );
  }
  if (args.some(arg => typeof arg !== "string")) {
    return finish("deny", "argv.invalid", "argv entries must be strings; non-string entries are rejected");
  }
  if (config.workspaceRoots.length > 0 && !withinRoots(cwd, config.workspaceRoots)) {
    return finish("deny", "workspace.scope", `cwd ${cwd} is outside the configured workspace roots`);
  }
  if (request.environmentDrift && !config.trustDriftedEnvironment) {
    return finish("deny", "environment.drift", "trusted environment baseline has drifted; re-trust with `skill-audit trust env`");
  }
  const allowed = config.allowedCommands.some(pattern => commandMatches(executable, pattern));
  if (!allowed) {
    return finish("deny", "allowlist.absent", `executable is not in the allowlist: ${executable}`);
  }
  const needsConfirmation = config.confirmCommands.some(pattern => commandMatches(executable, pattern));
  if (needsConfirmation && request.approved !== true) {
    return finish("confirm", "confirmation.required", "executable requires an explicit approval for this invocation");
  }
  return finish("allow", "policy.allow", "executable and argv within declared contract");
}

/**
 * Post-execution attestation: append the executed command's outcome and a
 * digest so the ledger can be reconciled against what actually ran.
 */
export function attestExecution(
  logPath: string,
  execution: { command: string; skill?: string; exitCode: number; durationMs: number }
): boolean {
  return appendGatewayLog(logPath, {
    kind: "execution",
    skill: execution.skill,
    command: execution.command,
    exitCode: execution.exitCode,
    durationMs: execution.durationMs,
    commandSha256: createHash("sha256").update(execution.command).digest("hex"),
  });
}
