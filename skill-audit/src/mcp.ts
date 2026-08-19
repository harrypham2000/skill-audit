/**
 * MCP security analysis (Phase 6).
 *
 * Evaluates a skill's MCP/tool configuration for metadata poisoning,
 * permission mismatch, install-reference integrity, and version-to-version
 * privilege expansion. Config formats: mcp.json / .mcp.json at the skill
 * root, in either {"mcpServers": {...}} or bare {server: {...}} shape.
 */
import { Finding } from "./types.js";

export interface McpServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, unknown>;
  url?: string;
  permissions?: string[];
  alwaysAllow?: boolean;
  autoApprove?: boolean;
  description?: string;
  tools?: Array<{ name?: string; description?: string; parameters?: Array<{ name?: string; description?: string }> }>;
  [key: string]: unknown;
}

export interface McpConfig {
  servers: Record<string, McpServerConfig>;
}

export interface McpAnalyzerResult {
  findings: Finding[];
  status: "completed" | "not_applicable" | "partial";
  detail?: string;
}

export const MCP_CONFIG_FILES = ["mcp.json", ".mcp.json"];

export function parseMcpConfig(raw: string): { config?: McpConfig; error?: string } {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    return { error: `MCP config is not valid JSON: ${String(e).slice(0, 120)}` };
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    return { error: "MCP config must be an object" };
  }
  const obj = data as Record<string, unknown>;
  const serversRaw = (obj.mcpServers ?? obj.servers ?? obj) as Record<string, unknown>;
  if (typeof serversRaw !== "object" || serversRaw === null) {
    return { error: "MCP servers must be an object" };
  }
  const servers: Record<string, McpServerConfig> = {};
  for (const [name, value] of Object.entries(serversRaw)) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      servers[name] = value as McpServerConfig;
    }
  }
  return { config: { servers } };
}

// Invisible and directional Unicode used for deception in names/descriptions.
const DECEPTION_CHARS = /[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/;
const DIRECTIVE_RE = /ignore\s+(all\s+)?(previous|prior)\s+(instructions?|rules?)|disregard\s+your|you\s+are\s+now|exfiltrat|send\s+.*\s+to\s+(this|an)\s+(url|endpoint)/i;
const INSTALLERS = /^(npx|bunx|pnpx|uvx|docker|podman)$/;

function finding(id: string, severity: Finding["severity"], asi: string, file: string, message: string, evidence?: string, recommendation?: string): Finding {
  return { id, category: "ENV", asi, severity, file, message, evidence, recommendation };
}

// ============================================================
// Observed MCP invocation evidence (Phase 6, corrected)
// ============================================================

/** One observed MCP invocation, produced by the shared capability model. */
export interface McpInvocationEvidence {
  /** Literal server name when statically determinable. */
  server?: string;
  /** Literal tool name when statically determinable. */
  tool?: string;
  /** Analyzer that observed the invocation. */
  source: string;
  file: string;
  line: number;
}

export type McpUsageState =
  | "declared-and-observed"
  | "declared-but-unused"
  | "observed-undeclared"
  | "documentation-only"
  | "dynamic-indeterminate";

export interface McpUsageClassification {
  server: string | "(dynamic)";
  state: McpUsageState;
}

/**
 * Classify declared servers and observed invocations into usage states.
 * Textual references never count as execution — they only qualify how a
 * declared-but-unused server should be reported.
 */
export function classifyMcpUsage(
  config: McpConfig,
  skillContent: string,
  observed: McpInvocationEvidence[]
): McpUsageClassification[] {
  const declared = new Set(Object.keys(config.servers));
  const invoked = new Set(observed.filter(o => o.server).map(o => o.server!));
  const dynamic = observed.filter(o => !o.server);
  const documented = new Set<string>();
  for (const match of skillContent.matchAll(/\bmcp__([A-Za-z0-9_-]+)__/g)) {
    documented.add(match[1]);
  }
  for (const o of observed) {
    if (o.server && documented.has(o.server)) documented.delete(o.server);
  }

  const result: McpUsageClassification[] = [];
  for (const server of declared) {
    if (invoked.has(server)) {
      result.push({ server, state: "declared-and-observed" });
    } else if (documented.has(server)) {
      result.push({ server, state: "documentation-only" });
    } else {
      result.push({ server, state: "declared-but-unused" });
    }
  }
  for (const server of invoked) {
    if (!declared.has(server)) result.push({ server, state: "observed-undeclared" });
  }
  if (dynamic.length > 0) {
    result.push({ server: "(dynamic)", state: "dynamic-indeterminate" });
  }
  return result;
}

/**
 * Analyze one MCP config for poison, permission, and reference-integrity
 * issues. `skillContent` is the SKILL.md body (documentation evidence only);
 * `observed` carries observed MCP invocations from the shared capability
 * model. Permission mismatch is never claimed from text alone.
 */
export function analyzeMcpConfig(
  config: McpConfig,
  file: string,
  skillContent: string,
  observed: McpInvocationEvidence[] = []
): Finding[] {
  const findings: Finding[] = [];

  for (const [name, server] of Object.entries(config.servers)) {
    const label = `${name}`;

    // ---- Install-reference integrity ----
    if (server.command && INSTALLERS.test(server.command)) {
      const args = server.args ?? [];
      const ref = args.find(a => a.startsWith("-") === false && !/^-/.test(a)) ?? "";
      const pinned = /@(\d+|\d+\.\d+|latest)/.test(ref) && !/@latest/.test(ref)
        || /:[\w][\w.-]{0,63}/.test(ref) && /:\d+\.\d+/.test(ref)
        || /@sha256:[a-f0-9]{12,}/.test(ref);
      const explicitLatest = args.some(a => a === "@latest" || a === "latest");
      if (!ref || !pinned || explicitLatest) {
        findings.push(finding(
          "MCP-001", "high", "ASI04", file,
          `MCP server "${label}" uses unpinned ${server.command} execution`,
          `${server.command} ${args.join(" ")}`.slice(0, 160),
          `Pin the package to an exact version or digest instead of ${explicitLatest ? "@latest" : "a floating reference"}.`
        ));
      }
    }

    // ---- Permission mismatch / overprivilege ----
    const perms = server.permissions;
    if (perms?.some(p => p === "*" || p.includes("*"))) {
      findings.push(finding(
        "MCP-002", "high", "ASI09", file,
        `MCP server "${label}" requests wildcard permissions`,
        perms.join(", "),
        "Replace wildcard permissions with the minimum tool set the skill needs."
      ));
    }
    if (server.alwaysAllow === true || server.autoApprove === true) {
      findings.push(finding(
        "MCP-007", "medium", "ASI08", file,
        `MCP server "${label}" opts into dangerous auto-approval defaults`,
        server.alwaysAllow !== undefined ? `alwaysAllow: ${server.alwaysAllow}` : `autoApprove: ${server.autoApprove}`,
        "Remove alwaysAllow/autoApprove so invocations require user confirmation."
      ));
    }

    // ---- Metadata poisoning / Unicode deception ----
    const surfaces: Array<[string, string | undefined]> = [
      ["server name", name],
      ["server description", server.description],
      ...((server.tools ?? []).map(t => [`tool "${t.name ?? "?"}" description`, t.description] as [string, string | undefined])),
      ...((server.tools ?? []).flatMap(t => (t.parameters ?? []).map(p => [`parameter "${p.name ?? "?"}" of tool "${t.name ?? "?"}"`, p.description] as [string, string | undefined]))),
    ];
    for (const [surface, text] of surfaces) {
      if (!text) continue;
      if (DECEPTION_CHARS.test(text)) {
        findings.push(finding(
          "MCP-005", "critical", "ASI01", file,
          `MCP ${surface} contains invisible or directional Unicode (deception)`,
          JSON.stringify(text.slice(0, 80)),
          "Remove zero-width or bidirectional override characters from MCP metadata."
        ));
      } else if (DIRECTIVE_RE.test(text)) {
        const isParameter = surface.startsWith("parameter");
        findings.push(finding(
          isParameter ? "MCP-006" : "MCP-005", isParameter ? "critical" : "high", "ASI01", file,
          `MCP ${surface} contains hidden instructions (metadata poisoning)`,
          text.slice(0, 160),
          "Remove agent-directed instructions from tool metadata; describe behavior only."
        ));
      }
    }

  }

  // ---- Declared-vs-observed usage states ----
  const classifications = classifyMcpUsage(config, skillContent, observed);
  const byState = (state: McpUsageState) =>
    classifications.filter(c => c.state === state).map(c => c.server);

  const declaredButUnused = byState("declared-but-unused");
  if (declaredButUnused.length > 0) {
    findings.push(finding(
      "MCP-004", "low", "ASI09", file,
      "Declared MCP servers have no observed invocation",
      declaredButUnused.join(", "),
      "Remove unused MCP servers, or document why the skill needs them (unused permissions are overprivilege)."
    ));
  }

  const documentationOnly = byState("documentation-only");
  if (documentationOnly.length > 0) {
    findings.push(finding(
      "MCP-004", "low", "ASI09", file,
      "Declared MCP servers are referenced only in documentation, never invoked",
      documentationOnly.join(", "),
      "Documentation mentions are not execution evidence; confirm these servers are needed."
    ));
  }

  // Observed invocation of an undeclared server: high confidence mismatch.
  const observedUndeclared = observed.filter(o => o.server && !config.servers[o.server]);
  for (const o of observedUndeclared) {
    findings.push({
      ...finding(
        "MCP-003", "high", "ASI09", file,
        `Observed MCP invocation of undeclared server "${o.server}"`,
        `${o.source}: ${o.file}:${o.line}`,
        "Declare the server in mcp.json or remove the invocation."
      ),
      confidence: "high",
    });
  }

  // Textual reference to an undeclared server: supporting evidence only.
  for (const match of skillContent.matchAll(/\bmcp__([A-Za-z0-9_-]+)__/g)) {
    const used = match[1];
    const observedFor = observed.some(o => o.server === used);
    if (!config.servers[used] && !observedFor) {
      findings.push({
        ...finding(
          "MCP-003", "low", "ASI09", file,
          `Documentation references MCP server "${used}" that is not declared in the config (text-only evidence)`,
          match[0],
          "Declare the server in mcp.json or remove the reference."
        ),
        confidence: "low",
      });
    }
  }

  // Dynamic, unresolved invocation targets: indeterminate, never silently safe.
  const dynamic = observed.filter(o => !o.server);
  if (dynamic.length > 0) {
    findings.push({
      ...finding(
        "MCP-009", "medium", "ASI09", file,
        "Dynamic MCP usage cannot be verified against declared servers",
        dynamic.map(o => `${o.source}: ${o.file}:${o.line}`).slice(0, 5).join("; "),
        "Resolve the server name statically, or declare the full server set this skill may invoke."
      ),
      confidence: "low",
    });
  }

  return findings;
}

export interface McpDiffFindingInput {
  file: string;
}

/**
 * Version-to-version comparison: flag privilege expansion between two MCP
 * configs — new servers, new/wildcard permissions, new tools, endpoint or
 * parameter changes, and new auto-approval defaults.
 */
export function diffMcpConfigs(
  previous: McpConfig,
  current: McpConfig,
  file: string
): Finding[] {
  const findings: Finding[] = [];

  for (const [name, server] of Object.entries(current.servers)) {
    const prev = previous.servers[name];
    if (!prev) {
      findings.push(finding(
        "MCP-008", "high", "ASI09", file,
        `MCP server "${name}" was added since the previous version`,
        "new server",
        "Review the new server's permissions and package reference before upgrading."
      ));
      continue;
    }

    const prevPerms = new Set(prev.permissions ?? []);
    const newPerms = (server.permissions ?? []).filter(p => !prevPerms.has(p));
    if (newPerms.some(p => p === "*" || p.includes("*"))) {
      findings.push(finding(
        "MCP-008", "high", "ASI09", file,
        `MCP server "${name}" expanded permissions to a wildcard`,
        newPerms.join(", "),
        "Wildcard permission expansion is a privilege escalation; verify intent."
      ));
    } else if (newPerms.length > 0) {
      findings.push(finding(
        "MCP-008", "medium", "ASI09", file,
        `MCP server "${name}" gained new permissions`,
        newPerms.join(", "),
        "Review the newly granted tools before upgrading."
      ));
    }

    const prevTools = new Set((prev.tools ?? []).map(t => t.name ?? ""));
    const newTools = (server.tools ?? []).filter(t => !prevTools.has(t.name ?? ""));
    if (newTools.length > 0) {
      findings.push(finding(
        "MCP-008", "medium", "ASI09", file,
        `MCP server "${name}" added tools since the previous version`,
        newTools.map(t => t.name ?? "?").join(", "),
        "New tools expand the attack surface; review their descriptions for poisoning."
      ));
    }

    if ((server.alwaysAllow === true || server.autoApprove === true)
      && prev.alwaysAllow !== true && prev.autoApprove !== true) {
      findings.push(finding(
        "MCP-008", "high", "ASI08", file,
        `MCP server "${name}" switched to auto-approval in this version`,
        "alwaysAllow/autoApprove enabled",
        "Approval boundaries were removed between versions; verify intent."
      ));
    }

    if (prev.url && server.url && prev.url !== server.url) {
      findings.push(finding(
        "MCP-008", "high", "ASI04", file,
        `MCP server "${name}" changed its endpoint`,
        `${prev.url} → ${server.url}`,
        "Endpoint changes can redirect tool traffic; verify the new destination."
      ));
    }

    for (const tool of server.tools ?? []) {
      const prevTool = (prev.tools ?? []).find(t => t.name === tool.name);
      if (!prevTool) continue;
      const prevParams = new Set((prevTool.parameters ?? []).map(p => p.name ?? ""));
      const newParams = (tool.parameters ?? []).filter(p => !prevParams.has(p.name ?? ""));
      if (newParams.length > 0) {
        findings.push(finding(
          "MCP-008", "low", "ASI09", file,
          `Tool "${tool.name}" on "${name}" gained new parameters`,
          newParams.map(p => p.name ?? "?").join(", "),
          "Review new parameter descriptions for injection."
        ));
      }
    }
  }

  return findings;
}
