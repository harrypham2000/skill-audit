/**
 * Contract tests for schemas/scan-report.schema.json.
 *
 * Preferred path: REAL validation via python3 + jsonschema (draft 2020-12),
 * mirroring the external validator consumers would run. When the module is
 * unavailable, a structural fallback still pins the enum/scope/level facts.
 */
import { describe, expect, it } from "vitest";
import { spawnSync } from "child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { fileURLToPath } from "url";

const here = join(fileURLToPath(import.meta.url), "..");
const schemaPath = join(here, "..", "schemas", "scan-report.schema.json");
const schema = JSON.parse(readFileSync(schemaPath, "utf-8")) as {
  properties: Record<string, { $ref?: string }>;
  required: string[];
  $defs: Record<string, any>;
};

// Availability probe: fall back to structural assertions when missing.
const probe = spawnSync("python3", ["-c", "import jsonschema"], { stdio: "ignore" });
const pythonValidatorAvailable = probe.status === 0;
if (!pythonValidatorAvailable) {
  // eslint-disable-next-line no-console
  console.warn("python3/jsonschema unavailable — falling back to structural schema assertions");
}

const VALIDATE_PY = [
  "import json, sys, jsonschema",
  "with open(sys.argv[1]) as f: schema = json.load(f)",
  "with open(sys.argv[2]) as f: instance = json.load(f)",
  "jsonschema.validate(instance, schema)",
].join("\n");

/** Validate an instance against the shipped schema; throws with python's stderr on failure. */
function validateAgainstSchema(instance: unknown): void {
  const dir = mkdtempSync(join(tmpdir(), "skill-audit-schema-"));
  try {
    const schemaFile = join(dir, "schema.json");
    const instanceFile = join(dir, "instance.json");
    writeFileSync(schemaFile, JSON.stringify(schema));
    writeFileSync(instanceFile, JSON.stringify(instance));
    const res = spawnSync("python3", ["-c", VALIDATE_PY, schemaFile, instanceFile], { encoding: "utf-8" });
    if (res.status !== 0) {
      throw new Error(`schema validation failed: ${res.stderr.trim()}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function reportWithCapabilities(capabilities: unknown[]): Record<string, unknown> {
  return {
    schemaVersion: "1",
    scanner: { name: "skill-audit", version: "0.9.4" },
    input: { skill: "schema-skill", path: "/x/schema-skill", fileCount: 1, totalBytes: 42, snapshotDigest: "0".repeat(64) },
    findings: [],
    capabilities,
    analyzerRuns: [{ analyzer: "shell-structural", status: "completed", findings: 0, durationMs: 3 }],
    diagnostics: [],
    exclusions: [],
    scanStatus: "complete",
    decision: { outcome: "allow", rule: "default-allow", reason: "no blocking findings", exitCode: 0 },
    suppressedCount: 0,
    riskScore: 0,
  };
}

const ALL_KINDS = ["process.exec", "network.request", "fs.read", "fs.write", "env.read", "mcp.invoke"] as const;

const exactLocation = {
  file: "run.ts",
  startLine: 3,
  startColumn: 1,
  endLine: 3,
  endColumn: 19,
  precision: "exact",
};

describe("scan-report schema structure", () => {
  it("accepts every CapabilityKind value in the capability enum", () => {
    const enumValues: string[] = schema.$defs.capability.properties.capability.enum;
    for (const kind of ALL_KINDS) {
      expect(enumValues).toContain(kind);
    }
  });

  it("allows an optional scope with string server/tool on capabilities", () => {
    const scope = schema.$defs.capability.properties.scope;
    expect(scope).toBeDefined();
    expect(scope.type).toBe("object");
    expect(scope.properties.server).toEqual({ type: "string" });
    expect(scope.properties.tool).toEqual({ type: "string" });
    expect(scope.required ?? []).toEqual([]); // both members optional
  });

  it("keeps level fixed at observed and locations allowed", () => {
    expect(schema.$defs.capability.properties.level).toEqual({ const: "observed" });
    expect(schema.$defs.capability.properties.location).toEqual({ $ref: "#/$defs/sourceLocation" });
    expect(schema.$defs.finding.properties.location).toEqual({ $ref: "#/$defs/sourceLocation" });
  });

  it("does not include manifest/contract capabilities in the report schema", () => {
    expect(schema.properties.contract).toBeUndefined();
    expect(schema.properties.manifest).toBeUndefined();
    expect(schema.required).not.toContain("contract");
    expect(Object.keys(schema.$defs)).not.toContain("contract");
  });
});

describe.skipIf(!pythonValidatorAvailable)("scan-report schema validation (python jsonschema)", () => {
  it.each(ALL_KINDS)("accepts a %s capability", (kind) => {
    validateAgainstSchema(reportWithCapabilities([
      { capability: kind, level: "observed", evidence: `evidence for ${kind}`, file: "run.ts", line: 3 },
    ]));
  });

  it("accepts mcp.invoke with a full scope (server + tool)", () => {
    validateAgainstSchema(reportWithCapabilities([
      {
        capability: "mcp.invoke",
        level: "observed",
        evidence: "callTool({ serverName: 'github', toolName: 'create_issue' })",
        file: "run.ts",
        line: 7,
        scope: { server: "github", tool: "create_issue" },
      },
    ]));
  });

  it("accepts mcp.invoke with partial scope and an exact location", () => {
    validateAgainstSchema(reportWithCapabilities([
      {
        capability: "mcp.invoke",
        level: "observed",
        evidence: "claude mcp call github",
        file: "run.sh",
        line: 2,
        location: exactLocation,
        scope: { server: "github" },
      },
    ]));
  });

  it("accepts a scope without tool", () => {
    validateAgainstSchema(reportWithCapabilities([
      { capability: "mcp.invoke", level: "observed", evidence: "x", file: "run.ts", line: 1, scope: { tool: "list_tools" } },
    ]));
  });

  it("rejects an unknown capability kind (enum is enforced)", () => {
    expect(() => validateAgainstSchema(reportWithCapabilities([
      { capability: "time.travel", level: "observed", evidence: "x", file: "run.ts", line: 1 },
    ]))).toThrow(/schema validation failed/);
  });

  it("rejects non-string scope members", () => {
    expect(() => validateAgainstSchema(reportWithCapabilities([
      { capability: "mcp.invoke", level: "observed", evidence: "x", file: "run.ts", line: 1, scope: { server: 42 } },
    ]))).toThrow(/schema validation failed/);
  });

  it("accepts a suppressed finding with governance suppression metadata", () => {
    const report = reportWithCapabilities([]);
    (report as Record<string, unknown>).findings = [{
      id: "PI-001",
      category: "PI",
      asi: "ASI01",
      severity: "high",
      file: "SKILL.md",
      line: 4,
      message: "prompt injection",
      fingerprint: "f".repeat(64),
      suppressed: true,
      suppression: {
        reason: "verified false positive in docs example",
        approver: "security-team",
        ticket: "SEC-42",
        created: "2026-08-16T00:00:00Z",
        expires: "2027-08-16T00:00:00Z",
      },
    }];
    validateAgainstSchema(report);
  });
});
