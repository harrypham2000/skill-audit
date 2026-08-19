/**
 * SARIF 2.1.0 output adapter (Phase 4).
 *
 * Renders canonical scan reports as a SARIF log for GitHub code scanning and
 * other consumers. Suppressed findings remain visible as results with a
 * suppressions entry, so audits stay complete. The decision is derived from
 * the same reports as JSON output — renderers never disagree.
 */
import { ScanReport } from "./scan.js";
import { Finding } from "./types.js";

type SarifLevel = "error" | "warning" | "note";

function levelFor(severity: Finding["severity"]): SarifLevel {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function relativeUri(path: string, root: string): string {
  if (path.startsWith(root)) {
    return path.slice(root.length).replace(/^[/\\]/, "");
  }
  return path;
}

/**
 * SARIF region from a Finding. SARIF lines/columns are 1-based and
 * endColumn is INCLUSIVE, while SourceLocation.endColumn is exclusive —
 * subtract 1. Exact locations emit startColumn/endLine/endColumn;
 * line-only locations (and legacy line-only findings) emit startLine only.
 * Never fabricate column precision the analyzer does not have.
 */
function regionFor(finding: Finding): Record<string, number> | undefined {
  const loc = finding.location;
  if (loc && loc.precision === "exact") {
    return {
      startLine: loc.startLine,
      startColumn: loc.startColumn,
      endLine: loc.endLine,
      endColumn: loc.endColumn - 1, // inclusive for SARIF
    };
  }
  if (loc) {
    return { startLine: loc.startLine };
  }
  if (finding.line !== undefined) {
    return { startLine: finding.line };
  }
  return undefined;
}

interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          shortDescription: { text: string };
          properties?: Record<string, unknown>;
        }>;
      };
    };
    originalUriBaseIds?: { ROOT: { uri: string } };
    results: Array<Record<string, unknown>>;
    properties?: Record<string, unknown>;
  }>;
}

export function toSarif(reports: ScanReport[]): SarifLog {
  const ruleIds = new Map<string, { id: string; shortDescription: { text: string }; properties?: Record<string, unknown> }>();

  for (const report of reports) {
    for (const finding of report.findings) {
      if (!ruleIds.has(finding.id)) {
        ruleIds.set(finding.id, {
          id: finding.id,
          shortDescription: { text: finding.message.slice(0, 100) || finding.id },
          properties: { asi: finding.asi, category: finding.category },
        });
      }
    }
  }
  const rules = [...ruleIds.values()];
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const results = reports.flatMap(report =>
    report.findings.map(finding => {
      const result: Record<string, unknown> = {
        ruleId: finding.id,
        ruleIndex: ruleIndex.get(finding.id),
        level: levelFor(finding.severity),
        message: { text: finding.message },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: relativeUri(finding.file, report.input.path),
              uriBaseId: "ROOT",
            },
            region: regionFor(finding),
          },
        }],
        properties: {
          asi: finding.asi,
          category: finding.category,
          confidence: finding.confidence,
          cwe: finding.cwe,
          skill: report.input.skill,
          suppressed: finding.suppressed === true,
        },
      };
      if (finding.evidence) {
        (result.properties as Record<string, unknown>).evidence = finding.evidence;
      }
      const fp = (finding as Finding & { fingerprint?: string }).fingerprint;
      if (fp) {
        result.partialFingerprints = { "skillAuditFingerprint/v1": fp };
      }
      if (finding.suppressed && finding.suppression) {
        const s = finding.suppression;
        // Governance metadata travels on the suppression entry so auditors can
        // see WHO approved WHAT under WHICH ticket until WHEN.
        const governance: Record<string, string> = {};
        if (s.approver) governance.approver = s.approver;
        if (s.ticket) governance.ticket = s.ticket;
        if (s.expires) governance.expires = s.expires;
        // `created` is not yet declared on Finding.suppression (types.ts is
        // owned elsewhere); pass it through when the runtime value exists.
        const created = (s as { created?: string }).created;
        if (created) governance.created = created;
        const suppression: Record<string, unknown> = {
          kind: "external",
          justification: s.reason,
          state: "accepted",
        };
        if (Object.keys(governance).length > 0) suppression.properties = governance;
        result.suppressions = [suppression];
      }
      return result;
    })
  );

  const exitCodes = reports.map(r => r.decision.exitCode);
  const worstExit = reports.length === 0 ? 2 : Math.max(...exitCodes);

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "skill-audit",
          version: reports[0]?.scanner.version ?? "0.0.0",
          informationUri: "https://github.com/harrypham2000/skill-audit",
          rules,
        },
      },
      originalUriBaseIds: {
        ROOT: { uri: "file://" + (reports[0]?.input.path ?? "/") + "/" },
      },
      results,
      properties: {
        schemaVersion: reports[0]?.schemaVersion ?? "1",
        decisions: reports.map(r => ({ skill: r.input.skill, outcome: r.decision.outcome, rule: r.decision.rule, exitCode: r.decision.exitCode })),
        worstExitCode: worstExit,
        scanStatuses: reports.map(r => ({ skill: r.input.skill, status: r.scanStatus })),
      },
    }],
  };
}
