/**
 * Finding fingerprints and governed suppressions (Phase 4).
 *
 * Fingerprints digest scanner version, analyzer, rule id, path, source digest,
 * and evidence — so any change to the source, evidence, rule, or scanner
 * reactivates the finding automatically. Suppressions require a reason and
 * may carry approver, ticket, creation, and expiration metadata. Suppressed
 * findings stay visible in reports; they simply do not affect policy or score.
 */
import { createHash } from "crypto";
import { readFileSync, existsSync } from "fs";
import { Finding, SourceLocation } from "./types.js";
import { Diagnostic } from "./scan.js";

// ============================================================
// Fingerprints
// ============================================================

export interface FingerprintInput {
  scannerVersion: string;
  analyzer: string;
  ruleId: string;
  path: string;
  sourceDigest: string;
  evidence: string;
  /** Evidence source range; part of the digest so moved evidence reactivates. */
  location?: Omit<SourceLocation, "file">;
}

export function findingFingerprint(input: FingerprintInput): string {
  const locationMaterial = input.location
    ? `${input.location.precision}:${input.location.startLine}:${input.location.startColumn}:${input.location.endLine}:${input.location.endColumn}`
    : "";
  const material = [
    input.scannerVersion,
    input.analyzer,
    input.ruleId,
    input.path,
    input.sourceDigest,
    input.evidence,
    locationMaterial,
  ].join("\u0000");
  return createHash("sha256").update(material).digest("hex");
}

// ============================================================
// Suppression file
// ============================================================

export interface SuppressionEntry {
  fingerprint: string;
  reason: string;
  approver?: string;
  ticket?: string;
  created?: string;
  expires?: string;
}

export interface SuppressionFile {
  version: 1;
  suppressions: SuppressionEntry[];
}

export interface SuppressionParseResult {
  entries: SuppressionEntry[];
  errors: string[];
}

export function parseSuppressions(raw: string): SuppressionParseResult {
  const errors: string[] = [];
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    return { entries: [], errors: [`suppressions file is not valid JSON: ${String(e)}`] };
  }

  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    return { entries: [], errors: ["suppressions file must be an object with a suppressions array"] };
  }
  const obj = data as Record<string, unknown>;
  if (obj.version !== 1) {
    errors.push("suppressions version must be 1");
  }
  if (!Array.isArray(obj.suppressions)) {
    return { entries: [], errors: [...errors, "suppressions must be an array"] };
  }

  const entries: SuppressionEntry[] = [];
  obj.suppressions.forEach((item, i) => {
    if (typeof item !== "object" || item === null) {
      errors.push(`suppressions[${i}] must be an object`);
      return;
    }
    const s = item as Record<string, unknown>;
    if (typeof s.fingerprint !== "string" || s.fingerprint.length === 0) {
      errors.push(`suppressions[${i}].fingerprint is required`);
      return;
    }
    if (typeof s.reason !== "string" || s.reason.trim().length < 10) {
      // A suppression without a substantive reason is not governed.
      errors.push(`suppressions[${i}].reason is required (min 10 chars)`);
      return;
    }
    for (const key of ["approver", "ticket", "created", "expires"] as const) {
      if (s[key] !== undefined && typeof s[key] !== "string") {
        errors.push(`suppressions[${i}].${key} must be a string`);
      }
    }
    if (s.expires !== undefined && isNaN(Date.parse(String(s.expires)))) {
      errors.push(`suppressions[${i}].expires is not a valid date`);
    }
    entries.push({
      fingerprint: s.fingerprint,
      reason: s.reason,
      approver: s.approver as string | undefined,
      ticket: s.ticket as string | undefined,
      created: s.created as string | undefined,
      expires: s.expires as string | undefined,
    });
  });

  if (errors.length > 0) return { entries: [], errors };
  return { entries, errors: [] };
}

export function loadSuppressions(path: string): SuppressionParseResult {
  if (!existsSync(path)) {
    return { entries: [], errors: [`suppressions file not found: ${path}`] };
  }
  try {
    return parseSuppressions(readFileSync(path, "utf-8"));
  } catch (e) {
    return { entries: [], errors: [`could not read suppressions file: ${String(e)}`] };
  }
}

function isExpired(entry: SuppressionEntry, now: Date): boolean {
  if (!entry.expires) return false;
  const expiry = Date.parse(entry.expires);
  if (isNaN(expiry)) return true;
  return now.getTime() > expiry;
}

// ============================================================
// Application
// ============================================================

export interface SuppressionOutcome {
  /** Findings annotated with suppression metadata (same order and length). */
  findings: Finding[];
  /** Number of findings currently suppressed. */
  suppressedCount: number;
  /** Diagnostics about invalid files, expired entries, etc. */
  diagnostics: Diagnostic[];
}

/**
 * Apply suppressions by fingerprint. Suppressed findings are kept in the list,
 * flagged, and excluded from policy/score by the caller. Anything that changes
 * the fingerprint (source, evidence, rule, scanner version) reactivates the
 * finding because the digest simply no longer matches.
 */
export function applySuppressions(
  findings: Finding[],
  entries: SuppressionEntry[],
  now: Date = new Date()
): SuppressionOutcome {
  const diagnostics: Diagnostic[] = [];
  const active = new Map<string, SuppressionEntry>();
  let expired = 0;

  for (const entry of entries) {
    if (isExpired(entry, now)) {
      expired++;
      continue;
    }
    active.set(entry.fingerprint, entry);
  }
  if (expired > 0) {
    diagnostics.push({
      source: "suppressions",
      message: `${expired} suppression(s) expired and were reactivated`,
    });
  }

  let suppressedCount = 0;
  const annotated = findings.map(f => {
    const fp = (f as Finding & { fingerprint?: string }).fingerprint;
    if (!fp) return f;
    const entry = active.get(fp);
    if (!entry) return f;
    suppressedCount++;
    return {
      ...f,
      suppressed: true,
      suppression: {
        reason: entry.reason,
        approver: entry.approver,
        ticket: entry.ticket,
        expires: entry.expires,
        // Governance retention: `created` is defined on SuppressionEntry but
        // not yet on Finding.suppression (src/types.ts is owned by another
        // editor). The value passes through structurally; declaring it on the
        // Finding type is the remaining follow-up.
        created: entry.created,
      },
    };
  });

  return { findings: annotated, suppressedCount, diagnostics };
}
