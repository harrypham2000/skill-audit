import { readFileSync, readdirSync, statSync } from "fs";
import { basename, join } from "path";
import matter from "gray-matter";
import { SkillManifest, Finding } from "./types.js";

/**
 * Phase 1 - Layer 1: Spec Validator
 * 
 * Validates skills against the Agent Skills specification.
 * This runs BEFORE security checks - spec errors block publication.
 * 
 * Agent Skills spec rules:
 * - SKILL.md must exist
 * - frontmatter must parse
 * - name: 1-64 chars, lowercase a-z0-9-, no leading/trailing hyphens, no double hyphens
 * - name must match parent directory
 * - description: 1-1024 chars
 * - Optional: license, compatibility, metadata, allowed-tools
 * - Directory structure sanity: scripts/, references/, assets/
 */

export interface SpecValidationResult {
  valid: boolean;
  manifest?: SkillManifest;
  findings: Finding[];
}

/**
 * Validate a skill directory against Agent Skills specification
 */
export function validateSkillSpec(skillPath: string, dirName: string): SpecValidationResult {
  const findings: Finding[] = [];
  let manifest: SkillManifest | undefined;

  // SPEC-01: Check SKILL.md exists
  const skillMdPath = join(skillPath, "SKILL.md");
  let skillMdContent: string;
  
  try {
    skillMdContent = readFileSync(skillMdPath, "utf-8");
  } catch (e) {
    findings.push({
      id: "SPEC-01",
      category: "SPEC",
      asixx: "SPEC",
      severity: "critical",
      file: skillPath,
      message: "SKILL.md is required but not found",
      evidence: skillMdPath
    });
    return { valid: false, findings };
  }

  // SPEC-02: Parse frontmatter
  let parsed: matter.GrayMatterFile<string>;
  try {
    parsed = matter(skillMdContent);
  } catch (e) {
    findings.push({
      id: "SPEC-02",
      category: "SPEC",
      asixx: "SPEC",
      severity: "critical",
      file: skillMdPath,
      message: "Failed to parse SKILL.md frontmatter",
      evidence: String(e).slice(0, 100)
    });
    return { valid: false, findings };
  }

  manifest = {
    name: parsed.data.name || "",
    description: parsed.data.description || "",
    origin: parsed.data.origin,  // Custom metadata (not spec-required)
    license: parsed.data.license,
    compatibility: parsed.data.compatibility,
    metadata: parsed.data.metadata,
    allowedTools: parsed.data["allowed-tools"],
    content: parsed.content,
    files: []
  };

  // SPEC-03: Validate required 'name' field
  if (!manifest.name) {
    findings.push({
      id: "SPEC-03",
      category: "SPEC",
      asixx: "SPEC",
      severity: "critical",
      file: skillMdPath,
      message: "Frontmatter missing required 'name' field"
    });
  } else {
    // SPEC-04: name length check (<=64 chars)
    if (manifest.name.length > 64) {
      findings.push({
        id: "SPEC-04",
        category: "SPEC",
        asixx: "SPEC",
        severity: "high",
        file: skillMdPath,
        message: `name exceeds 64 char limit (${manifest.name.length} chars)`
      });
    }

    // SPEC-05: name format (lowercase a-z0-9-)
    if (!/^[a-z0-9-]+$/.test(manifest.name)) {
      findings.push({
        id: "SPEC-05",
        category: "SPEC",
        asixx: "SPEC",
        severity: "high",
        file: skillMdPath,
        message: "name must only contain lowercase letters, numbers, and hyphens"
      });
    }

    // SPEC-06: no leading/trailing hyphen
    if (manifest.name.startsWith('-') || manifest.name.endsWith('-')) {
      findings.push({
        id: "SPEC-06",
        category: "SPEC",
        asixx: "SPEC",
        severity: "high",
        file: skillMdPath,
        message: "name cannot start or end with a hyphen"
      });
    }

    // SPEC-07: no consecutive hyphens
    if (manifest.name.includes('--')) {
      findings.push({
        id: "SPEC-07",
        category: "SPEC",
        asixx: "SPEC",
        severity: "high",
        file: skillMdPath,
        message: "name cannot contain consecutive hyphens"
      });
    }

    // SPEC-08: name must match directory
    if (manifest.name !== dirName) {
      findings.push({
        id: "SPEC-08",
        category: "SPEC",
        asixx: "SPEC",
        severity: "high",
        file: skillMdPath,
        message: `name '${manifest.name}' must match directory '${dirName}'`
      });
    }
  }

  // SPEC-09: Validate required 'description' field
  if (!manifest.description) {
    findings.push({
      id: "SPEC-09",
      category: "SPEC",
      asixx: "SPEC",
      severity: "critical",
      file: skillMdPath,
      message: "Frontmatter missing required 'description' field"
    });
  } else if (manifest.description.length > 1024) {
    findings.push({
      id: "SPEC-10",
      category: "SPEC",
      asixx: "SPEC",
      severity: "high",
      file: skillMdPath,
      message: `description exceeds 1024 char limit (${manifest.description.length} chars)`
    });
  }

  // SPEC-11: Optional license field validation
  if (manifest.license && typeof manifest.license !== "string") {
    findings.push({
      id: "SPEC-11",
      category: "SPEC",
      asixx: "SPEC",
      severity: "medium",
      file: skillMdPath,
      message: "license must be a string"
    });
  }

  // SPEC-12: Optional compatibility field length
  if (manifest.compatibility && String(manifest.compatibility).length > 500) {
    findings.push({
      id: "SPEC-12",
      category: "SPEC",
      asixx: "SPEC",
      severity: "medium",
      file: skillMdPath,
      message: "compatibility field exceeds 500 char limit"
    });
  }

  // SPEC-13: Validate allowed-tools structure (if present)
  if (manifest.allowedTools) {
    findings.push(...validateAllowedTools(manifest.allowedTools, skillMdPath));
  }

  // SPEC-14: SKILL.md length budget check
  const lineCount = skillMdContent.split('\n').length;
  if (lineCount > 500) {
    findings.push({
      id: "SPEC-13",
      category: "SPEC",
      asixx: "SPEC",
      severity: "info",
      file: skillMdPath,
      message: `SKILL.md has ${lineCount} lines - consider progressive disclosure (typical max ~500)`
    });
  }

  // SPEC-15: Directory structure sanity check
  findings.push(...validateDirectoryStructure(skillPath));

  const valid = !findings.some(f => f.severity === "critical");

  return { valid, manifest, findings };
}

function validateAllowedTools(allowedTools: unknown, filePath: string): Finding[] {
  const findings: Finding[] = [];

  if (Array.isArray(allowedTools)) {
    for (const tool of allowedTools) {
      if (typeof tool !== "string" && typeof tool !== "object") {
        findings.push({
          id: "SPEC-14",
          category: "SPEC",
          asixx: "SPEC",
          severity: "medium",
          file: filePath,
          message: `allowed-tools contains non-string/object: ${typeof tool}`
        });
      }
    }
  } else if (allowedTools !== undefined) {
    findings.push({
      id: "SPEC-15",
      category: "SPEC",
      asixx: "SPEC",
      severity: "medium",
      file: filePath,
      message: "allowed-tools should be an array or undefined"
    });
  }

  return findings;
}

function validateDirectoryStructure(skillPath: string): Finding[] {
  const findings: Finding[] = [];

  // Check for recommended directories
  const recommendedDirs = ["scripts", "references", "assets"];
  const foundDirs: string[] = [];

  try {
    const entries = readdirSync(skillPath);
    for (const entry of entries) {
      const entryPath = join(skillPath, entry);
      try {
        const stat = statSync(entryPath);
        if (stat.isDirectory()) {
          foundDirs.push(entry);
        }
      } catch {
        // Skip inaccessible entries
      }
    }
  } catch (e) {
    findings.push({
      id: "SPEC-16",
      category: "SPEC",
      asixx: "SPEC",
      severity: "low",
      file: skillPath,
      message: "Could not read skill directory structure",
      evidence: String(e).slice(0, 100)
    });
    return findings;
  }

  // Warn if no recognized directories (not critical, just informational)
  const hasAnyDir = recommendedDirs.some(d => foundDirs.includes(d));
  if (foundDirs.length > 0 && !hasAnyDir) {
    findings.push({
      id: "SPEC-17",
      category: "SPEC",
      asixx: "SPEC",
      severity: "info",
      file: skillPath,
      message: `Found directories: ${foundDirs.join(', ')} - consider scripts/, references/, assets/ for organization`
    });
  }

  return findings;
}

/**
 * Quick spec validation (for use in lint mode - less strict)
 */
export function quickValidate(skillPath: string, dirName: string): { valid: boolean; errors: string[] } {
  const { valid, findings } = validateSkillSpec(skillPath, dirName);
  const errors = findings
    .filter(f => f.severity === "critical" || f.severity === "high")
    .map(f => `[${f.id}] ${f.message}`);
  return { valid, errors };
}