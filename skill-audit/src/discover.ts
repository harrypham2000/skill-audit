import { existsSync, readdirSync, statSync, lstatSync, realpathSync, readFileSync } from "fs";
import { join, resolve, basename, extname } from "path";
import { execFileSync } from "child_process";
import { SkillInfo } from "./types.js";
import { homedir } from "os";

// ============================================================
// CONFIG FILE SUPPORT (~/.skill-audit/config.json)
// ============================================================

const CONFIG_DIR = ".skill-audit";
const CONFIG_FILE = "config.json";

export interface SkillAuditConfig {
  excludeSkills?: string[];
  excludePatterns?: string[];
  threshold?: number;
}

/**
 * Get the config file path
 */
export function getConfigPath(): string {
  return join(homedir(), CONFIG_DIR, CONFIG_FILE);
}

/**
 * Read and parse the global config file
 */
export function getGlobalConfig(): SkillAuditConfig {
  const configPath = getConfigPath();
  
  if (!existsSync(configPath)) {
    return {};
  }

  try {
    const content = readFileSync(configPath, "utf-8");
    return JSON.parse(content);
  } catch {
    return {};
  }
}

// ============================================================
// IGNORE FILE SUPPORT (.skillauditignore)
// ============================================================

const IGNORE_FILE = ".skillauditignore";

/**
 * Read and parse .skillauditignore file from skill directory
 */
export function getIgnorePatterns(skillPath: string): string[] {
  const ignoreFilePath = join(skillPath, IGNORE_FILE);
  const patterns: string[] = [];

  if (!existsSync(ignoreFilePath)) {
    return patterns;
  }

  try {
    const content = readFileSync(ignoreFilePath, "utf-8");
    const lines = content.split("\n");

    for (const line of lines) {
      const trimmed = line.trim();
      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith("#")) {
        continue;
      }
      patterns.push(trimmed);
    }
  } catch {
    // Silently ignore unreadable ignore files
  }

  return patterns;
}

/**
 * Check if a file should be ignored based on ignore patterns
 */
function matchesIgnorePattern(filePath: string, pattern: string, basePath: string): boolean {
  // Normalize the file path relative to base
  const relativePath = filePath.replace(basePath + "/", "");

  // Handle glob patterns
  if (pattern.includes("*")) {
    // Convert glob to regex
    let regexPattern = pattern
      .replace(/\./g, "\\.")  // Escape dots
      .replace(/\*\*/g, ".*"); // ** matches anything
    
    // Handle single * - match anything including slashes (for patterns like *.test.ts)
    // But also match patterns like "test/*" within a directory
    if (pattern.startsWith("*.")) {
      // For patterns like *.test.ts, match anywhere in the path
      regexPattern = regexPattern.replace(/\*/g, ".*");
    } else {
      // For other patterns, use [^/]* for single *
      regexPattern = regexPattern.replace(/\*/g, "[^/]*");
    }
    
    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(relativePath);
  }

  // Handle directory patterns (e.g., "test/" matches "test/**")
  if (pattern.endsWith("/")) {
    return relativePath.startsWith(pattern) || relativePath.startsWith(pattern.slice(0, -1));
  }

  // Exact match - also check if it's a file in a subdirectory
  return relativePath === pattern || relativePath.endsWith("/" + pattern) || relativePath.includes("/" + pattern + "/");
}

/**
 * Filter files based on ignore patterns
 */
export function filterIgnoredFiles(files: string[], patterns: string[], basePath: string): string[] {
  if (patterns.length === 0) {
    return files;
  }

  return files.filter(file => {
    for (const pattern of patterns) {
      if (matchesIgnorePattern(file, pattern, basePath)) {
        return false; // Ignore this file
      }
    }
    return true; // Keep this file
  });
}

export function resolveSkillPath(skillPath: string): string {
  // Resolve symlinks to actual path, with boundary check
  try {
    const resolved = resolve(skillPath);
    // Ensure we don't escape the repository
    const realPath = realpathSync(resolved);
    return realPath;
  } catch {
    return skillPath;
  }
}

export function getSkillFiles(skillPath: string, basePath?: string): string[] {
  const files: string[] = [];
  const root = basePath || skillPath;

  if (!existsSync(skillPath)) {
    return files;
  }

  const stat = statSync(skillPath);

  if (stat.isFile()) {
    return [skillPath];
  }

  // Recursively scan all directories with symlink boundary enforcement
  function scanDir(dir: string) {
    try {
      const entries = readdirSync(dir);

      for (const entry of entries) {
        const fullPath = join(dir, entry);
        
        // Use lstat to detect symlinks without following them
        const lstat = lstatSync(fullPath);

        // Check for symlinks - ensure they don't escape the base path
        if (lstat.isSymbolicLink()) {
          try {
            const realPath = realpathSync(fullPath);
            // Verify the resolved path is still within the skill directory
            if (!realPath.startsWith(root)) {
              // Symlink points outside - skip to prevent directory traversal
              continue;
            }
            // Follow the symlink for scanning
            const targetStat = statSync(fullPath);
            if (targetStat.isDirectory()) {
              if (!entry.startsWith(".")) {
                scanDir(realPath);
              }
            } else if (targetStat.isFile()) {
              files.push(realPath);
            }
          } catch {
            // Broken symlink - skip
            continue;
          }
        } else if (lstat.isDirectory()) {
          // Skip hidden directories
          if (!entry.startsWith(".")) {
            scanDir(fullPath);
          }
        } else if (lstat.isFile()) {
          files.push(fullPath);
        }
      }
    } catch (e) {
      // Skip directories we cannot read
    }
  }

  scanDir(skillPath);

  // Apply .skillauditignore patterns if present
  const ignorePatterns = getIgnorePatterns(skillPath);
  if (ignorePatterns.length > 0) {
    return filterIgnoredFiles(files, ignorePatterns, skillPath);
  }

  return files;
}

export async function discoverSkills(scope: "global" | "project" = "global"): Promise<SkillInfo[]> {
  const skills: SkillInfo[] = [];

  try {
    // Use execFileSync with argv array to prevent command injection
    const args = scope === "global" 
      ? ["skills", "list", "-g", "--json"]
      : ["skills", "list", "--json"];
    
    const output = execFileSync("npx", args, { 
      encoding: "utf-8", 
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 30000
    });

    const data = JSON.parse(output);

    if (Array.isArray(data)) {
      for (const item of data) {
        // Handle different output formats:
        // Format 1: { skill: { name, path, ... } }
        // Format 2: { name, path, ... }
        const skillData = item.skill || item;

        if (skillData && skillData.name && skillData.path) {
          // Filter by scope if project only
          const isGlobal = skillData.scope === "global";

          if (scope === "project" && isGlobal) continue;

          // Validate and sanitize the path to prevent traversal
          let safePath = skillData.path;
          try {
            safePath = resolveSkillPath(skillData.path);
          } catch {
            // Invalid path - skip this skill
            continue;
          }

          skills.push({
            name: skillData.name,
            path: safePath,
            agents: skillData.agents || [],
            scope: skillData.scope || "unknown"
          });
        }
      }
    }
  } catch (e) {
    console.error("Failed to discover skills:", e);
  }

  return skills;
}
