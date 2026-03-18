import { existsSync, readdirSync, statSync, lstatSync, realpathSync } from "fs";
import { join, resolve } from "path";
import { execFileSync } from "child_process";
export function resolveSkillPath(skillPath) {
    // Resolve symlinks to actual path, with boundary check
    try {
        const resolved = resolve(skillPath);
        // Ensure we don't escape the repository
        const realPath = realpathSync(resolved);
        return realPath;
    }
    catch {
        return skillPath;
    }
}
export function getSkillFiles(skillPath, basePath) {
    const files = [];
    const root = basePath || skillPath;
    if (!existsSync(skillPath)) {
        return files;
    }
    const stat = statSync(skillPath);
    if (stat.isFile()) {
        return [skillPath];
    }
    // Recursively scan all directories with symlink boundary enforcement
    function scanDir(dir) {
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
                        }
                        else if (targetStat.isFile()) {
                            files.push(realPath);
                        }
                    }
                    catch {
                        // Broken symlink - skip
                        continue;
                    }
                }
                else if (lstat.isDirectory()) {
                    // Skip hidden directories
                    if (!entry.startsWith(".")) {
                        scanDir(fullPath);
                    }
                }
                else if (lstat.isFile()) {
                    files.push(fullPath);
                }
            }
        }
        catch (e) {
            // Skip directories we cannot read
        }
    }
    scanDir(skillPath);
    return files;
}
export async function discoverSkills(scope = "global") {
    const skills = [];
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
                    if (scope === "project" && isGlobal)
                        continue;
                    // Validate and sanitize the path to prevent traversal
                    let safePath = skillData.path;
                    try {
                        safePath = resolveSkillPath(skillData.path);
                    }
                    catch {
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
    }
    catch (e) {
        console.error("Failed to discover skills:", e);
    }
    return skills;
}
