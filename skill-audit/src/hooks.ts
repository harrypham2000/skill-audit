/**
 * Hook Configuration for Claude Code
 * 
 * Provides PreToolUse hook that audits skills before installation.
 * Hook is triggered when user runs `npx skills add <package>`.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, copyFileSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";

// Default settings path for Claude Code
const CLAUDE_SETTINGS_PATH = join(homedir(), ".claude", "settings.json");
const CLAUDE_SETTINGS_BACKUP = join(homedir(), ".claude", "settings.json.backup");
const SKIP_HOOK_FILE = join(homedir(), ".skill-audit-skip-hook");

// Hook identifier for skill-audit
const HOOK_ID = "skill-audit-pre-install";

export interface HookConfig {
  threshold: number;
  blockOnFailure: boolean;
}

/**
 * Get the default hook configuration
 */
export function getDefaultHookConfig(): HookConfig {
  return {
    threshold: 3.0,
    blockOnFailure: true
  };
}

/**
 * Generate the PreToolUse hook configuration
 */
export function generateHookConfig(config: HookConfig = getDefaultHookConfig()): object {
  return {
    hooks: {
      PreToolUse: [
        {
          id: HOOK_ID,
          matcher: {
            toolName: "run_shell_command",
            input: "npx skills add"
          },
          hooks: [
            {
              type: "command",
              command: `skill-audit --mode audit --threshold ${config.threshold}${config.blockOnFailure ? " --block" : ""}`
            }
          ]
        }
      ]
    }
  };
}

/**
 * Check if the skip hook file exists
 */
export function shouldSkipHookPrompt(): boolean {
  return existsSync(SKIP_HOOK_FILE);
}

/**
 * Create the skip hook file
 */
export function createSkipHookFile(): void {
  writeFileSync(SKIP_HOOK_FILE, JSON.stringify({
    createdAt: new Date().toISOString(),
    reason: "User chose to skip hook installation prompt"
  }, null, 2));
}

/**
 * Remove the skip hook file
 */
export function removeSkipHookFile(): void {
  if (existsSync(SKIP_HOOK_FILE)) {
    const fs = require("fs");
    fs.unlinkSync(SKIP_HOOK_FILE);
  }
}

/**
 * Load existing settings.json
 */
function loadSettings(): Record<string, unknown> {
  if (!existsSync(CLAUDE_SETTINGS_PATH)) {
    return {};
  }

  try {
    const content = readFileSync(CLAUDE_SETTINGS_PATH, "utf-8");
    return JSON.parse(content);
  } catch (e) {
    console.error("Failed to parse existing settings.json:", e);
    return {};
  }
}

/**
 * Backup existing settings.json
 */
function backupSettings(): boolean {
  if (!existsSync(CLAUDE_SETTINGS_PATH)) {
    return true; // Nothing to backup
  }

  try {
    // Ensure directory exists
    const settingsDir = dirname(CLAUDE_SETTINGS_BACKUP);
    if (!existsSync(settingsDir)) {
      mkdirSync(settingsDir, { recursive: true });
    }

    copyFileSync(CLAUDE_SETTINGS_PATH, CLAUDE_SETTINGS_BACKUP);
    return true;
  } catch (e) {
    console.error("Failed to backup settings.json:", e);
    return false;
  }
}

/**
 * Check if hook is already installed
 */
export function isHookInstalled(): boolean {
  const settings = loadSettings();

  if (!settings.hooks || !Array.isArray((settings.hooks as Record<string, unknown>).PreToolUse)) {
    return false;
  }

  // PreToolUse can be an array of arrays or array of objects
  const preToolUseHooks = (settings.hooks as Record<string, unknown>).PreToolUse as Array<unknown>;
  
  for (const item of preToolUseHooks) {
    // Handle nested array structure
    if (Array.isArray(item)) {
      if (item.some((h) => h.id === HOOK_ID)) {
        return true;
      }
    } else if (typeof item === "object" && item !== null) {
      if ((item as Record<string, unknown>).id === HOOK_ID) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Install the PreToolUse hook
 */
export function installHook(config: HookConfig = getDefaultHookConfig()): { success: boolean; message: string } {
  // Check if already installed
  if (isHookInstalled()) {
    return { success: true, message: "Hook is already installed" };
  }

  // Backup existing settings
  if (!backupSettings()) {
    return { success: false, message: "Failed to backup settings.json" };
  }

  // Load existing settings
  const settings = loadSettings();

  // Initialize hooks structure if not present
  if (!settings.hooks) {
    settings.hooks = {};
  }

  if (!(settings.hooks as Record<string, unknown>).PreToolUse) {
    (settings.hooks as Record<string, unknown>).PreToolUse = [];
  }

  // Create the new hook object
  const newHook = {
    id: HOOK_ID,
    matcher: {
      toolName: "run_shell_command",
      input: "npx skills add"
    },
    hooks: [
      {
        type: "command",
        command: `skill-audit --mode audit --threshold ${config.threshold}${config.blockOnFailure ? " --block" : ""}`
      }
    ]
  };

  // Add the hook - wrap in array to match existing structure
  const preToolUseHooks = (settings.hooks as Record<string, unknown>).PreToolUse as Array<unknown>;
  preToolUseHooks.push([newHook]);

  // Ensure directory exists
  const settingsDir = dirname(CLAUDE_SETTINGS_PATH);
  if (!existsSync(settingsDir)) {
    mkdirSync(settingsDir, { recursive: true });
  }

  // Write updated settings
  try {
    writeFileSync(CLAUDE_SETTINGS_PATH, JSON.stringify(settings, null, 2));
    return { success: true, message: `Hook installed successfully (threshold: ${config.threshold})` };
  } catch (e) {
    // Restore backup on failure
    if (existsSync(CLAUDE_SETTINGS_BACKUP)) {
      copyFileSync(CLAUDE_SETTINGS_BACKUP, CLAUDE_SETTINGS_PATH);
    }
    return { success: false, message: `Failed to write settings: ${e}` };
  }
}

/**
 * Uninstall the PreToolUse hook
 */
export function uninstallHook(): { success: boolean; message: string } {
  const settings = loadSettings();

  if (!settings.hooks || !Array.isArray((settings.hooks as Record<string, unknown>).PreToolUse)) {
    return { success: true, message: "No hooks to remove" };
  }

  const preToolUseHooks = (settings.hooks as Record<string, unknown>).PreToolUse as Array<unknown>;
  const initialLength = preToolUseHooks.length;

  // Filter out our hook (handles nested array structure)
  const filteredHooks = preToolUseHooks.filter((item) => {
    if (Array.isArray(item)) {
      return !item.some((h) => h.id === HOOK_ID);
    } else if (typeof item === "object" && item !== null) {
      return (item as Record<string, unknown>).id !== HOOK_ID;
    }
    return true;
  });

  if (filteredHooks.length === initialLength) {
    return { success: true, message: "Hook was not installed" };
  }

  // Backup before modification
  if (!backupSettings()) {
    return { success: false, message: "Failed to backup settings.json" };
  }

  // Update settings
  (settings.hooks as Record<string, unknown>).PreToolUse = filteredHooks;

  // Remove hooks object if empty
  if (filteredHooks.length === 0) {
    delete (settings.hooks as Record<string, unknown>).PreToolUse;
  }

  if (Object.keys(settings.hooks as Record<string, unknown>).length === 0) {
    delete settings.hooks;
  }

  // Write updated settings
  try {
    writeFileSync(CLAUDE_SETTINGS_PATH, JSON.stringify(settings, null, 2));
    return { success: true, message: "Hook uninstalled successfully" };
  } catch (e) {
    // Restore backup on failure
    if (existsSync(CLAUDE_SETTINGS_BACKUP)) {
      copyFileSync(CLAUDE_SETTINGS_BACKUP, CLAUDE_SETTINGS_PATH);
    }
    return { success: false, message: `Failed to write settings: ${e}` };
  }
}

/**
 * Get hook status
 */
export function getHookStatus(): {
  installed: boolean;
  config?: HookConfig;
  settingsPath: string;
} {
  const settings = loadSettings();

  if (!settings.hooks || !Array.isArray((settings.hooks as Record<string, unknown>).PreToolUse)) {
    return { installed: false, settingsPath: CLAUDE_SETTINGS_PATH };
  }

  const preToolUseHooks = (settings.hooks as Record<string, unknown>).PreToolUse as Array<unknown>;
  
  // Find the hook in nested array structure
  let hook: Record<string, unknown> | undefined;
  for (const item of preToolUseHooks) {
    if (Array.isArray(item)) {
      hook = item.find((h) => h.id === HOOK_ID);
      if (hook) break;
    } else if (typeof item === "object" && item !== null) {
      if ((item as Record<string, unknown>).id === HOOK_ID) {
        hook = item as Record<string, unknown>;
        break;
      }
    }
  }

  if (!hook) {
    return { installed: false, settingsPath: CLAUDE_SETTINGS_PATH };
  }

  // Extract config from hook command
  const hookHooks = hook.hooks as Array<Record<string, unknown>>;
  const command = (hookHooks[0] as Record<string, unknown>).command as string;
  const thresholdMatch = command.match(/--threshold\s+([\d.]+)/);
  const threshold = thresholdMatch ? parseFloat(thresholdMatch[1]) : 3.0;
  const blockOnFailure = command.includes("--block");

  return {
    installed: true,
    config: { threshold, blockOnFailure },
    settingsPath: CLAUDE_SETTINGS_PATH
  };
}