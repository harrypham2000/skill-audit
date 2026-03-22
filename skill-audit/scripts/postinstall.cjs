#!/usr/bin/env node

/**
 * Postinstall script for skill-audit
 *
 * Displays information about hook setup. Does NOT prompt for input
 * to avoid blocking installation in non-interactive contexts.
 *
 * Users can run 'skill-audit --install-hook' to set up the hook.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");

// Paths
const SKIP_HOOK_FILE = path.join(os.homedir(), ".skill-audit-skip-hook");
const SETTINGS_PATH = path.join(os.homedir(), ".claude", "settings.json");

// Check if running in CI
function isCI() {
  return (
    process.env.CI === "true" ||
    process.env.CONTINUOUS_INTEGRATION === "true" ||
    process.env.GITHUB_ACTIONS === "true" ||
    process.env.GITLAB_CI === "true" ||
    process.env.CIRCLECI === "true" ||
    process.env.TRAVIS === "true" ||
    process.env.JENKINS_URL !== undefined ||
    process.env.BUILDKITE === "true"
  );
}

// Check if skip file exists
function shouldSkipPrompt() {
  return fs.existsSync(SKIP_HOOK_FILE);
}

// Check if hook is already installed
function isHookInstalled() {
  if (!fs.existsSync(SETTINGS_PATH)) {
    return false;
  }

  try {
    const settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, "utf-8"));
    if (!settings.hooks || !Array.isArray(settings.hooks.PreToolUse)) {
      return false;
    }

    // Check nested array structure
    for (const item of settings.hooks.PreToolUse) {
      if (Array.isArray(item)) {
        if (item.some((h) => h.id === "skill-audit-pre-install")) {
          return true;
        }
      } else if (item && item.id === "skill-audit-pre-install") {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

// Main function - non-blocking, just prints info
function main() {
  // Skip in CI environments
  if (isCI()) {
    return;
  }

  // Skip if user previously chose to skip
  if (shouldSkipPrompt()) {
    return;
  }

  // Skip if hook is already installed
  if (isHookInstalled()) {
    console.log("\n  ✓ skill-audit hook is already installed\n");
    return;
  }

  // Just print a message, don't prompt
  console.log("\n");
  console.log("  ┌─────────────────────────────────────────────────────────┐");
  console.log("  │           🛡️  skill-audit installed!                   │");
  console.log("  ├─────────────────────────────────────────────────────────┤");
  console.log("  │                                                         │");
  console.log("  │  Protect your skills from vulnerabilities:              │");
  console.log("  │                                                         │");
  console.log("  │    skill-audit --install-hook                           │");
  console.log("  │                                                         │");
  console.log("  │  This adds a PreToolUse hook that audits skills         │");
  console.log("  │  before installation via 'npx skills add'.             │");
  console.log("  │                                                         │");
  console.log("  │  Run 'skill-audit --help' for more options.             │");
  console.log("  │                                                         │");
  console.log("  └─────────────────────────────────────────────────────────┘");
  console.log("\n");
}

// Run main (synchronous, no async/await)
try {
  main();
} catch (error) {
  // Silently fail - don't block installation
}