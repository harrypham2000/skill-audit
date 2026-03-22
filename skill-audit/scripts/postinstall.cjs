#!/usr/bin/env node

/**
 * Postinstall script for skill-audit
 * 
 * Prompts user to install PreToolUse hook that audits skills
 * before installation via `npx skills add`.
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
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
    process.env.BUILDKITE === "true" ||
    process.env.npm_config_global === undefined && process.env.npm_package_name === undefined
  );
}

// Check if skip file exists
function shouldSkipPrompt() {
  return fs.existsSync(SKIP_HOOK_FILE);
}

// Create skip file
function createSkipFile() {
  fs.writeFileSync(
    SKIP_HOOK_FILE,
    JSON.stringify(
      {
        createdAt: new Date().toISOString(),
        reason: "User chose to skip hook installation prompt",
      },
      null,
      2
    )
  );
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

    return settings.hooks.PreToolUse.some(
      (hook) => hook.id === "skill-audit-pre-install"
    );
  } catch {
    return false;
  }
}

// Install hook using the CLI
function installHook() {
  try {
    execSync("skill-audit --install-hook", { stdio: "inherit" });
    return true;
  } catch (error) {
    console.error("Failed to install hook:", error.message);
    return false;
  }
}

// Prompt user for input
function prompt(question) {
  const readline = require("readline");
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase());
    });
  });
}

// Main function
async function main() {
  // Skip in CI environments
  if (isCI()) {
    console.log("Skipping hook installation prompt (CI environment)");
    return;
  }

  // Skip if user previously chose to skip
  if (shouldSkipPrompt()) {
    return;
  }

  // Skip if hook is already installed
  if (isHookInstalled()) {
    console.log("✓ skill-audit hook is already installed");
    return;
  }

  // Check if running in a terminal
  if (!process.stdout.isTTY) {
    console.log("\n📦 skill-audit installed!");
    console.log("   Run 'skill-audit --install-hook' to set up automatic skill auditing.");
    return;
  }

  // Display prompt
  console.log("\n");
  console.log("╔════════════════════════════════════════════════════════════╗");
  console.log("║                 🛡️  skill-audit hook setup                 ║");
  console.log("╠════════════════════════════════════════════════════════════╣");
  console.log("║                                                            ║");
  console.log("║  skill-audit can automatically audit skills before        ║");
  console.log("║  installation to protect you from malicious packages.     ║");
  console.log("║                                                            ║");
  console.log("║  When you run 'npx skills add <package>', the hook will:  ║");
  console.log("║    • Scan the skill for security vulnerabilities          ║");
  console.log("║    • Check for prompt injection, secrets, code execution  ║");
  console.log("║    • Block installation if risk score > 3.0               ║");
  console.log("║                                                            ║");
  console.log("╚════════════════════════════════════════════════════════════╝");
  console.log("\n");

  console.log("Options:");
  console.log("  [Y] Yes, install the hook (recommended)");
  console.log("  [N] No, skip for now");
  console.log("  [S] Skip forever (don't ask again)");
  console.log("");

  const answer = await prompt("Your choice [Y/n/s]: ");

  switch (answer) {
    case "":
    case "y":
    case "yes":
      console.log("\nInstalling hook...");
      if (installHook()) {
        console.log("\n✅ Hook installed successfully!");
        console.log("   Skills will now be audited before installation.");
        console.log("   Run 'skill-audit --uninstall-hook' to remove.\n");
      } else {
        console.log("\n❌ Failed to install hook.");
        console.log("   You can try manually: skill-audit --install-hook\n");
      }
      break;

    case "n":
    case "no":
      console.log("\nSkipping hook installation.");
      console.log("   Run 'skill-audit --install-hook' anytime to set up.\n");
      break;

    case "s":
    case "skip":
      createSkipFile();
      console.log("\nSkipping hook installation (won't ask again).");
      console.log("   Delete ~/.skill-audit-skip-hook to re-enable prompt.\n");
      break;

    default:
      console.log("\nInvalid choice. Skipping for now.");
      console.log("   Run 'skill-audit --install-hook' anytime to set up.\n");
  }
}

// Run main
main().catch((error) => {
  console.error("Postinstall error:", error.message);
  process.exit(0); // Don't fail install
});