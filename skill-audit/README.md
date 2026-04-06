# skill-audit

Security auditing CLI for AI agent skills.

## Features

- **Static Analysis**: Detect prompt injection, dangerous scripts, hardcoded secrets
- **Dependency Scanning**: Uses Trivy to scan for known vulnerabilities in dependencies
- **Risk Scoring**: 0-10 score mapped to OWASP Agentic Top 10 (ASI01-ASI10)
- **Multi-Agent Support**: Groups results by agent (Claude Code, Qwen Code, Gemini CLI, etc.)
- **CI/CD Ready**: JSON output, threshold-based pass/fail

## Installation

### Option 1: Install via npm (Recommended for CLI)

```bash
npm install -g @hungpg/skill-audit
```

This installs the CLI globally and triggers the postinstall hook prompt.

### Option 2: Install via bun (Fast Alternative)

```bash
bun install -g @hungpg/skill-audit
```

Bun is significantly faster than npm for installation.

### Option 3: Install as a Skill (For Claude Code)

```bash
# Install from GitHub repo (not npm package name)
npx skills add harrypham2000/skill-audit -g -y
```

> ⚠️ **Important**: The skills CLI expects `owner/repo` format, not npm scoped packages.
> - ✅ Correct: `harrypham2000/skill-audit`
> - ❌ Incorrect: `@hungpg/skill-audit`

### Option 4: Install for Qwen Code

```bash
# Clone to Qwen skills directory
mkdir -p ~/.qwen/skills
git clone https://github.com/harrypham2000/skill-audit.git ~/.qwen/skills/skill-audit
cd ~/.qwen/skills/skill-audit/skill-audit
npm install && npm run build

# Or with bun (faster)
bun install && bun run build
```

### Option 5: Install for Gemini CLI

```bash
# Clone to Gemini skills directory
mkdir -p ~/.gemini/skills
git clone https://github.com/harrypham2000/skill-audit.git ~/.gemini/skills/skill-audit
cd ~/.gemini/skills/skill-audit/skill-audit
npm install && npm run build

# Or with bun (faster)
bun install && bun run build
```

## About the Postinstall Script

This package includes a `postinstall` script that runs automatically after `npm install`. **This script is completely safe and informational only:**

- ✅ Does NOT automatically install any hooks
- ✅ Does NOT execute any code that could be considered malicious
- ✅ Does NOT make any network requests
- ✅ Does NOT modify any files without user consent
- ✅ Does NOT collect any user data

The script simply displays a banner message prompting users to optionally run `skill-audit --install-hook` if they want to set up automatic skill auditing. Users must manually run this command to install the hook.

In CI environments (GitHub Actions, GitLab CI, Jenkins, etc.), the script exits silently without displaying anything.

## Automatic Hook Setup

After installation, you'll see a message about setting up the PreToolUse hook:

```
┌─────────────────────────────────────────────────────────┐
│           🛡️  skill-audit installed!                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Protect your skills from vulnerabilities:              │
│                                                         │
│    skill-audit --install-hook                           │
│                                                         │
│  This adds a PreToolUse hook that audits skills         │
│  before installation via 'npx skills add'.             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

Run the command to set up automatic skill auditing:

```bash
skill-audit --install-hook
```

### Manual Hook Management

```bash
# Install hook manually
skill-audit --install-hook

# Install with custom threshold
skill-audit --install-hook --hook-threshold 5.0

# Check hook status
skill-audit --hook-status

# Remove hook
skill-audit --uninstall-hook
```

### How the Hook Works

1. **Trigger**: When you run `npx skills add <package>`
2. **Scan**: skill-audit analyzes the skill before installation
3. **Decision**:
   - Risk score ≤ 3.0 → Installation proceeds
   - Risk score > 3.0 → Installation blocked
4. **Report**: Detailed findings shown in terminal

## Usage

```bash
# Audit global skills
skill-audit -g

# Audit with verbose output
skill-audit -v

# JSON output for CI
skill-audit --json > audit-results.json

# Fail if risk score exceeds threshold
skill-audit --threshold 5.0

# Skip dependency scanning (faster)
skill-audit --no-deps

# Filter by agent
skill-audit -a "Claude Code" "Qwen Code"

# Project-level skills only
skill-audit --project

# Lint mode (spec validation only)
skill-audit --mode lint

# Update vulnerability DB manually
skill-audit --update-db
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-g, --global` | Audit global skills | ✓ |
| `-p, --project` | Audit project-level skills | |
| `--mode <lint|audit>` | Lint (spec) or full audit | audit |
| `-t, --threshold <score>` | Fail if risk > threshold | 7.0 |
| `-j, --json` | JSON output | |
| `-o, --output <file>` | Save to file | |
| `--no-deps` | Skip dependency scan | |
| `-v, --verbose` | Verbose output | |
| `--install-hook` | Install PreToolUse hook | |
| `--uninstall-hook` | Remove PreToolUse hook | |
| `--hook-threshold <score>` | Hook risk threshold | 3.0 |
| `--hook-status` | Show hook status | |
| `--block` | Exit 1 if threshold exceeded | |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (no blocking issues) |
| 1 | Threshold exceeded or errors |

## Risk Levels

| Level | Score | Icon |
|-------|-------|------|
| Safe | 0-3.0 | ✅ |
| Risky | 3.1-5.0 | ⚠️ |
| Dangerous | 5.1-7.0 | 🔴 |
| Malicious | 7.1+ | ☠️ |

## OWASP Agentic Top 10 Mapping

- **ASI01** - Goal Hijack (prompt injection)
- **ASI02** - Tool Misuse and Exploitation
- **ASI04** - Supply Chain Vulnerabilities (secrets, deps)
- **ASI05** - Unexpected Code Execution (dangerous scripts)

## Vulnerability Intelligence

Feeds are cached locally with automatic freshness checks:

| Source | Update Frequency | Cache Lifetime |
|--------|------------------|----------------|
| CISA KEV | Daily | 1 day |
| NIST NVD | Daily | 1 day |
| FIRST EPSS | Daily | 3 days |
| OSV.dev | On-query | 7 days |
| GHSA | On-query | 3 days |

**Automatic updates:**
- Runs on `npm install` via `postinstall` hook
- Daily GitHub Actions workflow (public repos)
- Manual: `npx skill-audit --update-db`

**Stale cache warning:** Audit output warns if feeds are >3 days old.

### NVD Synchronization

The `--update-db` command fetches CVEs modified in the last 24 hours only.
For initial setup or after extended offline periods, run multiple times to build historical data:

```bash
# Multiple updates to build historical data
skill-audit --update-db
skill-audit --update-db
skill-audit --update-db
```

Note: NVD API rate limits apply (5 requests/30 sec without API key). Set `NVD_API_KEY` environment variable for 50 requests/30 sec.

## Trust Sources

1. Static pattern matching for known attack vectors
2. Trivy for dependency vulnerability scanning
3. Heuristic rules for common security issues

## Requirements

- Node.js 18+
- npx (for skills CLI)
- trivy (optional, for dependency scanning)

## Troubleshooting

**False positives**: Review finding at file:line, add inline comment explaining legitimate use

**Stale DB warning**: Run `skill-audit --update-db` to refresh KEV/EPSS/OSV feeds

**Skill not found**: Verify `SKILL.md` exists in root or `skills/` directory

**postinstall update fails**: The `--quiet || true` flags ensure install continues even if update fails. Run manually later.

**Offline mode**: Cached feeds work offline. Re-run audit with existing cache.

