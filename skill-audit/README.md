# skill-audit

Security auditing CLI for AI agent skills.

## Features

- **Static Analysis**: Detect prompt injection, dangerous scripts, hardcoded secrets
- **Dependency Scanning**: Uses Trivy to scan for known vulnerabilities in dependencies
- **Risk Scoring**: 0-10 score mapped to OWASP Agentic Top 10 (ASI01-ASI10)
- **Multi-Agent Support**: Groups results by agent (Claude Code, Qwen Code, Gemini CLI, etc.)
- **CI/CD Ready**: JSON output, threshold-based pass/fail

## Installation

```bash
npm install -g @hungpg/skill-audit
```

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
| CISA KEV | Daily | 7 days |
| FIRST EPSS | Daily | 7 days |
| OSV.dev | On-query | 7 days |

**Automatic updates:**
- Runs on `npm install` via `postinstall` hook
- Daily GitHub Actions workflow (public repos)
- Manual: `npx skill-audit --update-db`

**Stale cache warning:** Audit output warns if feeds are >3 days old.

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
