# skill-audit

![npm](https://img.shields.io/npm/v/skill-audit)
![npm downloads](https://img.shields.io/npm/dm/skill-audit)
![License](https://img.shields.io/npm/l/skill-audit)

Security auditing tool for AI agent skills.

> Part of the [Vercel Skills](https://skills.sh) ecosystem — validating skills against the Agent Skills specification and detecting vulnerabilities across OWASP Agentic Top 10 categories.

## Why

AI agent skills can execute arbitrary code, access files, and make network requests.
Before installing a third-party skill, you need to know:
- Does it try to hijack the agent's goals?
- Does it leak your API keys or tokens?
- Does it run dangerous scripts?
- Are its dependencies vulnerable?

`skill-audit` answers these questions automatically.

## Overview

`skill-audit` is a CLI tool that validates AI agent skills for security risks before installation. It detects:

- **Prompt injection** patterns (ASI01)
- **Credential leaks** / hardcoded secrets (ASI04)
- **Code execution** risks (ASI05)
- **Exfiltration** patterns (ASI02)
- **Behavioral manipulation** (ASI09)
- **Dependency vulnerabilities** (CVE/GHSA/KEV/EPSS)

## Quick Start

```bash
# Audit global skills
npx skill-audit -g

# Lint mode (spec validation only - fast)
npx skill-audit --mode lint

# Full audit with JSON output
npx skill-audit --mode audit -j > audit-results.json

# Fail CI/CD on dangerous skills
npx skill-audit -g -t 3.0
```

## Sample Output

```
🔍 Auditing 3 skills...

✅ safe-skill (0.5) - No issues
⚠️  risky-skill (3.2) - 2 findings
   - PI-001: Prompt injection pattern detected (SKILL.md:15)
   - SC-003: Hardcoded API key pattern (src/index.ts:8)
🔴 dangerous-skill (6.8) - 5 findings, exceeds threshold

❌ 1 skill exceeds threshold 3.0
```

## CI/CD Integration

```yaml
# .github/workflows/audit-skills.yml
name: Audit Skills
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx skill-audit -g -t 3.0 --json > results.json
      - uses: actions/upload-artifact@v4
        with:
          name: audit-results
          path: results.json
```

## Project Structure

```
.
├── README.md              # This file (project overview)
├── skill-audit/           # npm package
│   ├── README.md          # Package documentation
│   ├── SKILL.md           # Agent skill definition
│   ├── src/               # TypeScript source
│   └── package.json       # npm manifest
└── rules/                 # Security patterns (future)
```

## Packages

| Package | Description |
|---------|-------------|
| [`skill-audit`](./skill-audit/) | CLI tool for auditing AI agent skills |

## Risk Scoring

| Level | Score | Action |
|-------|-------|--------|
| ✅ Safe | 0-3.0 | No issues or minor concerns |
| ⚠️ Risky | 3.1-5.0 | Review recommended |
| 🔴 Dangerous | 5.1-7.0 | Fix before use |
| ☠️ Malicious | 7.1+ | Do not use |

## Vulnerability Intelligence

Enriched with real-time threat data from:

- **CISA KEV** — Known Exploited Vulnerabilities (daily updates)
- **FIRST EPSS** — Exploit Prediction Scoring System (3-day updates)
- **OSV.dev** — Open Source Vulnerabilities database

### Automatic Updates

The vulnerability database updates automatically:

1. **On install** - `postinstall` hook fetches latest KEV/EPSS feeds
2. **Daily** - GitHub Actions workflow keeps cache fresh (public repos)
3. **Manual** - Run `npx skill-audit --update-db` anytime

⚠️ **Stale cache warning**: If feeds are >3 days old, audit output will warn you to update.

### Manual Cron Setup (Enterprise)

For environments without GitHub Actions:

```bash
# Daily update at 2 AM (Linux/macOS)
0 2 * * * cd /path/to/skill-audit && npx skill-audit --update-db --quiet

# Windows Task Scheduler
schtasks /create /tn "skill-audit-update" /tr "npx skill-audit --update-db" /sc daily /st 02:00
```

## Use Cases

### For Skill Authors
- Validate your skill before publishing
- Catch security issues early in development
- Ensure Agent Skills spec compliance

### For Skill Users
- Audit third-party skills before installation
- CI/CD gate for skill installation pipelines
- Generate security reports for compliance

### For Registries
- Automated skill validation at submission
- Risk scoring for skill discovery
- Vulnerability monitoring across skill ecosystem

## Related Projects

### Vercel Skills Ecosystem
- **[Vercel Skills](https://skills.sh)** — Agent skills registry and runtime where `skill-audit` validates submissions
- **[Anthropic Agent Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills)** — SKILL.md specification that `skill-audit` validates against

### Security & Validation
- **[GoClaw](https://github.com/nextlevelbuilder/goclaw)** — Multi-agent gateway with 5-layer security (prompt injection detection, SSRF protection, shell deny patterns). Inspired `skill-audit`'s pattern-based vulnerability detection
- **[Trivy](https://github.com/aquasecurity/trivy)** — Vulnerability scanner used by `skill-audit` for dependency CVE scanning

### Standards
- **[OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai-application-security-verification-standard/)** — ASI01-ASI10 threat categories that `skill-audit` maps findings to

## License

MIT
