# skill-audit

Security auditing tool for AI agent skills.

> Part of the [Vercel Skills](https://skills.sh) ecosystem — validating skills against the Agent Skills specification and detecting vulnerabilities across OWASP Agentic Top 10 categories.

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

- **[Vercel Skills](https://skills.sh)** — Agent skills registry and runtime
- **[GoClaw](https://github.com/nextlevelbuilder/goclaw)** — Eval-driven approach inspiration
- **[OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai-application-security-verification-standard/)** — Security standard reference

## License

MIT
