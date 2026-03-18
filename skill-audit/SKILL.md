---
name: skill-audit
description: Security auditing CLI for AI agent skills in the Vercel ecosystem. Validates skills against Agent Skills spec, detects vulnerabilities (prompt injection, code execution, secrets, exfiltration), and enriches findings with CVE/GHSA/KEV/EPSS intelligence.
license: MIT
compatibility: Node.js 18+ with npm or yarn
metadata:
  repo: https://github.com/vercel/skill-audit
  version: 0.1.0
allowed-tools:
  - skill:exec
  - skill:read
  - skill:write
---

# skill-audit

Security auditing tool for AI agent skills.

## Usage

```bash
# Lint skills (spec validation only - fast)
npx skill-audit --mode lint

# Full audit (spec + security + dependency scanning)
npx skill-audit --mode audit

# Update advisory intelligence feeds
npx skill-audit --update-db
```

## Commands

### `lint`

Validates skills against Agent Skills specification:
- SKILL.md exists with valid frontmatter
- name matches directory (lowercase, 1-64 chars, no consecutive hyphens)
- description present (1-1024 chars)
- allowed-tools structure valid
- Progressive disclosure (warns if SKILL.md > 500 lines)

### `audit`

Full security audit including:
- Prompt injection patterns (ASI01)
- Credential leaks / secrets (ASI04)
- Code execution risks (ASI05)
- Exfiltration patterns (ASI02)
- Behavioral manipulation (ASI09)
- Provenance checks (trusted domains, pinned refs)
- Dependency vulnerability scanning

### `update-db`

Pulls latest vulnerability intelligence:
- CISA KEV (Known Exploited Vulnerabilities)
- FIRST EPSS (Exploit Prediction Scoring) - via api.first.org/data/v1
- OSV.dev vulnerabilities

Caches to `.cache/skill-audit/feeds/` for offline use.

## Options

| Flag | Description |
|------|-------------|
| `-g, --global` | Audit global skills (default) |
| `-p, --project` | Audit project-level skills |
| `-a, --agent <agents>` | Filter by specific agents |
| `-j, --json` | Output as JSON |
| `-o, --output <file>` | Save report to file (JSON format) |
| `-v, --verbose` | Show detailed findings |
| `-t, --threshold <score>` | Fail if risk score exceeds threshold |
| `--no-deps` | Skip dependency scanning |
| `--mode <mode>` | `lint` or `audit` (default: audit) |

## Risk Scoring

| Level | Score | Description |
|-------|-------|-------------|
| ✅ Safe | 0 | No issues found |
| ⚠️ Risky | 0.1-3.0 | Minor issues, review recommended |
| 🔴 Dangerous | 3.1-7.0 | Significant risks, fix before use |
| ☠️ Malicious | 7.1-10.0 | Critical issues, do not use |

## Exit Codes

- `0`: Success (no blocking issues)
- `1`: Threshold exceeded or blocking findings

## Examples

```bash
# Quick spec check
npx skill-audit -g --mode lint -v

# Full audit with JSON output
npx skill-audit -g --mode audit -j > audit-results.json

# Export report to file
npx skill-audit -g -o ./audit-report.json

# Fail on dangerous skills
npx skill-audit -g -t 3.0

# Update intelligence feeds
npx skill-audit --update-db --source kev epss
```

## Architecture

Three-layer validation approach:

1. **Spec Validator** (`src/spec.ts`)
   - Validates Agent Skills format
   - Blocks on spec errors before security scan

2. **Security Auditor** (`src/security.ts`)
   - Pattern-based detection for vulnerabilities
   - Maps to OWASP Agentic Top 10

3. **Intelligence Service** (`src/intel.ts`)
   - Caches CVE/GHSA/KEV/EPSS data
   - Native HTTP/fetch (no shell dependencies)