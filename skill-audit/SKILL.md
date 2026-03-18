---
name: skill-audit
description: This skill should be used when the user asks to "audit AI agent skills for security vulnerabilities", "evaluate third-party skills before installing", "check for prompt injection or secrets leakage", "scan skills for code execution risks", "validate skills against Agent Skills specification", or "assess skill security posture with CVE/GHSA/KEV/EPSS intelligence".
license: MIT
compatibility: Node.js 18+ with npm or yarn
metadata:
  repo: https://github.com/vercel/skill-audit
  version: 0.2.0
allowed-tools:
  - skill:exec
  - skill:read
  - skill:write
---

# skill-audit

Security auditing CLI for AI agent skills in the Vercel ecosystem.

## When to Use

Activate this skill when:

- **Evaluating third-party skills** before installing from untrusted sources
- **Security concerns arise** about prompt injection, secrets leakage, code execution, or data exfiltration
- **Compliance verification** needed against Agent Skills specification
- **Pre-deployment audit** before publishing your own skill
- **Investigating suspicious behavior** from an installed skill

### When NOT to Use

- Auditing general npm/Python packages (use `npm audit`, `safety`, or dependency scanners directly)
- Reviewing non-skill code (use `security-reviewer` agent instead)
- Checking only spec format without security concerns (use `--mode lint` for fast validation)

## Quick Start

```bash
# Fast spec validation (no security scan)
npx skill-audit --mode lint

# Full security audit
npx skill-audit --mode audit

# Fail if risk score exceeds threshold
npx skill-audit -t 3.0

# Export JSON report
npx skill-audit -j -o ./audit-report.json
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

## After Running Audit

### Decision Matrix

| Risk Level | Score | Action |
|------------|-------|--------|
| ✅ Safe | 0 | Deploy or install without concerns |
| ⚠️ Risky | 0.1-3.0 | Review findings; acceptable for low-risk use cases |
| 🔴 Dangerous | 3.1-7.0 | Fix issues before deployment; significant risks present |
| ☠️ Malicious | 7.1-10.0 | DO NOT USE; contains critical vulnerabilities or malicious patterns |

### Common Findings Interpretation

| Finding ID | Category | Meaning |
|------------|----------|---------|
| SPEC-01 | Specification | SKILL.md missing or malformed frontmatter |
| ASI01-01 | Prompt Injection | Contains patterns that could override system instructions |
| ASI04-01 | Secrets | Hardcoded API keys, tokens, or credentials detected |
| ASI05-01 | Code Execution | Dynamic code execution without proper sandboxing |
| ASI02-01 | Exfiltration | Potential data leakage to untrusted endpoints |
| VULN-* | Dependency | Known vulnerability in skill's dependencies (see CVE ID) |

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
| `--update-db` | Update vulnerability intelligence feeds |
| `--strict` | Fail if feed update errors occur |
| `--quiet` | Suppress non-error output |

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

# Fail on dangerous skills (score > 3.0)
npx skill-audit -g -t 3.0

# Update intelligence feeds
npx skill-audit --update-db --source kev epss

# Audit project-level skills only
npx skill-audit -p --mode audit -v
```

### Sample Output Interpretation

```
🔍 Auditing skills (full security + intelligence)...
Found 3 skills

📊 Summary (audit mode):
   Safe: 1 | Risky: 1 | Dangerous: 1 | Malicious: 0
   Skills with spec issues: 1 | Security issues: 2

⚠️  Vulnerability DB is stale (4.2 days for KEV, 5.1 days for EPSS)
   Run: npx skill-audit --update-db

❌ 1 skills exceed threshold 3.0
   - suspicious-skill: 5.8
```

**Actions:**
1. Run `--update-db` if vulnerability feeds are stale
2. Review verbose output (`-v`) for skills exceeding threshold
3. Block deployment for skills scoring > 3.0 without remediation

## How It Works

Three-layer validation approach:

1. **Spec Validator**
   - Validates Agent Skills format
   - Blocks on spec errors before security scan

2. **Security Auditor**
   - Pattern-based detection for vulnerabilities
   - Maps to OWASP Agentic Top 10

3. **Intelligence Service**
   - Caches CVE/GHSA/KEV/EPSS data
   - Native HTTP/fetch (no shell dependencies)

## Related Skills

| Skill | When to Use |
|-------|-------------|
| `security-review` | Manual security checklist for code implementation |
| `tdd-workflow` | Test-driven development for skill development |
| `writing-skills` | Creating new skills with TDD methodology |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Vulnerability DB is stale" warning | Run `npx skill-audit --update-db` |
| False positive on prompt injection | Review context - sample JSON output may trigger detections |
| Dependency scan fails | Ensure lockfile exists; run `npm install` or equivalent |
| Skill path not found | Verify symlink resolution; check case sensitivity |

## References

### External Resources

- **[OWASP AI Security Top 10](https://owasp.org/www-project-top-ten.html)** - ASI01-ASI10 threat categories
- **[CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** - Actively exploited vulnerabilities
- **[FIRST EPSS](https://www.first.org/epss/)** - Exploit Prediction Scoring System
- **[OSV.dev](https://osv.dev/)** - Open Source Vulnerability database

### Intelligence Cache

| Source | Update Frequency | Max Cache Age | Warning Threshold |
|--------|-----------------|---------------|-------------------|
| CISA KEV | Daily | 1 day | 3 days |
| FIRST EPSS | 3-day cycle | 3 days | 3 days |
| OSV.dev | On-query | 7 days | 3 days |
