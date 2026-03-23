---
name: skill-audit
description: This skill should be used when the user asks to "audit AI agent skills for security vulnerabilities", "evaluate third-party skills before installing", "check for prompt injection or secrets leakage", "scan skills for PII exposure", "validate compliance with AI regulations", "scan skills for code execution risks", "validate skills against Agent Skills specification", or "assess skill security posture with CVE/GHSA/KEV/EPSS/NVD intelligence".
license: MIT
compatibility: Node.js 18+ with npm or yarn
metadata:
  repo: https://github.com/harrypham2000/skill-audit
  version: 0.5.1
allowed-tools:
  - skill:exec
  - skill:read
  - skill:write
---

# skill-audit

Security auditing CLI for AI agent skills with **PII detection** and **compliance validation**.

## What's New in v0.5.1

- 📦 **Progressive Disclosure**: Added `references/`, `examples/`, and `scripts/` directories for better skill organization
- 📚 **Reference Documentation**: 4 new reference files with detailed PII patterns, compliance frameworks, scoring methodology, and intelligence sources
- 🧪 **Example Outputs**: Sample audit, lint, and compliance reports for users
- 🔧 **Utility Scripts**: `validate-skill.sh` and `test-audit.sh` for development workflows

## What's New in v0.5.0

- ⚡ **Auto-Update Intelligence Feeds**: Vulnerability databases (KEV, EPSS, NVD) now update automatically when the skill is loaded in audit mode - no manual `--update-db` needed
- 🔐 **PII Detection**: 39 patterns for Vietnam and International PII (CCCD, SSN, Credit Cards, API Keys, etc.)
- 📋 **Compliance Validation**: Checks against Vietnam AI Law 2026, EU AI Act, and GDPR
- 🚨 **PII-Aware Exfiltration Detection**: Detects when PII is being sent to external endpoints

## Installation for Agents

### Claude Code

```bash
# Option 1: Install as skill from GitHub
npx skills add harrypham2000/skill-audit -g -y

# Option 2: Install CLI via npm
npm install -g @hungpg/skill-audit

# Option 3: Install CLI via bun (faster)
bun install -g @hungpg/skill-audit
```

### Qwen Code

```bash
# Clone to Qwen skills directory
mkdir -p ~/.qwen/skills
git clone https://github.com/harrypham2000/skill-audit.git ~/.qwen/skills/skill-audit
cd ~/.qwen/skills/skill-audit/skill-audit

# Install with npm
npm install && npm run build

# Or with bun (faster)
bun install && bun run build
```

### Gemini CLI

```bash
# Clone to Gemini skills directory
mkdir -p ~/.gemini/skills
git clone https://github.com/harrypham2000/skill-audit.git ~/.gemini/skills/skill-audit
cd ~/.gemini/skills/skill-audit/skill-audit

# Install with npm
npm install && npm run build

# Or with bun (faster)
bun install && bun run build
```

> ⚠️ **Important for Skills CLI**: Use `owner/repo` format, not npm scoped names.
> - ✅ Correct: `harrypham2000/skill-audit`
> - ❌ Incorrect: `@hungpg/skill-audit`

## When to Use

This skill activates when:

- **Evaluating third-party skills** before installing from untrusted sources
- **Security concerns arise** about prompt injection, secrets leakage, code execution, or data exfiltration
- **Compliance verification** needed against Agent Skills specification
- **Pre-deployment audit** before publishing your own skill
- **Investigating suspicious behavior** from an installed skill

### When NOT to Use

- Auditing general npm/Python packages (use `npm audit`, `safety`, or dependency scanners)
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
- **PII detection (ASI03)** - 39 patterns for Vietnam and International PII
- **Compliance validation** - Vietnam AI Law 2026, EU AI Act, GDPR

### PII Detection

Detects 39 types of Personally Identifiable Information:

| Category | Types |
|----------|-------|
| **Vietnam PII** | CCCD (Citizen ID), CMND (Old ID), Tax ID (TIN), Phone, Bank Account, License Plate, BHXH, Military ID, Passport |
| **International PII** | US SSN, Credit Card, IBAN, NHS (UK), Passport (US/EU/UK/JP/KR), IP Address, Email |
| **Secrets** | OpenAI/Anthropic/AWS/GitHub/Stripe API keys, PEM keys, JWTs, Database connection strings |

See `references/pii-patterns.md` for complete pattern list and regex details.

### Compliance Validation

Validates skills against regulatory frameworks:

| Framework | Requirements | Risk Levels |
|-----------|-------------|-------------|
| **Vietnam AI Law 2026** | Data localization, User consent, Transparency, Human oversight, Data minimization, Right to explanation, Bias prevention | minimal, limited, high, unacceptable |
| **EU AI Act** | Risk assessment, Data governance, Technical documentation, Record keeping, Transparency | minimal, limited, high, unacceptable |
| **GDPR** | Lawful basis, Data subject rights, Privacy by design, DPIA, Breach notification, International transfers | minimal, limited, high, unacceptable |

See `references/compliance-frameworks.md` for detailed requirements and remediation guidance.

### `update-db`

Pulls latest vulnerability intelligence:
- CISA KEV (Known Exploited Vulnerabilities)
- FIRST EPSS (Exploit Prediction Scoring) - via api.first.org/data/v1
- NIST NVD (National Vulnerability Database) - CVSS scores, CWE mappings
- GitHub Security Advisories (GHSA) - ecosystem-specific advisories
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
| **PII-001 to PII-039** | **PII Detection** | **Personally Identifiable Information detected (Vietnam CCCD, SSN, Credit Cards, etc.)** |
| **PEX-01 to PEX-11** | **PII Exfiltration** | **PII being sent to external endpoints - data leak risk** |
| **VN-AI-001 to VN-AI-007** | **Compliance** | **Vietnam AI Law 2026 requirement not met** |
| **EU-AI-001 to EU-AI-005** | **Compliance** | **EU AI Act requirement not met** |
| **GDPR-001 to GDPR-006** | **Compliance** | **GDPR requirement not met** |
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

See `references/scoring-methodology.md` for detailed scoring algorithm and threshold rationale.

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
npx skill-audit --update-db --source kev epss nvd

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

⚠️  Vulnerability DB is stale (4.2 days for KEV, 5.1 days for EPSS, 2.0 days for NVD)
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
   - Caches CVE/GHSA/KEV/EPSS/NVD data
   - Native HTTP/fetch (no shell dependencies)
   - Differentiated cache lifetimes by source (KEV/NVD: 1 day, EPSS/GHSA: 3 days, OSV: 7 days)

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

## Additional Resources

### Reference Files

For detailed information, consult:

- **`references/pii-patterns.md`** - Complete list of 39 PII detection patterns for Vietnam and International data
- **`references/compliance-frameworks.md`** - Detailed Vietnam AI Law 2026, EU AI Act, and GDPR requirements
- **`references/scoring-methodology.md`** - Risk scoring algorithm and threshold rationale
- **`references/intelligence-sources.md`** - Vulnerability intelligence sources and cache management

### Example Files

Working examples in `examples/`:

- **`examples/example-audit-output.json`** - Sample JSON audit report
- **`examples/example-lint-output.txt`** - Sample lint mode output
- **`examples/example-compliance-report.md`** - Sample compliance findings

### Utility Scripts

Development tools in `scripts/`:

- **`scripts/validate-skill.sh`** - Validate SKILL.md structure and frontmatter
- **`scripts/test-audit.sh`** - Test audit functionality on sample directories

## References

### External Resources

- **[OWASP AI Security Top 10](https://owasp.org/www-project-top-ten.html)** - ASI01-ASI10 threat categories
- **[CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** - Actively exploited vulnerabilities
- **[FIRST EPSS](https://www.first.org/epss/)** - Exploit Prediction Scoring System
- **[NIST NVD](https://nvd.nist.gov/)** - National Vulnerability Database (official CVE database)
- **[GitHub Security Advisories](https://github.com/advisories)** - GHSA vulnerability database
- **[OSV.dev](https://osv.dev/)** - Open Source Vulnerability database

### Intelligence Cache

| Source | Update Frequency | Max Cache Age | Warning Threshold |
|--------|-----------------|---------------|-------------------|
| CISA KEV | Daily | 1 day | 3 days |
| NIST NVD | Daily | 1 day | 3 days |
| GitHub GHSA | 3 days | 3 days | 3 days |
| FIRST EPSS | 3-day cycle | 3 days | 3 days |
| OSV.dev | On-query | 7 days | 3 days |
