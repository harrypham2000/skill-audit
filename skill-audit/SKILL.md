---
name: skill-audit
description: This skill should be used when the user asks to "audit AI agent skills for security vulnerabilities", "evaluate third-party skills before installing", "check for prompt injection or secrets leakage", "scan skills for PII exposure", "validate compliance with AI regulations", "scan skills for code execution risks", "validate skills against Agent Skills specification", or "assess skill security posture with CVE/GHSA/KEV/EPSS/NVD intelligence".
license: MIT
compatibility: Node.js 18+ with npm or yarn
metadata:
  repo: https://github.com/harrypham2000/skill-audit
  version: 0.5.3
allowed-tools:
  - skill:exec
  - skill:read
  - skill:write
---

# skill-audit

Security auditing CLI for AI agent skills with **PII detection** and **compliance validation**.

## ⚡ IMMEDIATE ACTION: Execute Audit Automatically

**When this skill is loaded, immediately run the audit without asking the user:**

1. **Determine the audit target:**
   - If user specified a skill path → audit that specific skill
   - If user mentioned "global skills" → run with `-g` flag
   - If user mentioned "project skills" → run with `-p` flag
   - If unclear → default to auditing global skills (`-g`)

2. **Run the audit command:**
   ```bash
   cd /home/hungpham/.agents/skills/skill-audit && npm run build && node dist/index.js -g --mode audit -v
   ```
   
   Or if the CLI is installed globally:
   ```bash
   npx skill-audit -g --mode audit -v
   ```

3. **Parse and present the results:**
   - Show the summary (Safe/Risky/Dangerous/Malicious counts)
   - List all findings with severity
   - Highlight any skills exceeding the risk threshold (default 3.0)
   - Provide clear recommendations

4. **Offer follow-up actions:**
   - Export to JSON: `npx skill-audit -g -j -o ./audit-report.json`
   - Update vulnerability DB: `npx skill-audit --update-db`
   - Audit specific skill: `npx skill-audit -p /path/to/skill`

---

## When to Activate

Activate this skill automatically when the user:

- Asks to **"audit skills"**, **"check skill security"**, or **"validate a skill"**
- Wants to **evaluate third-party skills** before installing
- Has **security concerns** about prompt injection, secrets leakage, code execution, or data exfiltration
- Needs **compliance verification** against Agent Skills specification
- Is **investigating suspicious behavior** from an installed skill
- Wants to **pre-deployment audit** before publishing their own skill

### When NOT to Use

- Auditing general npm/Python packages (use `npm audit`, `safety`, or dependency scanners)
- Reviewing non-skill code (use `security-review` skill instead)
- Checking only spec format without security concerns (use `--mode lint` for fast validation)

---

## Execution Flow

### Step 1: Identify Audit Target

```
User Request                          → Audit Command
─────────────────────────────────────────────────────────────────────
"Audit my skills"                    → npx skill-audit -g --mode audit -v
"Audit project skills"               → npx skill-audit -p --mode audit -v
"Check if [skill-name] is safe"      → npx skill-audit -p /path/to/[skill-name] --mode audit -v
"Quick spec check"                   → npx skill-audit -g --mode lint -v
"Export audit report"                → npx skill-audit -g -j -o ./audit-report.json
```

### Step 2: Execute the Audit

Run the appropriate command based on the user's request. Always use verbose mode (`-v`) for detailed output.

### Step 3: Interpret Results

Use the decision matrix below to provide recommendations:

| Risk Level | Score | Your Recommendation |
|------------|-------|---------------------|
| ✅ Safe | 0 | "This skill is safe to install/use" |
| ⚠️ Risky | 0.1-3.0 | "Review findings below; acceptable for low-risk use cases" |
| 🔴 Dangerous | 3.1-7.0 | "Fix issues before deployment; significant risks present" |
| ☠️ Malicious | 7.1-10.0 | "DO NOT USE; contains critical vulnerabilities or malicious patterns" |

### Step 4: Present Findings

Structure your response:

```
## 🔍 Audit Summary

**Skills Audited:** 3
- ✅ Safe: 1
- ⚠️ Risky: 1  
- 🔴 Dangerous: 1
- ☠️ Malicious: 0

## 📋 Detailed Findings

### [Skill Name] - Risk Score: X.X

**Findings:**
1. [Finding ID] Description (Location: file:line)
2. ...

**Recommendation:** [Based on risk level]

## 🎯 Next Steps

[Specific actions user should take]
```

---

## 📚 Reference: Audit Commands

> **Note:** As an AI agent, you execute these commands automatically when the skill is loaded. This section is for your reference to understand what the CLI does.

### Modes

| Mode | Command | Use Case |
|------|---------|----------|
| **lint** | `npx skill-audit --mode lint` | Fast spec validation (no security scan) |
| **audit** | `npx skill-audit --mode audit` | Full security audit (default) |

### What Gets Scanned

#### Lint Mode (Spec Validation)
- SKILL.md exists with valid frontmatter
- name matches directory (lowercase, 1-64 chars, no consecutive hyphens)
- description present (1-1024 chars)
- allowed-tools structure valid
- Progressive disclosure (warns if SKILL.md > 500 lines)

#### Audit Mode (Full Security)
- Prompt injection patterns (ASI01)
- Credential leaks / secrets (ASI04)
- Code execution risks (ASI05)
- Exfiltration patterns (ASI02)
- Behavioral manipulation (ASI09)
- Provenance checks (trusted domains, pinned refs)
- Dependency vulnerability scanning
- **PII detection (ASI03)** - 39 patterns for Vietnam and International PII
- **Compliance validation** - Vietnam AI Law 2026, EU AI Act, GDPR

### PII Detection Reference

Detects 39 types of Personally Identifiable Information:

| Category | Types |
|----------|-------|
| **Vietnam PII** | CCCD (Citizen ID), CMND (Old ID), Tax ID (TIN), Phone, Bank Account, License Plate, BHXH, Military ID, Passport |
| **International PII** | US SSN, Credit Card, IBAN, NHS (UK), Passport (US/EU/UK/JP/KR), IP Address, Email |
| **Secrets** | OpenAI/Anthropic/AWS/GitHub/Stripe API keys, PEM keys, JWTs, Database connection strings |

See `references/pii-patterns.md` for complete pattern list and regex details.

### Compliance Frameworks Reference

| Framework | Requirements | Risk Levels |
|-----------|-------------|-------------|
| **Vietnam AI Law 2026** | Data localization, User consent, Transparency, Human oversight, Data minimization, Right to explanation, Bias prevention | minimal, limited, high, unacceptable |
| **EU AI Act** | Risk assessment, Data governance, Technical documentation, Record keeping, Transparency | minimal, limited, high, unacceptable |
| **GDPR** | Lawful basis, Data subject rights, Privacy by design, DPIA, Breach notification, International transfers | minimal, limited, high, unacceptable |

See `references/compliance-frameworks.md` for detailed requirements and remediation guidance.

### Vulnerability Intelligence (`update-db`)

Pulls latest vulnerability intelligence:
- CISA KEV (Known Exploited Vulnerabilities)
- FIRST EPSS (Exploit Prediction Scoring) - via api.first.org/data/v1
- NIST NVD (National Vulnerability Database) - CVSS scores, CWE mappings
- GitHub Security Advisories (GHSA) - ecosystem-specific advisories
- OSV.dev vulnerabilities

Caches to `.cache/skill-audit/feeds/` for offline use.

---

## 📚 Reference: Findings Interpretation

### Common Findings

| Finding ID | Category | Meaning |
|------------|----------|---------|
| SPEC-01 | Specification | SKILL.md missing or malformed frontmatter |
| ASI01-01 | Prompt Injection | Contains patterns that could override system instructions |
| ASI04-01 | Secrets | Hardcoded API keys, tokens, or credentials detected |
| ASI05-01 | Code Execution | Dynamic code execution without proper sandboxing |
| ASI02-01 | Exfiltration | Potential data leakage to untrusted endpoints |
| **PII-001 to PII-039** | **PII Detection** | **Personally Identifiable Information detected** |
| **PEX-01 to PEX-11** | **PII Exfiltration** | **PII being sent to external endpoints** |
| **VN-AI-001 to VN-AI-007** | **Compliance** | **Vietnam AI Law 2026 requirement not met** |
| **EU-AI-001 to EU-AI-005** | **Compliance** | **EU AI Act requirement not met** |
| **GDPR-001 to GDPR-006** | **Compliance** | **GDPR requirement not met** |
| VULN-* | Dependency | Known vulnerability in skill's dependencies (see CVE ID) |

### CLI Options Reference

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
| `--mode <mode>` | `lint` or `audit` (default: audit) |
| `--update-db` | Update vulnerability intelligence feeds |
| `--strict` | Fail if feed update errors occur |
| `--quiet` | Suppress non-error output |

---

## 📚 Reference: Risk Scoring & Interpretation

### Risk Levels

| Level | Score | Description |
|-------|-------|-------------|
| ✅ Safe | 0 | No issues found |
| ⚠️ Risky | 0.1-3.0 | Minor issues, review recommended |
| 🔴 Dangerous | 3.1-7.0 | Significant risks, fix before use |
| ☠️ Malicious | 7.1-10.0 | Critical issues, do not use |

See `references/scoring-methodology.md` for detailed scoring algorithm and threshold rationale.

### Exit Codes

- `0`: Success (no blocking issues)
- `1`: Threshold exceeded or blocking findings

---

## 📚 Reference: Additional Resources

### Reference Files (in this skill directory)

- **`references/pii-patterns.md`** - Complete list of 39 PII detection patterns
- **`references/compliance-frameworks.md`** - Vietnam AI Law 2026, EU AI Act, GDPR details
- **`references/scoring-methodology.md`** - Risk scoring algorithm
- **`references/intelligence-sources.md`** - Vulnerability intelligence sources

### Example Files

- **`examples/example-audit-output.json`** - Sample JSON audit report
- **`examples/example-lint-output.txt`** - Sample lint mode output
- **`examples/example-compliance-report.md`** - Sample compliance findings

### External Resources

- **[OWASP AI Security Top 10](https://owasp.org/www-project-top-ten.html)** - ASI01-ASI10 threat categories
- **[CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** - Actively exploited vulnerabilities
- **[FIRST EPSS](https://www.first.org/epss/)** - Exploit Prediction Scoring System
- **[NIST NVD](https://nvd.nist.gov/)** - National Vulnerability Database
- **[GitHub Security Advisories](https://github.com/advisories)** - GHSA vulnerability database
- **[OSV.dev](https://osv.dev/)** - Open Source Vulnerability database
