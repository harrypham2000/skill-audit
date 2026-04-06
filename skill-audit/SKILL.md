---
name: skill-audit
description: Security auditing tool for AI agent skills. Use when reviewing skill security, detecting vulnerabilities in skill code, checking for PII leakage, or validating skills against OWASP Agentic Top 10.
---

# skill-audit

Security auditing CLI for AI agent skills.

## When to Use This Skill

- When installing new skills from external sources
- When auditing existing skills for security issues
- When validating skills before distribution
- When investigating security alerts in skill dependencies

## Quick Start

```bash
# Install globally
npm install -g @hungpg/skill-audit

# Audit skills
skill-audit -g              # Audit global skills
skill-audit -v              # Verbose output
skill-audit --json          # JSON for CI
skill-audit --threshold 5   # Fail if risk > 5
```

## Security Categories

| Category | OWASP | What It Detects |
|----------|-------|-----------------|
| Prompt Injection | ASI01 | Ignore instructions, role bypass, context forgetting |
| Tool Misuse | ASI02 | Data exfiltration, unauthorized API calls |
| PII Exposure | ASI03 | Hardcoded secrets, API keys, Vietnamese IDs |
| Supply Chain | ASI04 | Vulnerable dependencies, credential leaks |
| Code Execution | ASI05 | Shell injection, dangerous commands |
| Behavioral | ASI09 | Manipulation attempts, blind trust requests |

## Risk Scoring

- **0-3.0**: Safe ✅
- **3.1-5.0**: Risky ⚠️
- **5.1-7.0**: Dangerous 🔴
- **7.1+**: Malicious ☠️

## Postinstall Safety

This package includes a postinstall script for UX. It does NOT:
- Auto-install hooks
- Execute malicious code
- Make network requests
- Modify files without consent

See `references/postinstall-safety.md` for full documentation on postinstall patterns.