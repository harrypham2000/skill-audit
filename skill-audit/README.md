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
cd skill-audit
npm install
npm run build
```

## Usage

```bash
# Audit all global skills
npx skills-audit

# Audit with verbose output
npx skills-audit -v

# JSON output for CI
npx skills-audit --json > audit-results.json

# Fail if risk score exceeds threshold
npx skills-audit --threshold 5.0

# Skip dependency scanning (faster)
npx skills-audit --no-deps

# Filter by agent
npx skills-audit -a "Claude Code" "Qwen Code"

# Project-level skills only
npx skills-audit --project
```

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

## Trust Sources

1. Static pattern matching for known attack vectors
2. Trivy for dependency vulnerability scanning
3. Heuristic rules for common security issues

## Requirements

- Node.js 18+
- npx (for skills CLI)
- trivy (optional, for dependency scanning)
