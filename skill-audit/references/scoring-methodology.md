# Risk Scoring Methodology

This reference documents how skill-audit calculates risk scores for AI agent skills.

## Overview

skill-audit uses a weighted scoring system that aggregates findings across multiple categories to produce a single risk score between 0 and 10.

## Score Classification

| Level | Score Range | Action |
|-------|-------------|--------|
| ✅ Safe | 0 | Deploy or install without concerns |
| ⚠️ Risky | 0.1 - 3.0 | Review findings; acceptable for low-risk use cases |
| 🔴 Dangerous | 3.1 - 7.0 | Fix issues before deployment; significant risks present |
| ☠️ Malicious | 7.1 - 10.0 | DO NOT USE; contains critical vulnerabilities |

## Scoring Algorithm

Scoring differs by mode. In both modes the total is capped at 10.0, rounded to one decimal, and computed from active findings only (findings suppressed by a governed baseline never contribute).

### Scan mode (default, canonical)

The canonical scan kernel scores severity only — categories and ASI mappings never change the score:

```
Total Score = min(10, Σ(severity weight of each active finding))
```

| Severity | Weight |
|----------|--------|
| critical | 5.0 |
| high | 3.0 |
| medium | 1.5 |
| low | 0.5 |
| info | 0.1 |

Unknown severities default to 1.

### Lint/grouped mode

The grouped reporter scores each finding as severity weight × category-code weight, sums the five finding layers (spec, security, PII, compliance, intel), and blends them with fixed layer weights:

```
Layer Score   = min(10, Σ(severity weight × category weight))
Total Score   = min(10, spec × 0.2 + security × 0.35 + pii × 0.25 + compliance × 0.1 + intel × 0.1)
```

| Category code | Weight | Description |
|---------------|--------|-------------|
| **SC** | 2.0 | Secrets/credentials |
| **CE** | 1.5 | Code execution |
| **PI** | 1.2 | Prompt injection |
| **BM** | 1.0 | Behavioral manipulation |
| **TM** | 1.0 | Tool misuse |
| **PII** | 2.5 | PII detection |
| **COMP** | 1.0 | Compliance |
| **SPEC** | 0.5 | Specification |
| **PROV** | 0.8 | Provenance |
| **INTEL** | 1.0 | Intelligence findings |

Unknown category codes default to a weight of 1.0.

### Example Calculations (scan mode)

#### Example 1: Single Critical Finding

```
Finding: SC-001 (severity: critical)

Score = 5.0 (Dangerous)
```

#### Example 2: Multiple High-Severity Findings

```
Findings: 3 × high

Score = 3.0 + 3.0 + 3.0 = 9.0 (Malicious)
```

#### Example 3: Mixed Findings

```
Findings: 1 × critical, 1 × medium, 2 × low

Score = 5.0 + 1.5 + 0.5 + 0.5 = 7.5 (Malicious)
```

## Threshold Configuration

There is no default threshold. `--threshold` is advisory and never blocks: the exit code is decided by the policy (critical findings, preflight gates, inspection completeness), never by the score.

```bash
# Prioritize review of skills scoring above 3.0 (advisory)
npx skill-audit -t 3.0

# Surface even minor scores in the review list
npx skill-audit -t 1.0

# Effectively disable score-based prioritization
npx skill-audit -t 10.0
```

## Score Aggregation Rules

1. **Exclude suppressed findings** — findings matched by a governed suppression baseline never contribute to the score
2. **Sum all active findings** — severity-only in scan mode; severity × category-code weight (then layer blend) in lint/grouped mode
3. **Apply the ceiling at 10.0** — there are no per-category caps; two critical findings already exceed the ceiling in scan mode

## Decision Matrix

| Risk Level | Score | Recommended Action |
|------------|-------|-------------------|
| ✅ Safe | 0 | Deploy without concerns |
| ⚠️ Risky | 0.1 - 1.0 | Review minor findings |
| ⚠️ Risky | 1.1 - 3.0 | Address findings before production |
| 🔴 Dangerous | 3.1 - 5.0 | Fix critical issues |
| 🔴 Dangerous | 5.1 - 7.0 | Significant rework required |
| ☠️ Malicious | 7.1 - 10.0 | Do not use |

## Factors Not Included in Score

The following are tracked but don't affect the numeric score:

- **Vulnerability intelligence staleness**: Warning only, doesn't increase risk score
- **Spec format warnings**: Advisory, not blocking
- **Performance considerations**: Out of scope for security audit

## Output Interpretation

### JSON Output

Scan mode (`-j`) emits `{features, decision, reports}`; saving to a file with `-o` adds `generated`, `mode`, and `schemaVersion` envelope fields. Each entry in `reports` is a canonical scan report (schema `1`):

```json
{
  "features": [
    { "feature": "canonical-scan-kernel", "state": "stable", "detail": "Versioned report, inspection ledger, policy decision, 0/1/2 exit contract (--mode scan)" }
  ],
  "decision": {
    "outcome": "reject",
    "rule": "findings.critical",
    "reason": "Critical finding SC-001: Hardcoded credential detected",
    "exitCode": 1
  },
  "reports": [
    {
      "schemaVersion": "1",
      "scanner": { "name": "skill-audit", "version": "0.9.0" },
      "input": {
        "skill": "writing-skills",
        "path": "/home/user/.qwen/skills/writing-skills",
        "fileCount": 12,
        "totalBytes": 48213,
        "snapshotDigest": "sha256-…"
      },
      "findings": [
        {
          "id": "SC-001",
          "category": "SC",
          "asi": "ASI04",
          "severity": "critical",
          "file": "scripts/deploy.sh",
          "line": 12,
          "message": "Hardcoded credential detected",
          "fingerprint": "…"
        }
      ],
      "capabilities": [],
      "analyzerRuns": [
        { "analyzer": "security-patterns", "status": "ok", "findings": 1, "durationMs": 14 }
      ],
      "diagnostics": [],
      "exclusions": [],
      "scanStatus": "complete",
      "decision": {
        "outcome": "reject",
        "rule": "findings.critical",
        "reason": "Critical finding SC-001: Hardcoded credential detected",
        "exitCode": 1
      },
      "suppressedCount": 0,
      "riskScore": 5
    }
  ]
}
```

Lint mode (`--mode lint -j`) emits `{features, results, decision}` with one grouped result per skill:

```json
{
  "features": [],
  "results": [
    {
      "skill": { "name": "tdd-workflow", "path": "/home/user/.qwen/skills/tdd-workflow", "agents": ["Claude Code"] },
      "manifest": { "name": "tdd-workflow" },
      "specFindings": [
        { "id": "SPEC-002", "category": "SPEC", "severity": "low", "message": "SKILL.md exceeds 500 lines (523 lines)" }
      ],
      "securityFindings": [],
      "piiFindings": [],
      "complianceFindings": [],
      "intelFindings": [],
      "riskScore": 0.1,
      "riskLevel": "risky",
      "complianceStatus": "not_run"
    }
  ],
  "decision": { "outcome": "allow", "rule": "policy.default", "reason": "No blocking findings", "exitCode": 0 }
}
```

### Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Allowed — scan completed and policy allowed execution |
| 1 | Rejected — critical finding or preflight reject |
| 2 | Invalid input, required analyzer failure, or insufficient inspection |

The score never affects the exit code.

---

## Rationale

### Why severity-only in scan mode?

The canonical scan kernel treats the score as a secondary prioritization signal: the policy decision (critical findings, preflight gates, inspection completeness) is what blocks. A severity-only sum keeps the signal transparent — reviewers can reproduce it from the finding list without category internals, and it can never contradict the policy exit.

### Why category weights in lint/grouped mode?

The grouped reporter keeps category weighting to rank spec-plus-security mixes: PII carries the highest weight (2.5) because exposure is hard to remediate after the fact, secrets (SC 2.0) and code execution (CE 1.5) follow, and SPEC (0.5) is lowest because spec issues reduce clarity more than safety.

### Why Cap at 10.0?

Prevents score inflation and ensures meaningful differentiation between extremely dangerous skills and moderately dangerous ones.

---

## References

- [OWASP AI Security Top 10](https://owasp.org/www-project-top-ten.html)
- [CVSS 3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [NIST Risk Management Framework](https://csrc.nist.gov/projects/risk-management)