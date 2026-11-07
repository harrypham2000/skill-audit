---
name: skill-audit
description: Security auditing CLI for AI agent skills — detects prompt injection, data exfiltration, PII and secret leakage, unsafe shell and code execution, and vulnerable dependencies mapped to the OWASP Agentic Top 10, with a 0/1/2 policy exit contract. Use when auditing or reviewing agent skills for security, before installing external or third-party skills, when validating skills for distribution, investigating skill dependency CVEs or security alerts, concerned about prompt injection, data exfiltration, PII or hardcoded secrets, or unsafe execution, checking agent environment safety such as hooks, shell startup files, PATH hijacking or MCP configs, detecting environment drift against a trusted baseline, or assessing a shell command before an agent runs it.
---

# skill-audit

Security auditing CLI for AI agent skills.

## When to Use This Skill

- When installing new skills from external sources
- When auditing existing skills for security issues
- When validating skills before distribution
- When investigating security alerts in skill dependencies
- When checking whether the local agent shell/config environment is safe before invoking skills
- When comparing current agent environment state against a trusted baseline

## Quick Start

```bash
# Install globally
npm install -g @hungpg/skill-audit

# Audit skills
skill-audit -g              # Audit global skills (default mode is the canonical scan;
                            # exits 0 allowed / 1 rejected / 2 invalid or incomplete)
skill-audit -v              # Verbose output
skill-audit --json          # JSON for CI
skill-audit --threshold 5   # Advisory prioritization hint (does not affect exit code)

# Audit the agent execution environment
skill-audit doctor          # Read-only shell/config/PATH/hook scan
skill-audit trust env       # Save current environment baseline
skill-audit diff-env        # Detect drift from baseline

# Hook-friendly shell command assessment
skill-audit --check-command "npx skills add owner/repo"
```

## Security Categories

| Category | OWASP | What It Detects |
|----------|-------|-----------------|
| Prompt Injection | ASI01 | Ignore instructions, role bypass, context forgetting |
| Tool Misuse | ASI02 | Data exfiltration, unauthorized API calls |
| PII Exposure | ASI03 | Vietnamese IDs / PII |
| Supply Chain | ASI04 | Hardcoded secrets, API keys, vulnerable dependencies, credential leaks |
| Code Execution | ASI05 | Shell injection, dangerous commands |
| Behavioral | ASI09 | Manipulation attempts, blind trust requests |

## Agent Environment Checks

`skill-audit doctor` checks risks outside a skill package, including:

- Agent hooks and config files
- Shell startup files
- PATH hijacking and workspace-local sensitive binaries
- MCP/tool command config risks
- Workspace instruction files such as `AGENTS.md`, `CLAUDE.md`, `QWEN.md`, and `GEMINI.md`
- Package lifecycle scripts that an agent might run through shell commands

Use `skill-audit trust env` and `skill-audit diff-env` to keep a compact trusted baseline across sessions. The baseline stores file hashes and redacted finding summaries, not full conversation history.

## Session Context Contracts

Executable skills should declare the narrow session facts they read, the preconditions required before invocation, what they write back after execution, and when user confirmation is needed. `skill-audit` reports `CTX-*` findings when executable skills lack these boundaries.

This skill's own contract:

```yaml
reads:
  - user_goal
  - target_skill_path
  - agent_environment_config
  - shell_command_under_review
requires:
  - explicit_user_intent_for_audit_or_environment_check
writes:
  - risk_summary
  - findings_count
  - environment_drift_summary
  - recommended_next_action
confirmation: on-risk
```

## Risk Scoring

- **0**: Safe ✅
- **0.1-3.0**: Risky ⚠️
- **3.1-7.0**: Dangerous 🔴
- **7.1-10.0**: Malicious ☠️

## Postinstall Safety

This package includes a postinstall script for UX. It does NOT:
- Auto-install hooks
- Execute malicious code
- Make network requests
- Modify files without consent

See `references/postinstall-safety.md` for full documentation on postinstall patterns.
