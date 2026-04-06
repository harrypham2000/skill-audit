# Security Policy

## Reporting Vulnerabilities

If you find a security vulnerability in skill-audit, please report it by opening an issue on GitHub. We take security seriously and will respond promptly.

## Security Auditing Scope

skill-audit is a security auditing tool for AI agent skills. It scans skills for:

- Prompt injection vulnerabilities (ASI01)
- Tool misuse and exfiltration (ASI02)
- Sensitive data exposure (ASI03)
- Supply chain vulnerabilities (ASI04)
- Unexpected code execution (ASI05)
- Behavioral manipulation (ASI09)

## Postinstall Script Safety

This package includes a `postinstall` script (`scripts/postinstall.cjs`) that runs automatically after installation. **This script is NOT a security vulnerability and is intentionally included for user experience.**

### What the postinstall does:

1. **Checks if running in CI** - If detected, exits silently (no output)
2. **Checks if hook already installed** - If yes, shows a brief confirmation
3. **Displays informational banner** - If no hook installed, shows a message encouraging users to run `skill-audit --install-hook`

### What the postinstall does NOT do:

- ❌ Does NOT automatically install any hooks
- ❌ Does NOT execute arbitrary code
- ❌ Does NOT make network requests
- ❌ Does NOT modify any files without explicit user action
- ❌ Does NOT collect or transmit any user data

### Why this is safe:

- The script runs only in user's home directory checking for existing configurations
- It only displays console messages - no file modifications without user consent
- Users must manually run `skill-audit --install-hook` to actually install the hook
- The hook installation itself requires explicit user authorization

## False Positives

If skill-audit reports a false positive finding for this package's postinstall script, please note:

1. The postinstall is intentionally included for UX purposes
2. It is a well-known, documented behavior
3. It can be audited in the source code at `scripts/postinstall.cjs`

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.7.x   | ✅ Supported       |
| < 0.7   | ❌ Unsupported     |

## Vulnerability Disclosure

We follow a responsible disclosure process:
1. Report via GitHub Issues
2. We will acknowledge within 48 hours
3. We will provide updates on timeline for fixes
4. Public disclosure after patch release