# skill-audit Project Context

Security auditing tool for AI agent skills. Part of the Vercel Skills ecosystem.

## Project Overview

**Package:** `@hungpg/skill-audit`  
**Version:** 0.3.0  
**Purpose:** Validate AI agent skills for security risks before installation

### Key Features
- Static analysis for prompt injection, secrets, code execution risks
- Dependency vulnerability scanning (Trivy, CVE/GHSA/KEV/EPSS/NVD)
- Risk scoring (0-10) mapped to OWASP Agentic Top 10 (ASI01-ASI10)
- PreToolUse hook for automatic skill auditing before installation
- Multi-agent support (Claude Code, Qwen Code, Gemini CLI)

## Project Structure

```
/home/hungpham/research/audit-skill/
├── skill-audit/           # npm package (@hungpg/skill-audit)
│   ├── src/               # TypeScript source files
│   │   ├── index.ts       # CLI entry point (commander)
│   │   ├── discover.ts    # Skill discovery logic
│   │   ├── security.ts    # Security pattern detection
│   │   ├── spec.ts        # Agent Skills spec validation
│   │   ├── scoring.ts     # Risk score calculation
│   │   ├── intel.ts       # Vulnerability intelligence (KEV/EPSS/NVD/GHSA)
│   │   ├── deps.ts        # Dependency scanning
│   │   ├── hooks.ts       # PreToolUse hook management
│   │   ├── patterns.ts    # Pattern loading/compilation
│   │   ├── reporter.ts    # Output formatting
│   │   ├── audit.ts       # Core audit orchestration
│   │   └── types.ts       # TypeScript interfaces
│   ├── scripts/           # Build/install scripts
│   │   └── postinstall.cjs # Non-blocking postinstall message
│   ├── rules/             # Security patterns (JSON)
│   ├── dist/              # Compiled JavaScript (gitignored)
│   ├── package.json       # npm manifest
│   ├── SKILL.md           # Agent skill definition
│   └── README.md          # Package documentation
├── .github/workflows/     # CI/CD
│   └── ci.yml             # Build, test, lint smoke test
└── README.md              # Project overview
```

## Build & Development

```bash
# Navigate to package directory
cd skill-audit

# Install dependencies
npm install

# Build TypeScript
npm run build

# Development mode (with tsx)
npm run dev -- --help

# Run CLI
node dist/index.js --help

# Run lint mode (fast spec validation)
node dist/index.js --mode lint --global

# Run full audit
node dist/index.js --mode audit --global -v
```

## CLI Commands

```bash
# Audit global skills
skill-audit -g

# Audit with verbose output
skill-audit -v

# JSON output for CI
skill-audit --json > audit-results.json

# Fail if risk score exceeds threshold
skill-audit -t 3.0

# Lint mode (spec validation only - fast)
skill-audit --mode lint

# Update vulnerability database
skill-audit --update-db

# Install PreToolUse hook
skill-audit --install-hook

# Check hook status
skill-audit --hook-status

# Uninstall hook
skill-audit --uninstall-hook
```

## Architecture

### Audit Pipeline

1. **Discovery** (`discover.ts`) - Find skills in global/project directories
2. **Spec Validation** (`spec.ts`) - Validate SKILL.md against Agent Skills spec
3. **Security Scan** (`security.ts`) - Pattern-based vulnerability detection
4. **Dependency Scan** (`deps.ts`) - Trivy-based CVE scanning
5. **Intel Enrichment** (`intel.ts`) - KEV/EPSS/NVD/GHSA correlation
6. **Scoring** (`scoring.ts`) - Calculate risk score (0-10)
7. **Reporting** (`reporter.ts`) - Format output

### Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| Safe | 0-3.0 | No issues or minor concerns |
| Risky | 3.1-5.0 | Review recommended |
| Dangerous | 5.1-7.0 | Fix before use |
| Malicious | 7.1+ | Do not use |

### Finding Categories

| Prefix | Category | OWASP ASI |
|--------|----------|-----------|
| PI | Prompt Injection | ASI01 |
| BM | Behavioral Manipulation | ASI09 |
| SC | Secrets/Credentials | ASI04 |
| CE | Code Execution | ASI05 |
| TM | Tool Misuse | ASI02 |
| MC | Malicious Content | - |
| HT | Hidden Techniques | - |
| RA | Resource Abuse | - |
| SPEC | Spec Violation | - |
| PROV | Provenance | - |
| INTEL | Intel Correlation | - |

## PreToolUse Hook

The hook automatically audits skills before installation via `npx skills add`:

```bash
# Install hook
skill-audit --install-hook

# Hook configuration stored in ~/.claude/settings.json
# Structure: hooks.PreToolUse: [[{id, matcher, hooks}]]
```

### Hook Flow

1. User runs `npx skills add <package>`
2. Hook triggers, runs `skill-audit` on the skill
3. If risk score > threshold (default 3.0), installation blocked
4. User sees detailed findings in terminal

## Installation Methods

| Platform | Command |
|----------|---------|
| npm (CLI) | `npm install -g @hungpg/skill-audit` |
| bun (CLI) | `bun install -g @hungpg/skill-audit` |
| Claude Code | `npx skills add harrypham2000/skill-audit -g -y` |
| Qwen Code | Clone to `~/.qwen/skills/skill-audit` |
| Gemini CLI | Clone to `~/.gemini/skills/skill-audit` |

> **Note:** Skills CLI expects `owner/repo` format, not npm scoped names.
> - Correct: `harrypham2000/skill-audit`
> - Incorrect: `@hungpg/skill-audit`

## CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`):
1. Checkout
2. Setup Node.js 20
3. Install dependencies (`npm ci`)
4. Build (`npm run build`)
5. Test CLI (`node dist/index.js --help`)
6. Smoke test (`--mode lint --global --json`)

## Dependencies

### Runtime
- `commander` - CLI framework
- `gray-matter` - YAML frontmatter parsing
- `semver` - Version handling

### Dev
- `typescript` - TypeScript compiler
- `tsx` - TypeScript execution
- `@types/node` - Node.js types

## Key Files to Read

- `skill-audit/src/index.ts` - CLI entry point, all commands
- `skill-audit/src/security.ts` - Security patterns and detection
- `skill-audit/src/types.ts` - TypeScript interfaces
- `skill-audit/src/hooks.ts` - Hook installation logic
- `skill-audit/SKILL.md` - Agent skill definition with usage guide

## Development Conventions

- **TypeScript:** Strict mode, ES2022 target, ESNext modules
- **ESM:** Package uses `"type": "module"`
- **File extension:** Use `.js` in imports (TypeScript ESM requirement)
- **Postinstall:** Must be `.cjs` (CommonJS) to avoid ESM issues
- **No tests:** Currently no test framework configured
- **Linting:** No linter configured (manual code review)

## Publishing

```bash
cd skill-audit
npm run build
npm version patch|minor|major
npm publish --access public --otp=XXXXXX
```

## Related Projects

- [Vercel Skills](https://skills.sh) - Agent skills registry
- [Anthropic Agent Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills) - SKILL.md spec
- [OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai-application-security-verification-standard/) - ASI01-ASI10
- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability scanner