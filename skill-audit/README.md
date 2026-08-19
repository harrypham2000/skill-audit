# skill-audit

Security auditing CLI for AI agent skills.

## Features

- **Static Analysis**: Detect prompt injection, dangerous scripts, hardcoded secrets
- **Dependency Scanning**: osv-scanner > trivy > OSV API (network opt-in) for known vulnerabilities in dependencies
- **Risk Scoring**: 0-10 score mapped to OWASP Agentic Top 10 (ASI01-ASI10)
- **Multi-Agent Support**: Groups results by agent (Claude Code, Qwen Code, Gemini CLI, etc.)
- **Agent Environment Doctor**: Detect risky hooks, shell startup files, PATH hijacking, MCP/tool configs, and workspace lifecycle scripts
- **Session Context Contracts**: Warn when executable skills do not declare what agent/session facts they read, require, and write back
- **CI/CD Ready**: JSON output, policy-driven 0/1/2 exit contract

## Canonical Scan Mode

`--mode scan` runs the versioned scan kernel: immutable file snapshot → analyzers with an inspection ledger → policy decision → canonical report (schema `1`).

```bash
# Scan one skill directory (or a SKILL.md file)
skill-audit --mode scan --skill-path ./my-skill

# Discover and scan all global skills with an advisory score threshold
skill-audit --mode scan -t 3.0 --no-deps

# Canonical JSON report with decision and analyzer ledger
skill-audit --mode scan --skill-path ./my-skill -j
```

Exit codes are part of the contract:

| Exit code | Meaning |
|---:|---|
| `0` | Scan completed and policy allowed execution |
| `1` | Scan completed and policy rejected execution |
| `2` | Invalid input, required analyzer failure, or insufficient inspection |

Critical findings and incomplete inspection are direct policy gates; the aggregate score is a secondary signal. Scan limits (`--max-files`, `--max-file-bytes`, `--max-total-bytes`, `--max-depth`, `--scan-timeout`) bound every scan — hitting a limit marks the scan `partial` and exits `2` so an incomplete scan can never look safe.

### Dependency scanning and network behavior

Dependency scanning uses **one authoritative route per run**, in fixed precedence: `osv-scanner` CLI → `trivy` CLI → OSV API. The OSV API route and background intelligence-feed refresh perform network I/O and are **opt-in via `--network`**; by default scans are fully offline and deterministic. Scanner errors and stale feeds are reported as diagnostics in the canonical report — they never become findings and never affect the risk score or exit decision. When local KEV/EPSS caches exist, dependency findings are enriched with known-exploited markers and EPSS scores (refresh caches with `--update-db`).

## Preflight: declared vs observed

`--mode preflight` decides whether a skill is safe to invoke *right now*, comparing what the skill declares against what static analysis observes, invocation approvals, and environment drift:

```bash
skill-audit --mode preflight --skill-path ./my-skill
skill-audit --mode preflight --skill-path ./my-skill --approve my-skill   # record a confirmation approval
skill-audit --mode preflight --skill-path ./my-skill --no-drift-check     # skip baseline drift
```

Outcomes map onto the exit contract: `allow` → 0, `confirmation_required`/`reject` → 1, `indeterminate` → 2.

- **Undeclared shell execution is rejected.** `process.exec` observed (fenced shell blocks, shebangs, exec calls) without `allowed-tools` declaring shell tools is a direct reject with file:line evidence.
- **Confirmation boundaries are enforced.** A contract with `confirmation: always` (or `on-risk` when risk findings exist) cannot pass without an approval recorded for this invocation.
- **Environment drift degrades the decision.** When the trusted baseline (`skill-audit trust env`) has drifted, preflight returns `indeterminate` until the environment is re-trusted.
- **Invalid contract values fail validation.** Context contracts are validated against schema v1 (`version: 1`, string-array `reads`/`requires`/`writes`, `confirmation` in `never|on-risk|always`); violations produce `CTX-007` findings and an `indeterminate` preflight.

## Structural analysis and taint paths

Beyond regex patterns, `--mode scan` runs structural analyzers that emit a shared capability model with exact file:line evidence:

- **TypeScript/JavaScript AST** — via the TypeScript compiler API when resolvable; detects `process.exec`, `network.request`, `fs.read`/`fs.write`, `env.read`.
- **Shell structural parsing** — quote-aware logical-command splitting (single-quoted `$VAR` is literal); maps curl/nc/ssh, redirections, shebangs, and expansions to capabilities.
- **Python AST** — parsed with the reference `python3` interpreter (parse-only, never executed); detects subprocess/os.system, requests/urllib, open() modes, and os.environ reads.
- **Intra-file taint paths** — `TAINT-001` env secret → network, `TAINT-002` file read → network, `TAINT-003` external input → execution, `TAINT-004` session context → output.

## MCP security analysis

Skills carrying `mcp.json`/`.mcp.json` are analyzed for metadata poisoning (`MCP-005`/`MCP-006`: hidden instructions and invisible/directional Unicode in server names, tool and parameter descriptions), permission mismatch (`MCP-002` wildcards, `MCP-003` undeclared references, `MCP-004` unused overprivilege), install-reference integrity (`MCP-001` unpinned `npx`/`uvx`/`docker`), and dangerous defaults (`MCP-007` auto-approval). Version-to-version privilege expansion is one command away:

```bash
skill-audit --mode mcp-diff --skill-path ./my-skill --baseline-config ./previous-mcp.json
```

## Remote input scanning

Scan a skill before installing it:

```bash
skill-audit --mode scan --remote ./downloaded.zip            # local ZIP archive
```

Remote HTTPS and git acquisition is **disabled (fail-closed) pending security review**; only local `.zip` archives and local directory/git paths are accepted. The hardened acquisition controls remain implemented for the disabled route: HTTPS-only with host allowlists and private/reserved address rejection (loopback, RFC1918, link-local metadata endpoints, IPv6 ULA), per-hop redirect revalidation, streamed download caps, archive member/size limits, ZIP-slip rejection, symlink skipping, shallow clones without submodules or `.git` metadata, deterministic cleanup, and recorded origin digests.

## Optional semantic analysis

`--semantic` (with `--network` and `SKILL_AUDIT_SEMANTIC_URL`/`_KEY`/`_MODEL`) adds LLM intent analysis for paraphrased injection, natural-language exfiltration, purpose mismatch, unjustified scope, and missing warnings. Every report states whether it was requested, available, and successful, partial, or degraded; egress is disclosed; responses are structurally validated; and semantic findings can only add (severity capped at high) — they can never remove or lower deterministic findings.

**Egress policy (SSRF controls).** The provider endpoint must be an allowlisted host over `https` — plain `http` is accepted only for loopback hosts the operator explicitly allowlisted (local model servers). Endpoints embedding credentials are rejected, redirects are never followed, and model identifiers must be syntactically valid. Policy rejections are reported explicitly instead of silently falling back to "not configured".

- `SKILL_AUDIT_SEMANTIC_ALLOWED_HOSTS` — comma-separated host allowlist (default: `api.openai.com,api.anthropic.com`; setting it replaces the default, so include the hosted hosts if you still want them). Example for a local server: `SKILL_AUDIT_SEMANTIC_ALLOWED_HOSTS=127.0.0.1 SKILL_AUDIT_SEMANTIC_URL=http://127.0.0.1:11434/v1/chat/completions`.
- `SKILL_AUDIT_SEMANTIC_ALLOWED_MODELS` — optional comma-separated model allowlist; when set, `SKILL_AUDIT_SEMANTIC_MODEL` must be in it.

DNS-level redirection of an allowlisted host remains the operator's network responsibility.

## Policy decision and attestation adapter (gateway mode)

`--mode gateway` is a policy decision and attestation adapter for agent tool wrappers — it never executes commands and provides no containment or sandboxing; the wrapper that honors its decisions owns the execution boundary:

```bash
echo '{"command":"npm test","skill":"ci","cwd":"/tmp/build"}' \
  | skill-audit --mode gateway --gateway-config ./gateway.json
```

Decisions enforce the context contract at invocation time: command allowlists (exact, `prefix:*`, or explicit `*`), confirmation rules (`confirm` until an approval is recorded), environment trust (baseline drift denies until re-trusted), and working-directory scope. Every decision is appended to a JSONL ledger; post-execution attestations (`--attest`) record exit codes and command digests for reconciliation.

## Finding fingerprints, suppressions, and SARIF

Every finding carries a stable fingerprint digesting scanner version, analyzer, rule id, path, source digest, and evidence. Suppression baselines reference these fingerprints:

```json
{
  "version": 1,
  "suppressions": [
    {
      "fingerprint": "<finding fingerprint>",
      "reason": "verified false positive: documentation quotes the pattern",
      "approver": "security-team",
      "ticket": "SEC-42",
      "created": "2026-08-16T00:00:00Z",
      "expires": "2027-08-16T00:00:00Z"
    }
  ]
}
```

```bash
skill-audit --mode scan --skill-path ./my-skill --suppressions ./suppressions.json --sarif ./report.sarif
```

Governance rules: a substantive `reason` is mandatory (files without one are rejected and ignored, with a diagnostic); expired suppressions reactivate automatically; any change to source, evidence, rule, or scanner version changes the fingerprint and reactivates the finding; suppressed findings stay visible in JSON and SARIF output (with suppression metadata) but never affect the policy decision, score, or a `partial`/`failed` scan status. SARIF 2.1.0 output includes `partialFingerprints` for code-scanning matching, and its decisions always agree with the JSON report. The canonical report schema is published at [`schemas/scan-report.schema.json`](./schemas/scan-report.schema.json).

## Feature Status

Every report states which features actually ran and how far each implementation goes. Scan output (terminal and JSON) includes a `features` list with one of these states: `stable`, `experimental`, `initial slice`, `partially integrated`, `unavailable`, `not run`, `planned` — derived from analyzer outcomes after each run.

| Feature | Status | Notes |
|---|---|---|
| Spec validation | stable | Agent Skills frontmatter and structure checks |
| Canonical scan kernel | stable | Default mode: versioned report, inspection ledger, analyzers consume the materialized snapshot, policy decision, 0/1/2 exit contract |
| Pattern detection | stable | Regex security patterns (PI, SC, CE, PII, ENV, CTX); regex precision is line-only |
| Dependency scanning | stable when a route runs; coverage varies | One authoritative route per run (osv-scanner > trivy > OSV API with `--network`); route and coverage are reported per scan |
| Environment doctor | stable | Hooks, shell startup, PATH, MCP/tool configs |
| Fingerprints and suppressions | stable | Governed baselines with reasons, approvers, expirations; automatic reactivation |
| SARIF output | stable (CI acceptance unverified) | SARIF 2.1.0 with partial fingerprints; decisions agree with JSON |
| Session context contracts | experimental (partial) | Preflight governs process.exec, network hosts, MCP servers; fs/env/secrets remain ungoverned pending later gates |
| Vulnerability intel enrichment | experimental | Local KEV/EPSS caches enrich dependency findings when present; refresh with `--update-db` |
| Structural analysis | initial slice | TS/JS AST, shell structural parsing, Python AST (needs python3), intra-file taint paths; parse failures degrade coverage honestly |
| MCP security analysis | partially integrated | Config checks fully wired; usage comparison consumes observed mcp.invoke evidence with five usage states |
| Remote input | initial slice | Local ZIP only (ZIP-slip/symlink/size hardened); HTTPS and git acquisition disabled pending security review |
| Compliance frameworks | unavailable | VN AI Law / EU AI Act / GDPR checklists exist as library code but are not wired into scans |
| Semantic analysis | unavailable by default | `--semantic` + provider env + `--network`; findings pass through the same fingerprint → suppress → policy sequence |
| Policy decision adapter | initial slice | Gateway mode: process.exec policy decisions and attestations over structured executable/argv; does not own execution, no containment |

Feature labels use one vocabulary — `stable`, `experimental`, `initial slice`, `partially integrated`, `unavailable`, `not run`, `planned` — and runtime statuses in reports are derived from analyzer outcomes, not just the selected mode. Machine-readable fields (for example `complianceStatus: "not_run"`) use their schema spellings.

Compliance scores are only reported when compliance checks actually execute; a run without those checks reports `complianceStatus: "not_run"` instead of a perfect score.

## Installation

### Option 1: Install via npm (Recommended for CLI)

```bash
npm install -g @hungpg/skill-audit
```

This installs the CLI globally and triggers the postinstall hook prompt.

### Option 2: Install via bun (Fast Alternative)

```bash
bun install -g @hungpg/skill-audit
```

Bun is significantly faster than npm for installation.

### Option 3: Install as a Skill (For Claude Code)

```bash
# Install from GitHub repo (not npm package name)
npx skills add harrypham2000/skill-audit -g -y
```

> ⚠️ **Important**: The skills CLI expects `owner/repo` format, not npm scoped packages.
> - ✅ Correct: `harrypham2000/skill-audit`
> - ❌ Incorrect: `@hungpg/skill-audit`

### Option 4: Install for Qwen Code

```bash
# Clone to Qwen skills directory
mkdir -p ~/.qwen/skills
git clone https://github.com/harrypham2000/skill-audit.git ~/.qwen/skills/skill-audit
cd ~/.qwen/skills/skill-audit/skill-audit
npm install && npm run build

# Or with bun (faster)
bun install && bun run build
```

### Option 5: Install for Gemini CLI

```bash
# Clone to Gemini skills directory
mkdir -p ~/.gemini/skills
git clone https://github.com/harrypham2000/skill-audit.git ~/.gemini/skills/skill-audit
cd ~/.gemini/skills/skill-audit/skill-audit
npm install && npm run build

# Or with bun (faster)
bun install && bun run build
```

## About the Postinstall Script

This package includes a `postinstall` script that runs automatically after `npm install`. **This script is completely safe and informational only:**

- ✅ Does NOT automatically install any hooks
- ✅ Does NOT execute any code that could be considered malicious
- ✅ Does NOT make any network requests
- ✅ Does NOT modify any files without user consent
- ✅ Does NOT collect any user data

The script simply displays a banner message prompting users to optionally run `skill-audit --install-hook` if they want to set up automatic skill auditing. Users must manually run this command to install the hook.

In CI environments (GitHub Actions, GitLab CI, Jenkins, etc.), the script exits silently without displaying anything.

## Automatic Hook Setup

After installation, you'll see a message about setting up the PreToolUse hook:

```
┌─────────────────────────────────────────────────────────┐
│           🛡️  skill-audit installed!                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Protect your skills from vulnerabilities:              │
│                                                         │
│    skill-audit --install-hook                           │
│                                                         │
│  This adds a PreToolUse hook that audits skills         │
│  before installation via 'npx skills add'.             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

Run the command to set up automatic skill auditing:

```bash
skill-audit --install-hook
```

### Manual Hook Management

```bash
# Install hook manually
skill-audit --install-hook

# Install with custom threshold
skill-audit --install-hook --hook-threshold 5.0

# Check hook status
skill-audit --hook-status

# Remove hook
skill-audit --uninstall-hook
```

### How the Hook Works (legacy install-time gate)

1. **Trigger**: When you run `npx skills add <package>`
2. **Scan**: skill-audit analyzes the skill before installation
3. **Decision** (legacy install-time gate, separate from the canonical engine):
   - Risk score ≤ threshold → Installation proceeds
   - Risk score > threshold → Installation blocked
   The score is a prioritization signal; the canonical scan mode uses explicit policy gates instead.

## Usage

The default mode is the **canonical scan**: immutable snapshot → analyzers → observed capabilities → context comparison → one policy decision → canonical report (exit 0 allowed / 1 rejected / 2 invalid or incomplete).

```bash
# Canonical scan of discovered global skills (default mode)
skill-audit

# Scan one skill directory or SKILL.md
skill-audit --skill-path ./my-skill

# Verbose canonical scan with JSON + SARIF output
skill-audit -v -j --sarif report.sarif

# Skip dependency scanning (faster)
skill-audit --no-deps

# Filter by agent
skill-audit -a "Claude Code" "Qwen Code"

# Project-level skills only
skill-audit --project

# Lint mode (spec validation only)
skill-audit --mode lint

# Agent environment scan (hooks, shell, PATH, MCP/tool configs)
skill-audit doctor

# Save current agent environment as trusted baseline
skill-audit trust env

# Compare current environment against the trusted baseline
skill-audit diff-env

# Hook-friendly check for sensitive shell commands
skill-audit --check-command "npx skills add owner/repo"

# Update vulnerability DB manually
skill-audit --update-db
```

## Agent Environment Doctor

`skill-audit doctor` is a read-only scan of the local agent execution environment. It complements skill auditing by checking whether the shell and agent configuration are safe before any skill is invoked.

It currently checks:

- Agent hook/config files for shell-command hooks, remote script execution, unpinned `npx` MCP/tool servers, and secrets in config
- Shell startup files for remote script execution, reverse shells, command-shadowing aliases, and exported secrets
- `PATH` entries and sensitive binaries for workspace-local or world-writable executable resolution
- Workspace instruction files (`AGENTS.md`, `CLAUDE.md`, `QWEN.md`, `GEMINI.md`) for prompt-injection style directives
- Workspace package files for risky lifecycle scripts such as `postinstall`, `prepare`, `preinstall`, and `install`

Examples:

```bash
# Human-readable environment report
skill-audit doctor

# Full evidence and recommendations
skill-audit doctor --verbose

# JSON output for automation
skill-audit doctor --json

# Block automation if environment risk exceeds a threshold
skill-audit doctor --threshold 5 --block
```

Secret-like evidence is redacted in reports. The doctor mode does not modify files.

### Environment baselines and drift

Use a baseline when you want agents to keep a compact, durable understanding of the trusted shell/config state across sessions:

```bash
# Record hashes and redacted findings for the current environment
skill-audit trust env

# Detect changed files, new findings, and resolved findings since baseline
skill-audit diff-env

# Fail automation if drift is detected
skill-audit diff-env --block
```

The baseline is stored at `~/.skill-audit/baselines/environment.json`. It records file hashes and redacted finding summaries, not full conversation history.

### Hook-sensitive command assessment

Hooks can call `--check-command` to avoid scanning everything on every shell command. The command is classified first, and environment drift is checked only for sensitive commands such as skill installs, package installs, remote script execution, agent config edits, shell startup edits, and executable permission changes.

```bash
skill-audit --check-command "npm install" --json
skill-audit --check-command "curl https://example.test/install.sh | bash" --block
```

## Session Context Contracts

Executable skills can declare how they interact with agent session context. `skill-audit` warns when a skill can run shell/tool behavior but does not declare this contract.

Example frontmatter:

```yaml
context:
  reads:
    - user_goal
    - target_environment
    - changed_files
  requires:
    - explicit_user_intent
    - confirmation_for_mutating_actions
  writes:
    - commands_run
    - files_changed
    - verification_result
  confirmation: on-risk
```

Context checks include:

- `CTX-001`: executable skill has no context contract
- `CTX-002`: missing declared session facts read by the skill
- `CTX-003`: missing invocation preconditions
- `CTX-004`: missing write-back summary fields
- `CTX-005`: missing confirmation boundary
- `CTX-006`: overbroad context reads such as full conversation or all files

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-g, --global` | Audit global skills only | ✓ |
| `-p, --project` | Audit project-level skills only | |
| `-a, --agent <agents...>` | Filter by specific agents | |
| `-x, --exclude-skill <names...>` | Skills to exclude from audit (by name) | |
| `-j, --json` | Output as JSON | |
| `-o, --output <file>` | Save report to file (JSON format) | |
| `-v, --verbose` | Show detailed findings | |
| `-t, --threshold <score>` | Advisory prioritization hint only; no default; never affects the exit code | none |
| `--no-deps` | Skip dependency scanning (faster) | |
| `--mode <mode>` | `scan` (default, canonical), `lint`, `preflight`, `mcp-diff`, `gateway`, `doctor`, `trust-env`, or `diff-env` | scan |
| `--skill-path <path>` | Scan a single skill directory or SKILL.md (canonical scan mode) | |
| `--max-files <n>` | Scan limit: maximum files per skill | |
| `--max-file-bytes <n>` | Scan limit: maximum bytes per file | |
| `--max-total-bytes <n>` | Scan limit: maximum aggregate bytes per skill | |
| `--max-depth <n>` | Scan limit: maximum directory depth | |
| `--scan-timeout <ms>` | Scan limit: wall-clock timeout in milliseconds | |
| `--update-db` | Update advisory intelligence feeds | |
| `--source <sources...>` | Sources for update-db: kev, epss, nvd, all | all |
| `--strict` | Fail if feeds are stale | |
| `--quiet` | Suppress non-error output | |
| `--download-offline-db <dir>` | Download offline vulnerability databases to directory | |
| `--check-command <command>` | Assess whether a shell command should trigger environment safety checks | |
| `--install-hook` | Install PreToolUse hook for automatic skill auditing | |
| `--uninstall-hook` | Remove the PreToolUse hook | |
| `--hook-threshold <score>` | Risk threshold for hook | 3.0 |
| `--hook-status` | Show current hook status | |
| `--block` | Exit 1 on the severity-policy rejection (critical findings) in lint mode; threshold-gated only for check-command/doctor/diff-env | |
| `--network` | Allow network operations (OSV API dependency route, background feed refresh) | |
| `--approve <skills...>` | Record invocation approvals for preflight confirmation checks | |
| `--no-drift-check` | Skip environment drift check in preflight mode | |
| `--suppressions <file>` | Governed suppression baseline (JSON v1) for scan mode | |
| `--sarif <file>` | Write a SARIF 2.1.0 report (scan mode) | |
| `--baseline-config <file>` | Previous MCP config for version-to-version diff (mcp-diff mode) | |
| `--remote <source>` | Scan a remote source: local `.zip` archive (HTTPS and git acquisition disabled pending security review) | |
| `--allow-host <hosts...>` | HTTPS host allowlist for remote artifact downloads | |
| `--semantic` | Opt in to LLM semantic analysis (requires a provider and `--network`) | |
| `--gateway-config <file>` | Gateway config JSON | `~/.skill-audit/gateway.json` |
| `--attest` | Gateway mode: read an execution attestation from stdin instead of a request | |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Allowed — scan completed and policy allowed execution |
| 1 | Rejected — critical finding or preflight reject |
| 2 | Invalid input, required analyzer failure, or insufficient inspection |

The exit code is decided by the policy (critical findings, preflight gates, inspection completeness), never by the risk score or `--threshold`.

## Risk Levels

| Level | Score | Icon |
|-------|-------|------|
| Safe | 0 | ✅ |
| Risky | 0.1-3.0 | ⚠️ |
| Dangerous | 3.1-7.0 | 🔴 |
| Malicious | 7.1-10.0 | ☠️ |

## OWASP Agentic Top 10 Mapping

- **ASI01** - Goal Hijack (prompt injection)
- **ASI02** - Tool Misuse and Exploitation
- **ASI04** - Supply Chain Vulnerabilities (secrets, deps)
- **ASI05** - Unexpected Code Execution (dangerous scripts)

## Vulnerability Intelligence

Feeds are cached locally with automatic freshness checks:

| Source | Update Frequency | Cache Lifetime |
|--------|------------------|----------------|
| CISA KEV | Daily | 1 day |
| NIST NVD | Daily | 1 day |
| FIRST EPSS | Daily | 3 days |
| OSV.dev | On-query | 7 days |
| GHSA | On-query | 3 days |

**Updates:**
- Daily GitHub Actions workflow (public repos)
- Manual: `npx skill-audit --update-db`

The postinstall script only prints a banner and never performs network I/O; feeds update only via explicit `--update-db` or the repo CI workflow.

**Stale cache warning:** In lint (terminal) output a warning appears when feeds are >3 days old; in scan mode staleness is reported as a diagnostic in the canonical report.

### NVD Synchronization

The `--update-db` command fetches CVEs modified in the last 24 hours only.
For initial setup or after extended offline periods, run multiple times to build historical data:

```bash
# Multiple updates to build historical data
skill-audit --update-db
skill-audit --update-db
skill-audit --update-db
```

Note: NVD API rate limits apply (5 requests/30 sec without API key). Set `NVD_API_KEY` environment variable for 50 requests/30 sec.

## Trust Sources

1. Static pattern matching for known attack vectors
2. osv-scanner > trivy > OSV API (network opt-in) for dependency vulnerability scanning
3. Heuristic rules for common security issues

## Requirements

- Node.js 20+
- npx (for skills CLI)
- osv-scanner or trivy (optional, local dependency scanning; otherwise the OSV API route requires `--network`)

## Troubleshooting

**False positives**: Review finding at file:line, add inline comment explaining legitimate use

**Stale DB warning**: Run `skill-audit --update-db` to refresh KEV/EPSS/OSV feeds

**Skill not found**: Verify `SKILL.md` exists in root or `skills/` directory

**Feed updates after install**: The postinstall script only prints a banner — it never updates feeds. Run `skill-audit --update-db` explicitly or rely on the repo CI workflow.

**Offline mode**: Cached feeds work offline. Re-run audit with existing cache.
