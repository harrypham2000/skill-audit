# Changelog

All notable changes to `@hungpg/skill-audit` are documented here.

## [Unreleased]

### Added

- `.env` files (`.env`, `.env.local`, `production.env`, and similar variants) and common config formats (`.json`, `.jsonc`, `.toml`, `.ini`, `.cfg`, `.conf`, `.properties`, `.xml`, `.txt`) are now scanned. They use the credential-focused rule set only — credential leaks, exfiltration, shell execution, secret formats, and credential-shaped PII — because config values are data, not agent instructions, and numeric PII rules would match ordinary lockfile versions and hashes. A config file over 2 MiB is reported as `SCAN-ERR-04` and makes the security analyzer `partial` instead of being skipped silently.
- Reports now carry `coverageGaps`: analyzers that had material in scope but did not cover it. A dependency scan skipped for lack of a scanner (or because of `--no-deps`) while manifests are present is stated explicitly instead of being readable as full coverage.
- Finding and capability evidence is redacted at report assembly. Secret values become a value-derived `[REDACTED:xxxxxxxx]` placeholder in JSON, SARIF, and terminal output; variable references such as `$TOKEN` or `process.env.X` stay readable.

### Changed

- Finding fingerprints now digest analyzer, rule id, skill-root-relative path, source digest, redacted evidence, and location. The scanner version and absolute checkout path are excluded, so a patch release or a different checkout directory no longer invalidates every suppression. **Existing suppression baselines must be regenerated once.**
- `scanStatus` continues to describe required inspection; optional coverage is reported in `coverageGaps` rather than folded into the status.
- `requiredAnalyzers: ["dependencies"]` now actually gates: a skipped dependency run with manifests in scope is insufficient inspection.
- `location.file` no longer points at the throwaway materialization directory.

## [0.10.1] - 2026-09-28

### Changed

- Context-contract v1 validation now rejects empty declarations and unsupported fields instead of silently accepting ineffective or misspelled policy.
- `confirmation: always` and applicable `on-risk` confirmation boundaries now cover observed network and MCP use as well as shell execution.
- Context-read warnings now identify broader workspace, system-instruction, secret, and conversation scopes.

## [0.10.0] - 2026-08-19

### Added

- Canonical `scanSkill()` API with immutable snapshots, analyzer execution records, diagnostics, scan completeness, and consistent policy decisions.
- Context contract preflight for declared versus observed process, network, and MCP capabilities.
- TypeScript/JavaScript AST analysis, shell structural analysis, Python AST analysis, and initial intra-file taint detection.
- MCP configuration, metadata-poisoning, least-privilege, and version-diff checks.
- Finding fingerprints, governed suppressions, versioned JSON schema, and SARIF output.
- Environment drift integration and structured gateway decision/attestation support.
- Optional semantic analysis with explicit network consent, bounded responses, and source-anchored evidence.
- A supported typed package API through `@hungpg/skill-audit`.
- Production tarball verification, including extraction and packaged-CLI smoke testing.

### Changed

- Canonical scan mode is now the default execution path.
- Node.js 20 or newer is required.
- TypeScript is now a runtime dependency so structural analysis is available in published installations.
- Dependency scanning uses one authoritative route per run and enriches canonical vulnerability findings from local intelligence caches.
- Scanner failures and incomplete inspection are represented separately from security findings and can produce an indeterminate decision.
- Context preflight is evaluated before the final canonical policy decision.
- Package and feature status reporting now distinguishes maturity from execution availability more accurately.
- Updated runtime and development dependencies, including patched transitive `js-yaml`, `esbuild`, `vite`, and `postcss` versions.

### Security

- Added bounded full-file hashing while retaining limited analysis content.
- Hardened symlink containment across POSIX and Windows path semantics.
- Added contained symlink traversal, target race handling, and realpath-based cycle detection.
- Quarantined unsupported HTTPS and Git remote acquisition paths rather than exposing incomplete SSRF protections.
- Replaced unsafe raw command-prefix authorization with structured command assessment.
- Added bounded ZIP extraction and improved temporary-resource cleanup.
- Added semantic response limits and source-evidence validation.

### Deprecated

- Legacy audit semantics have been removed from the default path. Consumers should use canonical scan reports and exit codes.

### Known limitations

- Context policy currently governs process execution, network hosts, and MCP servers; filesystem, environment-secret, package-installation, Git-mutation, and agent-configuration policy remain future work.
- HTTPS and Git remote acquisition remain unavailable until their network security boundary is fully implemented.
- Compliance checks remain an experimental, disconnected documentation checklist and do not constitute legal compliance validation.
- Semantic analysis is optional and must be explicitly enabled with network consent and an approved provider configuration.

## [0.9.3]

- Previous npm registry release. See the repository history for changes published before this changelog was introduced.
