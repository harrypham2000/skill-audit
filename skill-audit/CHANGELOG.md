# Changelog

All notable changes to `@hungpg/skill-audit` are documented here.

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
