# skill-audit Strict Mission-Drift Review

## Review status

**Verdict: non-conformant and not release-ready.**

The implementation still points toward the intended product, but it has drifted from a deep, trustworthy context-aware preflight engine toward several broad, partially integrated security surfaces.

Verification performed during the review:

- 212 tests passed across 20 files
- TypeScript build passed
- `npm audit` reported 0 vulnerabilities
- `git diff --check` passed

Passing tests do not cover the architectural and security failures documented below.

## Intended mission

The implementation plan requires one canonical flow:

```text
snapshot
→ analyzers
→ observed capabilities
→ context comparison
→ policy decision
→ canonical report
→ output adapters
```

The product should answer whether a skill is safe for a particular user goal, declared context, approval state, and execution environment. Score is for prioritization, not authorization.

## Critical drift

### 1. Context preflight does not control the canonical decision

`src/scan.ts` computes the generic policy decision before evaluating context preflight. The report can therefore contain a canonical `allow` decision alongside a `reject`, `confirmation_required`, or `indeterminate` preflight result. Scan-mode exit behavior follows the canonical decision rather than the context result.

This directly breaks the central product mission.

**Required correction:** evaluate capabilities and context before policy, and feed contract violations, approvals, and environment trust into one final decision.

### 2. The immutable snapshot is not the source of truth

Specification, legacy security, dependency, Python, and semantic analyzers reread live filesystem paths instead of exclusively consuming immutable snapshot content.

Consequences:

- TOCTOU inconsistency
- Findings may not match recorded hashes
- Snapshot exclusions and truncation can be bypassed
- Fingerprints may bind to different content
- Reports are not reproducible from their snapshots

**Required correction:** every deterministic analyzer must consume the snapshot or an immutable artifact derived from it.

### 3. Default audit mode bypasses the canonical architecture

The default CLI path remains legacy `audit`, which lacks the snapshot, analyzer ledger, capability model, preflight comparison, canonical suppressions, and unified policy semantics.

**Required correction:** make canonical scanning the default and deprecate or remove the legacy path.

### 4. Gateway prefix matching permits command injection

A prefix policy can approve commands such as:

```text
npm test && touch /tmp/pwn
```

when `npm:*` is allowed. The complete raw shell string is accepted because it starts with the approved prefix.

**Required correction:** quarantine prefix matching. Authorize structured executable/argv values rather than raw shell strings.

### 5. HTTPS remote scanning is vulnerable to DNS-based SSRF

Remote validation checks literal addresses and hostname patterns but does not resolve and validate DNS addresses before connecting. A public hostname can resolve or rebind to private, loopback, link-local, or metadata addresses.

**Required correction:** resolve, validate, and pin connection addresses; revalidate every redirect hop.

### 6. Scanner failures remain security findings

Legacy `SCAN-ERR-*` conditions are imported into canonical findings, fingerprints, scores, and policy.

**Required correction:** scanner failures must be diagnostics and completeness outcomes. They may cause `indeterminate`, but must not modify vulnerability risk.

## High-priority architecture drift

### 7. Risk score still authorizes rejection

Canonical and legacy paths use aggregate score as a blocking decision even though the plan explicitly defines score as a prioritization signal.

**Required correction:** use explicit policy gates for critical findings, contract violations, environment drift, and incomplete inspection.

### 8. Dependency failures can appear completed

A selected dependency route can return an error while the analyzer is marked completed. This can produce zero findings, a complete scan, and an allow decision.

**Required correction:** inspect route diagnostics and mark failed or partial coverage accurately.

### 9. Structural parse failures appear successful

Invalid TypeScript and malformed shell input can be reported as completed analysis because parser diagnostics and malformed syntax are not surfaced.

**Required correction:** report parse failure or degraded coverage explicitly.

### 10. Snapshot hashes can ignore truncated suffixes

The scanner truncates content before hashing. Files with the same retained prefix but different suffixes can share a hash.

**Required correction:** hash the complete file using bounded-memory streaming while retaining only bounded analysis content.

### 11. Symlink containment uses unsafe string-prefix matching

A sibling path beginning with the same text as the root can pass containment checks.

**Required correction:** use normalized, path-segment-aware relative containment.

### 12. ZIP limits trust attacker-controlled metadata

Archive limits rely on declared uncompressed sizes before unbounded inflation. Local ZIP files are also loaded fully into memory without equivalent input limits.

**Required correction:** use bounded decompression and apply archive-size limits before reading or inflating.

### 13. SSH Git remotes bypass the HTTPS policy

SSH syntax is converted to synthetic HTTPS only for validation, while the original SSH target is cloned.

**Required correction:** reject SSH and clone only the exact HTTPS URL that passed validation.

### 14. Remote provenance is discarded

Origin and artifact digest information returned during acquisition do not reach the canonical report.

**Required correction:** preserve remote origin, artifact digest, Git identity, and acquisition metadata in `ScanReport.input`.

### 15. Failed remote acquisition leaks temporary files

Temporary directories are not guaranteed to be removed when download, extraction, or clone fails before a cleanup handle reaches the caller.

**Required correction:** clean acquisition state with internal `try/finally` handling.

### 16. Network consent is inconsistent

Dependency and semantic access require `--network`; remote HTTP and Git access use a separate implicit consent model.

**Required correction:** define and enforce one explicit network-consent contract.

## Context-model drift

### 17. Only `process.exec` meaningfully affects preflight

Filesystem, network, environment, secret, package, Git, agent configuration, and MCP capabilities are not uniformly compared against declarations.

**Required correction:** freeze analyzer expansion and connect existing capabilities to policy one vertical slice at a time.

### 18. MCP permission analysis remains partly textual

Documentation references can be interpreted as MCP usage, while dynamic calls can be missed.

**Required correction:** distinguish observed invocation, declared-but-unused, observed-but-undeclared, documentation-only, and indeterminate use.

### 19. Contract violations have competing representations

Context violations exist as preflight records and can also be converted to findings, but no single canonical decision seam is used.

**Required correction:** capability comparison must produce policy inputs consumed exactly once by the canonical engine.

### 20. Gateway policy is not compiled from context contracts

Gateway mode reads a separate policy file rather than compiling the skill's context declaration.

**Required correction:** call it a decision adapter until context contracts are its actual policy source.

## Semantic-analysis drift

### 21. Semantic evidence is not anchored to source

Any non-empty evidence returned by the model can be accepted, even if it does not exist in the supplied content.

**Required correction:** require and validate exact excerpts or source ranges.

### 22. Semantic responses lack transport-level bounds

The response is fully downloaded and parsed before output limits are applied.

**Required correction:** enforce byte limits while streaming before JSON parsing.

### 23. Provider controls are incomplete

Model and endpoint allowlists are incomplete, and lifecycle reporting does not fully represent attempted, partial, unavailable, and degraded states.

**Required correction:** enforce provider, endpoint, and model policy separately.

### 24. Semantic findings bypass suppression ordering

Semantic findings are appended after normal fingerprint and suppression processing.

**Required correction:** all findings must use one sequence:

```text
normalize → fingerprint → suppress → score → policy
```

## Reporting and schema drift

### 25. The JSON schema rejects valid emitted capabilities

The implementation can emit `mcp.invoke` and scoped capabilities that are absent from the schema.

**Required correction:** validate the schema against every capability variant generated by the scanner.

### 26. Exact source ranges are not preserved

Several analyzers expose only line numbers rather than start/end lines and columns.

**Required correction:** use one shared source-location model through capabilities, findings, fingerprints, JSON, SARIF, and suppressions.

### 27. Analyzer ledger attribution is inaccurate

Some analyzers produce taint findings while reporting zero findings; the taint analyzer may have no corresponding run record; semantic duration/status can be inaccurate.

**Required correction:** every finding must point to a real analyzer run with correct coverage, status, duration, and counts.

### 28. Feature status is mode-derived rather than outcome-derived

Features may be labelled stable or available because a mode was selected, even when an analyzer did not run or was unavailable.

**Required correction:** derive feature status only from analyzer and adapter execution records.

### 29. Suppression governance metadata is incomplete

Creation and approval metadata is parsed but not fully retained in reports.

**Required correction:** preserve reason, creator, approver, ticket, creation date, and expiration in JSON and SARIF.

### 30. SARIF stability is unverified

No CI evidence demonstrates acceptance by GitHub code scanning.

**Required correction:** validate SARIF in CI before calling the adapter stable.

### 31. Target adapters remain incomplete

Canonical Markdown and a thin MCP scanner adapter are absent.

This is roadmap incompleteness, but it contradicts claims that the target architecture is complete.

## Multiple-pipeline drift

### 32. Legacy rendering still controls policy

Legacy JSON/file output can return before threshold enforcement, producing output-dependent exit behavior.

**Required correction:** route legacy output through the canonical report or remove the legacy path.

### 33. MCP diff invents an independent policy

MCP diff fails whenever any finding exists, including low-severity observations, bypassing suppressions and canonical policy.

**Required correction:** send MCP diff results through the shared policy engine.

### 34. CLI modes implement incompatible security semantics

Legacy audit, canonical scan, preflight, MCP diff, gateway, and semantic processing make partially independent decisions.

**Required correction:** all modes must create or extend one canonical report and policy decision.

## Dependency and MCP completeness drift

### 35. Dependency enrichment is incomplete

The plan requires structured OSV identity, KEV, EPSS, CVSS, fix version, source, and freshness information. Current enrichment does not fully model these fields.

### 36. Dependency maturity is overstated

Coverage depends on installed scanners and network permissions, but documentation labels dependency scanning stable without reporting actual route and coverage.

### 37. MCP version-diff coverage is incomplete

Trigger expansion, context-access expansion, existing parameter semantic changes, and command/argument behavior changes are not fully compared.

## Packaging and release drift

### 38. Dependency patches and major features are mixed

The working tree combines dependency patches with new kernel, context, SARIF, structural, MCP, remote, semantic, and gateway behavior.

Recommended split:

- `0.9.4`: dependency and metadata corrections only
- `0.10.0` or later: new scanner architecture and experimental surfaces
- Major release if defaults or exit semantics change incompatibly

### 39. Local version is stale

The local package remains behind versions already published to npm and cannot be released as-is.

### 40. Release automation conflicts with the intended process

Push-triggered publication, hard-coded release notes, audit continuation, and publish-before-commit expectations do not provide one reproducible workflow.

**Required correction:** publish only from a committed, tagged, tested artifact.

### 41. Compiled tests may enter the npm package

Test sources are compiled while all of `dist` is published.

**Required correction:** exclude tests from the production build and verify tarball contents.

### 42. Packaging can inspect stale build output

There is no guaranteed clean production build before packing.

**Required correction:** add `clean → build → package-content test → pack`.

### 43. The programmatic API is not formally exported

`scanSkill()` is described as an API, but package exports, declaration output, and type metadata do not establish a supported programmatic interface.

### 44. Two lockfiles are not continuously verified

Both npm and Bun locks exist, but CI does not prove both are reproducible.

### 45. The reviewed implementation is largely untracked

New modules, tests, schemas, and the plan lack committed source identity. CI and npm cannot reproduce the reviewed workspace.

### 46. Unrelated session HTML is an accidental-commit risk

The root `omp-session-*.html` file is untracked and may contain sensitive session data.

## Documentation drift

### 47. “All phases complete” is inaccurate

Progress entries simultaneously describe initial slices and completed phases.

### 48. Compliance claims remain overstated

Documentation alternates between compliance detection, compliance validation, disconnected checks, and experimental checklists.

### 49. Feature-state vocabulary is inconsistent

Runtime and documentation use incompatible labels such as `not_run`, `not run`, `not_connected`, `unavailable`, `optional`, and `initial slice`.

### 50. The feature-status table contains malformed Markdown

Literal newline text collapses multiple feature rows.

### 51. Pattern and structural analysis claims contradict one another

One section describes regex-only analysis while another claims AST, shell, Python, and taint coverage.

### 52. Postinstall update claims are false

Documentation claims package installation fetches vulnerability feeds, while the actual postinstall script performs no network update.

### 53. Vulnerability source documentation is inconsistent

READMEs and CLI behavior disagree about KEV, EPSS, NVD, OSV, and GHSA support and refresh behavior.

### 54. GitHub cache claims overstate user impact

A repository-local Actions cache does not update npm users' local vulnerability data.

### 55. Registry/ecosystem integration claims lack evidence

Claims about automatic validation in the Vercel Skills ecosystem are unsupported by repository integrations.

### 56. “Automatically answers” security questions overstates coverage

Actual coverage depends on mode, installed tools, network permission, language support, semantic provider availability, and inspection completeness.

### 57. Validation records lack traceability

Test counts are stale and historical entries lack commit hashes, schema versions, package digests, or artifact identities.

## Strict phase status

| Area | Status |
|---|---|
| Core architecture | Failed — snapshot and policy order are not canonical |
| Phase 0 | Partial — feature and compliance claims remain inconsistent |
| Phase 1 | Failed gate — analyzers bypass snapshot and legacy remains default |
| Phase 2 | Partial — scanner failures and intelligence structure unresolved |
| Phase 3 | Partial — mainly `process.exec`, detached from canonical policy |
| Phase 4 | Partial — schema and suppression metadata gaps |
| Phase 5 | Initial slices — parse, range, and completeness gates unmet |
| Phase 6 | Partial — MCP behavior and diff coverage incomplete |
| Phase 7 | Failed security gate — DNS SSRF, ZIP limits, and SSH transport |
| Phase 8 | Initial slice — evidence and response limits incomplete |
| Phase 9 | Unsafe prototype — prefix bypass and no contract compilation |
| Release preparation | Blocked |
| Mission alignment | Partially retained, materially drifted |

## Mandatory correction order

1. Disable or quarantine gateway prefix command matching.
2. Disable remote HTTPS/Git scanning until SSRF, archive, SSH, and cleanup issues are fixed.
3. Feed context comparison into canonical policy.
4. Make the snapshot the only analyzer input.
5. Replace legacy default audit with canonical scan.
6. Separate scanner failures from findings.
7. Remove score-based authorization.
8. Correct dependency and structural completeness reporting.
9. Connect existing capabilities to context policy.
10. Unify suppression, semantic, schema, and ledger ordering.
11. Correct documentation and maturity claims.
12. Split dependency release from feature releases.
13. Add deterministic packaging and committed release traceability.

## Drift-control rule

Until the mandatory correction order is complete:

- Do not add analyzers.
- Do not add CLI modes.
- Do not expand semantic analysis.
- Do not expand remote input support.
- Do not claim runtime enforcement or containment.
- Do not publish, commit, or push broad changes as a patch release.

The governing principle is:

> Stop expanding detection breadth. Make one canonical, reproducible, context-aware policy pipeline trustworthy from acquisition through final decision.
