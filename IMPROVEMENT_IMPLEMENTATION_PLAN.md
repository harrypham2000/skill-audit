# skill-audit Improvement Implementation Plan

## Progress log

**2026-08-17 (gate pass, round 4) — release blockers closed per follow-up review.**

1. Semantic endpoint/model policy (SSRF controls): provider endpoints must be allowlisted hosts over https — plain http only for operator-allowlisted loopback (local model servers); URLs with embedded credentials rejected; redirects never followed (`redirect: "error"`); models validated syntactically and against an optional `SKILL_AUDIT_SEMANTIC_ALLOWED_MODELS` allowlist. Hosts come from `SKILL_AUDIT_SEMANTIC_ALLOWED_HOSTS` (default: the major hosted providers; the setting replaces the default). Policy rejections surface as an explicit reason (`explainSemanticProviderEnv`) instead of a silent "not configured". Documented in the README egress-policy block.
2. Beta workflow ordering corrected at the ACTIVE root workflow: commit the bump FIRST and push it to the dispatched branch (`GITHUB_REF_NAME` — the previous `git push origin develop` targeted a branch that does not exist), then tests + byte-level verify:pack on the committed tree, then publish, then tag the EXACT bump SHA with commit-derived notes (`bodyFile` path fixed). The inert duplicate workflows under `skill-audit/.github/workflows/` (never read by GitHub, not shipped in the tarball) were deleted.
3. SARIF validation deterministic: the suite test is now a hermetic structural acceptance (version/$schema/driver, every result referencing a declared rule, regions with 1-based lines and EXCLUSIVE endColumn, JSON round-trip); the official @microsoft/sarif-multitool run is opt-in via `SKILL_AUDIT_SARIF_MULTITOOL=1` (CI keeps its own validator step). New CI job `sarif-upload` additionally accepts the generated SARIF into GitHub code scanning (pinned `github/codeql-action/upload-sarif@v3.37.7` SHA, push-to-main only, `security-events: write`).
4. Symlink target-cycle detection: `buildSnapshot` tracks walked directory realpaths; a followed link resolving to an already-walked directory is recorded as a `symlink-cycle` exclusion instead of recursing (previously cycles misclassified as depth/limit failures — `limitsExceeded` → exit 2 — or duplicated subtrees). A link to the root itself remains a containment escape (targets must be strictly interior).
5. Feature-state edge cases: `not_applicable` never reads as "ran" (pure-markdown skills no longer claim structural analysis ran); skipped-with-`filesInScope` maps to `unavailable`, mirroring the kernel's exit-2 gate; dependency route errors read `unavailable` (environment failure) instead of "partially integrated" while route-none stays "not run"; semantic `degraded`/`requested_unavailable` read `unavailable` instead of "experimental" (worst status across skills wins); mcp-diff now derives feature states from actual analyzer outcomes instead of claiming everything "not run"; the semantic analyzer ledger records the honest status (failed/skipped/partial) instead of always "completed"; the no-snapshot MCP detail no longer claims "no MCP config in scope".
6. README/CLI contradictions repaired (29 findings): eight real modes with default `scan` (no `audit`), the 0/1/2 exit contract everywhere, `--threshold` documented as advisory with no default, `--block` semantics corrected, remote HTTPS/git marked disabled fail-closed, dependency route precedence (osv-scanner > trivy > OSV API), banner-only postinstall, corrected risk boundaries (Safe 0 / Risky 0.1-3.0 / Dangerous 3.1-7.0 / Malicious 7.1-10.0), regenerated options table (all 38 flags), corrected sample outputs and JSON examples, KEV/EPSS enrichment marked active, compliance marked unavailable, ASI03/ASI04 split fixed, scoring methodology rewritten to the real algorithms, SECURITY.md version table updated, AGENTS.md lifecycle-script claim narrowed.
7. Code bugs surfaced by the doc/feature audits and fixed: `--install-hook` generated a hook invoking the removed `--mode audit` (exited 2 on every invocation — the documented pre-install gate could never run; now generates `skill-audit`, the canonical scan); lint terminal summary printed `undefined` for Dangerous/Malicious counts; lint file output (`-o`) omitted the `decision` object that JSON carried and the terminal never printed it — all three renderers now carry the decision (parity tested by smoke runs); and piped `--json` output was truncated at the ~64KB pipe buffer because `process.exit()` fired before async stdout drained — the report-bearing exits (scan, lint `--block`, mcp-diff, preflight) now drain stdout/stderr before exiting, verified with a 940KB / 126-report JSON round-trip through a pipe.
8. Release split materialized as reproducible units: the uncommitted tree is split into six review-sized patch units (`release-units/01..06`), each with SHA-256 digests in `release-units/MANIFEST.md`, apply-in-order instructions, and the full-chain gate; `omp-session-*.html` is excluded from every unit. Committed/tagged/digest-verified artifacts remain the owner's action.
9. Full verification chain green after all fixes: 306 tests / 23 files (305 passing, 1 opt-in skip), tsc clean, verify:pack (bytes + smoke-run) passing, 0 vulnerabilities, diff-check clean, all five workflows valid YAML.
10. Windows containment bug fixed: `isContained` built its parent-escape prefix from the hard-coded `"../"`, so on Windows — where `path.relative` emits `..\outside` — escaping targets passed the check. The prefix now uses the active path module's separator, and path semantics are injectable so Windows behavior is tested on any platform (`paths.test.ts`: sibling-prefix, parent-exact, root-itself, and cross-drive rejection under `win32` semantics; strictly-interior targets still contained).
11. Symlink target-stat race guarded: between `realpathSync` and `statSync(target)` in the snapshot walk the target can vanish; the unguarded `statSync` crashed the whole scan. It now records an `unreadable` exclusion for that entry and continues — the same failure discipline as every other walk guard.

**2026-08-17 (gate pass, round 3) — nine remediation items closed.**

1. Default discovered-skill scan crash fixed: the snapshot map read `reports.length` inside the map callback before assignment (TDZ); replaced with an explicit accumulation loop. Default scan verified: 126 reports, correct worst-exit.
2. Dependency route tests fully deterministic: route selection extracted into pure `selectDependencyRoute`; tests assert precedence/fallback/none without invoking trivy or any scanner binary.
3. Lint policy is renderer-independent: `reportGroupedResults` returns the shared severity decision; the caller applies `--block` exits once — terminal, JSON, and file outputs exit identically.
4. Feature status truthful for failed analyzers: any failed analyzer maps its feature to `unavailable`; skipped semantics per feature (structural=tool-unavailable, deps=capability gap).
5. Symlink-follow fixed: contained symlinked directories are walked by TARGET type through the SYMLINK PATH (namespace preserved); default remains no-follow; escaping links still excluded (segment-aware).
6. Semantic responses bounded at transport (streamed byte cap before parsing) and evidence anchored: verdicts are kept only when their evidence appears verbatim in the snapshot content; unanchored verdicts are discarded and degrade the run to partial.
7. Beta release traceability repaired: version bump is committed and pushed FIRST, tests + byte-level verify:pack run on the committed tree, npm publishes that exact state, and the GitHub prerelease tags the exact published SHA with commit-derived notes.
8. SARIF acceptance validated with the official @microsoft/sarif-multitool locally (passing) and added as a CI step plus a guarded test.
9. Full verification chain green: 290 tests / 22 files, tsc clean, verify:pack (bytes + smoke-run) passing, 0 vulnerabilities, diff-check clean, all five workflows valid YAML.

## Progress log

**2026-08-17 (gate pass, round 2) — nine follow-up gates closed.**

1. Applicable skipped required analyzers now gate: a required analyzer skipped while files were in scope (python3/typescript unavailable with analyzable material) is insufficient inspection → indeterminate; `not_applicable` (no material) remains honest.
2. Semantic analysis consumes THE canonical snapshot object (single-snapshot flow: the CLI builds one snapshot per skill; scan and semantic share it; no second build, no live rereads; fingerprints bound to its digests).
3. Legacy `--mode audit` removed (rejected with guidance); lint keeps the shared severity policy for `--block`; dead audit code paths deleted.
4. MCP analysis is required whenever MCP inputs or observed `mcp.invoke` capabilities exist; invocation without any config synthesizes observed-undeclared/dynamic findings and degrades the analyzer.
5. Feature statuses derive from execution records (pattern-detection and dependency-scanning from analyzer outcomes; only canonical scan marks full analysis as run).
6. Tarball verification now inspects actual packed bytes: real pack → extract → required files non-empty → no test artifacts → packed CLI smoke-run → cleanup; wired under verify:pack/prepack.
7. mcp-diff canonicalized: it is a canonical scan with `--baseline-config`; expansion findings, ledger entry, suppressions, decision, and exit all flow through the one pipeline (high-severity expansions report but only critical findings block, per unified policy).
8. Release workflows repaired: release.yml/publish.yml/release-beta.yml are manual dispatch only (no push-triggered publication), publish from a matched committed tag with tests + verify:pack, release notes derive from commits (hard-coded notes removed); ci.yml adds typecheck, verify:pack, and npm/bun lockfile reproducibility.
9. No capability expansion: preflight still governs only process.exec, network hosts, and MCP servers — docs and feature states label Phase 3 as partial with fs/env/secrets explicitly ungoverned.

## Progress log

**2026-08-17 (gate pass) — seven remaining correctness gates closed per review follow-up.**

1. Required-analyzer degradation (partial or failed) now yields `inspection.insufficient` → indeterminate exit 2; incomplete inspection can no longer return allow. The default required set is the canonical deterministic pipeline (spec, security-patterns, ast-typescript, shell-structural, python-ast); dependency coverage gaps are `skipped` (capability unavailable), while route errors are `partial`. Manifest-invalid input keeps its precise `input.invalid_manifest` label.
2. Semantic analysis consumes snapshot content only (`extractSemanticInput`), detects snapshot drift and discards findings on mismatch, binds fingerprints to the SKILL.md/snapshot digest, and records real analyzer durations. No live rereads after snapshot creation.
3. Symlink containment is segment-aware everywhere (`src/paths.ts` `isContained`); prefix-sharing siblings are rejected (tested).
4. Legacy audit and mcp-diff exit through the shared `decideFindingsPolicy` (critical-findings gate, no score authorization); legacy audit prints a deprecation warning; its threshold is advisory-only.
5. Feature status derives dependency-scanning state from analyzer outcomes; remote-input claims state local-ZIP-only with HTTPS/git disabled.
6. Tarball-content verification (`scripts/verify-tarball.mjs`) asserts required files present and zero test artifacts; wired as `verify:pack` (clean → build → verify) under `prepack`, recursion-safe via `--ignore-scripts`.
7. Release-splitting proposal below. No version changes, commits, pushes, or publishes in this pass.

## Release-splitting proposal (gate 7)

The working tree mixes seven workstreams and cannot ship as one patch. Proposed split into reviewable commits/PRs (order matters; nothing here versions or publishes):

- **PR A — dependency/metadata only (candidate 0.9.4):** `package.json` dependency move (typescript runtime), `engines >=20`, `files` + schemas, description, both lockfiles, README Node line, `pkg-meta.test.ts` metadata assertions. Cherry-pick cleanly; no runtime code.
- **PR B — canonical kernel + policy:** `scan.ts`, `paths.ts`, `api.ts`, `types.ts`, tsconfig exclude, clean/verify scripts, `verify-tarball.mjs`, scan/pkg-meta/schema tests, default-mode switch in `index.ts`. Breaking: default mode and exit semantics → minor bump at least.
- **PR C — context + preflight:** `context.ts` (contract capabilities, preflight policy seam), preflight mode, context tests.
- **PR D — analyzers + reporting:** `ast/shell/python/mcp/sarif/suppress` + schemas + their tests (ranges, taint, MCP states, suppression metadata).
- **PR E — quarantined surfaces:** `remote.ts` (local-ZIP-only), `semantic.ts` (opt-in scaffold), `gateway.ts` (decision adapter) + tests; README sections describing them as initial slices.
- **PR F — docs + plan:** READMEs, `IMPROVEMENT_IMPLEMENTATION_PLAN.md`, progress logs.

Release steps when the owner is ready: commit PRs A–F, tag A as 0.9.4 (metadata-only), tag B+ as 0.10.0 (or 1.0.0 if exit-contract breakage warrants major), publish only from committed tags with `npm run verify:pack` green in CI. The untracked `omp-session-*.html` must NOT be committed (accidental disclosure risk) — add to `.gitignore` or delete.

## Progress log

**2026-08-16 (strict review correction pass) — executed per MISSION_DRIFT_REVIEW.md.**

Mandatory correction order status (1-13):

1. Gateway prefix matching quarantined - structured executable/argv authorization; raw compound shell strings denied (rule `structured-command-required`).
2. Remote HTTPS/Git acquisition disabled (fail-closed) pending DNS-SSRF, archive-limit, SSH-transport, and cleanup fixes; local ZIP hardened (bounded decompression, archive size cap); temp cleanup guaranteed via try/finally.
3. Context comparison now feeds the canonical policy decision at one seam (`preflight.*` rules fold into the exit contract; scan-mode exit follows it).
4. Snapshot materialization is the sole analyzer input - analyzers run against an immutable materialized copy of the hashed snapshot; finding paths are normalized back to the original root so fingerprints stay reproducible.
5. Canonical scan is the default CLI mode; legacy `--mode audit` is explicit and deprecated.
6. Scanner failures (`SCAN-*`) are diagnostics and completeness outcomes; they never become findings, fingerprints, or score.
7. Score-based authorization removed from the canonical decision (threshold is advisory only); the legacy hook gate is documented as a separate install-time convenience.
8. Dependency route errors degrade the analyzer to `partial` with explicit detail; TS/shell parse failures report degraded coverage.
9. Existing capabilities connected to context policy: `network.request` (host scope) and `mcp.invoke` (server scope) compared against `context.capabilities` declarations with default-deny.
10. Semantic findings pass through the same fingerprint -> suppress -> score -> policy sequence; suppression governance metadata retained in SARIF.
11. Documentation claims corrected: postinstall, cache, ecosystem, coverage-conditionality; vocabulary unified to the feature taxonomy; feature table rebuilt.
12. Release split unchanged: 0.9.4 = dependency/metadata only; 0.10.0+ = architecture work. Nothing published or committed from this workspace.
13. Packaging: production build excludes tests; clean -> build -> pack via prepack; programmatic API formally exported (dist/api.js).

Strict phase status after this pass:

| Area | Status |
|---|---|
| Core architecture | Corrected - snapshot and policy order are canonical; committed CI evidence still pending |
| Phase 0 | Substantially corrected - vocabulary and claims unified |
| Phase 1 | Gate re-run pending - snapshot is the sole input, canonical mode is default |
| Phase 2 | Partial - scanner failures separated; enrichment structure still incomplete |
| Phase 3 | Connected - exec/network/mcp compared, preflight drives policy |
| Phase 4 | Partially corrected - schema variants and SARIF metadata fixed; CI acceptance unverified |
| Phase 5 | Initial slices - parse-failure reporting added; completeness gates honest |
| Phase 6 | Partially integrated - five usage states; version-diff coverage still narrow |
| Phase 7 | Quarantined - local ZIP only, HTTPS/git disabled |
| Phase 8 | Initial slice - opt-in; transport bounds and evidence anchoring still limited |
| Phase 9 | Decision adapter - prefix bypass fixed; contract compilation not implemented |
| Release preparation | Blocked on commit/tag/publish discipline (see release process) |

Release process requirement: publish only from a committed, tagged, tested artifact - clean -> build -> pack-contents verification -> commit -> tag -> publish. Push-triggered publication and publish-before-commit expectations in the current workflow contradict this and should be revised before the 0.10.0 line.

Validation traceability: post-correction test counts are recorded in Validation status below. This workspace is uncommitted by instruction; commit hashes cannot be cited until the owner commits the tree.


**2026-08-16 (correction pass) — foundation correctness, packaging, and claim repairs.**

- **Snapshot hashing corrected.** Files are now streamed with bounded memory; SHA-256 covers the COMPLETE file while at most maxFileBytes is retained for analysis. Changes beyond the retained prefix change the digest; sizes reflect actual bytes; read failures stay visible in the ledger.
- **TypeScript AST available in installs.** `typescript` moved to runtime dependencies, so published installations run the TS/JS analyzer instead of silently skipping it.
- **Node compatibility corrected.** `engines` raised to `>=20.0.0` (Commander 14 requirement); lockfiles synced; `schemas/` added to published files; package description no longer claims "compliance validation".
- **Exact source ranges.** Shared 1-based SourceLocation (file, start/end line+column, precision) carried through capabilities, findings, fingerprints, JSON, and SARIF; analyzers report honest precision (exact vs line-only); markdown fenced-shell findings map to original markdown positions.
- **MCP analysis connected to observed capabilities.** Usage comparison consumes observed mcp.invoke evidence with five states (declared-and-observed, declared-but-unused, observed-undeclared, documentation-only, dynamic-indeterminate); text references are low-confidence supporting evidence only; poisoning/Unicode/unpinned/version-diff checks preserved.
- **Claims corrected.** Feature statuses reclassified (stable / experimental / initial slice / partially integrated / unavailable / not run / planned), derived from actual analyzer outcomes after each scan; gateway mode described as a policy decision and attestation adapter that owns no execution and provides no containment; "all phases complete" language removed.
- Release guidance: dependency/metadata corrections belong in 0.9.4; the scan-kernel/context/SARIF/structural/MCP/remote/semantic/gateway work belongs in 0.10.0 or later. No versions changed in this pass.


**2026-08-16 (later) — Phases 5–9: initial slices implemented.** These are first working implementations of much larger planned areas, not completed phases.

- **Phase 5 complete (all slices).** Shell structural analysis (`src/shell.ts`): quote-aware logical-command tokenizer mapping commands/redirections/shebangs to capabilities (single-quoted `$VAR` stays literal). Python AST (`src/python.ts`): parse-only via the reference `python3` interpreter, graceful skip when absent, capabilities plus assignment tracking. Intra-file taint paths in both TS and Python analyzers: `TAINT-001` env secret → network, `TAINT-002` file read → network, `TAINT-003` external input → execution, `TAINT-004` session context → output, fingerprinted under a `taint` analyzer with exact file:line evidence.
- **Phase 6 done.** `src/mcp.ts` analyzes `mcp.json`/`.mcp.json` for metadata poisoning and Unicode deception (MCP-005/006, including tool and parameter descriptions), permission mismatch and overprivilege (MCP-002/003/004), unpinned `npx`/`uvx`/`docker` references (MCP-001), dangerous auto-approval defaults (MCP-007), and version-to-version privilege expansion (MCP-008) via `--mode mcp-diff --baseline-config`.
- **Phase 7 done.** `src/remote.ts`: dependency-free ZIP parser with ZIP-slip rejection, symlink skipping, member/aggregate size limits; HTTPS downloads with private/reserved address rejection (loopback, RFC1918, CGNAT, link-local metadata, IPv6 ULA/mapped), host allowlists, per-hop redirect revalidation, streamed caps; shallow git clones (`--depth 1`, no submodules, `.git` stripped, HEAD digest recorded); single-top-level-directory descent; deterministic cleanup. Wired as `--mode scan --remote <source>`.
- **Phase 8 done.** `src/semantic.ts`: opt-in (`--semantic` + `--network`), OpenAI-compatible provider from environment, strict structured validation of model output, egress disclosure, prompt/model version metadata, static-only fallback, findings capped at high severity and merge-only (`withExtraFindings` never clears exit-2 gates). Status machine reports not_requested / requested_unavailable / successful / partial / degraded.
- **Phase 9 (initial slice).** `src/gateway.ts` + `--mode gateway`: a process.exec policy decision and attestation adapter with command allowlists (exact/prefix/wildcard), confirmation rules, environment-drift trust checks, working-directory scope, append-only JSONL decision ledger, and post-execution attestations with command digests (`--attest`). The CLI documents that it never executes commands — containment belongs to the calling wrapper.
- Verification: tests green at each step (final counts tracked in Validation status below), `tsc --noEmit` clean, build clean, and CLI smoke tests for every new surface (taint findings via scan, mcp-diff, remote ZIP scan, gateway allow/deny/confirm/drift/attest, semantic gating and unavailability).

**2026-08-16 — Milestones 1–3 complete, Milestone 4 started (slice 1).**

- Release prep: `nanoid` advisory fixed via `npm audit fix` (0 vulnerabilities). Note: npm registry contains 0.9.1–0.9.3 published from another tree; reconcile before releasing 0.9.4 from this one.
- **Phase 0 done.** Feature-status model (`src/features.ts`) reports `stable/experimental/optional/planned/not_run/not_connected` in terminal, JSON, and file output. The phantom `complianceScore: 100` is gone — scores are only emitted when checks actually ran (`complianceStatus`). Intel disconnection is stated in output and READMEs; both READMEs now carry a feature-status table.
- **Phase 1 done.** Canonical kernel `scanSkill()` in `src/scan.ts`: immutable snapshot with per-file hashes/sizes/exec bits/exclusions, configurable limits (files/bytes/depth/symlinks/timeout), analyzer ledger with `completed/partial/skipped/failed/not_applicable`, diagnostics separated from findings, policy computed before any renderer, exit contract 0/1/2 (breaking change — see assessment), `--mode scan` CLI, `aggregateDecision`. Fixture tests cover clean/malicious/unreadable/oversized/disabled-analyzer/analyzer-failure/invalid-manifest.
- **Phase 2 done.** One authoritative dependency route per run (`osv-scanner` > `trivy` > OSV API), scanner errors are diagnostics (SCAN-* error-findings removed), local KEV/EPSS cache enrichment joined into canonical `VULN-*` findings (severity escalation, CWE, confidence), `Finding` gained `confidence`/`cwe`, all network I/O is opt-in via `--network` (background feed refresh included).
- **Phase 3 done.** Typed context contract schema v1 (`src/context.ts`) with strict validation (invalid values → `CTX-007` + indeterminate preflight), trust levels (declared/observed/invocation/environment), `process.exec` observation (regex-grade) and `evaluatePreflight` returning `allow/confirmation_required/reject/indeterminate`. `--mode preflight` CLI with approvals (`--approve`), environment drift integration, undeclared-exec rejection, confirmation gating.
- **Phase 4 done.** Finding fingerprints (scanner+analyzer+rule+path+source digest+evidence), governed suppressions (`src/suppress.ts`) requiring reasons with approver/ticket/created/expires, automatic reactivation on expiry or fingerprint change, suppressed findings visible in JSON and SARIF but excluded from policy/score, SARIF 2.1.0 adapter (`src/sarif.ts`) with `partialFingerprints`, versioned report schema `schemas/scan-report.schema.json` (validated against real output).
- **Phase 5 slice 1 done.** TypeScript/JavaScript AST analyzer (`src/ast.ts`) using the TypeScript compiler API when resolvable (graceful skip otherwise), emitting shared `ObservedCapability` records (`process.exec`, `network.request`, `fs.read`, `fs.write`, `env.read`) with exact file:line evidence, deduplicated with regex observation in the kernel.
- Verification at each step: 112 tests / 12 files green, `tsc --noEmit` clean, build clean, CLI smoke tests for every mode (exit codes 0/1/2 verified end-to-end; suppression flip 1→0; SARIF/JSON decision agreement; schema validation pass).
- Remaining: Phase 5 slices 2+ (shell structural analysis, Python AST, intra-file taint), Phases 6–9 (MCP depth, remote input, optional semantic analysis, runtime enforcement) — per the milestone plan these are separate releases.

## Objective

Evolve `skill-audit` from a regex-oriented package scanner into a trustworthy, context-aware preflight security engine that determines whether a skill is safe to invoke for a specific user goal, declared context, and execution environment.

The implementation should:

1. Reach foundational parity with NVIDIA SkillSpector.
2. Preserve and deepen `skill-audit`'s environment and session-context strengths.
3. Verify declared contracts against observed behavior.
4. Establish a path toward runtime policy enforcement.
5. Improve incrementally without a large rewrite.

## Current release preparation

Dependency security patches have been applied locally:

- `semver`: `^7.5.4` → `^7.8.5`
- `@types/node`: `^25.5.0` → `^25.9.5`
- `tsx`: `^4.7.0` → `^4.23.7`
- `vitest`: `^4.1.0` → `^4.1.10`
- Vulnerable transitive versions of `js-yaml`, `esbuild`, `vite`, and `postcss` were resolved through lockfile updates.
- `package-lock.json` and `bun.lock` were synchronized.

Validation status (updated after the 2026-08-16 correctness pass):

- `npm audit`: 0 vulnerabilities (`nanoid` GHSA-2v37-7h3g-55p8 fixed via `npm audit fix`)
- Tests: 174 passed (17 files)
- TypeScript build: passed
- `git diff --check`: passed

Publishing is currently blocked because:

- npm authentication returns `E401 Unauthorized`.
- The local package version is `0.9.0`, while npm already contains `0.9.3`.

Recommended next release: `0.9.4` after npm authentication is restored. No commit or push should occur until the package has been published and verified.

## Target architecture

```text
Input
  → immutable skill snapshot
  → analyzers and inspection ledger
  → observed capability model
  → context contract comparison
  → policy decision
  → canonical scan report
  → terminal / JSON / SARIF / Markdown / MCP adapters
```

Reporting must not determine policy. The processing order should be:

```text
snapshot → analyzers → capabilities → context comparison
         → policy decision → canonical report → renderer → exit code
```

## Core model

Keep these concepts separate:

- **Finding:** Security evidence about the target skill.
- **Diagnostic:** Evidence that an analyzer failed or degraded.
- **Capability:** Behavior observed in the implementation.
- **Decision:** Policy outcome for the caller.
- **Score:** Prioritization signal, not authorization.

Core result types should include:

```ts
interface ScanReport {
  schemaVersion: "1";
  scanner: ScannerIdentity;
  input: ScanInputSummary;
  findings: Finding[];
  capabilities: ObservedCapability[];
  analyzerRuns: AnalyzerRun[];
  scanStatus: "complete" | "partial" | "failed";
  decision: PolicyDecision;
}
```

## Phase 0 — Correct trust and documentation issues

### Goal

Stop overstating capabilities that are present in code but disconnected from the real audit pipeline.

### Tasks

- Do not emit a perfect compliance score when compliance checks did not run.
- Report explicit feature states such as `not_run`, `not_connected`, and `experimental`.
- Treat current compliance checks as an experimental regulatory documentation checklist, not legal compliance verification.
- Mark vulnerability intelligence as disconnected until KEV/EPSS/NVD data enriches actual dependency findings.
- Update README claims to distinguish stable, experimental, optional, and planned features.

### Acceptance gate

- No output claims an analyzer ran when it did not.
- Disabled features cannot affect security decisions.
- Terminal and JSON output report the same feature status.

## Phase 1 — Canonical scan kernel and inspection ledger

### Goal

Create a dependable foundation before adding more detectors.

### Tasks

1. Extract a programmatic `scanSkill()` API from the CLI.
2. Enumerate and read files once into an immutable snapshot.
3. Record normalized paths, hashes, sizes, types, executable status, exclusions, and read failures.
4. Add configurable file-count, file-size, aggregate-byte, depth, symlink, and timeout limits.
5. Record every analyzer as completed, partial, skipped, failed, or not applicable.
6. Separate findings, diagnostics, scope exclusions, and policy decisions.
7. Compute policy before selecting an output renderer.

Recommended exit contract:

| Exit code | Meaning |
|---:|---|
| `0` | Scan completed and policy allowed execution |
| `1` | Scan completed and policy rejected execution |
| `2` | Invalid input, required analyzer failure, or insufficient inspection |

Critical findings and incomplete required inspection must be direct policy gates. Aggregate score should remain a secondary signal.

### Acceptance gate

- Clean, malicious, unreadable, oversized, disabled-analyzer, analyzer-failure, and invalid-manifest fixtures pass end-to-end tests.
- Terminal, JSON, and file output produce the same decision and exit code.
- Incomplete scans cannot appear safe.
- The report schema is versioned and stable.

## Phase 2 — Harden existing detection and dependency intelligence

### Goal

Make current capabilities deterministic, accurate, and fully connected.

### Tasks

- Replace broad known-safe script filtering with narrow, fingerprinted exceptions.
- Normalize finding category, severity, confidence, rule ID, evidence, and OWASP/CWE mappings.
- Select one authoritative vulnerability resolution route per run.
- Join OSV, KEV, EPSS, CVSS, fix, and freshness data into one canonical dependency finding.
- Make all network operations explicit and separately configurable.
- Harden traversal against symlink escape and unsupported file types.
- Record ignored, binary, oversized, malformed, and unreadable files in coverage.

### Acceptance gate

- Repeated offline scans are deterministic.
- One vulnerable package produces one enriched finding.
- Missing tools and stale feeds are diagnostics, not vulnerabilities.
- No scanner error contributes to the security score.

## Phase 3 — Typed context contracts and capability comparison

### Goal

Turn context awareness from metadata linting into evidence-based preflight analysis.

### Tasks

1. Replace `context?: unknown` with a versioned schema.
2. Separate declared contract, static observations, invocation facts, and environment state by trust level.
3. Implement `process.exec` as the first observed capability.
4. Compare observed execution against declarations, confirmation rules, approvals, and environment drift.
5. Return `allow`, `confirmation_required`, `reject`, or `indeterminate`.
6. Expand incrementally to filesystem, environment, secrets, network, package installation, Git mutation, agent configuration, and MCP use.

Example capability comparison:

```text
Capability       Declared       Observed       Result
process.exec     npm test       npm test       match
fs.read          changed/**     ~/.ssh/**      violation
network.connect  none           api.x.com      violation
```

### Acceptance gate

- Undeclared shell execution is rejected.
- Required confirmation cannot pass without approval.
- Environment drift changes the preflight decision.
- Invalid contract values fail schema validation.
- Findings contain exact evidence and locations.

## Phase 4 — Finding fingerprints, suppressions, and SARIF

### Goal

Support governed false-positive handling and enterprise CI.

### Tasks

- Generate fingerprints from scanner/rule version, analyzer ID, path, source digest, and evidence.
- Add YAML/JSON finding-level baselines.
- Require suppression reasons and support approver, ticket, creation, and expiration fields.
- Reactivate suppressions after source, evidence, rule, or expiration changes.
- Keep suppressed findings visible in JSON and SARIF.
- Prevent suppressions from hiding failed or incomplete inspection.
- Add SARIF 2.1.0 and a versioned JSON schema.

### Acceptance gate

- GitHub code scanning accepts generated SARIF.
- JSON and SARIF decisions agree.
- Expired or invalidated suppressions reactivate findings.
- Suppressed findings do not affect policy but remain auditable.

## Phase 5 — Structural code analysis

### Goal

Move beyond regex detection and reach or exceed SkillSpector's static analysis depth.

### Delivery order

1. TypeScript/JavaScript AST
2. Shell structural analysis
3. Python AST
4. Intra-file taint analysis
5. MCP static analysis
6. Optional YARA support where justified

Each analyzer should emit the shared `ObservedCapability` model rather than introducing a language-specific policy model.

Initial taint paths:

- Environment secret → network request
- File read → network request
- External input → process execution
- Session context → log or network output

### Acceptance gate per analyzer

- Parse failures and exclusions are visible.
- Exact source ranges are preserved.
- Applicability and limitations are documented.
- Benign corpus false-positive limits are maintained.
- Runtime and memory remain bounded.

## Phase 6 — MCP security analysis

### Goal

Add dedicated MCP permission, metadata, supply-chain, and drift analysis.

### Tasks

- Compare declared MCP permissions against observed capabilities.
- Detect wildcards, missing declarations, unused permissions, and overprivilege.
- Detect hidden instructions, Unicode deception, dangerous defaults, and parameter-description injection.
- Detect unpinned `npx`, `uvx`, Docker, and package references.
- Compare versions for permission, endpoint, parameter, tool, trigger, and context-access expansion.

### Acceptance gate

An MCP skill can be evaluated for metadata poisoning, permission mismatch, install-reference integrity, and version-to-version privilege expansion.

## Phase 7 — Safe remote input support

### Goal

Scan skills before installation.

### Delivery order

1. Local ZIP
2. HTTPS artifact
3. Git repository

### Required controls

- HTTPS and host allowlists
- Private/reserved address rejection
- Redirect revalidation
- Streamed download limits
- Archive expansion and member limits
- ZIP-slip and symlink protection
- Shallow Git clone with timeout
- No implicit submodules or Git LFS
- Deterministic cleanup
- Recorded origin and immutable snapshot digest

### Acceptance gate

Remote inputs cannot reach private services, escape extraction roots, exhaust storage without limits, execute lifecycle hooks, or pull implicit submodules.

## Phase 8 — Optional semantic analysis

### Goal

Detect intent and narrative risks that static analysis cannot reliably identify.

### Tasks

Add independent semantic checks for:

- Paraphrased prompt injection and social engineering
- Natural-language exfiltration
- Declared-purpose versus observed-behavior mismatch
- Unjustified capability scope
- Missing warning or confirmation boundaries

Required controls:

- Explicit opt-in and source-egress disclosure
- Provider/model allowlists and local-provider support
- Input/output limits and structured validation
- Prompt/model version metadata
- Static-only fallback
- No tools available to the analysis model
- LLM results cannot remove or lower critical deterministic findings

### Acceptance gate

Every report states whether semantic analysis was requested, available, attempted, successful, partial, or degraded.

## Phase 9 — Runtime contract enforcement

### Goal

Compile context contracts into enforceable tool policies.

### Initial slice

Enforce `process.exec` through an agent tool gateway with:

- Command allowlists
- Confirmation rules
- Environment trust checks
- Working-directory scope
- Command and result logging
- Post-execution attestation

Later expand to filesystem paths, network destinations, MCP tools, secrets, package installation, and agent configuration.

The CLI must not claim containment unless it owns or wraps the actual execution boundary.

## Delivery milestones

### Milestone 1 — Trustworthy scanner core

Includes Phases 0–2 foundations:

- Canonical scan report
- Inspection ledger
- Correct exit semantics
- Deterministic offline scanning
- Accurate feature-status reporting
- Connected dependency intelligence

Target: approximately two weeks.

### Milestone 2 — Context-aware preflight

Includes:

- Typed context schema
- `process.exec` capability
- Declared-versus-observed comparison
- Environment drift integration
- Preflight policy decisions

Target: approximately one to two weeks.

### Milestone 3 — Enterprise CI foundation

Includes:

- Fingerprints
- Governed suppressions
- SARIF
- Versioned JSON schema

Target: approximately one week.

### Milestone 4 — Structural analysis advantage

Includes:

- TypeScript AST
- Shell structural analysis
- Python AST
- Initial taint paths

Target: approximately three to five weeks, delivered incrementally.

### Milestone 5 — Supply-chain and MCP depth

Includes:

- MCP least privilege
- Tool poisoning
- Rug-pull diffing
- Remote artifact scanning
- Stronger provenance

Target: approximately three to four weeks.

### Milestone 6 — Semantic and runtime layers

Includes optional semantic analysis, a thin MCP scanner adapter, and a runtime policy prototype. These should be separate releases.

## Deliberately deferred features

Until the foundational phases are complete, defer:

- Legal compliance scoring based on keywords
- General code-property graphs
- Cross-language or interprocedural taint
- LLM-based suppression of static findings
- Mandatory YARA/native bindings
- Live execution of untrusted MCP servers
- Public unauthenticated MCP HTTP service
- OPA/Rego policy hierarchy
- Fleet dashboards and central rule distribution
- Runtime sandbox claims
- Full SLSA, signing, and SBOM platforms

## Definition of success

The improved tool must answer independently:

1. What did the skill declare?
2. What capabilities did its implementation exhibit?
3. What sensitive data could flow to which sinks?
4. What was not fully inspected, and why?
5. Is the local execution environment still trusted?
6. Does this invocation have the required approvals?
7. Which policy rule produced the decision?
8. What was suppressed, by whom, and until when?
9. Can CI consume the result consistently?
10. Can the result be reproduced from the same artifact and configuration?

The implementation priority is:

> Make every result trustworthy, make context contracts evidence-based, add deeper structural analyzers, and only then pursue semantic analysis and runtime enforcement.
