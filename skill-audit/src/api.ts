/**
 * Supported programmatic API for @hungpg/skill-audit.
 *
 * The canonical pipeline is exposed here: build an immutable snapshot,
 * scan a skill, and consume the versioned report and policy decision.
 */
export {
  buildSnapshot,
  scanSkill,
  aggregateDecision,
  withExtraFindings,
  DEFAULT_SCAN_LIMITS,
  getScannerVersion,
  type ScanLimits,
  type SkillSnapshot,
  type ScanReport,
  type ScanOptions,
  type AnalyzerRun,
  type AnalyzerStatus,
  type Diagnostic,
  type PolicyDecision,
  type ScopeExclusion,
} from "./scan.js";
export {
  parseContextContract,
  evaluatePreflight,
  observeProcessExec,
  type ContextContractV1,
  type PreflightDecision,
  type ObservedCapability,
  type CapabilityKind,
} from "./context.js";
export { findingFingerprint, loadSuppressions, applySuppressions } from "./suppress.js";
export type { Finding, SourceLocation } from "./types.js";
