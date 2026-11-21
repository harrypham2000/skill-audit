/**
 * Secret redaction for report evidence.
 *
 * Reports are meant to be shared: with a reviewer, a client, a CI artifact, or
 * a release record. Evidence must therefore never carry a live credential.
 *
 * Redaction replaces the secret VALUE with a short digest of that value:
 *
 *   export API_KEY="sk-live-…"   ->   export API_KEY="[REDACTED:1a2b3c4d]"
 *
 * The digest matters for two reasons:
 *   1. Fingerprints are derived from evidence. A constant placeholder would make
 *      two different secrets look identical, so a replaced credential would be
 *      reported as "unchanged" — the exact failure a release review must not
 *      have. Distinct secrets keep distinct placeholders.
 *   2. The same secret keeps the same placeholder across runs and releases, so
 *      identity stays stable.
 *
 * Surrounding context (variable name, file, line) is preserved so a reviewer
 * can still tell what was found without seeing the value.
 */
import { createHash } from "crypto";

/** Values that are references, not secrets: leave them visible. */
const REFERENCE_VALUE = /^(?:\$|%|<|process\.env\b|env\.|os\.environ|import\.meta|undefined$|null$)/;

/** Matched secrets shorter than this are not worth redacting. */
const MIN_SECRET_LENGTH = 8;

function placeholder(secret: string): string {
  const digest = createHash("sha256").update(secret).digest("hex").slice(0, 8);
  return `[REDACTED:${digest}]`;
}

/** Known credential token shapes, each a full-token match. */
const TOKEN_RULES: RegExp[] = [
  // PEM private key blocks, including the body.
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bghp_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bASIA[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  /\bnpm_[A-Za-z0-9]{36}\b/g,
];

/** `Authorization: Bearer <token>` — keep the scheme, redact the credential. */
const AUTH_SCHEME_RULE = /\b(Bearer|Basic)(\s+)([A-Za-z0-9._~+/=-]{16,})/g;

/**
 * `key = "value"` / `token: value` assignments where the value looks like a
 * credential rather than a variable reference or prose.
 */
const ASSIGNMENT_RULE =
  /(\b(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|secret|token|password|passwd|pwd|credential|authorization|auth)[A-Za-z0-9_-]*\s*[:=]\s*)(["']?)([^\s"',;]{8,})\2/gi;

/** Credentials embedded in a URL: scheme://user:password@host */
const URL_CREDENTIAL_RULE = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:)([^\s/@]+)(@)/gi;

/** True when a value must stay visible (reference, placeholder, or too short). */
function keepValue(value: string): boolean {
  return value.length < MIN_SECRET_LENGTH || REFERENCE_VALUE.test(value) || value.startsWith("[REDACTED:");
}

/**
 * Replace secret values in a piece of evidence with stable, value-derived
 * placeholders. Idempotent: redacting an already-redacted string changes
 * nothing.
 */
export function redactEvidence(text: string): string {
  if (!text) return text;

  let out = text;
  for (const rule of TOKEN_RULES) {
    out = out.replace(rule, (match: string) => placeholder(match));
  }
  out = out.replace(AUTH_SCHEME_RULE, (match: string, scheme: string, space: string, secret: string) =>
    keepValue(secret) ? match : `${scheme}${space}${placeholder(secret)}`
  );
  out = out.replace(ASSIGNMENT_RULE, (match: string, prefix: string, quote: string, value: string) =>
    keepValue(value) ? match : `${prefix}${quote}${placeholder(value)}${quote}`
  );
  out = out.replace(URL_CREDENTIAL_RULE, (match: string, prefix: string, secret: string, at: string) =>
    keepValue(secret) ? match : `${prefix}${placeholder(secret)}${at}`
  );
  return out;
}
