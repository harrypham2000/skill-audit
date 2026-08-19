/**
 * Optional semantic analysis (Phase 8).
 *
 * Opt-in only. Detects intent-level risks static analysis cannot reliably
 * identify: paraphrased prompt injection, natural-language exfiltration,
 * declared-purpose versus observed-behavior mismatch, unjustified capability
 * scope, and missing warning/confirmation boundaries.
 *
 * Controls: explicit opt-in, source-egress disclosure, provider/model
 * configuration from environment (local providers supported via URL),
 * bounded input/output, structured validation, prompt/model version
 * metadata, static-only fallback, no tools available to the analysis model,
 * and semantic results can never remove or lower deterministic findings —
 * they only add findings capped at high severity.
 *
 * Egress policy (SSRF controls): endpoints must be https for allowlisted
 * hosts — http is only accepted for loopback hosts the operator explicitly
 * allowlisted (local model servers); URLs must not embed credentials;
 * redirects are never followed; hosts must pass the
 * SKILL_AUDIT_SEMANTIC_ALLOWED_HOSTS allowlist (default: the major hosted
 * providers); models must be syntactically valid and pass the optional
 * SKILL_AUDIT_SEMANTIC_ALLOWED_MODELS allowlist. DNS-level redirection of
 * an allowlisted host remains the operator's network responsibility.
 */
import { Finding } from "./types.js";

export const SEMANTIC_PROMPT_VERSION = "sem-v1";

export type SemanticStatus =
  | "not_requested"
  | "requested_unavailable"
  | "attempted"
  | "successful"
  | "partial"
  | "degraded";

export interface SemanticProvider {
  name: string;
  model: string;
  /** Origin the prompt is sent to (egress disclosure). */
  endpoint?: string;
  /** Sends the prompt to the provider and returns raw model text. */
  request(prompt: string): Promise<string>;
}

export interface SemanticInput {
  optIn: boolean;
  skillName: string;
  /** Bounded excerpt of skill content that will be disclosed to the provider. */
  content: string;
  declaredPurpose: string;
  observedCapabilities: string[];
  provider: SemanticProvider | null;
  /** Why the env provider was rejected by policy (surfaced when provider is null). */
  providerUnavailableReason?: string;
}

export interface SemanticResult {
  requested: boolean;
  available: boolean;
  status: SemanticStatus;
  provider?: string;
  model?: string;
  promptVersion: string;
  /** Egress disclosure: what left the machine, in what form. */
  disclosure?: string;
  findings: Finding[];
  detail?: string;
}

const MAX_CONTENT_CHARS = 8000;
const MAX_RESPONSE_CHARS = 16_000;

const CHECK_IDS: Record<string, { id: string; asi: string; message: string }> = {
  injection: { id: "SEM-001", asi: "ASI01", message: "Paraphrased prompt injection or social engineering detected" },
  exfiltration: { id: "SEM-002", asi: "ASI02", message: "Natural-language exfiltration instruction detected" },
  "purpose-mismatch": { id: "SEM-003", asi: "ASI09", message: "Declared purpose does not match observed behavior" },
  "unjustified-scope": { id: "SEM-004", asi: "ASI09", message: "Capability scope is not justified by the declared purpose" },
  "missing-warning": { id: "SEM-005", asi: "ASI08", message: "Destructive or risky actions lack warning or confirmation boundaries" },
};

const VALID_SEVERITIES = new Set(["high", "medium", "low"]);

function buildPrompt(input: SemanticInput): string {
  const content = input.content.slice(0, MAX_CONTENT_CHARS);
  return [
    "You are a security analyzer for AI agent skills. You have no tools and cannot take actions.",
    "Analyze the SKILL below and return STRICT JSON only — no prose, no markdown fences.",
    "Return a JSON array of objects: {\"check\": <one of injection|exfiltration|purpose-mismatch|unjustified-scope|missing-warning>, \"severity\": <high|medium|low>, \"evidence\": <exact quote from the skill>, \"reasoning\": <one sentence>}.",
    "Return [] when nothing applies. Do not invent evidence.",
    "",
    `Skill name: ${input.skillName}`,
    `Declared purpose: ${input.declaredPurpose || "(none)"}`,
    `Observed capabilities (static analysis): ${input.observedCapabilities.join(", ") || "(none)"}`,
    "",
    "=== SKILL CONTENT START ===",
    content,
    "=== SKILL CONTENT END ===",
  ].join("\n");
}

interface ModelVerdict {
  check?: unknown;
  severity?: unknown;
  evidence?: unknown;
  reasoning?: unknown;
}

/** Strict structural validation of the model response. */
export function parseVerdicts(raw: string): { verdicts: Array<{ check: string; severity: "high" | "medium" | "low"; evidence: string; reasoning: string }>; invalid: boolean } {
  const text = raw.trim().replace(/^```(?:json)?\n?/, "").replace(/\n?```$/, "").slice(0, MAX_RESPONSE_CHARS);
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return { verdicts: [], invalid: true };
  }
  if (!Array.isArray(data)) return { verdicts: [], invalid: true };

  const verdicts: Array<{ check: string; severity: "high" | "medium" | "low"; evidence: string; reasoning: string }> = [];
  for (const item of data as ModelVerdict[]) {
    if (typeof item !== "object" || item === null) return { verdicts: [], invalid: true };
    const check = String(item.check ?? "");
    const severity = String(item.severity ?? "");
    const evidence = String(item.evidence ?? "");
    const reasoning = String(item.reasoning ?? "");
    if (!(check in CHECK_IDS)) return { verdicts: [], invalid: true };
    if (!VALID_SEVERITIES.has(severity)) return { verdicts: [], invalid: true };
    if (evidence.trim().length === 0) return { verdicts: [], invalid: true };
    verdicts.push({
      check,
      severity: severity as "high" | "medium" | "low",
      evidence: evidence.slice(0, 300),
      reasoning: reasoning.slice(0, 300),
    });
  }
  return { verdicts, invalid: false };
}

export function verdictsToFindings(verdicts: Array<{ check: string; severity: "high" | "medium" | "low"; evidence: string; reasoning: string }>, skillName: string): Finding[] {
  return verdicts.map(v => {
    const rule = CHECK_IDS[v.check];
    return {
      id: rule.id,
      category: "ENV",
      asi: rule.asi,
      // Semantic findings are capped at high: they can never assert the
      // certainty of a deterministic critical finding.
      severity: v.severity === "high" ? "high" : v.severity,
      file: "SKILL.md",
      message: `${rule.message} (${skillName})`,
      evidence: v.evidence,
      recommendation: v.reasoning,
      confidence: "low",
    };
  });
}

// ---- Egress policy (SSRF controls) ------------------------------------

const DEFAULT_ALLOWED_HOSTS = ["api.openai.com", "api.anthropic.com"];

function loopbackHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

/** Hosts skill content may egress to; operators replace the default via env. */
export function allowedSemanticHosts(env: Record<string, string | undefined> = process.env): string[] {
  const raw = env.SKILL_AUDIT_SEMANTIC_ALLOWED_HOSTS;
  if (!raw) return [...DEFAULT_ALLOWED_HOSTS];
  return raw.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
}

export type EndpointCheck = { ok: true; url: URL } | { ok: false; reason: string };

/** Endpoint policy: allowlisted https hosts; http only for opted-in loopback. */
export function validateSemanticEndpoint(rawUrl: string | undefined, allowedHosts: string[]): EndpointCheck {
  if (!rawUrl) return { ok: false, reason: "SKILL_AUDIT_SEMANTIC_URL is not set" };
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: "SKILL_AUDIT_SEMANTIC_URL is not a valid URL" };
  }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return { ok: false, reason: `endpoint protocol must be https (or http for allowlisted loopback hosts), got ${url.protocol}` };
  }
  if (!allowedHosts.includes(host)) {
    return { ok: false, reason: `endpoint host "${host}" is not allowlisted (configure SKILL_AUDIT_SEMANTIC_ALLOWED_HOSTS)` };
  }
  if (url.protocol !== "https:" && !loopbackHost(host)) {
    return { ok: false, reason: `http endpoints are only permitted for loopback hosts, got ${host}` };
  }
  if (url.username !== "" || url.password !== "") {
    return { ok: false, reason: "endpoint URL must not embed credentials" };
  }
  return { ok: true, url };
}

const MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,119}$/;

export type ModelCheck = { ok: true; model: string } | { ok: false; reason: string };

/** Model policy: syntactically valid identifier plus optional allowlist. */
export function validateSemanticModel(rawModel: string | undefined, env: Record<string, string | undefined> = process.env): ModelCheck {
  if (!rawModel) return { ok: false, reason: "SKILL_AUDIT_SEMANTIC_MODEL is not set" };
  if (!MODEL_PATTERN.test(rawModel)) return { ok: false, reason: "SKILL_AUDIT_SEMANTIC_MODEL contains invalid characters" };
  const allow = env.SKILL_AUDIT_SEMANTIC_ALLOWED_MODELS?.split(",").map(s => s.trim()).filter(Boolean);
  if (allow && allow.length > 0 && !allow.includes(rawModel)) {
    return { ok: false, reason: `model "${rawModel}" is not allowlisted (SKILL_AUDIT_SEMANTIC_ALLOWED_MODELS)` };
  }
  return { ok: true, model: rawModel };
}

/**
 * Why defaultProviderFromEnv would return null for a CONFIGURED environment
 * (policy rejection), or null when the provider would be constructed. Plainly
 * unconfigured environments also return null: callers keep their default
 * "not configured" detail for those.
 */
export function explainSemanticProviderEnv(env: Record<string, string | undefined> = process.env): string | null {
  const url = env.SKILL_AUDIT_SEMANTIC_URL;
  const key = env.SKILL_AUDIT_SEMANTIC_KEY;
  const model = env.SKILL_AUDIT_SEMANTIC_MODEL;
  if (!url || !key || !model) return null;
  const name = env.SKILL_AUDIT_SEMANTIC_PROVIDER ?? "openai-compat";
  const nameAllow = env.SKILL_AUDIT_SEMANTIC_ALLOWED?.split(",").map(s => s.trim()).filter(Boolean);
  if (nameAllow && nameAllow.length > 0 && !nameAllow.includes(name)) {
    return `provider "${name}" is not allowlisted (SKILL_AUDIT_SEMANTIC_ALLOWED)`;
  }
  const endpoint = validateSemanticEndpoint(url, allowedSemanticHosts(env));
  if (!endpoint.ok) return endpoint.reason;
  const modelCheck = validateSemanticModel(model, env);
  if (!modelCheck.ok) return modelCheck.reason;
  return null;
}

/** OpenAI-compatible provider from environment; null when unconfigured or rejected by egress policy. */
export function defaultProviderFromEnv(env: Record<string, string | undefined> = process.env): SemanticProvider | null {
  const url = env.SKILL_AUDIT_SEMANTIC_URL;
  const key = env.SKILL_AUDIT_SEMANTIC_KEY;
  const model = env.SKILL_AUDIT_SEMANTIC_MODEL;
  const allow = env.SKILL_AUDIT_SEMANTIC_ALLOWED?.split(",").map(s => s.trim()).filter(Boolean);
  if (allow && allow.length > 0 && !allow.includes(env.SKILL_AUDIT_SEMANTIC_PROVIDER ?? "openai-compat")) {
    return null;
  }
  if (!url || !key || !model) return null;
  // SSRF controls: allowlisted https host (or operator-opted loopback http),
  // no embedded credentials. Redirects are refused at request time.
  const endpoint = validateSemanticEndpoint(url, allowedSemanticHosts(env));
  if (!endpoint.ok) return null;
  const modelCheck = validateSemanticModel(model, env);
  if (!modelCheck.ok) return null;
  const name = env.SKILL_AUDIT_SEMANTIC_PROVIDER ?? "openai-compat";
  return {
    name,
    model,
    endpoint: endpoint.url.origin,
    async request(prompt: string): Promise<string> {
      const response = await fetch(endpoint.url, {
        method: "POST",
        redirect: "error",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({
          model,
          messages: [{ role: "user", content: prompt }],
          // No tools are exposed to the analysis model.
          tools: undefined,
          temperature: 0,
        }),
        signal: AbortSignal.timeout(30_000),
      });
      if (!response.ok) throw new Error(`semantic provider returned HTTP ${response.status}`);

      // Stream the response with a hard byte bound BEFORE parsing anything.
      const declaredLength = Number(response.headers.get("content-length") ?? 0);
      if (declaredLength > MAX_RESPONSE_CHARS) {
        throw new Error(`semantic provider response exceeds byte limit (${declaredLength})`);
      }
      const reader = response.body?.getReader();
      if (!reader) throw new Error("semantic provider returned no body");
      const chunks: Uint8Array[] = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_RESPONSE_CHARS) {
          await reader.cancel();
          throw new Error(`semantic provider response exceeded byte limit (${MAX_RESPONSE_CHARS})`);
        }
        chunks.push(value);
      }
      const bodyText = new TextDecoder().decode(Buffer.concat(chunks));
      let json: { choices?: Array<{ message?: { content?: string } }> };
      try {
        json = JSON.parse(bodyText);
      } catch {
        throw new Error("semantic provider returned malformed JSON");
      }
      const text = json.choices?.[0]?.message?.content;
      if (typeof text !== "string") throw new Error("semantic provider returned no content");
      return text;
    },
  };
}

export async function runSemanticAnalysis(input: SemanticInput): Promise<SemanticResult> {
  const base = { promptVersion: SEMANTIC_PROMPT_VERSION, findings: [] as Finding[] };

  if (!input.optIn) {
    return { ...base, requested: false, available: false, status: "not_requested", detail: "semantic analysis is opt-in (--semantic)" };
  }
  if (!input.provider) {
    return {
      ...base,
      requested: true,
      available: false,
      status: "requested_unavailable",
      detail: input.providerUnavailableReason
        ? `semantic provider rejected by egress policy: ${input.providerUnavailableReason}. Falling back to static-only results.`
        : "no semantic provider configured; set SKILL_AUDIT_SEMANTIC_URL/KEY/MODEL. Falling back to static-only results.",
    };
  }
  const egressTarget = input.provider.endpoint
    ? `${input.provider.name} (${input.provider.endpoint})`
    : input.provider.name;

  const prompt = buildPrompt(input);
  let raw: string;
  try {
    raw = await input.provider.request(prompt);
  } catch (e) {
    return {
      ...base,
      requested: true,
      available: true,
      status: "degraded",
      provider: input.provider.name,
      model: input.provider.model,
      disclosure: `skill excerpt (≤${MAX_CONTENT_CHARS} chars) sent to ${egressTarget}`,
      detail: `provider request failed; static-only results stand (${String(e).slice(0, 120)})`,
    };
  }

  const { verdicts, invalid } = parseVerdicts(raw);
  if (invalid) {
    return {
      ...base,
      requested: true,
      available: true,
      status: "degraded",
      provider: input.provider.name,
      model: input.provider.model,
      disclosure: `skill excerpt (≤${MAX_CONTENT_CHARS} chars) sent to ${egressTarget}`,
      detail: "model response failed structured validation; static-only results stand",
    };
  }

  // Evidence anchoring: a verdict is only trusted when its evidence is a
  // verbatim excerpt of the supplied snapshot content. Unanchored verdicts
  // are discarded and degrade the result rather than inventing findings.
  const anchored = verdicts.filter(v => v.evidence.trim().length > 0 && input.content.includes(v.evidence));
  const unanchored = verdicts.length - anchored.length;

  const findings = verdictsToFindings(anchored, input.skillName);
  let status: SemanticStatus = findings.length === 0 ? "partial" : "successful";
  let detail: string | undefined;
  if (unanchored > 0) {
    status = "partial";
    detail = `${unanchored} verdict(s) discarded: evidence not found verbatim in the analyzed content`;
  }
  return {
    requested: true,
    available: true,
    status,
    provider: input.provider.name,
    model: input.provider.model,
    promptVersion: SEMANTIC_PROMPT_VERSION,
    disclosure: `skill excerpt (≤${MAX_CONTENT_CHARS} chars) sent to ${egressTarget} (${input.provider.model})`,
    findings,
    detail,
  };
}
