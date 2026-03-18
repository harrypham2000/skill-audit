import { readFileSync, existsSync, mkdirSync, writeFileSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

// Cache directory - in package root (parent of src)
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CACHE_DIR = join(PACKAGE_ROOT, ".cache/skill-audit/feeds");
const METRICS_FILE = join(PACKAGE_ROOT, ".cache/skill-audit/metrics.json");

/**
 * Phase 1 - Layer 3: Vulnerability Intelligence Service
 *
 * Enriches dependency findings with CVE/GHSA/OSV/KEV/EPSS intelligence.
 * Uses local cache with freshness policy.
 *
 * Advisory sources:
 * - OSV: https://osv.dev/vulnerability/ (package-specific)
 * - GHSA: GitHub Advisory Database
 * - KEV: CISA Known Exploited Vulnerabilities
 * - EPSS: First.org Exploit Prediction Scoring
 */

export interface AdvisoryRecord {
  id: string;
  aliases: string[];
  source: "OSV" | "GHSA" | "NVD" | "KEV" | "EPSS" | "SONATYPE";
  ecosystem?: string;
  packageName?: string;
  affectedVersions?: string[];
  severity?: string;
  cvss?: number;
  cvssVector?: string;
  epss?: number;
  kev?: boolean;
  published?: string;
  modified?: string;
  references: string[];
  summary?: string;
  cwe?: string[];
  fixVersion?: string;
}

export interface IntelResult {
  findings: AdvisoryRecord[];
  cacheAge?: number;
  stale?: boolean;
  warn?: boolean;
}

export interface CacheMetadata {
  source: string;
  fetchedAt: string;
  lastModified?: string;
  etag?: string;
  recordCount: number;
}

export interface UpdateMetrics {
  lastUpdate: string;
  kevCount: number;
  epssCount: number;
  fetchDurationMs: number;
  errors: string[];
}

// Cache configuration - differentiated by source update frequency
const MAX_CACHE_AGE_DAYS: Record<string, number> = {
  kev: 1,   // Daily updates - critical for actively exploited vulns
  epss: 3,  // Matches FIRST.org update cycle
  osv: 7    // Stable database - weekly acceptable
};
const WARN_CACHE_AGE_DAYS = 3;
const FETCH_TIMEOUT_MS = 30000; // 30 seconds
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 1000; // Base delay for exponential backoff

/**
 * Ensure cache directory exists
 */
function ensureCacheDir(): void {
  if (!existsSync(CACHE_DIR)) {
    mkdirSync(CACHE_DIR, { recursive: true });
  }
  // Also ensure parent dir exists for metrics file
  const metricsDir = dirname(METRICS_FILE);
  if (!existsSync(metricsDir)) {
    mkdirSync(metricsDir, { recursive: true });
  }
}

/**
 * Fetch with retry and exponential backoff
 */
async function fetchWithRetry(
  url: string,
  timeoutMs: number = FETCH_TIMEOUT_MS,
  options: RequestInit = {}
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'User-Agent': 'skill-audit/0.1.0 (Vulnerability Intelligence Scanner)',
          ...options.headers
        }
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        return response;
      }
      
      console.error(`Fetch failed (${url}): HTTP ${response.status}`);
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (attempt === MAX_RETRIES - 1) {
        throw error; // Last attempt - rethrow
      }
      
      // Exponential backoff: 1s, 2s, 4s
      const delay = RETRY_DELAY_MS * Math.pow(2, attempt);
      console.error(`Fetch failed (${url}), retrying in ${delay}ms... (attempt ${attempt + 1}/${MAX_RETRIES})`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  throw new Error('Max retries exceeded');
}

/**
 * Load update metrics
 */
function loadMetrics(): UpdateMetrics {
  if (!existsSync(METRICS_FILE)) {
    return { lastUpdate: '', kevCount: 0, epssCount: 0, fetchDurationMs: 0, errors: [] };
  }
  try {
    return JSON.parse(readFileSync(METRICS_FILE, 'utf-8')) as UpdateMetrics;
  } catch {
    return { lastUpdate: '', kevCount: 0, epssCount: 0, fetchDurationMs: 0, errors: [] };
  }
}

/**
 * Save update metrics
 */
function saveMetrics(metrics: UpdateMetrics): void {
  try {
    writeFileSync(METRICS_FILE, JSON.stringify(metrics, null, 2));
  } catch (error) {
    console.error('Failed to save metrics:', error);
  }
}

/**
 * Record fetch result in metrics
 */
function recordFetchResult(source: string, count: number, durationMs: number, error?: string): void {
  const metrics = loadMetrics();
  metrics.lastUpdate = new Date().toISOString();
  metrics.fetchDurationMs += durationMs;
  
  if (source === 'kev') {
    metrics.kevCount = count;
  } else if (source === 'epss') {
    metrics.epssCount = count;
  }
  
  if (error) {
    metrics.errors.push(`${source}: ${error}`);
    // Keep only last 10 errors
    if (metrics.errors.length > 10) {
      metrics.errors = metrics.errors.slice(-10);
    }
  }
  
  saveMetrics(metrics);
}

/**
 * Get cache file path for a source
 */
function getCachePath(source: string): string {
  ensureCacheDir();
  return join(CACHE_DIR, `${source.toLowerCase()}.jsonl`);
}

/**
 * Get metadata file path
 */
function getMetaPath(source: string): string {
  ensureCacheDir();
  return join(CACHE_DIR, `${source.toLowerCase()}.meta.json`);
}

/**
 * Check if cache is stale and return age info
 */
export function isCacheStale(source: string): { stale: boolean; age?: number; warn: boolean } {
  const metaPath = getMetaPath(source);

  if (!existsSync(metaPath)) {
    return { stale: true, warn: false };
  }

  try {
    const meta: CacheMetadata = JSON.parse(readFileSync(metaPath, "utf-8"));
    const fetchedAt = new Date(meta.fetchedAt);
    const now = new Date();
    const ageMs = now.getTime() - fetchedAt.getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);

    // Use source-specific max age
    const maxAge = MAX_CACHE_AGE_DAYS[source.toLowerCase()] || MAX_CACHE_AGE_DAYS.osv;

    return { 
      stale: ageDays > maxAge, 
      age: ageDays,
      warn: ageDays > WARN_CACHE_AGE_DAYS
    };
  } catch {
    return { stale: true, warn: false };
  }
}

/**
 * Save advisory records to cache
 */
function saveToCache(source: string, records: AdvisoryRecord[]): void {
  const cachePath = getCachePath(source);
  const metaPath = getMetaPath(source);

  // Save records as JSONL
  const lines = records.map(r => JSON.stringify(r)).join('\n');
  writeFileSync(cachePath, lines);

  // Save metadata
  const meta: CacheMetadata = {
    source,
    fetchedAt: new Date().toISOString(),
    recordCount: records.length
  };
  writeFileSync(metaPath, JSON.stringify(meta, null, 2));
}

/**
 * Load cached records
 */
function loadFromCache(source: string): AdvisoryRecord[] {
  const cachePath = getCachePath(source);
  
  if (!existsSync(cachePath)) {
    return [];
  }

  try {
    const content = readFileSync(cachePath, "utf-8");
    return content.split('\n').filter(Boolean).map(line => JSON.parse(line) as AdvisoryRecord);
  } catch {
    return [];
  }
}

/**
 * Query OSV API for vulnerabilities (using native fetch)
 * Note: Replaces curl-based approach with native Node.js HTTP
 */
export async function queryOSV(ecosystem: string, packageName: string): Promise<AdvisoryRecord[]> {
  try {
    const response = await fetchWithRetry('https://api.osv.dev/v1/query', FETCH_TIMEOUT_MS, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        package: {
          name: packageName,
          ecosystem: ecosystem
        }
      })
    });

    if (!response.ok) {
      console.error(`OSV API error: ${response.status}`);
      return [];
    }

    const data = await response.json() as { vulns?: Array<{
      id: string;
      aliases?: string[];
      severity?: Array<{ type: string; score: string }>;
      published?: string;
      modified?: string;
      summary?: string;
      references?: Array<{ type: string; url: string }>;
    }> };

    if (!data.vulns) {
      return [];
    }

    return data.vulns.map(v => ({
      id: v.id,
      aliases: v.aliases || [],
      source: "OSV" as const,
      ecosystem,
      packageName,
      severity: v.severity?.[0]?.type,
      published: v.published,
      modified: v.modified,
      summary: v.summary,
      references: v.references?.map(r => r.url) || []
    }));
  } catch (error) {
    console.error(`OSV query failed for ${ecosystem}/${packageName}:`, error);
    return [];
  }
}

/**
 * Query GHSA via GitHub GraphQL API
 * 
 * Note: GHSA integration requires GitHub API authentication.
 * For now, OSV provides comprehensive coverage for most ecosystems.
 * 
 * To implement GHSA:
 * 1. Get GitHub token: https://github.com/settings/tokens
 * 2. Set GITHUB_TOKEN environment variable
 * 3. Use GraphQL API with SecurityAdvisory query
 * 
 * Example:
 * ```
 * const token = process.env.GITHUB_TOKEN;
 * const response = await fetch('https://api.github.com/graphql', {
 *   method: 'POST',
 *   headers: {
 *     'Authorization': `Bearer ${token}`,
 *     'Content-Type': 'application/json'
 *   },
 *   body: JSON.stringify({
 *     query: `query {
 *       securityVulnerabilities(first: 100, ecosystem: NPM, package: "packageName") {
 *         nodes {
 *           advisory { ghsaId, summary, severity }
 *         }
 *       }
 *     }`
 *   })
 * });
 * ```
 */
export async function queryGHSA(ecosystem: string, packageName: string): Promise<AdvisoryRecord[]> {
  const token = process.env.GITHUB_TOKEN;
  
  if (!token) {
    // GHSA requires authentication - skip silently
    // OSV provides comprehensive coverage as fallback
    return [];
  }

  try {
    const response = await fetchWithRetry('https://api.github.com/graphql', FETCH_TIMEOUT_MS, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'skill-audit/0.1.0 (Vulnerability Intelligence Scanner)'
      },
      body: JSON.stringify({
        query: `
          query GetAdvisories($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
            securityVulnerabilities(first: 100, ecosystem: $ecosystem, package: $package) {
              nodes {
                advisory {
                  ghsaId
                  summary
                  severity
                  publishedAt
                  identifiers { type, value }
                }
                severity
                vulnerableVersionRange
              }
            }
          }
        `,
        variables: {
          ecosystem: ecosystem.toUpperCase(),
          package: packageName
        }
      })
    });

    if (!response.ok) {
      console.error(`GHSA API error: ${response.status}`);
      return [];
    }

    const data = await response.json() as {
      data?: {
        securityVulnerabilities?: {
          nodes?: Array<{
            advisory?: {
              ghsaId: string;
              summary: string;
              severity: string;
              publishedAt: string;
              identifiers?: Array<{ type: string; value: string }>;
            };
            severity: string;
            vulnerableVersionRange: string;
          }>;
        };
      };
    };

    if (!data.data?.securityVulnerabilities?.nodes) {
      return [];
    }

    return data.data.securityVulnerabilities.nodes.map(node => ({
      id: node.advisory?.ghsaId || `GHSA-unknown`,
      aliases: node.advisory?.identifiers?.map(i => i.value) || [],
      source: "GHSA" as const,
      ecosystem,
      packageName,
      severity: node.advisory?.severity || node.severity,
      published: node.advisory?.publishedAt,
      summary: node.advisory?.summary,
      references: []
    }));
  } catch (error) {
    console.error(`GHSA query failed for ${ecosystem}/${packageName}:`, error);
    return [];
  }
}

/**
 * Fetch CISA KEV (Known Exploited Vulnerabilities)
 */
export async function fetchKEV(): Promise<AdvisoryRecord[]> {
  const startTime = Date.now();
  const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  
  try {
    const response = await fetchWithRetry(url);
    const data = await response.json() as {
      title?: string;
      catalogVersion?: string;
      dateReleased?: string;
      vulnerabilities?: Array<{
        cveID: string;
        vendorProjectName?: string;
        productName?: string;
        vulnerabilityName?: string;
        dateAdded?: string;
        shortDescription?: string;
        reference?: string;
        knownRansomwareCampaignUse?: string;
      }>;
    };

    if (!data.vulnerabilities) {
      recordFetchResult('kev', 0, Date.now() - startTime, 'No vulnerabilities in response');
      return [];
    }

    const records = data.vulnerabilities.map(v => ({
      id: v.cveID,
      aliases: [v.cveID],
      source: "KEV" as const,
      kev: true,
      published: v.dateAdded,
      summary: v.shortDescription,
      references: v.reference ? [v.reference] : []
    }));

    recordFetchResult('kev', records.length, Date.now() - startTime);
    return records;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    recordFetchResult('kev', 0, Date.now() - startTime, errorMsg);
    console.error(`KEV fetch failed:`, error);
    return [];
  }
}

/**
 * Fetch EPSS scores
 */
export async function fetchEPSS(): Promise<AdvisoryRecord[]> {
  const startTime = Date.now();
  const url = 'https://api.first.org/data/v1/epss?limit=500&sort=epss';
  
  try {
    const response = await fetchWithRetry(url);
    const data = await response.json() as {
      status: string;
      total: number;
      limit: number;
      data: Array<{
        cve: string;
        epss: string;
        percentile: string;
        date: string;
      }>
    };

    if (!data.data) {
      recordFetchResult('epss', 0, Date.now() - startTime, 'No data in response');
      return [];
    }

    const records: AdvisoryRecord[] = data.data.map(entry => ({
      id: entry.cve,
      aliases: [entry.cve],
      source: "EPSS" as const,
      epss: parseFloat(entry.epss),
      published: entry.date,
      references: []
    }));

    recordFetchResult('epss', records.length, Date.now() - startTime);
    return records;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    recordFetchResult('epss', 0, Date.now() - startTime, errorMsg);
    console.error(`EPSS fetch failed:`, error);
    return [];
  }
}

/**
 * Query vulnerability intelligence for a package
 */
export async function queryIntel(ecosystem: string, packageName: string): Promise<IntelResult> {
  const findings: AdvisoryRecord[] = [];

  // Check cache freshness
  const { stale, age } = isCacheStale("osv");
  
  // Try OSV first (most comprehensive for package vulns)
  const osvResults = await queryOSV(ecosystem, packageName);
  findings.push(...osvResults);

  // Try GHSA
  const ghsaResults = await queryGHSA(ecosystem, packageName);
  findings.push(...ghsaResults);

  return {
    findings,
    cacheAge: age,
    stale
  };
}

/**
 * Get KEV vulnerabilities (enriched)
 */
export async function getKEV(): Promise<IntelResult> {
  const { stale, age, warn } = isCacheStale("kev");

  let records = loadFromCache("kev");

  if (records.length === 0 || stale) {
    records = await fetchKEV();
    if (records.length > 0) {
      saveToCache("kev", records);
    }
  }

  return {
    findings: records,
    cacheAge: age,
    stale,
    warn
  };
}

/**
 * Get EPSS scores (enriched)
 */
export async function getEPSS(): Promise<IntelResult> {
  const { stale, age, warn } = isCacheStale("epss");

  let records = loadFromCache("epss");

  if (records.length === 0 || stale) {
    records = await fetchEPSS();
    if (records.length > 0) {
      saveToCache("epss", records);
    }
  }

  return {
    findings: records,
    cacheAge: age,
    stale,
    warn
  };
}

/**
 * Merge advisory records by alias
 */
export function mergeByAlias(records: AdvisoryRecord[]): Map<string, AdvisoryRecord[]> {
  const aliasMap = new Map<string, AdvisoryRecord[]>();

  for (const record of records) {
    // Use all IDs and aliases as keys
    const ids = [record.id, ...record.aliases];
    
    for (const id of ids) {
      const key = id.toUpperCase();
      if (!aliasMap.has(key)) {
        aliasMap.set(key, []);
      }
      aliasMap.get(key)!.push(record);
    }
  }

  return aliasMap;
}

/**
 * Prioritize records by source (OSV/GHSA > KEV > EPSS)
 */
export function prioritizeRecords(records: AdvisoryRecord[]): AdvisoryRecord[] {
  const sourcePriority: Record<string, number> = {
    "OSV": 1,
    "GHSA": 2,
    "NVD": 3,
    "KEV": 4,
    "EPSS": 5
  };

  return [...records].sort((a, b) => {
    const aP = sourcePriority[a.source] || 10;
    const bP = sourcePriority[b.source] || 10;
    
    if (aP !== bP) return aP - bP;
    
    // Secondary: EPSS score (higher is worse)
    if (a.epss !== undefined && b.epss !== undefined) {
      return b.epss - a.epss;
    }
    
    return 0;
  });
}