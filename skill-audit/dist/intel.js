import { readFileSync, existsSync, mkdirSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
// Cache directory - in package root (parent of src)
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CACHE_DIR = join(PACKAGE_ROOT, ".cache/skill-audit/feeds");
// Cache configuration
const MAX_CACHE_AGE_DAYS = 7;
/**
 * Ensure cache directory exists
 */
function ensureCacheDir() {
    if (!existsSync(CACHE_DIR)) {
        mkdirSync(CACHE_DIR, { recursive: true });
    }
}
/**
 * Get cache file path for a source
 */
function getCachePath(source) {
    ensureCacheDir();
    return join(CACHE_DIR, `${source.toLowerCase()}.jsonl`);
}
/**
 * Get metadata file path
 */
function getMetaPath(source) {
    ensureCacheDir();
    return join(CACHE_DIR, `${source.toLowerCase()}.meta.json`);
}
/**
 * Check if cache is stale
 */
function isCacheStale(source) {
    const metaPath = getMetaPath(source);
    if (!existsSync(metaPath)) {
        return { stale: true };
    }
    try {
        const meta = JSON.parse(readFileSync(metaPath, "utf-8"));
        const fetchedAt = new Date(meta.fetchedAt);
        const now = new Date();
        const ageMs = now.getTime() - fetchedAt.getTime();
        const ageDays = ageMs / (1000 * 60 * 60 * 24);
        return { stale: ageDays > MAX_CACHE_AGE_DAYS, age: ageDays };
    }
    catch {
        return { stale: true };
    }
}
/**
 * Save advisory records to cache
 */
function saveToCache(source, records) {
    const cachePath = getCachePath(source);
    const metaPath = getMetaPath(source);
    // Save records as JSONL
    const lines = records.map(r => JSON.stringify(r)).join('\n');
    writeFileSync(cachePath, lines);
    // Save metadata
    const meta = {
        source,
        fetchedAt: new Date().toISOString(),
        recordCount: records.length
    };
    writeFileSync(metaPath, JSON.stringify(meta, null, 2));
}
/**
 * Load cached records
 */
function loadFromCache(source) {
    const cachePath = getCachePath(source);
    if (!existsSync(cachePath)) {
        return [];
    }
    try {
        const content = readFileSync(cachePath, "utf-8");
        return content.split('\n').filter(Boolean).map(line => JSON.parse(line));
    }
    catch {
        return [];
    }
}
/**
 * Query OSV API for vulnerabilities (using native fetch)
 * Note: Replaces curl-based approach with native Node.js HTTP
 */
export async function queryOSV(ecosystem, packageName) {
    try {
        const response = await fetch('https://api.osv.dev/v1/query', {
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
        const data = await response.json();
        if (!data.vulns) {
            return [];
        }
        return data.vulns.map(v => ({
            id: v.id,
            aliases: v.aliases || [],
            source: "OSV",
            ecosystem,
            packageName,
            severity: v.severity?.[0]?.type,
            published: v.published,
            modified: v.modified,
            summary: v.summary,
            references: v.references?.map(r => r.url) || []
        }));
    }
    catch (error) {
        console.error(`OSV query failed for ${ecosystem}/${packageName}:`, error);
        return [];
    }
}
/**
 * Query GHSA via GitHub API
 */
export async function queryGHSA(ecosystem, packageName) {
    // GHSA API requires authentication for higher rate limits
    // This is a placeholder - in production, use a GitHub token
    try {
        const ghsaEcosystemMap = {
            'npm': 'npm',
            'pypi': 'PyPI',
            'go': 'Go',
            'cargo': 'Cargo',
            'rubygems': 'RubyGems',
            'maven': 'Maven',
            'nuget': 'NuGet'
        };
        const ghsaQuery = encodeURIComponent(`${packageName} repo:github/advisory-database`);
        // Note: This is a simplified approach - production would use GraphQL API
        console.log(`GHSA query: ${ecosystem}/${packageName} (API token recommended for production)`);
        return [];
    }
    catch (error) {
        console.error(`GHSA query failed:`, error);
        return [];
    }
}
/**
 * Fetch CISA KEV (Known Exploited Vulnerabilities)
 */
export async function fetchKEV() {
    try {
        const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
        if (!response.ok) {
            console.error(`KEV fetch error: ${response.status}`);
            return [];
        }
        const data = await response.json();
        if (!data.vulnerabilities) {
            return [];
        }
        return data.vulnerabilities.map(v => ({
            id: v.cveID,
            aliases: [v.cveID],
            source: "KEV",
            kev: true,
            published: v.dateAdded,
            summary: v.shortDescription,
            references: v.reference ? [v.reference] : []
        }));
    }
    catch (error) {
        console.error(`KEV fetch failed:`, error);
        return [];
    }
}
/**
 * Fetch EPSS scores
 */
export async function fetchEPSS() {
    try {
        // Official FIRST.org EPSS API (beta) - get top 500 by EPSS score
        const url = 'https://api.first.org/data/v1/epss?limit=500&sort=epss';
        const response = await fetch(url);
        if (!response.ok) {
            console.error(`EPSS fetch error: ${response.status}`);
            return [];
        }
        // Parse JSON response
        const data = await response.json();
        if (!data.data) {
            return [];
        }
        const records = data.data.map(entry => ({
            id: entry.cve,
            aliases: [entry.cve],
            source: "EPSS",
            epss: parseFloat(entry.epss),
            published: entry.date,
            references: []
        }));
        return records;
    }
    catch (error) {
        console.error(`EPSS fetch failed:`, error);
        return [];
    }
}
/**
 * Query vulnerability intelligence for a package
 */
export async function queryIntel(ecosystem, packageName) {
    const findings = [];
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
export async function getKEV() {
    const { stale, age } = isCacheStale("kev");
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
        stale
    };
}
/**
 * Get EPSS scores (enriched)
 */
export async function getEPSS() {
    const { stale, age } = isCacheStale("epss");
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
        stale
    };
}
/**
 * Merge advisory records by alias
 */
export function mergeByAlias(records) {
    const aliasMap = new Map();
    for (const record of records) {
        // Use all IDs and aliases as keys
        const ids = [record.id, ...record.aliases];
        for (const id of ids) {
            const key = id.toUpperCase();
            if (!aliasMap.has(key)) {
                aliasMap.set(key, []);
            }
            aliasMap.get(key).push(record);
        }
    }
    return aliasMap;
}
/**
 * Prioritize records by source (OSV/GHSA > KEV > EPSS)
 */
export function prioritizeRecords(records) {
    const sourcePriority = {
        "OSV": 1,
        "GHSA": 2,
        "NVD": 3,
        "KEV": 4,
        "EPSS": 5
    };
    return [...records].sort((a, b) => {
        const aP = sourcePriority[a.source] || 10;
        const bP = sourcePriority[b.source] || 10;
        if (aP !== bP)
            return aP - bP;
        // Secondary: EPSS score (higher is worse)
        if (a.epss !== undefined && b.epss !== undefined) {
            return b.epss - a.epss;
        }
        return 0;
    });
}
