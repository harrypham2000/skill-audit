import { execFileSync, execSync } from 'child_process';
import { readdirSync, existsSync, realpathSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { resolve, relative, join } from 'path';
import { resolveSkillPath } from './discover.js';
import { Finding } from './types.js';
import { AdvisoryRecord, getLocalAdvisories } from './intel.js';
import { tmpdir } from 'os';

interface TrivyResult {
  Results?: Array<{
    Target: string;
    Vulnerabilities?: Array<{
      VulnerabilityID: string;
      Severity: string;
      Title: string;
      PackageName: string;
    }>;
  }>;
}

// OSV Scanner result format
interface OSVResult {
  results?: Array<{
    packages?: Array<{
      package: {
        name: string;
        version?: string;
        ecosystem?: string;
        commit?: string;
      };
      vulnerabilities?: Array<{
        id: string;
        summary?: string;
        severity?: string;
      }>;
    }>;
  }>;
}

// OSV.dev API response format
interface OSVQueryResponse {
  vulns?: Array<{
    id: string;
    summary?: string;
    details?: string;
    severity?: Array<{
      type: string;
      score?: string;
    }>;
    affected?: Array<{
      package: {
        name: string;
        ecosystem: string;
      };
      ranges?: Array<{
        type: string;
        events?: Array<{
          introduced?: string;
          fixed?: string;
        }>;
      }>;
    }>;
  }>;
}

// Map OSV ecosystem names to our package managers
const OSV_ECOSYSTEMS: Record<string, string> = {
  'npm': 'npm',
  'PyPI': 'python',
  'pypi': 'python',
  'Go': 'go',
  'crates.io': 'rust',
  'Maven': 'java',
  'maven': 'java',
  'RubyGems': 'ruby',
  'Packagist': 'php',
  'Pub': 'dart',
  'NuGet': 'dotnet',
  'Hex': 'elixir',
  'ConanCenter': 'cpp',
  'Bioconductor': 'r',
  'SwiftURL': 'swift',
};

// Supported lockfile patterns and their ecosystems
const LOCKFILE_PATTERNS: Record<string, { ecosystem: string; parser: string }> = {
  // JavaScript/TypeScript
  'package-lock.json': { ecosystem: 'npm', parser: 'json' },
  'yarn.lock': { ecosystem: 'npm', parser: 'yarn' },
  'pnpm-lock.yaml': { ecosystem: 'npm', parser: 'yaml' },
  'bun.lockb': { ecosystem: 'npm', parser: 'binary' },
  
  // Python
  'requirements.txt': { ecosystem: 'PyPI', parser: 'text' },
  'Pipfile.lock': { ecosystem: 'PyPI', parser: 'json' },
  'poetry.lock': { ecosystem: 'PyPI', parser: 'toml' },
  'pdm.lock': { ecosystem: 'PyPI', parser: 'toml' },
  'uv.lock': { ecosystem: 'PyPI', parser: 'toml' },
  'pylock.toml': { ecosystem: 'PyPI', parser: 'toml' },
  
  // Rust
  'Cargo.lock': { ecosystem: 'crates.io', parser: 'toml' },
  
  // Ruby
  'Gemfile.lock': { ecosystem: 'RubyGems', parser: 'text' },
  'gems.locked': { ecosystem: 'RubyGems', parser: 'text' },
  
  // PHP
  'composer.lock': { ecosystem: 'Packagist', parser: 'json' },
  
  // Java
  'pom.xml': { ecosystem: 'Maven', parser: 'xml' },
  'buildscript-gradle.lockfile': { ecosystem: 'Maven', parser: 'text' },
  'gradle.lockfile': { ecosystem: 'Maven', parser: 'text' },
  
  // Go
  'go.mod': { ecosystem: 'Go', parser: 'text' },
  'go.sum': { ecosystem: 'Go', parser: 'text' },
  
  // .NET
  'packages.lock.json': { ecosystem: 'NuGet', parser: 'json' },
  'deps.json': { ecosystem: 'NuGet', parser: 'json' },
  'packages.config': { ecosystem: 'NuGet', parser: 'xml' },
  
  // Dart
  'pubspec.lock': { ecosystem: 'Pub', parser: 'yaml' },
  
  // Elixir
  'mix.lock': { ecosystem: 'Hex', parser: 'elixir' },
  
  // C/C++
  'conan.lock': { ecosystem: 'ConanCenter', parser: 'text' },
  
  // R
  'renv.lock': { ecosystem: 'Bioconductor', parser: 'json' },
};

// Check if a scanner is available
function isScannerAvailable(scanner: string): boolean {
  try {
    execFileSync('which', [scanner], { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}

// ============================================================
// Phase 2: single authoritative route, diagnostics, enrichment
// ============================================================

export type DependencyRoute = "osv-scanner" | "trivy" | "osv-api" | "none";

export interface DependencyDiagnostic {
  source: string;
  message: string;
}

export interface DependencyScanResult {
  findings: Finding[];
  diagnostics: DependencyDiagnostic[];
  route: DependencyRoute;
}

export interface DependencyScanOptions {
  /** Allow the OSV API network route. Local CLI scanners never need this. */
  allowNetwork?: boolean;
  /** Injectable for tests. */
  scannerAvailable?: (name: string) => boolean;
}

interface ScannerRun {
  findings: Finding[];
  error?: string;
}

/** Pure route selection: osv-scanner CLI > trivy CLI > OSV API (network-only). */
export function selectDependencyRoute(
  available: (name: string) => boolean,
  allowNetwork: boolean
): { route: DependencyRoute; diagnostic?: DependencyDiagnostic } {
  if (available("osv-scanner")) return { route: "osv-scanner" };
  if (available("trivy")) {
    return {
      route: "trivy",
      diagnostic: { source: "dependencies", message: "osv-scanner not found; using trivy as the authoritative route" },
    };
  }
  if (allowNetwork) {
    return {
      route: "osv-api",
      diagnostic: { source: "dependencies", message: "no local scanner found; using OSV API (network enabled)" },
    };
  }
  return {
    route: "none",
    diagnostic: { source: "dependencies", message: "no local vulnerability scanner available (install trivy or osv-scanner, or pass --network)" },
  };
}

/**
 * One authoritative vulnerability route per run, in fixed precedence:
 * osv-scanner CLI > trivy CLI > OSV API (only with allowNetwork).
 * Scanner problems are diagnostics, never findings, and never affect the score.
 */
export function scanDependenciesDetailed(
  skillPath: string,
  options: DependencyScanOptions = {}
): DependencyScanResult {
  const diagnostics: DependencyDiagnostic[] = [];
  const available = options.scannerAvailable ?? isScannerAvailable;

  let resolvedPath: string;
  try {
    resolvedPath = realpathSync(resolveSkillPath(skillPath));
  } catch (e) {
    diagnostics.push({ source: "dependencies", message: `Could not resolve skill path: ${String(e)}` });
    return { findings: [], diagnostics, route: "none" };
  }
  if (!existsSync(resolvedPath)) {
    diagnostics.push({ source: "dependencies", message: `Skill path does not exist: ${resolvedPath}` });
    return { findings: [], diagnostics, route: "none" };
  }

  const { route, diagnostic } = selectDependencyRoute(available, options.allowNetwork === true);
  if (diagnostic) diagnostics.push(diagnostic);
  let run: ScannerRun = { findings: [] };
  if (route === "osv-scanner") {
    run = runOsvScanner(resolvedPath, available);
  } else if (route === "trivy") {
    run = scanWithTrivy(resolvedPath, available);
  } else if (route === "osv-api") {
    run = scanWithOSVAPI(resolvedPath);
  }

  if (run.error) {
    diagnostics.push({ source: "dependencies", message: `${route} scan error: ${run.error}` });
  }

  const { findings: enriched, diagnostics: intelDiags } = enrichWithLocalIntel(run.findings);
  diagnostics.push(...intelDiags);

  return { findings: enriched, diagnostics, route };
}

/** Back-compat wrapper: findings only, no error-findings. */
export function scanDependencies(skillPath: string): Finding[] {
  return scanDependenciesDetailed(skillPath).findings;
}

function runOsvScanner(resolvedPath: string, available: AvailabilityCheck): ScannerRun {
  const direct = scanWithOSV(resolvedPath, available);
  const lockfile = scanWithOSVLockfile(resolvedPath, available);
  const findings = [...direct.findings, ...lockfile.findings];
  const seen = new Set<string>();
  const deduped = findings.filter(f => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
  const error = direct.error && lockfile.error
    ? `${direct.error}; ${lockfile.error}`
    : direct.error || lockfile.error;
  return { findings: deduped, error };
}

/**
 * Enrich VULN-* findings with the locally cached KEV/EPSS feeds.
 * Cache reads are local only; missing or stale caches are diagnostics.
 */
function enrichWithLocalIntel(findings: Finding[]): { findings: Finding[]; diagnostics: DependencyDiagnostic[] } {
  const diagnostics: DependencyDiagnostic[] = [];
  const vulnFindings = findings.filter(f => f.id.startsWith("VULN-"));
  if (vulnFindings.length === 0) return { findings, diagnostics };

  let kevRecords: AdvisoryRecord[] = [];
  let epssRecords: AdvisoryRecord[] = [];
  try {
    const kev = getLocalAdvisories("kev");
    kevRecords = kev.records;
    if (kev.stale && kev.records.length > 0) {
      diagnostics.push({ source: "intel-kev", message: "KEV cache is stale; enrichment may be outdated" });
    }
  } catch (e) {
    diagnostics.push({ source: "intel-kev", message: `KEV cache unavailable: ${String(e)}` });
  }
  try {
    const epss = getLocalAdvisories("epss");
    epssRecords = epss.records;
    if (epss.stale && epss.records.length > 0) {
      diagnostics.push({ source: "intel-epss", message: "EPSS cache is stale; enrichment may be outdated" });
    }
  } catch (e) {
    diagnostics.push({ source: "intel-epss", message: `EPSS cache unavailable: ${String(e)}` });
  }

  if (kevRecords.length === 0 && epssRecords.length === 0) {
    diagnostics.push({ source: "intel", message: "no local intel caches; run --update-db to enable enrichment" });
    return { findings, diagnostics };
  }

  return { findings: enrichDependencyFindings(findings, kevRecords, epssRecords), diagnostics };
}

/**
 * Pure enrichment: join KEV/EPSS intel into canonical VULN-* findings.
 * KEV membership escalates severity to at least high and marks confidence high.
 */
export function enrichDependencyFindings(
  findings: Finding[],
  kevRecords: AdvisoryRecord[],
  epssRecords: AdvisoryRecord[]
): Finding[] {
  const kevByAdvisory = new Map<string, AdvisoryRecord>();
  for (const r of kevRecords) {
    kevByAdvisory.set(r.id, r);
    for (const alias of r.aliases ?? []) kevByAdvisory.set(alias, r);
  }
  const epssByAdvisory = new Map<string, AdvisoryRecord>();
  for (const r of epssRecords) {
    epssByAdvisory.set(r.id, r);
    for (const alias of r.aliases ?? []) epssByAdvisory.set(alias, r);
  }

  return findings.map(f => {
    if (!f.id.startsWith("VULN-")) return f;
    const advisory = f.id.slice("VULN-".length);
    const kev = kevByAdvisory.get(advisory);
    const epss = epssByAdvisory.get(advisory);
    if (!kev && !epss) return f;

    const markers: string[] = [];
    let severity = f.severity;
    let confidence = f.confidence;
    let cwe = f.cwe;

    if (kev) {
      markers.push("KEV known-exploited");
      if (severity !== "critical") severity = "high";
      confidence = "high";
      const kevCwe = (kev.cwe ?? []).join(", ");
      if (kevCwe) cwe = cwe ? `${cwe}, ${kevCwe}` : kevCwe;
    }
    if (epss?.epss !== undefined) {
      markers.push(`EPSS ${epss.epss.toFixed(2)}`);
      if (confidence === undefined && epss.epss >= 0.5) confidence = "medium";
    }

    return {
      ...f,
      severity: severity as Finding["severity"],
      confidence,
      cwe,
      message: `${f.message} [${markers.join("; ")}]`,
    };
  });
}

// Map OSV severity to our severity levels
function mapOSVSeverity(severity?: string): 'critical' | 'high' | 'medium' | 'low' {
  const s = severity?.toUpperCase() || '';
  if (s.includes('CRITICAL') || s.includes('HIGH')) return 'high';
  if (s.includes('MEDIUM')) return 'medium';
  return 'low';
}

// Scan with Trivy
type AvailabilityCheck = (name: string) => boolean;

function scanWithTrivy(resolvedPath: string, available: AvailabilityCheck = isScannerAvailable): ScannerRun {
  const findings: Finding[] = [];

  if (!available('trivy')) {
    return { findings };
  }

  try {
    const output = execFileSync(
      'trivy',
      ['fs', '--format', 'json', '--severity', 'HIGH,CRITICAL', resolvedPath],
      { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }
    );

    const result: TrivyResult = JSON.parse(output);

    if (result.Results && result.Results.length > 0) {
      for (const target of result.Results) {
        if (target.Vulnerabilities && target.Vulnerabilities.length > 0) {
          for (const vuln of target.Vulnerabilities) {
            const severity = vuln.Severity === 'CRITICAL' ? 'critical' :
                            vuln.Severity === 'HIGH' ? 'high' : 'medium';

            findings.push({
              id: 'VULN-' + vuln.VulnerabilityID,
              category: 'SC',
              asi: 'ASI04',
              severity,
              file: target.Target,
              message: '[Trivy] Dependency vulnerability in ' + vuln.PackageName + ': ' + vuln.Title,
              evidence: vuln.VulnerabilityID
            });
          }
        }
      }
    }
  } catch (e: any) {
    return { findings, error: e.message || String(e).slice(0, 200) };
  }

  return { findings };
}

// Scan with OSV Scanner (Google's OSV.dev)
function scanWithOSV(resolvedPath: string, available: AvailabilityCheck = isScannerAvailable): ScannerRun {
  const findings: Finding[] = [];

  if (!available('osv-scanner')) {
    return { findings };
  }

  try {
    // OSV Scanner can scan directories directly
    const output = execFileSync(
      'osv-scanner',
      ['--json', '-r', resolvedPath],
      { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }
    );

    const result: OSVResult = JSON.parse(output);

    if (result.results && result.results.length > 0) {
      for (const scanResult of result.results) {
        if (scanResult.packages) {
          for (const pkg of scanResult.packages) {
            if (pkg.vulnerabilities && pkg.vulnerabilities.length > 0) {
              for (const vuln of pkg.vulnerabilities) {
                findings.push({
                  id: 'VULN-' + vuln.id,
                  category: 'SC',
                  asi: 'ASI04',
                  severity: mapOSVSeverity(vuln.severity),
                  file: resolvedPath,
                  message: '[OSV] Vulnerability in ' + pkg.package.name + 
                          (pkg.package.version ? '@' + pkg.package.version : '') + ': ' + 
                          (vuln.summary || vuln.id),
                  evidence: vuln.id
                });
              }
            }
          }
        }
      }
    }
  } catch (e: any) {
    return { findings, error: e.message || String(e).slice(0, 200) };
  }

  return { findings };
}

// Scan with OSV using lockfile input (more precise)
function scanWithOSVLockfile(resolvedPath: string, available: AvailabilityCheck = isScannerAvailable): ScannerRun {
  const findings: Finding[] = [];

  if (!available('osv-scanner')) {
    return { findings };
  }

  const lockfiles = [
    'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock',
    'requirements.txt', 'Pipfile.lock', 'poetry.lock',
    'go.sum', 'go.mod', 'Cargo.lock', 'Gemfile.lock'
  ];

  const files = readdirSync(resolvedPath);
  const foundLockfiles = files.filter(f => lockfiles.includes(f));

  for (const lockfile of foundLockfiles) {
    try {
      const output = execFileSync(
        'osv-scanner',
        ['--json', '-r', join(resolvedPath, lockfile)],
        { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }
      );

      const result: OSVResult = JSON.parse(output);

      if (result.results && result.results.length > 0) {
        for (const scanResult of result.results) {
          if (scanResult.packages) {
            for (const pkg of scanResult.packages) {
              if (pkg.vulnerabilities && pkg.vulnerabilities.length > 0) {
                for (const vuln of pkg.vulnerabilities) {
                  findings.push({
                    id: 'VULN-' + vuln.id,
                    category: 'SC',
                    asi: 'ASI04',
                    severity: mapOSVSeverity(vuln.severity),
                    file: lockfile,
                    message: '[OSV-LOCK] Vulnerability in ' + pkg.package.name + 
                            (pkg.package.version ? '@' + pkg.package.version : '') + ': ' + 
                            (vuln.summary || vuln.id),
                    evidence: vuln.id
                  });
                }
              }
            }
          }
        }
      }
    } catch (e: any) {
      const error = e.message || String(e).slice(0, 200);
      return { findings, error: `lockfile ${lockfile}: ${error}` };
    }
  }

  return { findings };
}

// Query OSV.dev API directly for vulnerabilities (no CLI needed)
function scanWithOSVAPI(resolvedPath: string): ScannerRun {
  const findings: Finding[] = [];

  // Parse lockfiles to get packages
  const packages = extractPackagesFromLockfiles(resolvedPath);

  if (packages.length === 0) {
    return { findings };
  }

  // Query OSV API in batches (max 1000 per request)
  const batchSize = 100;
  for (let i = 0; i < packages.length; i += batchSize) {
    const batch = packages.slice(i, i + batchSize);
    
    try {
      // Query using OSV batch API
      const query = {
        queries: batch.map(pkg => ({
          package: {
            name: pkg.name,
            ecosystem: pkg.ecosystem
          },
          version: pkg.version
        }))
      };

      const response = execFileSync('curl', [
        '-s', '-X', 'POST',
        'https://api.osv.dev/v1/querybatch',
        '-H', 'Content-Type: application/json',
        '-d', JSON.stringify(query)
      ], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });

      const result: { results?: OSVQueryResponse[] } = JSON.parse(response);
      
      if (result.results) {
        for (const queryResult of result.results) {
          if (queryResult.vulns && queryResult.vulns.length > 0) {
            for (const vuln of queryResult.vulns) {
              // Get the package name from the query
              const pkgInfo = batch.find(p => 
                queryResult.vulns?.some(v => 
                  v.affected?.some(a => a.package.name === p.name)
                )
              );

              findings.push({
                id: 'VULN-' + vuln.id,
                category: 'SC',
                asi: 'ASI04',
                severity: mapOSVSeverity(vuln.severity?.[0]?.type),
                file: resolvedPath,
                message: '[OSV-API] Vulnerability in ' + (pkgInfo?.name || 'unknown') + 
                        (pkgInfo?.version ? '@' + pkgInfo.version : '') + ': ' + 
                        (vuln.summary || vuln.id),
                evidence: vuln.id
              });
            }
          }
        }
      }
    } catch (e: any) {
      // OSV API failure is a degraded route, not a vulnerability.
      return { findings, error: `OSV API query failed: ${e.message || String(e).slice(0, 200)}` };
    }
  }

  return { findings };
}

// Extract packages from lockfiles for OSV API query
function extractPackagesFromLockfiles(resolvedPath: string): Array<{name: string, version: string, ecosystem: string}> {
  const packages: Array<{name: string, version: string, ecosystem: string}> = [];

  try {
    const files = readdirSync(resolvedPath);

    // Iterate through all supported lockfile patterns
    for (const [filename, config] of Object.entries(LOCKFILE_PATTERNS)) {
      const lockfile = files.find(f => f === filename);
      if (!lockfile) continue;

      const filepath = join(resolvedPath, lockfile);
      const content = readFileSync(filepath, 'utf-8');

      try {
        switch (config.parser) {
          case 'json':
            parseJSONLockfile(content, config.ecosystem, packages);
            break;
          case 'yaml':
            parseYAMLLockfile(content, config.ecosystem, packages);
            break;
          case 'toml':
            parseTOMLLockfile(content, config.ecosystem, packages);
            break;
          case 'text':
            parseTextLockfile(content, config.ecosystem, packages, filename);
            break;
          // Binary and XML parsers would require additional dependencies
          // For now, skip binary files and use basic XML parsing
        }
      } catch (e) {
        console.warn(`Failed to parse ${filename}:`, e);
      }
    }
  } catch (e) {
    // Ignore top-level errors
  }

  return packages;
}

// Parse JSON lockfiles (package-lock.json, Pipfile.lock, composer.lock, etc.)
function parseJSONLockfile(content: string, ecosystem: string, packages: Array<{name: string, version: string, ecosystem: string}>) {
  const data = JSON.parse(content);

  // package-lock.json format (object with packages)
  if (data.packages && typeof data.packages === 'object' && !Array.isArray(data.packages)) {
    for (const [path, pkg] of Object.entries(data.packages)) {
      const p = pkg as { version?: string; name?: string };
      if (p.version && path !== '') {
        const name = p.name || path.split('node_modules/').pop()?.split('/')[0];
        if (name) {
          packages.push({ name, version: p.version.replace(/^\^|~/, ''), ecosystem });
        }
      }
    }
  }

  // Pipfile.lock format
  if (data.default || data.develop) {
    for (const section of ['default', 'develop']) {
      if (data[section]) {
        for (const [name, pkg] of Object.entries(data[section])) {
          const p = pkg as { version?: string };
          if (p.version) {
            packages.push({ name: name.toLowerCase(), version: p.version.replace(/^[=<>!~]+/, ''), ecosystem });
          }
        }
      }
    }
  }

  // composer.lock format (array of packages)
  if (Array.isArray(data.packages)) {
    for (const pkg of data.packages) {
      if (pkg.name && pkg.version) {
        packages.push({ name: pkg.name, version: pkg.version.replace(/^[=<>!~v]+/, ''), ecosystem });
      }
    }
  }

  // renv.lock format
  if (data.Packages) {
    for (const [name, pkg] of Object.entries(data.Packages)) {
      const p = pkg as { Version?: string };
      if (p.Version) {
        packages.push({ name, version: p.Version, ecosystem });
      }
    }
  }
}

// Parse YAML lockfiles (yarn.lock, pubspec.lock, pnpm-lock.yaml)
function parseYAMLLockfile(content: string, ecosystem: string, packages: Array<{name: string, version: string, ecosystem: string}>) {
  // Simple YAML parsing without external dependency
  // For production, consider using a YAML parser library
  const lines = content.split('\n');
  let currentPackage = '';
  
  for (const line of lines) {
    // yarn.lock format: "package@version":
    const yarnMatch = line.match(/^"?([^@"]+)@([^"]+)":/);
    if (yarnMatch) {
      packages.push({ name: yarnMatch[1], version: yarnMatch[2].replace(/^[^0-9]*/, ''), ecosystem });
      continue;
    }
    
    // pubspec.lock format
    const pubMatch = line.match(/^\s+name:\s*(.+)$/);
    if (pubMatch) {
      currentPackage = pubMatch[1].trim();
      continue;
    }
    
    const pubVersion = line.match(/^\s+version:\s*"?(.+)"?$/);
    if (pubVersion && currentPackage) {
      packages.push({ name: currentPackage, version: pubVersion[1], ecosystem });
      currentPackage = '';
    }
  }
}

// Parse TOML lockfiles (Cargo.lock, poetry.lock, etc.)
function parseTOMLLockfile(content: string, ecosystem: string, packages: Array<{name: string, version: string, ecosystem: string}>) {
  // Simple TOML parsing without external dependency
  const lines = content.split('\n');
  let currentPackage = '';
  
  for (const line of lines) {
    // Cargo.lock format: [[package]]
    if (line.startsWith('[[')) {
      currentPackage = '';
      continue;
    }
    
    const nameMatch = line.match(/^name\s*=\s*"(.+)"$/);
    if (nameMatch) {
      currentPackage = nameMatch[1];
      continue;
    }
    
    const versionMatch = line.match(/^version\s*=\s*"(.+)"$/);
    if (versionMatch && currentPackage) {
      packages.push({ name: currentPackage, version: versionMatch[1], ecosystem });
    }
  }
}

// Parse text-based lockfiles (requirements.txt, Gemfile.lock, go.mod, etc.)
function parseTextLockfile(content: string, ecosystem: string, packages: Array<{name: string, version: string, ecosystem: string}>, filename: string) {
  const lines = content.split('\n');
  
  // requirements.txt format
  if (filename === 'requirements.txt') {
    for (const line of lines) {
      const match = line.match(/^([a-zA-Z0-9_-]+)([=<>!~]+)(.+)$/);
      if (match) {
        packages.push({ name: match[1], version: match[3].trim(), ecosystem });
      }
    }
    return;
  }
  
  // Gemfile.lock format
  if (filename === 'Gemfile.lock') {
    let inSpecs = false;
    for (const line of lines) {
      if (line.includes('specs:')) {
        inSpecs = true;
        continue;
      }
      if (inSpecs && line.startsWith('    ')) {
        const match = line.match(/^\s+([a-zA-Z0-9_-]+)\s+\(([^)]+)\)/);
        if (match) {
          packages.push({ name: match[1], version: match[2], ecosystem });
        }
      }
      if (inSpecs && line.trim() && !line.startsWith(' ')) {
        inSpecs = false;
      }
    }
    return;
  }
  
  // go.mod format
  if (filename === 'go.mod') {
    let inRequire = false;
    for (const line of lines) {
      if (line.startsWith('require (')) {
        inRequire = true;
        continue;
      }
      if (inRequire) {
        if (line === ')') {
          inRequire = false;
          continue;
        }
        const match = line.match(/^\s*([a-zA-Z0-9\/]+)\s+v?(.+)$/);
        if (match) {
          packages.push({ name: match[1], version: match[2].replace(/^v/, ''), ecosystem });
        }
      }
      // Single-line require
      const singleMatch = line.match(/^require\s+([a-zA-Z0-9\/]+)\s+v?(.+)$/);
      if (singleMatch) {
        packages.push({ name: singleMatch[1], version: singleMatch[2].replace(/^v/, ''), ecosystem });
      }
    }
    return;
  }
  
  // go.sum format
  if (filename === 'go.sum') {
    for (const line of lines) {
      const match = line.match(/^([a-zA-Z0-9\/]+)\s+v?([^\/\s]+)\//);
      if (match) {
        packages.push({ name: match[1], version: match[2].replace(/^v/, ''), ecosystem });
      }
    }
    return;
  }
  
  // gradle.lockfile format
  if (filename.includes('gradle.lockfile')) {
    for (const line of lines) {
      const match = line.match(/:([a-zA-Z0-9_-]+):([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+)/);
      if (match) {
        packages.push({ name: `${match[2]}:${match[3]}`, version: match[3], ecosystem });
      }
    }
    return;
  }
}

export function getDependencySummary(skillPath: string): {
  hasLockfile: boolean;
  packageManager: string;
  manifest?: string;
} {
  const resolvedPath = resolveSkillPath(skillPath);
  const result = { hasLockfile: false, packageManager: 'none', manifest: undefined as string | undefined };

  try {
    const files = readdirSync(resolvedPath);

    if (files.includes('package-lock.json') || files.includes('pnpm-lock.yaml')) {
      result.hasLockfile = true;
      result.packageManager = 'npm';
    } else if (files.includes('yarn.lock')) {
      result.hasLockfile = true;
      result.packageManager = 'yarn';
    } else if (files.includes('poetry.lock') || files.includes('pyproject.toml')) {
      result.hasLockfile = true;
      result.packageManager = 'python';
    } else if (files.includes('requirements.txt')) {
      result.hasLockfile = true;
      result.packageManager = 'pip';
    } else if (files.includes('Gemfile.lock')) {
      result.hasLockfile = true;
      result.packageManager = 'ruby';
    } else if (files.includes('go.sum')) {
      result.hasLockfile = true;
      result.packageManager = 'go';
    }

    result.manifest = files.find(f =>
      f.endsWith('.toml') || f.endsWith('.json') || f === 'requirements.txt'
    );
  } catch (e) {
    // ignore
  }

  return result;
}