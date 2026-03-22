import { execFileSync, execSync } from 'child_process';
import { readdirSync, existsSync, realpathSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { resolve, relative, join } from 'path';
import { resolveSkillPath } from './discover.js';
import { Finding } from './types.js';
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

// Map OSV severity to our severity levels
function mapOSVSeverity(severity?: string): 'critical' | 'high' | 'medium' | 'low' {
  const s = severity?.toUpperCase() || '';
  if (s.includes('CRITICAL') || s.includes('HIGH')) return 'high';
  if (s.includes('MEDIUM')) return 'medium';
  return 'low';
}

// Scan with Trivy
function scanWithTrivy(resolvedPath: string): Finding[] {
  const findings: Finding[] = [];
  
  if (!isScannerAvailable('trivy')) {
    return findings;
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
              asixx: 'ASI04',
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
    // Convert scanner failure to explicit finding for observability
    findings.push({
      id: 'SCAN-TRIVY-01',
      category: 'SC',
      asixx: 'ASI04',
      severity: 'low',
      file: resolvedPath,
      message: 'Trivy scan completed with issues: ' + (e.message || String(e).slice(0, 100)),
      evidence: e.stack || String(e)
    });
  }

  return findings;
}

// Scan with OSV Scanner (Google's OSV.dev)
function scanWithOSV(resolvedPath: string): Finding[] {
  const findings: Finding[] = [];
  
  if (!isScannerAvailable('osv-scanner')) {
    return findings;
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
                  asixx: 'ASI04',
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
    findings.push({
      id: 'SCAN-OSV-01',
      category: 'SC',
      asixx: 'ASI04',
      severity: 'low',
      file: resolvedPath,
      message: 'OSV scan completed with issues: ' + (e.message || String(e).slice(0, 100)),
      evidence: e.stack || String(e)
    });
  }

  return findings;
}

// Scan with OSV using lockfile input (more precise)
function scanWithOSVLockfile(resolvedPath: string): Finding[] {
  const findings: Finding[] = [];
  
  if (!isScannerAvailable('osv-scanner')) {
    return findings;
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
                    asixx: 'ASI04',
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
      findings.push({
        id: 'SCAN-OSV-LOCK-01',
        category: 'SC',
        asixx: 'ASI04',
        severity: 'low',
        file: lockfile,
        message: 'OSV lockfile scan failed: ' + (e.message || String(e).slice(0, 100)),
        evidence: e.stack || String(e)
      });
    }
  }

  return findings;
}

// Query OSV.dev API directly for vulnerabilities (no CLI needed)
function scanWithOSVAPI(resolvedPath: string): Finding[] {
  const findings: Finding[] = [];

  // Parse lockfiles to get packages
  const packages = extractPackagesFromLockfiles(resolvedPath);
  
  if (packages.length === 0) {
    return findings;
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
                asixx: 'ASI04',
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
      // OSV API failure is OK - it's a fallback, but log for observability
      findings.push({
        id: 'SCAN-OSVAPI-01',
        category: 'SC',
        asixx: 'ASI04',
        severity: 'low',
        file: resolvedPath,
        message: 'OSV API query failed: ' + (e.message || String(e).slice(0, 100)),
        evidence: e.stack || String(e)
      });
    }
  }

  return findings;
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

export function scanDependencies(skillPath: string): Finding[] {
  const findings: Finding[] = [];
  let resolvedPath: string;

  try {
    resolvedPath = resolveSkillPath(skillPath);
    resolvedPath = realpathSync(resolvedPath);
  } catch (e) {
    findings.push({
      id: 'SCAN-01',
      category: 'SC',
      asixx: 'ASI04',
      severity: 'medium',
      file: skillPath,
      message: 'Could not resolve skill path - may be invalid symlink',
      evidence: String(e)
    });
    return findings;
  }

  if (!existsSync(resolvedPath)) {
    findings.push({
      id: 'SCAN-02',
      category: 'SC',
      asixx: 'ASI04',
      severity: 'medium',
      file: skillPath,
      message: 'Skill path does not exist',
      evidence: resolvedPath
    });
    return findings;
  }

  // Run all available scanners and aggregate results
  const trivyFindings = scanWithTrivy(resolvedPath);
  const osvFindings = scanWithOSV(resolvedPath);
  const osvLockFindings = scanWithOSVLockfile(resolvedPath);
  const osvAPIFindings = scanWithOSVAPI(resolvedPath);

  // Deduplicate by vulnerability ID (prefer OSV results as they're more current)
  const seen = new Set<string>();
  const deduped: Finding[] = [];

  // Add OSV API findings first (direct API = most current database)
  for (const f of osvAPIFindings) {
    if (!seen.has(f.id)) {
      seen.add(f.id);
      deduped.push(f);
    }
  }

  // Add OSV CLI findings (if CLI available)
  for (const f of [...osvLockFindings, ...osvFindings]) {
    if (!seen.has(f.id)) {
      seen.add(f.id);
      deduped.push(f);
    }
  }

  // Add Trivy findings if not already found
  for (const f of trivyFindings) {
    if (!seen.has(f.id)) {
      seen.add(f.id);
      deduped.push(f);
    }
  }

  return deduped;
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