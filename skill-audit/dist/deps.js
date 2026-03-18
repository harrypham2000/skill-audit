import { execFileSync } from 'child_process';
import { readdirSync, existsSync, realpathSync, readFileSync } from 'fs';
import { join } from 'path';
import { resolveSkillPath } from './discover.js';
// Map OSV ecosystem names to our package managers
const OSV_ECOSYSTEMS = {
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
};
// Check if a scanner is available
function isScannerAvailable(scanner) {
    try {
        execFileSync('which', [scanner], { stdio: 'ignore' });
        return true;
    }
    catch (e) {
        return false;
    }
}
// Map OSV severity to our severity levels
function mapOSVSeverity(severity) {
    const s = severity?.toUpperCase() || '';
    if (s.includes('CRITICAL') || s.includes('HIGH'))
        return 'high';
    if (s.includes('MEDIUM'))
        return 'medium';
    return 'low';
}
// Scan with Trivy
function scanWithTrivy(resolvedPath) {
    const findings = [];
    if (!isScannerAvailable('trivy')) {
        return findings;
    }
    try {
        const output = execFileSync('trivy', ['fs', '--format', 'json', '--severity', 'HIGH,CRITICAL', resolvedPath], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
        const result = JSON.parse(output);
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
    }
    catch (e) {
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
function scanWithOSV(resolvedPath) {
    const findings = [];
    if (!isScannerAvailable('osv-scanner')) {
        return findings;
    }
    try {
        // OSV Scanner can scan directories directly
        const output = execFileSync('osv-scanner', ['--json', '-r', resolvedPath], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
        const result = JSON.parse(output);
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
    }
    catch (e) {
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
function scanWithOSVLockfile(resolvedPath) {
    const findings = [];
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
            const output = execFileSync('osv-scanner', ['--json', '-r', join(resolvedPath, lockfile)], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
            const result = JSON.parse(output);
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
        }
        catch (e) {
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
function scanWithOSVAPI(resolvedPath) {
    const findings = [];
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
            const result = JSON.parse(response);
            if (result.results) {
                for (const queryResult of result.results) {
                    if (queryResult.vulns && queryResult.vulns.length > 0) {
                        for (const vuln of queryResult.vulns) {
                            // Get the package name from the query
                            const pkgInfo = batch.find(p => queryResult.vulns?.some(v => v.affected?.some(a => a.package.name === p.name)));
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
        }
        catch (e) {
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
function extractPackagesFromLockfiles(resolvedPath) {
    const packages = [];
    try {
        const files = readdirSync(resolvedPath);
        // Parse package-lock.json
        const pkgLock = files.find(f => f === 'package-lock.json');
        if (pkgLock) {
            const content = JSON.parse(readFileSync(join(resolvedPath, pkgLock), 'utf-8'));
            if (content.packages) {
                for (const [path, pkg] of Object.entries(content.packages)) {
                    const p = pkg;
                    if (p.version && path !== '') {
                        // Extract package name from path
                        const name = path.split('node_modules/').pop()?.split('/')[0];
                        if (name) {
                            packages.push({ name, version: p.version.replace(/^\^|~/, ''), ecosystem: 'npm' });
                        }
                    }
                }
            }
        }
        // Parse requirements.txt
        const reqTxt = files.find(f => f === 'requirements.txt');
        if (reqTxt) {
            const content = readFileSync(join(resolvedPath, reqTxt), 'utf-8');
            for (const line of content.split('\n')) {
                const match = line.match(/^([a-zA-Z0-9_-]+)([=<>!~]+)(.+)$/);
                if (match) {
                    packages.push({ name: match[1], version: match[3].trim(), ecosystem: 'PyPI' });
                }
            }
        }
        // Parse go.mod
        const goMod = files.find(f => f === 'go.mod');
        if (goMod) {
            const content = readFileSync(join(resolvedPath, goMod), 'utf-8');
            for (const line of content.split('\n')) {
                const match = line.match(/^\s+([a-zA-Z0-9\/]+)\s+v?(.+)$/);
                if (match && !match[1].startsWith('gopkg.in') && !match[1].startsWith('github.com/')) {
                    packages.push({ name: match[1], version: match[2].replace(/^v/, ''), ecosystem: 'Go' });
                }
            }
        }
        // Parse Cargo.lock
        const cargoLock = files.find(f => f === 'Cargo.lock');
        if (cargoLock) {
            const content = JSON.parse(readFileSync(join(resolvedPath, cargoLock), 'utf-8'));
            if (content.package) {
                for (const pkg of content.package) {
                    if (pkg.name && pkg.version) {
                        packages.push({ name: pkg.name, version: pkg.version, ecosystem: 'crates.io' });
                    }
                }
            }
        }
    }
    catch (e) {
        // Ignore parse errors
    }
    return packages;
}
export function scanDependencies(skillPath) {
    const findings = [];
    let resolvedPath;
    try {
        resolvedPath = resolveSkillPath(skillPath);
        resolvedPath = realpathSync(resolvedPath);
    }
    catch (e) {
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
    const seen = new Set();
    const deduped = [];
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
export function getDependencySummary(skillPath) {
    const resolvedPath = resolveSkillPath(skillPath);
    const result = { hasLockfile: false, packageManager: 'none', manifest: undefined };
    try {
        const files = readdirSync(resolvedPath);
        if (files.includes('package-lock.json') || files.includes('pnpm-lock.yaml')) {
            result.hasLockfile = true;
            result.packageManager = 'npm';
        }
        else if (files.includes('yarn.lock')) {
            result.hasLockfile = true;
            result.packageManager = 'yarn';
        }
        else if (files.includes('poetry.lock') || files.includes('pyproject.toml')) {
            result.hasLockfile = true;
            result.packageManager = 'python';
        }
        else if (files.includes('requirements.txt')) {
            result.hasLockfile = true;
            result.packageManager = 'pip';
        }
        else if (files.includes('Gemfile.lock')) {
            result.hasLockfile = true;
            result.packageManager = 'ruby';
        }
        else if (files.includes('go.sum')) {
            result.hasLockfile = true;
            result.packageManager = 'go';
        }
        result.manifest = files.find(f => f.endsWith('.toml') || f.endsWith('.json') || f === 'requirements.txt');
    }
    catch (e) {
        // ignore
    }
    return result;
}
