# Code Review Guidance for skill-audit

This document captures known issues, fixes, and best practices identified during code review.

---

## HIGH Priority Issues

### 1. GHSA Ecosystem Name Mapping (intel.ts)

**Location:** `src/intel.ts:369`

**Issue:** The `ecosystem.toUpperCase()` transformation doesn't produce valid GitHub SecurityAdvisoryEcosystem enum values. GitHub expects specific names:
- `PIP` (not `PYPI`)
- `RUST` (not `CRATES.IO`)
- `COMPOSER` (not `PACKAGIST`)
- `ERLANG` (not `HEX`)

**Impact:** GraphQL query failures for Python, Rust, PHP, and Elixir packages.

**Fix:**
```typescript
// Map internal ecosystem names to GitHub GraphQL enum values
const GHSA_ECOSYSTEM_MAP: Record<string, string> = {
  'npm': 'NPM',
  'PyPI': 'PIP',
  'pypi': 'PIP',
  'crates.io': 'RUST',
  'RubyGems': 'RUBYGEMS',
  'Maven': 'MAVEN',
  'Packagist': 'COMPOSER',
  'Go': 'GO',
  'NuGet': 'NUGET',
  'Pub': 'PUB',
  'Hex': 'ERLANG',
  'SwiftURL': 'SWIFT',
};

const ghsaEcosystem = GHSA_ECOSYSTEM_MAP[ecosystem] || ecosystem.toUpperCase();
```

---

## MEDIUM Priority Issues

### 2. parseJSONLockfile Duplicate Checks (deps.ts)

**Location:** `src/deps.ts:447-483`

**Issue:** `data.packages` is checked twice with different type assumptions:
- `package-lock.json`: `data.packages` is an object
- `composer.lock`: `data.packages` is an array

**Impact:** Composer.lock format check may never execute or cause runtime errors.

**Fix:**
```typescript
// package-lock.json format (object with packages)
if (data.packages && typeof data.packages === 'object' && !Array.isArray(data.packages)) {
  for (const [path, pkg] of Object.entries(data.packages)) {
    // ... existing logic
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
```

---

### 3. downloadOfflineDB Missing NVD (intel.ts)

**Location:** `src/intel.ts:845-870`

**Issue:** Function downloads KEV and EPSS but not NVD, despite being in the intel module.

**Impact:** Incomplete offline database downloads.

**Fix:** Add NVD download:
```typescript
// Download NVD
console.log('📥 Downloading NIST NVD...');
const nvdRecords = await fetchNVD();
if (nvdRecords.length > 0) {
  writeFileSync(
    join(outputDir, 'nvd.json'),
    JSON.stringify({ fetchedAt: new Date().toISOString(), records: nvdRecords }, null, 2)
  );
  results.nvd = { success: true, count: nvdRecords.length };
  console.log(`   ✓ NVD: ${nvdRecords.length} CVEs`);
}
```

---

### 4. NVD 24-hour Limitation (intel.ts)

**Location:** `src/intel.ts:555`

**Issue:** `fetchNVD()` only queries last 24 hours of modified CVEs.

**Impact:** New users or those with stale caches will have incomplete vulnerability data.

**Recommendation:** 
- Document this limitation in CLI help and README
- Consider adding `--full-sync` option for initial setup
- Future: Implement incremental sync with historical backfill

**Documentation Update:**
```markdown
### NVD Synchronization

The `--update-db` command fetches CVEs modified in the last 24 hours only.
For initial setup or after extended offline periods, run:

```bash
# Multiple updates to build historical data
skill-audit --update-db --source nvd
```

Note: NVD API rate limits apply (5 requests/30 sec without API key).
```

---

## LOW Priority Issues

### 5. YAML Parsing Fragility (deps.ts)

**Location:** `src/deps.ts:511-530`

**Issue:** Simple line-based YAML parsing may miss packages with complex version specs.

**Recommendation:** Consider using `js-yaml` package for production-grade parsing.

---

### 6. Missing Trailing Newline (intel.ts)

**Location:** `src/intel.ts:922`

**Issue:** File ends without newline character.

**Fix:** Add newline at end of file.

---

## Best Practices

### Ecosystem Name Conventions

When adding new vulnerability sources, ensure ecosystem names are mapped correctly:

| Internal Name | OSV | GHSA | NVD |
|---------------|-----|------|-----|
| npm | npm | NPM | - |
| PyPI | PyPI | PIP | - |
| crates.io | crates.io | RUST | - |
| RubyGems | RubyGems | RUBYGEMS | - |
| Maven | Maven | MAVEN | - |
| Packagist | Packagist | COMPOSER | - |
| Go | Go | GO | - |
| NuGet | NuGet | NUGET | - |

### Lockfile Parser Guidelines

1. Always check data type before processing (object vs array)
2. Handle both nested and flat structures
3. Normalize version strings (remove `^`, `~`, `v` prefixes)
4. Log warnings for parse failures, don't throw

### API Rate Limiting

| API | Rate Limit | Auth Required | Recommendation |
|-----|------------|---------------|----------------|
| OSV | Unlimited | No | Default choice |
| GHSA | 5000/hr | Yes | Use `GITHUB_TOKEN` |
| NVD | 5/30sec | No | Use `NVD_API_KEY` for 50/30sec |
| EPSS | Unlimited | No | Default choice |
| KEV | Unlimited | No | Default choice |

---

## Testing Checklist

Before releasing:

- [ ] Test GHSA queries with `GITHUB_TOKEN` set
- [ ] Test GHSA queries without token (should skip silently)
- [ ] Test lockfile parsing for all supported formats
- [ ] Test `--download-offline-db` creates all expected files
- [ ] Test `--update-db` with stale cache
- [ ] Verify NVD fetch handles rate limiting gracefully

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2024-03-18 | Initial code review guidance |