# skill-audit v0.6.0 Plan: Reliability & Trust

## Problem Statement
Current auto-update implementation has edge cases that hurt user experience and trust. Need to address hook latency, transparency, self-auditing, and resilience.

---

## Phase 1: Performance (Hook Latency)

### 1.1 Lazy Background Update
**Problem:** First hook use is slow (10-30s) because it fetches KEV/EPSS/NVD synchronously.

**Solution:** 
- Don't block on fetch during hook execution
- Use cached data if available, update in background
- Show "updating intelligence..." message but don't block

**Implementation:**
```typescript
// Instead of await ensureIntelFeedsFresh();
// Use fire-and-forget with timeout
setTimeout(() => ensureIntelFeedsFresh().catch(() => {}), 100);
```

### 1.2 Pre-populate Cache on Install
**Problem:** First run always slow.

**Solution:**
- Add `--prefetch` flag that runs on `postinstall`
- Or detect first-run and use `--update-db` silently

---

## Phase 2: Transparency & Diagnostics

### 2.1 Verbose Mode for Auto-Update
**Problem:** Users don't know what's happening.

**Solution:**
- Add `--verbose` flag to show update progress
- Show "Fetching KEV..." but don't block
- Only show in verbose mode (default: silent)

### 2.2 Network Diagnostics
**Problem:** No info when fetch fails.

**Solution:**
- Log structured error info (URL, status, error type)
- Suggest `--update-db --verbose` for diagnostics
- Detect common issues: proxy, SSL, rate-limit

### 2.3 Audit Log
**Problem:** No trail of what skill-audit did.

**Solution:**
- Write to `.cache/skill-audit/audit.log`
- Log: timestamp, action, result, duration
- User can inspect for compliance

---

## Phase 3: Self-Auditing

### 3.1 Self-Audit on Install
**Problem:** Who audits the auditor?

**Solution:**
- Add `--self-audit` that runs during `postinstall`
- Verify no malicious patterns in skill-audit itself
- Report to user: "Self-audit: ✅ No threats detected"

### 3.2 Dependency Scanning
**Problem:** commander, gray-matter, semver could be compromised.

**Solution:**
- Run `npm audit` on skill-audit's own deps during build
- Fail build if critical vulnerabilities found

---

## Phase 4: Resilience

### 4.1 Graceful Degradation
**Problem:** Network failures break the experience.

**Solution:**
- If fetch fails, use stale cache with warning
- Never block audit execution on fetch
- Show "Using cached data from X days ago"

### 4.2 Cache Corruption Handling
**Problem:** JSON parse fails on corrupted cache.

**Solution:**
- Wrap cache reads in try-catch
- If corrupted, delete and re-fetch
- Log warning: "Cache corrupted, rebuilding..."

### 4.3 Concurrent Access Protection
**Problem:** Multiple processes might corrupt cache.

**Solution:**
- Use file locking (e.g., `proper-lockfile`)
- Or use atomic writes (write to temp, then rename)

### 4.4 Rate Limiting Handling
**Problem:** APIs might throttle us.

**Solution:**
- Implement exponential backoff
- Respect `Retry-After` header
- Cache partial results if interrupted

---

## Phase 5: Trust & Verification

### 5.1 Provenance Verification
**Problem:** User can't verify skill is trustworthy.

**Solution:**
- Add `--verify` flag that checks:
  - GitHub repo matches published npm package
  - No unexpected network calls (uses proxy logging)
  - Dependencies are pinned to specific versions

### 5.2 SBOM Generation
**Problem:** Compliance requires software bill of materials.

**Solution:**
- Add `--sbom` flag to output SPDX/cyclonedx JSON
- Include all dependencies with versions

---

## Phase 6: Data Freshness Clarity

### 6.1 Freshness Indicator
**Problem:** False confidence in protection.

**Solution:**
- Show explicit warning: "Data may be 24-48h old"
- Link to source (CISA KEV last updated: [date])

### 6.2 Pin to Specific DB Version
**Problem:** No rollback if data is bad.

**Solution:**
- Add `--pin-db` flag to save current DB as "known good"
- Add `--use-pinned` to use pinned version

---

## Phase 7: Library vs CLI Usage

### 7.1 Import as Module
**Problem:** User imports skill-audit as library in their own code.

**Solution:**
- Export core functions: `auditSecurity()`, `validateSkillSpec()`
- Auto-update should be opt-in for library usage
- Add `autoUpdate: false` option for programmatic use

### 7.2 Windows Path Handling
**Problem:** Windows uses backslashes, case-insensitive.

**Solution:**
- Use `path.resolve()` everywhere
- Normalize paths before comparison
- Test on Windows in CI

---

## Phase 8: Security Edge Cases

### 8.1 Audit Malicious Skills Safely
**Problem:** Auditing a malicious skill could trigger the malicious code.

**Solution:**
- Don't execute any code from the skill being audited
- Only read files, never `require()` or `import()`
- Sandbox file reads to skill directory

### 8.2 Timing Attack Resistance
**Problem:** Audit timing could reveal information.

**Solution:**
- Add random delays to prevent timing attacks
- Don't expose which specific pattern was matched

### 8.3 Resource Exhaustion
**Problem:** Malicious skill could have huge files.

**Solution:**
- Limit file read size (max 1MB per file)
- Limit total files scanned (max 1000 files)
- Timeout for long-running audits

---

## Phase 9: Compliance & Legal

### 9.1 GDPR Data Deletion
**Problem:** User might request their data be deleted.

**Solution:**
- All data is cached from public APIs (CISA, NVD)
- No PII collected by skill-audit
- Add `--clear-cache` to delete all cached data

### 9.2 Export Controls
**Problem:** Some countries block CISA.gov.

**Solution:**
- Detect if CISA is blocked, suggest alternative sources
- Allow custom feed URLs via config

### 9.3 Audit Trail for Compliance
**Problem:** Enterprises need audit trails.

**Solution:**
- JSON output includes: timestamp, user, machine, results
- Sign audit results with HMAC (optional)
- Export to SIEM-compatible formats

---

## Phase 10: User Onboarding

### 10.1 First-Run Experience
**Problem:** User doesn't know what skill-audit does.

**Solution:**
- First run shows quick tutorial
- Explain what gets scanned and why
- Show sample output

### 10.2 Migration from v0.4
**Problem:** Existing users might lose settings.

**Solution:**
- Detect old config, migrate automatically
- Show "Migrated from v0.4" message

---

## Implementation Order

| Priority | Item | Complexity | Impact |
|----------|------|------------|--------|
| P0 | Lazy background update | Low | High (hook latency) |
| P0 | Graceful degradation | Low | High (reliability) |
| P1 | Verbose mode | Low | Medium (transparency) |
| P1 | Cache corruption handling | Medium | Medium (resilience) |
| P1 | Self-audit on install | Medium | High (trust) |
| P1 | Resource exhaustion limits | Medium | High (security) |
| P2 | Audit log | Medium | Low |
| P2 | Network diagnostics | Medium | Low |
| P2 | Concurrent access protection | High | Low |
| P2 | Library export | Medium | Medium |
| P3 | Rate limiting | High | Low |
| P3 | SBOM generation | Medium | Low |
| P3 | Pin DB version | Medium | Low |
| P3 | Windows path handling | Medium | Low |
| P3 | GDPR/export controls | High | Low |

---

## Version Bump Plan

- **v0.5.0** - Current (auto-update)
- **v0.6.0** - Performance + Graceful degradation + Security limits
- **v0.7.0** - Transparency + Diagnostics
- **v0.8.0** - Trust + Self-audit
- **v0.9.0** - Compliance + Onboarding