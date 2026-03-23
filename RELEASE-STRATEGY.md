# Release Strategy for skill-audit

## Version Channels

| Channel | Tag | Example | Purpose |
|---------|-----|---------|---------|
| **Production** | `latest` | `0.6.0` | Stable, recommended for all users |
| **Beta** | `beta` | `0.7.0-beta.1` | Feature testing, may have bugs |
| **RC** | `rc` | `0.7.0-rc.1` | Release candidate, final testing before production |

## Branch Strategy

```
main (protected)
  │
  ├── develop (integration branch)
  │     │
  │     └── feature/* (feature branches)
  │
  └── release/* (release branches)
        │
        └── hotfix/* (emergency fixes)
```

## Release Workflow

### 1. Feature Development → Beta Release

```bash
# Create feature branch
git checkout -b feature/lazy-update

# Develop, test, commit
git commit -m "feat: add lazy background update"

# Merge to develop
git checkout develop
git merge feature/lazy-update

# Push develop → triggers beta release
git push origin develop
# → Publishes @hungpg/skill-audit@0.7.0-beta.1 with tag "beta"
```

### 2. Beta Testing → RC Release

```bash
# After beta testing, create RC
git checkout -b release/0.7.0

# Push release branch → triggers RC release
git push origin release/0.7.0
# → Publishes @hungpg/skill-audit@0.7.0-rc.1 with tag "rc"
```

### 3. RC Testing → Production Release

```bash
# Merge RC to main
git checkout main
git merge release/0.7.0

# Push main → triggers production release
git push origin main
# → Publishes @hungpg/skill-audit@0.7.0 with tag "latest"
```

## npm Dist Tags

Users can install different versions:

```bash
# Production (default)
npm install @hungpg/skill-audit

# Beta (for testing new features)
npm install @hungpg/skill-audit@beta

# RC (for pre-production testing)
npm install @hungpg/skill-audit@rc

# Specific version
npm install @hungpg/skill-audit@0.7.0-beta.1
```

## Version Bump Rules

| Commit Type | Production | Pre-release |
|-------------|------------|-------------|
| `feat:` | minor (0.6.0 → 0.7.0) | pre-minor (0.7.0-beta.1 → 0.7.0-beta.2) |
| `fix:` | patch (0.6.0 → 0.6.1) | pre-patch (0.7.0-beta.1 → 0.7.0-beta.2) |
| `BREAKING CHANGE:` | major (0.6.0 → 1.0.0) | pre-major (1.0.0-beta.1) |

## GitHub Actions Workflows

### 1. `ci.yml` - Run on all PRs
- Tests on Node.js v20, v22, v24
- Build verification
- Lint check

### 2. `release-beta.yml` - Run on push to `develop`
- Bumps pre-release version
- Publishes to npm with `beta` tag
- Creates GitHub pre-release

### 3. `release-rc.yml` - Run on push to `release/*`
- Bumps RC version
- Publishes to npm with `rc` tag
- Creates GitHub pre-release

### 4. `release.yml` - Run on push to `main`
- Bumps production version
- Publishes to npm with `latest` tag
- Creates GitHub release

## Pre-release Checklist

### Beta Release
- [ ] All tests pass
- [ ] Build succeeds
- [ ] Manual smoke test
- [ ] Update CHANGELOG.md with "Unreleased" section
- [ ] Create PR from feature → develop

### RC Release
- [ ] Beta testing complete (min 3 days)
- [ ] No critical bugs reported
- [ ] Documentation updated
- [ ] Create PR from develop → release/*

### Production Release
- [ ] RC testing complete (min 2 days)
- [ ] No bugs reported
- [ ] CHANGELOG.md finalized
- [ ] SKILL.md version updated
- [ ] Create PR from release/* → main

## Rollback Plan

If production release has critical bug:

```bash
# Deprecate bad version
npm deprecate @hungpg/skill-audit@0.7.0 "Critical bug, use 0.6.0"

# Point latest to previous version
npm dist-tag add @hungpg/skill-audit@0.6.0 latest

# Hotfix
git checkout -b hotfix/0.7.1 main
# Fix bug, test, release
```

## Current Status

| Version | Channel | Status |
|---------|---------|--------|
| 0.5.0 | latest | Production |
| 0.6.0 | - | Pending (in main, auto-release) |
| 0.7.0 | beta | Planned (lazy update + graceful degradation) |

## Next Steps

1. **v0.6.0** → Already pushed to main, will auto-release
2. **v0.7.0-beta.1** → Create `develop` branch, implement remaining PLAN.md items
3. **v0.7.0** → After beta testing, merge to main

---

## Implementation Order

### Phase 1: Setup Pre-release Infrastructure
1. Create `develop` branch
2. Create `release-beta.yml` workflow
3. Create `release-rc.yml` workflow
4. Update `release.yml` for production only

### Phase 2: First Beta Release
1. Create feature branch for v0.7.0 items
2. Merge to `develop`
3. Verify beta release workflow
4. Test `npm install @hungpg/skill-audit@beta`

### Phase 3: Production Release
1. After beta testing, merge to `main`
2. Verify production release
3. Update documentation