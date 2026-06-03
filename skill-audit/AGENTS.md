# AGENTS.md - Agent-Specific Instructions

This file provides specialized guidance for different AI agents working on this project.

## Claude Code / Qwen Code / Gemini CLI

### Working with This Project

When asked to make changes to skill-audit:

1. **Always run tests first**: `npm test`
2. **Build after changes**: `npm run build`
3. **Check for lint errors**: Ensure no TypeScript errors

### Publishing New Versions

When asked to publish a new version:

1. **Option A - Automated (Preferred)**
   - Commit with conventional format: `feat:`, `fix:`, `BREAKING CHANGE:`
   - Push to main
   - Auto Release workflow handles versioning and publishing

2. **Option B - Manual**
   ```bash
   cd skill-audit
   npm version minor -m "release: v%s"  # or patch/major
   npm run build
   npm publish --access public
   git push origin main --follow-tags
   ```

### Troubleshooting

- **EOTP error**: npm token requires 2FA - regenerate at npm website without 2FA
- **Version mismatch**: Delete and recreate git tag on correct commit
- **Publish fails**: Check GitHub secret `NPM_TOKEN` is valid

## Security Auditing Context

When using skill-audit to audit other skills:

- This package includes a postinstall script for UX
- The postinstall is informational only - does NOT auto-install hooks
- Scanner excludes known-safe scripts (postinstall, preinstall, prepare)
- See `SECURITY.md` for full security policy

## Reference

- `references/postinstall-safety.md` - Documentation pattern for safe postinstall scripts
- `.github/workflows/release.yml` - Auto Release workflow
- `.github/workflows/publish.yml` - npm publish workflow