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

Keep unpublished business material outside the checkout. The `private/` ignore
rule is a convenience, not an access control. Normal packaging checks the
tarball against the public file list in `scripts/verify-tarball.mjs`; add new
public files there deliberately, and do not bypass lifecycle scripts when
packing an unreviewed directory.

1. **Option A - GitHub Actions**
   - Commit and test the version first.
   - Use the manually dispatched release and publish workflows.

2. **Option B - Manual**
   ```bash
   cd skill-audit
   npm version minor -m "release: v%s"  # or patch/major
   npm run build
   npm publish --access public
   git push origin main --follow-tags
   ```

### Troubleshooting

- **EOTP error**: Keep 2FA enabled; complete the required OTP or use configured npm trusted publishing.
- **Version mismatch**: Investigate the tag and package version; changing a published tag requires approval.
- **Publish fails**: Check the configured authentication method without printing credentials.

## Security Auditing Context

When using skill-audit to audit other skills:

- This package includes a postinstall script for UX
- The postinstall is informational only - does NOT auto-install hooks
- Scanner excludes only documented-safe lifecycle scripts (scripts/*.cjs with verified safe content); other lifecycle scripts are still analyzed
- See `SECURITY.md` for full security policy

## Reference

- `references/postinstall-safety.md` - Documentation pattern for safe postinstall scripts
- `.github/workflows/release.yml` - Manual release workflow
- `.github/workflows/publish.yml` - npm publish workflow
