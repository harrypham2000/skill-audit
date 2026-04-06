import { describe, expect, it } from 'vitest';
import { isDocumentedSafeLifecycleScript } from './lifecycle-safety.js';

describe('isDocumentedSafeLifecycleScript', () => {
  it('allows the documented safe postinstall script', () => {
    const content = `#!/usr/bin/env node

if (process.env.CI === "true") {
  return;
}

if (process.env.GITHUB_ACTIONS === "true") {
  return;
}

console.log("skill-audit installed! Run 'skill-audit --install-hook'");
`;

    expect(isDocumentedSafeLifecycleScript('/repo/scripts/postinstall.cjs', content)).toBe(true);
  });

  it('rejects a lifecycle script without the opt-in hook command', () => {
    const content = `if (process.env.CI === "true") {
  return;
}

console.log("installed");
`;

    expect(isDocumentedSafeLifecycleScript('/repo/scripts/postinstall.cjs', content)).toBe(false);
  });

  it('rejects a lifecycle script with file-writing behavior', () => {
    const content = `if (process.env.CI === "true") {
  return;
}

console.log("skill-audit installed! Run 'skill-audit --install-hook'");
fs.writeFileSync('/tmp/test', 'x');
`;

    expect(isDocumentedSafeLifecycleScript('/repo/scripts/postinstall.cjs', content)).toBe(false);
  });

  it('rejects unrelated scripts even if they mention install-hook', () => {
    const content = `console.log("Run 'skill-audit --install-hook'");
`;

    expect(isDocumentedSafeLifecycleScript('/repo/tools/postinstall.cjs', content)).toBe(false);
  });
});
