const SAFE_LIFECYCLE_SCRIPT_PATHS = [
  /(?:^|[\\/])scripts[\\/](?:postinstall|preinstall|prepare)\.cjs$/i,
];

const REQUIRED_SAFE_CONTENT_PATTERNS = [
  /process\.env\.(?:CI|CONTINUOUS_INTEGRATION|GITHUB_ACTIONS|GITLAB_CI|CIRCLECI|TRAVIS|JENKINS_URL|BUILDKITE)/,
  /--install-hook/,
];

const FORBIDDEN_SAFE_CONTENT_PATTERNS = [
  /\b(?:fetch|WebSocket|http\.request|https\.request|dns\.(?:resolve|query)|child_process|execFile|execSync|spawn|fork|eval)\b/i,
  /\b(?:writeFileSync|writeFile|appendFileSync|appendFile|mkdirSync|rmSync|unlinkSync|renameSync|copyFileSync)\b/i,
];

function normalizeFilePath(filePath: string): string {
  return filePath.replace(/ \(code block\)$/i, "");
}

export function isDocumentedSafeLifecycleScript(filePath: string, content: string): boolean {
  const normalizedPath = normalizeFilePath(filePath);

  if (!SAFE_LIFECYCLE_SCRIPT_PATHS.some(pattern => pattern.test(normalizedPath))) {
    return false;
  }

  if (!REQUIRED_SAFE_CONTENT_PATTERNS.every(pattern => pattern.test(content))) {
    return false;
  }

  if (FORBIDDEN_SAFE_CONTENT_PATTERNS.some(pattern => pattern.test(content))) {
    return false;
  }

  return true;
}
