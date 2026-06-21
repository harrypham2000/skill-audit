import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, describe, expect, it } from "vitest";
import { auditSkill } from "./audit.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots) {
    rmSync(root, { recursive: true, force: true });
  }
  roots.length = 0;
});

describe("auditSkill", () => {
  it("allows public social-source package and listing references", () => {
    const root = mkdtempSync(join(tmpdir(), "skill-audit-public-source-"));
    roots.push(root);
    const skillRoot = join(root, "tweetclaw-social-evidence");
    mkdirSync(skillRoot, { recursive: true });
    writeFileSync(
      join(skillRoot, "SKILL.md"),
      `---
name: tweetclaw-social-evidence
description: Review public X/Twitter evidence with explicit approval gates.
origin: https://github.com/Xquik-dev/tweetclaw
license: MIT
allowed-tools:
  - openclaw
---

# TweetClaw Social Evidence

Use [TweetClaw](https://github.com/Xquik-dev/tweetclaw) for public X/Twitter evidence review.

Check the [npm package metadata](https://registry.npmjs.org/@xquik%2ftweetclaw) and [ClawHub listing](https://clawhub.ai/plugins/@xquik/tweetclaw) before suggesting an install.

Require operator approval before any post, follow, message, or paid workflow.
`,
    );

    const result = auditSkill({
      name: "tweetclaw-social-evidence",
      path: skillRoot,
      scope: "project",
      agents: ["OpenClaw"],
    });

    expect(result.manifest?.name).toBe("tweetclaw-social-evidence");
    expect(result.findings.filter((finding) => ["EX", "SC", "CE", "PI"].includes(finding.category))).toEqual([]);
  });
});
