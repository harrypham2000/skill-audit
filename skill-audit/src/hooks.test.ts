import { describe, expect, it } from "vitest";
import { generateHookConfig } from "./hooks.js";

describe("install-hook gate command", () => {
  it("uses the canonical scan and never the removed --mode audit", () => {
    const config = generateHookConfig({ threshold: 3, blockOnFailure: true }) as {
      hooks: { PreToolUse: Array<{ hooks: Array<{ command: string }> }> };
    };
    const command = config.hooks.PreToolUse[0].hooks[0].command;
    // The old command ("--mode audit --threshold N") exited 2 on every
    // invocation because the CLI rejects that mode; the gate could never run.
    expect(command).toBe("skill-audit");
    expect(command).not.toContain("--mode audit");
    expect(command).not.toContain("--threshold");
  });
});
