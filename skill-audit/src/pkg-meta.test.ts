import { describe, expect, it } from "vitest";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import { join } from "path";

interface Pkg {
  engines?: { node?: string };
  files?: string[];
  description?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

const pkg: Pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

describe("package metadata", () => {
  it("requires Node >=20 (commander@14 needs Node >=20)", () => {
    expect(pkg.engines?.node).toBe(">=20.0.0");
  });

  it("ships typescript as a runtime dependency for the AST analyzer", () => {
    expect(pkg.dependencies?.typescript).toBe("^5.3.0");
    expect(pkg.devDependencies?.typescript).toBeUndefined();
  });

  it("keeps the commander range untouched", () => {
    expect(pkg.dependencies?.commander).toBe("^14.0.3");
  });

  it("publishes dist, schemas, and rules in the npm tarball", () => {
    expect(pkg.files).toContain("dist");
    expect(pkg.files).toContain("schemas");
    expect(pkg.files).toContain("rules");
  });

  it("does not overstate the compliance feature as validated", () => {
    expect(pkg.description).not.toContain("compliance validation");
  });
});

describe("production packaging invariants (mission review #41-43)", () => {
  it("excludes test sources from the production build", () => {
    const tsconfig = JSON.parse(readFileSync(new URL("../tsconfig.json", import.meta.url), "utf8"));
    expect(tsconfig.exclude).toContain("src/**/*.test.ts");
  });

  it("defines a deterministic packing pipeline", () => {
    expect(pkg.scripts.clean).toBe("rm -rf dist");
    expect(pkg.scripts["verify:pack"]).toContain("clean");
    expect(pkg.scripts["verify:pack"]).toContain("build");
    expect(pkg.scripts["verify:pack"]).toContain("verify-tarball.mjs");
    // prepack delegates to verify:pack, which cannot recurse (ignore-scripts)
    expect(pkg.scripts.prepack).toBe("npm run verify:pack");
  });

  it("exports the programmatic API surface", () => {
    expect(pkg.exports?.["."]?.import).toBe("./dist/api.js");
    expect(pkg.exports?.["."]?.types).toBe("./dist/api.d.ts");
    expect(pkg.bin?.["skill-audit"]).toBe("dist/index.js");
  });
});

describe("gate 6: tarball-content verification", () => {
  it("verify:pack runs clean → build → tarball verification", () => {
    expect(pkg.scripts["verify:pack"]).toContain("clean");
    expect(pkg.scripts["verify:pack"]).toContain("build");
    expect(pkg.scripts["verify:pack"]).toContain("verify-tarball.mjs");
    expect(pkg.scripts.prepack).toBe("npm run verify:pack");
  });

  it("rejects unexpected private files before npm creates a package", () => {
    const dir = mkdtempSync(join(tmpdir(), "skill-audit-package-test-"));
    try {
      for (const path of ["dist", "schemas", "rules", "scripts", "references", "node_modules"]) {
        mkdirSync(join(dir, path));
      }
      writeFileSync(join(dir, "package.json"), JSON.stringify({
        ...pkg,
        scripts: { prepack: "node scripts/verify-tarball.mjs" },
      }));
      copyFileSync(new URL("../scripts/verify-tarball.mjs", import.meta.url), join(dir, "scripts/verify-tarball.mjs"));
      for (const [path, content] of Object.entries({
        "dist/index.js": "console.log('fixture')",
        "dist/api.js": "export {}",
        "schemas/scan-report.schema.json": "{}",
        "rules/default-patterns.json": "{}",
        "README.md": "Public fixture",
        "references/.env": "dummy fixture",
        "references/business-plan.md": "dummy fixture",
      })) {
        writeFileSync(join(dir, path), content);
      }
      const npm = process.platform === "win32" ? "npm.cmd" : "npm";
      const tarball = join(dir, "verified.tgz");
      const result = spawnSync(npm, ["pack", "--json"], {
        cwd: dir,
        env: { ...process.env, SKILL_AUDIT_VERIFIED_TARBALL: tarball },
        encoding: "utf8",
        timeout: 30_000,
      });
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("unexpected file in tarball: references/.env");
      expect(result.stderr).toContain("unexpected file in tarball: references/business-plan.md");
      expect(existsSync(tarball)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("the clean build-and-pack pipeline accepts the current package contents", () => {
    const { spawnSync } = require("child_process") as typeof import("child_process");
    const npm = process.platform === "win32" ? "npm.cmd" : "npm";
    const result = spawnSync(npm, ["run", "verify:pack"], {
      cwd: new URL("..", import.meta.url).pathname,
      encoding: "utf-8",
      timeout: 120_000,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("tarball verified from bytes");
    expect(result.stdout).toContain("CLI smoke-run OK");
  }, 30_000);
});
