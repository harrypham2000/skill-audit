import { describe, expect, it } from "vitest";
import { readFileSync } from "fs";

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

  it("the tarball verifier accepts the current package contents", () => {
    const { spawnSync } = require("child_process") as typeof import("child_process");
    const result = spawnSync("node", ["scripts/verify-tarball.mjs"], {
      cwd: new URL("..", import.meta.url).pathname,
      encoding: "utf-8",
      timeout: 120_000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("tarball verified from bytes");
    expect(result.stdout).toContain("CLI smoke-run OK");
  });
});
