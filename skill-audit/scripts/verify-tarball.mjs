#!/usr/bin/env node
/**
 * Tarball-content verification (gate 6, bytes edition).
 *
 * Packs the package FOR REAL into a temp directory, extracts the tarball,
 * asserts the extracted bytes contain everything a production install needs
 * (and no test artifacts), smoke-runs the packed CLI, and cleans up.
 * Exits non-zero on any violation so it can gate `prepack`.
 */
import { execFileSync, spawnSync } from "child_process";
import { mkdtempSync, rmSync, existsSync, statSync, readdirSync, symlinkSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const REQUIRED = [
  "dist/index.js",
  "dist/api.js",
  "schemas/scan-report.schema.json",
  "rules/default-patterns.json",
  "README.md",
];
const FORBIDDEN = [/\.test\.js$/, /\.test\.d\.ts$/, /\.spec\.js$/, /\/tests?\//];

function listFiles(dir, prefix = "") {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const rel = prefix ? `${prefix}/${entry}` : entry;
    if (statSync(full).isDirectory()) out.push(...listFiles(full, rel));
    else out.push(rel);
  }
  return out;
}

function main() {
  const work = mkdtempSync(join(tmpdir(), "skill-audit-pack-verify-"));
  try {
    // --ignore-scripts: this script runs under prepack; a script-running pack
    // would re-trigger prepack and recurse forever.
    const packOutput = execFileSync(
      "npm",
      ["pack", "--json", "--ignore-scripts", "--pack-destination", work],
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }
    );
    const packResult = JSON.parse(packOutput);
    const packEntry = Array.isArray(packResult)
      ? packResult[0]
      : Object.values(packResult)[0];
    const tarballName = packEntry?.filename;
    if (typeof tarballName !== "string" || tarballName.length === 0) {
      throw new Error("pack did not report a tarball filename");
    }
    const tarball = join(work, tarballName);
    if (!existsSync(tarball)) throw new Error(`pack did not produce a tarball (got ${tarballName})`);

    const extractDir = join(work, "extracted");
    execFileSync("tar", ["-xzf", tarball, "-C", extractDir === extractDir ? work : work], { stdio: "ignore" });
    // npm packs under a package/ prefix
    const pkgDir = join(work, "package");
    if (!existsSync(pkgDir)) throw new Error("tarball did not contain a package/ root");
    void extractDir;

    const files = listFiles(pkgDir);
    const errors = [];

    for (const required of REQUIRED) {
      if (!files.includes(required)) errors.push(`missing required file: ${required}`);
      else if (statSync(join(pkgDir, required)).size === 0) errors.push(`required file is empty: ${required}`);
    }
    for (const file of files) {
      for (const pattern of FORBIDDEN) {
        if (pattern.test(file)) errors.push(`forbidden file in tarball: ${file}`);
      }
    }

    // Smoke-run the packed CLI from extracted bytes. The tarball ships no
    // dependencies (normal for npm); link the current workspace's modules so
    // the resolution path is exercised offline.
    symlinkSync(join(process.cwd(), "node_modules"), join(pkgDir, "node_modules"), "dir");
    const smoke = spawnSync("node", [join(pkgDir, "dist", "index.js"), "--version"], {
      encoding: "utf-8",
      timeout: 30_000,
    });
    if (smoke.status !== 0) {
      errors.push(`packed CLI smoke run failed (exit ${smoke.status}): ${(smoke.stderr || "").slice(0, 200)}`);
    }

    if (errors.length > 0) {
      console.error(`❌ tarball verification failed (${errors.length} problem(s)):`);
      for (const err of errors) console.error(`   - ${err}`);
      process.exit(1);
    }
    console.log(`✅ tarball verified from bytes: ${files.length} files, required present, no test artifacts, CLI smoke-run OK (${tarballName})`);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

main();
