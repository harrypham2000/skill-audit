import { describe, expect, it, afterEach } from "vitest";
import {
  isPrivateHostname,
  validateUrlForFetch,
  isSafeEntryName,
  extractZip,
  fetchRemoteSource,
  DEFAULT_REMOTE_LIMITS,
} from "./remote.js";
import { execFileSync } from "child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, readdirSync } from "fs";
import { deflateRawSync } from "zlib";
import { tmpdir } from "os";
import { join } from "path";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
  roots.length = 0;
});

// ---- Minimal ZIP writer (stored entries) for fixtures ----
function crc32(buf: Buffer): number {
  let c: number;
  const table: number[] = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  let crc = 0xffffffff;
  for (const byte of buf) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

interface ZipEntryInput {
  name: string;
  data: Buffer;
  symlink?: boolean;
  /** Write the entry deflated (method 8) instead of stored. */
  compress?: boolean;
  /** Lie about the uncompressed size in local + central headers. */
  declaredUncompressedSize?: number;
}

function makeZip(entries: ZipEntryInput[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, "utf-8");
    const crc = crc32(entry.data);
    const isDir = entry.name.endsWith("/");
    const externalAttrs = entry.symlink ? (0o120777 << 16) >>> 0 : isDir ? (0o40755 << 16) >>> 0 : (0o100644 << 16) >>> 0;
    const method = entry.compress ? 8 : 0;
    const payload = entry.compress ? deflateRawSync(entry.data) : entry.data;
    const uncompressedSize = entry.declaredUncompressedSize ?? entry.data.length;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(0, 4); // flags
    local.writeUInt16LE(method, 6); // method: stored or deflated
    local.writeUInt16LE(0, 8); // time
    local.writeUInt16LE(0x21, 10); // date (any)
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(payload.length, 18);
    local.writeUInt32LE(uncompressedSize, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, nameBuf, payload);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(method, 10); // method
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0x21, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(payload.length, 20);
    central.writeUInt32LE(uncompressedSize, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(externalAttrs, 38);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuf);

    offset += 30 + nameBuf.length + payload.length;
  }

  const cdStart = offset;
  const cdBuffer = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuffer.length, 12);
  eocd.writeUInt32LE(cdStart, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...locals, cdBuffer, eocd]);
}

function writeZip(entries: ZipEntryInput[]): string {
  const root = mkdtempSync(join(tmpdir(), "skill-audit-zip-"));
  roots.push(root);
  const path = join(root, "fixture.zip");
  writeFileSync(path, makeZip(entries));
  return path;
}

describe("isPrivateHostname", () => {
  it("rejects loopback, link-local, RFC1918, CGNAT, and IPv6 private ranges", () => {
    for (const host of [
      "localhost", "foo.localhost", "db.internal", "printer.local", "x.onion",
      "127.0.0.1", "0.0.0.0", "10.1.2.3", "192.168.1.1", "172.16.0.1", "172.31.255.255",
      "169.254.169.254", "100.64.0.1", "198.18.0.5", "224.0.0.1",
      "::1", "::", "fc00::1", "fd12::1", "fe80::1", "::ffff:127.0.0.1",
    ]) {
      expect(isPrivateHostname(host), host).toBe(true);
    }
  });

  it("accepts public hostnames", () => {
    for (const host of ["example.com", "api.github.com", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]) {
      expect(isPrivateHostname(host), host).toBe(false);
    }
  });
});

describe("validateUrlForFetch", () => {
  it("allows https to public hosts", () => {
    expect(validateUrlForFetch("https://example.com/a.zip").ok).toBe(true);
  });

  it("rejects non-https and private destinations", () => {
    expect(validateUrlForFetch("http://example.com/a.zip").ok).toBe(false);
    expect(validateUrlForFetch("file:///etc/passwd").ok).toBe(false);
    expect(validateUrlForFetch("https://127.0.0.1/a.zip").ok).toBe(false);
    expect(validateUrlForFetch("https://169.254.169.254/latest/meta-data").ok).toBe(false);
  });

  it("enforces host allowlists", () => {
    const policy = { allowHosts: ["trusted.example"] };
    expect(validateUrlForFetch("https://trusted.example/a.zip", policy).ok).toBe(true);
    expect(validateUrlForFetch("https://other.example/a.zip", policy).ok).toBe(false);
  });
});

describe("isSafeEntryName", () => {
  it("rejects zip-slip and absolute names", () => {
    expect(isSafeEntryName("../evil.txt")).toBe(false);
    expect(isSafeEntryName("a/../../evil.txt")).toBe(false);
    expect(isSafeEntryName("/etc/passwd")).toBe(false);
    expect(isSafeEntryName("C:\\evil")).toBe(false);
    expect(isSafeEntryName("dir\\evil")).toBe(false);
    expect(isSafeEntryName("skills/ok/SKILL.md")).toBe(true);
  });
});

describe("extractZip", () => {
  function dest(): string {
    const root = mkdtempSync(join(tmpdir(), "skill-audit-extract-"));
    roots.push(root);
    return root;
  }

  it("extracts stored entries with nested directories", () => {
    const zipPath = writeZip([
      { name: "my-skill/SKILL.md", data: Buffer.from("---\nname: z\n\ndescription: y\n---\nhi") },
      { name: "my-skill/scripts/run.sh", data: Buffer.from("#!/bin/sh\necho ok\n") },
    ]);
    const dir = dest();
    const result = extractZip(zipPath, dir);
    expect(result.extractedFiles).toBe(2);
    expect(readFileSync(join(dir, "my-skill/scripts/run.sh"), "utf-8")).toContain("echo ok");
  });

  it("rejects zip-slip entries", () => {
    const zipPath = writeZip([{ name: "../escape.txt", data: Buffer.from("x") }]);
    expect(() => extractZip(zipPath, dest())).toThrow(/ZIP-slip/);
  });

  it("skips symlink entries instead of extracting them", () => {
    const zipPath = writeZip([
      { name: "link", data: Buffer.from("/etc/passwd"), symlink: true },
      { name: "real.txt", data: Buffer.from("ok") },
    ]);
    const dir = dest();
    const result = extractZip(zipPath, dir);
    expect(result.extractedFiles).toBe(1);
    expect(result.skipped.some(s => s.reason.includes("symlink"))).toBe(true);
    expect(existsSync(join(dir, "link"))).toBe(false);
  });

  it("enforces member-count limits", () => {
    const zipPath = writeZip([
      { name: "a.txt", data: Buffer.from("a") },
      { name: "b.txt", data: Buffer.from("b") },
    ]);
    expect(() => extractZip(zipPath, dest(), { limits: { maxEntries: 1 } })).toThrow(/exceeding limit/);
  });

  it("enforces per-entry size limits", () => {
    const zipPath = writeZip([{ name: "big.bin", data: Buffer.alloc(1000) }]);
    expect(() => extractZip(zipPath, dest(), { limits: { maxEntryBytes: 100 } })).toThrow(/per-entry limit/);
  });

  it("enforces aggregate size limits", () => {
    const zipPath = writeZip([
      { name: "a.bin", data: Buffer.alloc(600) },
      { name: "b.bin", data: Buffer.alloc(600) },
    ]);
    expect(() => extractZip(zipPath, dest(), { limits: { maxTotalBytes: 1000 } })).toThrow(/total size exceeds/);
  });

  it("bounds decompression when the declared size header lies", () => {
    // ~1MB of zeros deflates tiny, but the headers claim a small uncompressed
    // size so the pre-inflate declared-size checks pass. maxOutputLength must
    // stop the inflate itself.
    const zipPath = writeZip([
      {
        name: "bomb.bin",
        data: Buffer.alloc(1024 * 1024, 0),
        compress: true,
        declaredUncompressedSize: 16,
      },
    ]);
    expect(() => extractZip(zipPath, dest(), { limits: { maxEntryBytes: 64 * 1024 } }))
      .toThrow(/bomb\.bin exceeds size limit during decompression/);
  });

  it("rejects archives larger than the download size limit before reading", () => {
    const zipPath = writeZip([{ name: "a.bin", data: Buffer.alloc(1000) }]);
    expect(() => extractZip(zipPath, dest(), { limits: { maxDownloadBytes: 100 } }))
      .toThrow(/archive exceeds download size limit/);
  });

  it("rejects non-zip input", () => {
    const root = mkdtempSync(join(tmpdir(), "skill-audit-notzip-"));
    roots.push(root);
    const path = join(root, "fake.zip");
    writeFileSync(path, "definitely not a zip");
    expect(() => extractZip(path, root)).toThrow(/not a ZIP/);
  });
});

describe("fetchRemoteSource", () => {
  it("extracts a local zip into a temporary directory and cleans up", async () => {
    const zipPath = writeZip([
      { name: "zip-skill/SKILL.md", data: Buffer.from("---\nname: zip-skill\ndescription: y\n---\n# Zip\n") },
    ]);
    const source = await fetchRemoteSource(zipPath);
    expect(source.origin.kind).toBe("zip");
    expect(source.digest).toMatch(/^[a-f0-9]{64}$/);
    // localPath resolves to the skill root after single-top-level-dir descent
    expect(existsSync(join(source.localPath, "SKILL.md"))).toBe(true);
    source.cleanup();
    expect(existsSync(source.localPath)).toBe(false);
  });

  it("clones a local git repository shallowly and records the HEAD digest", async () => {
    const root = mkdtempSync(join(tmpdir(), "skill-audit-git-"));
    roots.push(root);
    const repo = join(root, "origin-repo");
    mkdirSync(join(repo, "my-git-skill"), { recursive: true });
    writeFileSync(join(repo, "my-git-skill/SKILL.md"), "---\nname: my-git-skill\ndescription: y\n---\n# Git\n");
    execFileSync("git", ["init", "-q", "-b", "main", repo]);
    execFileSync("git", ["-C", repo, "add", "."]);
    execFileSync("git", ["-C", repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "init"]);

    const source = await fetchRemoteSource(repo);
    expect(source.origin.kind).toBe("git");
    expect(source.digest).toMatch(/^[0-9a-f]{40}$/);
    expect(existsSync(join(source.localPath, "SKILL.md"))).toBe(true);
    expect(existsSync(join(source.localPath, ".git"))).toBe(false); // no repo metadata leaks into scan
    source.cleanup();
  });

  it("rejects unsupported sources", async () => {
    await expect(fetchRemoteSource("ftp://example.com/x")).rejects.toThrow(/unsupported source/);
  });

  it("rejects https artifacts: disabled pending security review", async () => {
    const tmp = tmpdir();
    const before = new Set(readdirSync(tmp).filter(n => n.startsWith("skill-audit-remote-")));
    await expect(fetchRemoteSource("https://example.com/skill.zip"))
      .rejects.toThrow(/remote HTTPS and git acquisition are disabled pending security review.*DNS-rebased SSRF, archive limits, SSH transport policy, cleanup guarantees/);
    // failing closed must not leak the temp root
    const leaked = readdirSync(tmp).filter(n => n.startsWith("skill-audit-remote-") && !before.has(n));
    expect(leaked).toEqual([]);
  });

  it("rejects git@ SSH sources: disabled pending security review", async () => {
    await expect(fetchRemoteSource("git@github.com:owner/repo.git"))
      .rejects.toThrow(/disabled pending security review/);
  });

  it("rejects https git repository URLs: disabled pending security review", async () => {
    await expect(fetchRemoteSource("https://github.com/owner/repo.git"))
      .rejects.toThrow(/disabled pending security review/);
  });

  it("removes the temp directory when extraction fails", async () => {
    const zipPath = writeZip([{ name: "../escape.txt", data: Buffer.from("x") }]);
    const tmp = tmpdir();
    const before = new Set(readdirSync(tmp).filter(n => n.startsWith("skill-audit-remote-")));
    await expect(fetchRemoteSource(zipPath)).rejects.toThrow(/ZIP-slip/);
    const leaked = readdirSync(tmp).filter(n => n.startsWith("skill-audit-remote-") && !before.has(n));
    expect(leaked).toEqual([]);
  });

  it("default limits are bounded", () => {
    expect(DEFAULT_REMOTE_LIMITS.maxEntries).toBeLessThanOrEqual(2000);
    expect(DEFAULT_REMOTE_LIMITS.maxDownloadBytes).toBeLessThanOrEqual(100 * 1024 * 1024);
  });
});
