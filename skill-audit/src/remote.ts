/**
 * Safe remote input support (Phase 7).
 *
 * Delivery order: local ZIP → HTTPS artifact → Git repository. HTTPS and
 * remote git acquisition are currently DISABLED (fail closed) pending
 * security review of DNS-rebinding SSRF, archive limits, SSH transport
 * policy, and cleanup guarantees; only local `.zip` archives and local
 * directory/git-path clones are accepted. Local ZIP extraction keeps its
 * controls: archive size cap, member limits, bounded decompression,
 * ZIP-slip and symlink protection, deterministic cleanup, and recorded
 * origin with an immutable digest.
 */
import { createHash } from "crypto";
import { execFileSync } from "child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync, createWriteStream, existsSync, readdirSync, statSync } from "fs";
import { inflateRawSync } from "zlib";
import { tmpdir } from "os";
import { join, dirname } from "path";

export interface RemoteLimits {
  maxEntries: number;
  maxEntryBytes: number;
  maxTotalBytes: number;
  maxDownloadBytes: number;
  timeoutMs: number;
}

export const DEFAULT_REMOTE_LIMITS: RemoteLimits = {
  maxEntries: 2000,
  maxEntryBytes: 8 * 1024 * 1024,
  maxTotalBytes: 100 * 1024 * 1024,
  maxDownloadBytes: 100 * 1024 * 1024,
  timeoutMs: 30_000,
};

export interface RemoteFetchOptions {
  limits?: Partial<RemoteLimits>;
  /** When non-empty, HTTPS hosts must match this allowlist. */
  allowHosts?: string[];
}

/**
 * Remote HTTPS and git acquisition are quarantined (review findings #2):
 * fail closed with a clear reason until DNS-rebinding SSRF hardening,
 * archive limits, SSH transport policy, and cleanup guarantees land.
 */
export const REMOTE_ACQUISITION_DISABLED =
  "remote HTTPS and git acquisition are disabled pending security review: " +
  "DNS-rebased SSRF, archive limits, SSH transport policy, cleanup guarantees";

export interface FetchedSource {
  localPath: string;
  cleanup: () => void;
  origin: { kind: "zip" | "https" | "git"; source: string };
  digest: string;
}

// ============================================================
// URL validation: private/reserved address rejection
// ============================================================

function ipv4ToLong(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = value * 256 + n;
  }
  return value;
}

const IPV4_RANGES: Array<[string, string]> = [
  ["0.0.0.0", "0.255.255.255"],
  ["10.0.0.0", "10.255.255.255"],
  ["100.64.0.0", "100.127.255.255"],
  ["127.0.0.0", "127.255.255.255"],
  ["169.254.0.0", "169.254.255.255"],
  ["172.16.0.0", "172.31.255.255"],
  ["192.0.0.0", "192.0.0.255"],
  ["192.168.0.0", "192.168.255.255"],
  ["198.18.0.0", "198.19.255.255"],
  ["224.0.0.0", "255.255.255.255"],
];

export function isPrivateHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")
    || host.endsWith(".internal") || host.endsWith(".onion")) {
    return true;
  }
  // IPv4 literal
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const value = ipv4ToLong(host);
    if (value === null) return true; // unparseable numeric host: treat as reserved
    for (const [start, end] of IPV4_RANGES) {
      const s = ipv4ToLong(start)!;
      const e = ipv4ToLong(end)!;
      if (value >= s && value <= e) return true;
    }
    return false;
  }
  // IPv6 literal
  if (host.includes(":")) {
    const lower = host.toLowerCase();
    if (lower === "::" || lower === "::1") return true;
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // fc00::/7
    if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true;
    if (lower.startsWith("::ffff:")) return isPrivateHostname(lower.slice(7));
  }
  return false;
}

export interface UrlPolicy {
  allowHosts?: string[];
}

/** Validate one fetch hop: HTTPS only, host allowed, not private/reserved. */
export function validateUrlForFetch(rawUrl: string, policy: UrlPolicy = {}): { ok: true; url: URL } | { ok: false; reason: string } {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: `invalid URL: ${rawUrl}` };
  }
  if (url.protocol !== "https:") {
    return { ok: false, reason: `only https: URLs are allowed (got ${url.protocol})` };
  }
  if (policy.allowHosts && policy.allowHosts.length > 0) {
    if (!policy.allowHosts.includes(url.hostname)) {
      return { ok: false, reason: `host ${url.hostname} is not in the allowlist` };
    }
  }
  if (isPrivateHostname(url.hostname)) {
    return { ok: false, reason: `host ${url.hostname} resolves to a private or reserved address` };
  }
  return { ok: true, url };
}

// ============================================================
// HTTPS download with redirect revalidation and streamed limits
// ============================================================

export async function downloadHttps(
  rawUrl: string,
  destPath: string,
  options: RemoteFetchOptions = {}
): Promise<{ digest: string; bytes: number }> {
  const limits = { ...DEFAULT_REMOTE_LIMITS, ...options.limits };
  let current = rawUrl;
  let response: Response | null = null;

  for (let hop = 0; hop < 5; hop++) {
    const check = validateUrlForFetch(current, options);
    if (!check.ok) throw new Error(`blocked URL ${current}: ${check.reason}`);
    response = await fetch(current, {
      redirect: "manual",
      signal: AbortSignal.timeout(limits.timeoutMs),
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) throw new Error(`redirect without location from ${current}`);
      current = new URL(location, current).toString(); // revalidated next loop
      continue;
    }
    break;
  }
  if (!response) throw new Error("no response");
  if (!response.ok) throw new Error(`download failed with HTTP ${response.status}`);

  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > limits.maxDownloadBytes) {
    throw new Error(`declared size ${declared} exceeds download limit ${limits.maxDownloadBytes}`);
  }

  const chunks: Buffer[] = [];
  let total = 0;
  const reader = response.body?.getReader();
  if (!reader) throw new Error("empty response body");
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limits.maxDownloadBytes) {
      await reader.cancel();
      throw new Error(`download exceeded limit ${limits.maxDownloadBytes}`);
    }
    chunks.push(Buffer.from(value));
  }
  const buffer = Buffer.concat(chunks);
  writeFileSync(destPath, buffer);
  return { digest: createHash("sha256").update(buffer).digest("hex"), bytes: total };
}

// ============================================================
// ZIP extraction with ZIP-slip, symlink, and member limits
// ============================================================

const EOCD_SIG = 0x06054b50;
const CEN_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;

interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
  isSymlink: boolean;
  isDir: boolean;
}

function parseCentralDirectory(buffer: Buffer): ZipEntry[] {
  // Find EOCD from the tail (no ZIP64 support — bounded archives only).
  let eocd = -1;
  const tailStart = Math.max(0, buffer.length - 66_000);
  for (let i = buffer.length - 22; i >= tailStart; i--) {
    if (buffer.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a ZIP archive (end-of-central-directory not found)");

  const entryCount = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);

  const entries: ZipEntry[] = [];
  for (let i = 0; i < entryCount; i++) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== CEN_SIG) {
      throw new Error(`corrupt central directory at entry ${i}`);
    }
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLen = buffer.readUInt16LE(offset + 28);
    const extraLen = buffer.readUInt16LE(offset + 30);
    const commentLen = buffer.readUInt16LE(offset + 32);
    const externalAttrs = buffer.readUInt32LE(offset + 38);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString("utf-8", offset + 46, offset + 46 + nameLen);
    const mode = (externalAttrs >>> 16) & 0xffff;

    entries.push({
      name,
      method,
      compressedSize,
      uncompressedSize,
      localOffset,
      isSymlink: (mode & 0o170000) === 0o120000,
      isDir: name.endsWith("/"),
    });
    offset += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

export function isSafeEntryName(name: string): boolean {
  if (name.length === 0) return false;
  if (name.startsWith("/") || /^[a-zA-Z]:/.test(name)) return false;
  if (name.includes("\\")) return false;
  const parts = name.split("/");
  if (parts.some(p => p === "..")) return false;
  return true;
}

export interface ExtractResult {
  extractedFiles: number;
  skipped: Array<{ name: string; reason: string }>;
}

export function extractZip(zipPath: string, destDir: string, options: RemoteFetchOptions = {}): ExtractResult {
  const limits = { ...DEFAULT_REMOTE_LIMITS, ...options.limits };
  // Cap the archive file itself before reading it into memory (#12): the
  // same bound that applies to downloads applies to local archives.
  const archiveSize = statSync(zipPath).size;
  if (archiveSize > limits.maxDownloadBytes) {
    throw new Error(`archive exceeds download size limit (${archiveSize} > ${limits.maxDownloadBytes})`);
  }
  const buffer = readFileSync(zipPath);
  const entries = parseCentralDirectory(buffer);

  if (entries.length > limits.maxEntries) {
    throw new Error(`archive has ${entries.length} entries, exceeding limit ${limits.maxEntries}`);
  }

  let totalBytes = 0;
  const skipped: Array<{ name: string; reason: string }> = [];
  let extractedFiles = 0;

  for (const entry of entries) {
    if (entry.isDir) {
      if (!isSafeEntryName(entry.name)) throw new Error(`unsafe directory name: ${entry.name}`);
      mkdirSync(join(destDir, entry.name), { recursive: true });
      continue;
    }
    if (entry.isSymlink) {
      skipped.push({ name: entry.name, reason: "symlink entries are not extracted" });
      continue;
    }
    if (entry.uncompressedSize > limits.maxEntryBytes) {
      throw new Error(`entry ${entry.name} exceeds per-entry limit ${limits.maxEntryBytes}`);
    }
    totalBytes += entry.uncompressedSize;
    if (totalBytes > limits.maxTotalBytes) {
      throw new Error(`archive total size exceeds limit ${limits.maxTotalBytes}`);
    }
    if (!isSafeEntryName(entry.name)) {
      throw new Error(`unsafe entry name (ZIP-slip attempt): ${entry.name}`);
    }
    if (entry.method !== 0 && entry.method !== 8) {
      throw new Error(`unsupported compression method ${entry.method} for ${entry.name}`);
    }

    // Local header: skip its own name/extra lengths to find the data.
    if (entry.localOffset + 30 > buffer.length || buffer.readUInt32LE(entry.localOffset) !== LOC_SIG) {
      throw new Error(`corrupt local header for ${entry.name}`);
    }
    const localNameLen = buffer.readUInt16LE(entry.localOffset + 26);
    const localExtraLen = buffer.readUInt16LE(entry.localOffset + 28);
    const dataStart = entry.localOffset + 30 + localNameLen + localExtraLen;
    const compressed = buffer.subarray(dataStart, dataStart + entry.compressedSize);
    let data: Buffer;
    if (entry.method === 8) {
      // Bounded decompression (#12): declared sizes can lie, so cap the
      // inflater itself; exceeding the cap is an error, not an OOM.
      try {
        data = inflateRawSync(compressed, { maxOutputLength: limits.maxEntryBytes + 1 });
      } catch (e) {
        if (e instanceof Error && (e as NodeJS.ErrnoException).code === "ERR_BUFFER_TOO_LARGE") {
          throw new Error(`entry ${entry.name} exceeds size limit during decompression (limit ${limits.maxEntryBytes})`);
        }
        throw e;
      }
    } else {
      data = Buffer.from(compressed);
    }
    if (data.length !== entry.uncompressedSize) {
      throw new Error(`size mismatch for ${entry.name}: expected ${entry.uncompressedSize}, got ${data.length}`);
    }

    const target = join(destDir, entry.name);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, data);
    extractedFiles++;
  }

  return { extractedFiles, skipped };
}

// ============================================================
// Git shallow clone
// ============================================================

function gitAvailable(): boolean {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore", timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

export function shallowClone(
  repoUrl: string,
  destDir: string,
  options: RemoteFetchOptions = {}
): { digest: string } {
  const limits = { ...DEFAULT_REMOTE_LIMITS, ...options.limits };
  if (!gitAvailable()) throw new Error("git is not available for repository cloning");

  const isRemote = /^[a-z+]+:\/\//i.test(repoUrl) || repoUrl.startsWith("git@");
  if (isRemote) {
    const check = validateUrlForFetch(repoUrl.replace(/^git@([^:]+):/, "https://$1/"), options);
    if (!check.ok) throw new Error(`blocked repository URL ${repoUrl}: ${check.reason}`);
    // file:// and other transports are refused; only https clones.
    if (!/^https:\/\//i.test(repoUrl) && !repoUrl.startsWith("git@")) {
      throw new Error(`only https git URLs are allowed (got ${repoUrl})`);
    }
  } else if (!existsSync(repoUrl)) {
    throw new Error(`local repository path does not exist: ${repoUrl}`);
  }

  execFileSync("git", [
    "-c", "protocol.ext.allow=never",
    "clone", "--depth", "1", "--single-branch", "--no-tags",
    "--", repoUrl, destDir,
  ], { stdio: "ignore", timeout: limits.timeoutMs * 2 });

  // Record the immutable commit hash before dropping .git for scanning.
  const head = execFileSync("git", ["-C", destDir, "rev-parse", "HEAD"], { encoding: "utf-8" }).trim();
  rmSync(join(destDir, ".git"), { recursive: true, force: true });

  return { digest: head };
}

// ============================================================
// Public entry: fetch any supported source to a local directory
// ============================================================

/**
 * Archives commonly wrap the skill in a single top-level directory.
 * If the extraction root has no SKILL.md but exactly one child that does,
 * descend into it so scans target the skill root.
 */
export function resolveSkillRoot(extractedDir: string): string {
  if (existsSync(join(extractedDir, "SKILL.md"))) return extractedDir;
  const children = readdirSync(extractedDir).filter(c => !c.startsWith("."));
  if (children.length === 1) {
    const child = join(extractedDir, children[0]);
    if (statSync(child).isDirectory() && existsSync(join(child, "SKILL.md"))) {
      return child;
    }
  }
  return extractedDir;
}

export async function fetchRemoteSource(source: string, options: RemoteFetchOptions = {}): Promise<FetchedSource> {
  const tempRoot = mkdtempSync(join(tmpdir(), "skill-audit-remote-"));
  let kind: FetchedSource["origin"]["kind"];
  let localPath: string;
  let digest = "";

  try {
    const isLocalPath = source.startsWith("/") || source.startsWith("./");
    const isUrl = /^[a-z+]+:\/\//i.test(source) || source.startsWith("git@");
    const isRemoteHttpsOrGit = isUrl && (/^https:\/\//i.test(source) || source.startsWith("git@"));

    if (isRemoteHttpsOrGit) {
      // Quarantined (#2): fail closed before any network or SSH transport is
      // touched. Determine the kind BEFORE validating so the disablement
      // always leads the message; validation only enriches the reason.
      const normalized = source.startsWith("git@")
        ? source.replace(/^git@([^:]+):/, "https://$1/")
        : source;
      const check = validateUrlForFetch(normalized, options);
      const detail = check.ok ? "" : ` (would also be rejected: ${check.reason})`;
      throw new Error(`${REMOTE_ACQUISITION_DISABLED}${detail}`);
    }

    if (isLocalPath && source.endsWith(".zip")) {
      kind = "zip";
      const buffer = readFileSync(source);
      digest = createHash("sha256").update(buffer).digest("hex");
      localPath = join(tempRoot, "extracted");
      mkdirSync(localPath, { recursive: true });
      extractZip(source, localPath, options);
    } else if (isLocalPath && existsSync(source)) {
      // Local directory or a local git repository (testing mirrors).
      kind = "git";
      localPath = join(tempRoot, "repo");
      const result = shallowClone(source, localPath, options);
      digest = result.digest;
    } else {
      throw new Error(
        `unsupported source: ${source} (expected local .zip archive or local directory; ` +
        `${REMOTE_ACQUISITION_DISABLED})`
      );
    }

    return {
      localPath: resolveSkillRoot(localPath),
      origin: { kind, source },
      digest,
      cleanup: () => rmSync(tempRoot, { recursive: true, force: true }),
    };
  } catch (e) {
    // No temp leak on any failure path (#15): the temp root is only handed
    // out via the cleanup handle after success.
    rmSync(tempRoot, { recursive: true, force: true });
    throw e;
  }
}
