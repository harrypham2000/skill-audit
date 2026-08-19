/**
 * Shell structural analysis (Phase 5, slice 2).
 *
 * Parses shell scripts into logical commands with a quote-aware tokenizer —
 * not flat regex — then maps each command to the shared ObservedCapability
 * model: process.exec, network.request, fs.read, fs.write, env.read.
 * Single-quoted spans are treated as literal text (no expansion), matching
 * shell semantics.
 */
import { CapabilityKind } from "./context.js";
import { SourceLocation } from "./types.js";

export interface ShellCapability {
  capability: CapabilityKind;
  level: "observed";
  evidence: string;
  file: string;
  line: number;
  location?: SourceLocation;
  scope?: { server?: string; tool?: string };
}

export interface ShellAnalyzerResult {
  capabilities: ShellCapability[];
  status: "completed" | "partial" | "not_applicable";
  detail?: string;
  filesAnalyzed: number;
}

const SHELL_FILES = /\.(sh|bash|zsh|ksh)$/i;

interface LogicalCommand {
  text: string;
  line: number;
  /** Exact range in the ORIGINAL source; present when `file` is passed. */
  location?: SourceLocation;
}

const isWs = (ch: string): boolean => ch === " " || ch === "\t" || ch === "\n" || ch === "\r";

/**
 * Split shell source into logical commands on newline, ;, &&, ||, and |,
 * respecting single/double quotes.
 *
 * The RAW source is scanned (continuations are consumed inline rather than
 * pre-joined), so absolute offsets map 1:1 to the original file. Each command
 * carries its 1-based start line plus — when `file` is provided — an exact
 * SourceLocation covering the trimmed command text. Column convention:
 * startColumn inclusive, endColumn exclusive.
 */
export function splitLogicalCommands(source: string, file?: string): LogicalCommand[] {
  // Precomputed line-start offsets: line i (1-based) starts at lineStarts[i-1].
  const lineStarts: number[] = [0];
  for (let i = 0; i < source.length; i++) {
    if (source[i] === "\n") lineStarts.push(i + 1);
  }
  const positionOf = (offset: number): { line: number; column: number } => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - lineStarts[lo] + 1 };
  };

  const commands: LogicalCommand[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let cmdStart = -1; // offset of the first non-whitespace character of the command
  let cmdEnd = -1;   // exclusive offset just past the last non-whitespace character

  const flush = () => {
    const text = current.trim();
    if (text.length > 0 && cmdStart >= 0 && cmdEnd > cmdStart) {
      const start = positionOf(cmdStart);
      const end = positionOf(cmdEnd);
      commands.push({
        text,
        line: start.line,
        location: file
          ? {
              file,
              startLine: start.line,
              startColumn: start.column,
              endLine: end.line,
              endColumn: end.column, // exclusive
              precision: "exact",
            }
          : undefined,
      });
    }
    current = "";
    cmdStart = -1;
    cmdEnd = -1;
  };

  for (let i = 0; i < source.length; i++) {
    const ch = source[i];

    // Backslash-newline continuation: consume it plus the following blanks
    // inline (no separator, nothing appended) so offsets stay original.
    if (ch === "\\" && source[i + 1] === "\n") {
      i += 2;
      while (source[i] === " " || source[i] === "\t") i++;
      i--; // compensate the loop increment
      continue;
    }

    if (quote) {
      if (ch === quote && (quote === "'" || source[i - 1] !== "\\")) quote = null;
      current += ch;
      if (!isWs(ch)) {
        if (cmdStart === -1) cmdStart = i;
        cmdEnd = i + 1;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      if (cmdStart === -1) cmdStart = i;
      cmdEnd = i + 1;
      current += ch;
      continue;
    }

    const two = source.slice(i, i + 2);
    const isSeparator = ch === "\n" || ch === ";" || two === "&&" || two === "||" || ch === "|";
    if (isSeparator) {
      flush();
      if (two === "&&" || two === "||") i++;
      continue;
    }
    if (!isWs(ch)) {
      if (cmdStart === -1) cmdStart = i;
      cmdEnd = i + 1;
    }
    current += ch;
  }
  flush();
  return commands;
}

/**
 * True when a quote opens and never closes before end-of-input — the shell
 * would either error or silently swallow the rest of the file, so the split
 * commands cannot be trusted as complete. Mirrors splitLogicalCommands's
 * quote state machine exactly (same escape and continuation handling), so
 * the detector and the splitter can never disagree.
 */
export function hasUnclosedQuote(source: string): boolean {
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (ch === "\\" && source[i + 1] === "\n") {
      i += 2;
      while (source[i] === " " || source[i] === "\t") i++;
      i--; // compensate the loop increment
      continue;
    }
    if (quote) {
      if (ch === quote && (quote === "'" || source[i - 1] !== "\\")) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') quote = ch;
  }
  return quote !== null;
}

/** Strip quotes and return command name (first word) plus expanded-flag text. */
function commandParts(text: string): { name: string; rest: string; expandsEnv: boolean } {
  // Single-quoted spans are literal: mask them so $VAR inside stays inert.
  const unquoted = text.replace(/'[^']*'/g, m => " ".repeat(m.length));
  const words = unquoted.trim().split(/\s+/).filter(Boolean);
  const name = (words[0] ?? "").replace(/["']/g, "");
  const envRefs = /\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]+\}/.test(unquoted);
  return { name, rest: words.slice(1).join(" "), expandsEnv: envRefs };
}

const NETWORK_COMMANDS = new Set([
  "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp",
  "ftp", "telnet", "ping", "nslookup", "dig",
]);
const EXEC_COMMANDS = new Set([
  "bash", "sh", "zsh", "dash", "ksh", "eval", "exec", "source", ".",
  "xargs", "awk", "perl", "ruby", "python", "python3", "node", "npx", "bunx",
]);
const FS_READ_COMMANDS = new Set(["cat", "head", "tail", "less", "more", "wc"]);
const FS_WRITE_COMMANDS = new Set(["tee", "install", "truncate"]);

export function analyzeShell(files: Array<{ path: string; content?: string }>): ShellAnalyzerResult {
  const candidates = files.filter(f => SHELL_FILES.test(f.path) && f.content !== undefined);
  if (candidates.length === 0) {
    return { capabilities: [], status: "not_applicable", detail: "no shell scripts in scope", filesAnalyzed: 0 };
  }

  const capabilities: ShellCapability[] = [];
  const seen = new Set<string>();
  let unterminatedQuoteFiles = 0;

  const push = (capability: CapabilityKind, evidence: string, file: string, line: number, location?: SourceLocation, scope?: { server?: string; tool?: string }) => {
    const key = `${capability}:${file}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    capabilities.push({ capability, level: "observed", evidence: evidence.slice(0, 120), file, line, location, scope });
  };

  for (const file of candidates) {
    const lines = file.content!.split("\n");
    // Shebang files that are not shell interpreters (awk, python) are skipped.
    const shebang = lines[0] ?? "";
    if (/^#!.*\b(?:python|awk|perl|ruby|node)\b/.test(shebang)) continue;

    // A dangling quote reaching EOF means the tail of the file was swallowed
    // into one string: the commands below are parsed, but the file is not
    // fully analyzed. Downgrade to partial so the ledger says so.
    if (hasUnclosedQuote(file.content!)) unterminatedQuoteFiles++;

    for (const cmd of splitLogicalCommands(file.content!, file.path)) {
      const { name, rest, expandsEnv } = commandParts(cmd.text);
      if (!name || name.startsWith("#")) continue;

      if (NETWORK_COMMANDS.has(name)) push("network.request", cmd.text, file.path, cmd.line, cmd.location);
      if (EXEC_COMMANDS.has(name)) push("process.exec", cmd.text, file.path, cmd.line, cmd.location);
      if (FS_READ_COMMANDS.has(name) || /</.test(rest)) push("fs.read", cmd.text, file.path, cmd.line, cmd.location);
      if (FS_WRITE_COMMANDS.has(name) || />>?/.test(rest)) push("fs.write", cmd.text, file.path, cmd.line, cmd.location);
      // `claude mcp call <server>` invokes an MCP server from shell.
      if ((name === "claude" || name === "mcp") && /\bmcp\s+call\s+([\w.-]+)/.test(cmd.text)) {
        const server = cmd.text.match(/\bmcp\s+call\s+([\w.-]+)/)![1];
        push("mcp.invoke", cmd.text, file.path, cmd.line, cmd.location, { server });
      }
      // $VAR outside single quotes reads the environment.
      if (expandsEnv) push("env.read", cmd.text, file.path, cmd.line, cmd.location);
    }
  }

  if (unterminatedQuoteFiles > 0) {
    return {
      capabilities,
      status: "partial",
      detail: `unterminated quote in ${unterminatedQuoteFiles} file(s)`,
      filesAnalyzed: candidates.length,
    };
  }
  return { capabilities, status: "completed", filesAnalyzed: candidates.length };
}
