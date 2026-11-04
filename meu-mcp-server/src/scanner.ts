import { open, realpath } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { detectSecrets } from "./redaction.ts";

export const LIMITS = {
  maxPathLength: 260,
  maxFileBytes: 1024 * 1024,
  maxLines: 20_000,
  maxFindingsCap: 100,
  defaultMaxFindings: 50,
  binarySniffBytes: 8192,
  deadlineMs: 5_000,
} as const;

export type ErrorCode =
  | "E_VALIDATION"
  | "E_OUTSIDE_ROOT"
  | "E_DENIED"
  | "E_NOT_FOUND"
  | "E_TOO_LARGE"
  | "E_BINARY"
  | "E_TIMEOUT"
  | "E_INTERNAL";

const MESSAGES: Record<ErrorCode, string> = {
  E_VALIDATION: "Invalid input.",
  E_OUTSIDE_ROOT: "Path is outside the allowed root.",
  E_DENIED: "This file is not allowed to be scanned.",
  E_NOT_FOUND: "File not found.",
  E_TOO_LARGE: "File exceeds the size limit.",
  E_BINARY: "File looks binary and was not scanned.",
  E_TIMEOUT: "Scan exceeded the time limit.",
  E_INTERNAL: "Internal error.",
};

/** Errors carry only a code; the message is fixed so it can never echo input or absolute paths. */
export class ScanError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode) {
    super(MESSAGES[code]);
    this.name = "ScanError";
    this.code = code;
  }
}

export type ScanResult = {
  file: string;
  bytesScanned: number;
  linesScanned: number;
  findingsCount: number;
  truncated: boolean;
  findings: Array<{ line: number; kind: string; count: number }>;
};

const DENIED_BASENAME = [
  /^\.env/i,
  /\.(pem|key|pfx|p12|kdbx)$/i,
  /^id_(rsa|dsa|ecdsa|ed25519)/i,
  /^credentials/i,
];
const DENIED_SEGMENTS = new Set([".git", "node_modules"]);
// Opening a Windows device name (CON, NUL, COM1...) can block or read a device instead of a file.
const WINDOWS_DEVICE = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;
const INVALID_CHARS = /[\x00-\x1f<>:"|?*]/;

function isInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function checkSegments(segments: string[]): void {
  for (const seg of segments) {
    if (DENIED_SEGMENTS.has(seg.toLowerCase())) throw new ScanError("E_DENIED");
    if (WINDOWS_DEVICE.test(seg)) throw new ScanError("E_DENIED");
    if (/[. ]$/.test(seg)) throw new ScanError("E_VALIDATION");
  }
  const base = segments[segments.length - 1] ?? "";
  if (DENIED_BASENAME.some((re) => re.test(base))) throw new ScanError("E_DENIED");
}

function validateInput(rawPath: unknown, rawMax: unknown): { rel: string; maxFindings: number } {
  if (typeof rawPath !== "string") throw new ScanError("E_VALIDATION");
  if (rawPath.length < 1 || rawPath.length > LIMITS.maxPathLength) throw new ScanError("E_VALIDATION");
  if (INVALID_CHARS.test(rawPath)) throw new ScanError("E_VALIDATION");
  const maxFindings = rawMax === undefined ? LIMITS.defaultMaxFindings : rawMax;
  if (
    typeof maxFindings !== "number" ||
    !Number.isInteger(maxFindings) ||
    maxFindings < 1 ||
    maxFindings > LIMITS.maxFindingsCap
  ) {
    throw new ScanError("E_VALIDATION");
  }
  if (path.win32.isAbsolute(rawPath) || path.posix.isAbsolute(rawPath)) throw new ScanError("E_OUTSIDE_ROOT");
  const segments = rawPath.split(/[\\/]+/).filter((s) => s !== "" && s !== ".");
  if (segments.length === 0) throw new ScanError("E_VALIDATION");
  if (segments.includes("..")) throw new ScanError("E_OUTSIDE_ROOT");
  checkSegments(segments);
  return { rel: segments.join("/"), maxFindings };
}

/** Resolves the allowed root once, following symlinks, so later containment checks compare real paths. */
export async function resolveRoot(configured: string | undefined): Promise<string> {
  return realpath(path.resolve(configured && configured.length > 0 ? configured : process.cwd()));
}

export async function scanFile(root: string, rawPath: unknown, rawMax?: unknown): Promise<ScanResult> {
  const started = Date.now();
  const { rel, maxFindings } = validateInput(rawPath, rawMax);

  let real: string;
  try {
    real = await realpath(path.resolve(root, rel));
  } catch {
    throw new ScanError("E_NOT_FOUND");
  }
  if (!isInside(root, real)) throw new ScanError("E_OUTSIDE_ROOT");
  // A symlink may point at a denied name; apply the same rules to where it really lands.
  checkSegments(path.relative(root, real).split(path.sep));

  const handle = await open(real, constants.O_RDONLY).catch(() => {
    throw new ScanError("E_NOT_FOUND");
  });
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new ScanError("E_VALIDATION");
    // A hardlink gives a denied file (e.g. .env) a harmless second name, which name checks cannot see.
    if (stat.nlink > 1) throw new ScanError("E_DENIED");
    if (stat.size > LIMITS.maxFileBytes) throw new ScanError("E_TOO_LARGE");
    // Read from the already-open handle with a hard cap: the file may grow after stat().
    const buffer = Buffer.alloc(LIMITS.maxFileBytes + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > LIMITS.maxFileBytes) throw new ScanError("E_TOO_LARGE");
    if (buffer.subarray(0, Math.min(total, LIMITS.binarySniffBytes)).includes(0)) throw new ScanError("E_BINARY");

    const lines = buffer.subarray(0, total).toString("utf8").split(/\r\n|\n|\r/);
    if (lines.length > LIMITS.maxLines) throw new ScanError("E_TOO_LARGE");

    const findings: ScanResult["findings"] = [];
    let findingsCount = 0;
    for (let i = 0; i < lines.length; i++) {
      if (i % 1000 === 0 && Date.now() - started > LIMITS.deadlineMs) throw new ScanError("E_TIMEOUT");
      for (const hit of detectSecrets(lines[i] ?? "")) {
        findingsCount += 1;
        if (findings.length < maxFindings) findings.push({ line: i + 1, kind: hit.kind, count: hit.count });
      }
    }
    return {
      file: rel,
      bytesScanned: total,
      linesScanned: lines.length,
      findingsCount,
      truncated: findingsCount > findings.length,
      findings,
    };
  } finally {
    await handle.close();
  }
}
