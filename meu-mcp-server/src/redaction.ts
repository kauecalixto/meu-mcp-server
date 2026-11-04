/**
 * Sensitive Data Redaction Utility for Calixto AI.
 * Ensures API keys, tokens, auth headers and private secrets are never exposed
 * in logs, error messages, or wire responses to the renderer.
 */

const NAMED_SECRET_PATTERNS: ReadonlyArray<{ kind: string; pattern: RegExp }> = [
  { kind: "sk-key", pattern: /sk-[a-zA-Z0-9_-]{16,}/g }, // OpenAI / general sk keys
  { kind: "bearer-token", pattern: /Bearer\s+[a-zA-Z0-9._~+/-]+=*/gi },
  { kind: "github-token", pattern: /ghp_[a-zA-Z0-9]{36,}/g },
  { kind: "google-api-key", pattern: /AIza[0-9A-Za-z-_]{35}/g },
  { kind: "anthropic-key", pattern: /ant-[a-zA-Z0-9_-]{20,}/g },
  { kind: "xai-key", pattern: /xai-[a-zA-Z0-9_-]{20,}/g },
  { kind: "deepseek-key", pattern: /deepseek-[a-zA-Z0-9_-]{20,}/g },
  {
    kind: "json-credential",
    pattern: /"(apiKey|token|secret|password|bearer|authorization)"\s*:\s*"[^"]+"/gi,
  },
];

const SECRET_PATTERNS = NAMED_SECRET_PATTERNS.map((p) => p.pattern);

/**
 * Reports which secret kinds appear in `input`, with how many matches each.
 * Never returns the matched text itself, so callers can surface findings
 * without re-exposing the secret.
 */
export function detectSecrets(input: string): Array<{ kind: string; count: number }> {
  if (!input || typeof input !== "string") return [];
  const found: Array<{ kind: string; count: number }> = [];
  for (const { kind, pattern } of NAMED_SECRET_PATTERNS) {
    const count = [...input.matchAll(new RegExp(pattern.source, pattern.flags))].length;
    if (count > 0) found.push({ kind, count });
  }
  return found;
}

export function redactString(input: string): string {
  if (!input || typeof input !== "string") return input;
  let result = input;
  for (const pattern of SECRET_PATTERNS) {
    result = result.replace(pattern, (match) => {
      if (match.startsWith("Bearer ") || match.startsWith("bearer ")) {
        return "Bearer [REDACTED]";
      }
      if (match.includes(":")) {
        const key = match.split(":")[0];
        return `${key}: "[REDACTED]"`;
      }
      if (match.length > 8) {
        return `${match.slice(0, 3)}...${match.slice(-4)} [REDACTED]`;
      }
      return "[REDACTED]";
    });
  }
  return result;
}

export function maskSecretId(secret: string): string {
  if (!secret) return "";
  const trimmed = secret.trim();
  if (trimmed.length <= 8) return "••••••••";
  const prefix = trimmed.slice(0, Math.min(4, trimmed.length - 4));
  const suffix = trimmed.slice(-4);
  return `${prefix}••••${suffix}`;
}

export function redactObject<T>(obj: T): T {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === "string") return redactString(obj) as unknown as T;
  if (Array.isArray(obj)) return obj.map((item) => redactObject(item)) as unknown as T;
  if (typeof obj === "object") {
    const res: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      if (/^(apiKey|token|secret|password|privateKey|credential)$/i.test(k)) {
        res[k] = "[REDACTED]";
      } else {
        res[k] = redactObject(v);
      }
    }
    return res as unknown as T;
  }
  return obj;
}

export function redactError(error: unknown): Error {
  if (error instanceof Error) {
    const err = new Error(redactString(error.message));
    err.name = error.name;
    if (error.stack) err.stack = redactString(error.stack);
    return err;
  }
  return new Error(redactString(String(error)));
}
