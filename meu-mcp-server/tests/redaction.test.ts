import { describe, expect, it } from "vitest";
import { detectSecrets, redactString } from "../src/redaction.ts";

const FAKE_SK = "sk-FAKEFAKEFAKEFAKEFAKE1234";

describe("detectSecrets", () => {
  it("names each kind found and counts matches without returning the secret", () => {
    const found = detectSecrets(`key=${FAKE_SK} other=${FAKE_SK}\n"password": "hunter2"`);
    expect(found).toEqual([
      { kind: "sk-key", count: 2 },
      { kind: "json-credential", count: 1 },
    ]);
    expect(JSON.stringify(found)).not.toContain(FAKE_SK);
    expect(JSON.stringify(found)).not.toContain("hunter2");
  });

  it("finds bearer tokens and returns nothing for clean text or non-strings", () => {
    expect(detectSecrets("Authorization: Bearer abc.def-123")).toEqual([{ kind: "bearer-token", count: 1 }]);
    expect(detectSecrets("nothing sensitive here")).toEqual([]);
    expect(detectSecrets("")).toEqual([]);
    expect(detectSecrets(undefined as unknown as string)).toEqual([]);
  });

  it("is stable across repeated calls (global regexes keep no state between lines)", () => {
    for (let i = 0; i < 3; i++) expect(detectSecrets(FAKE_SK)).toEqual([{ kind: "sk-key", count: 1 }]);
  });

  it("agrees with redactString: whatever is detected is redacted", () => {
    expect(redactString(FAKE_SK)).toContain("[REDACTED]");
    expect(redactString("nothing sensitive here")).toBe("nothing sensitive here");
  });
});
