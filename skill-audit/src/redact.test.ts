import { describe, expect, it } from "vitest";
import { redactEvidence } from "./redact.js";

describe("redactEvidence", () => {
  it("removes credential values while keeping the surrounding context", () => {
    const out = redactEvidence('export API_KEY="sk-abcdefghijklmnopqrstuvwxyz0123456789"');
    expect(out).not.toContain("sk-abcdefghijklmnopqrstuvwxyz0123456789");
    expect(out).toContain("API_KEY");
    expect(out).toMatch(/\[REDACTED:[0-9a-f]{8}\]/);
  });

  it("redacts credentials embedded in a URL", () => {
    const out = redactEvidence('curl "https://deploy:hunter2pass@example.test/ingest"');
    expect(out).not.toContain("hunter2pass");
    expect(out).toContain("https://deploy:");
    expect(out).toContain("@example.test");
  });

  it("redacts authorization schemes but keeps the scheme name", () => {
    const out = redactEvidence("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456");
    expect(out).not.toContain("abcdefghijklmnopqrstuvwxyz123456");
    expect(out).toContain("Bearer");
  });

  it("keeps variable references and non-secret values readable", () => {
    for (const input of [
      'curl -H "token: $API_TOKEN" https://x.test',
      "const k = process.env.OPENAI_API_KEY",
      "token = env.GITHUB_TOKEN",
      'password = "abc"',
      "timeout: 30000",
      "This skill helps review releases.",
    ]) {
      expect(redactEvidence(input)).toBe(input);
    }
  });

  it("is idempotent so a re-rendered report does not hash a placeholder", () => {
    const once = redactEvidence('API_KEY="sk-abcdefghijklmnopqrstuvwxyz0123456789"');
    expect(redactEvidence(once)).toBe(once);
  });

  it("gives distinct secrets distinct placeholders", () => {
    // A constant placeholder would make a replaced credential look unchanged
    // to any comparison built on evidence.
    const a = redactEvidence('export API_KEY="sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"');
    const b = redactEvidence('export API_KEY="sk-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"');
    expect(a).not.toBe(b);
  });

  it("gives the same secret the same placeholder across occurrences", () => {
    const secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789";
    const one = redactEvidence(`key=${secret}`);
    const two = redactEvidence(`other=${secret}`);
    expect(one.match(/\[REDACTED:[0-9a-f]{8}\]/)![0]).toBe(two.match(/\[REDACTED:[0-9a-f]{8}\]/)![0]);
  });

  it("redacts PEM private key blocks", () => {
    const out = redactEvidence("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----");
    expect(out).not.toContain("MIIEowIBAAKCAQEA");
    expect(out).toMatch(/\[REDACTED:[0-9a-f]{8}\]/);
  });
});
