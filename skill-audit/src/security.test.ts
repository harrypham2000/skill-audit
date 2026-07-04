import { describe, expect, it } from "vitest";
import { getCategoryFromId, getAsiFromId, auditSecurity } from "./security.js";

describe("getCategoryFromId", () => {
  it("maps PI to Prompt Injection", () => {
    expect(getCategoryFromId("PI-001")).toBe("PI");
  });
  it("maps PII to PII (not shadowed by PI)", () => {
    // Before the fix this returned "PI" — the PI check shadowed the PII check.
    expect(getCategoryFromId("PII-001")).toBe("PII");
  });
  it("maps PEX to PII (exfiltration)", () => {
    expect(getCategoryFromId("PEX01")).toBe("PII");
  });
  it("maps PROV to PROV", () => {
    expect(getCategoryFromId("PROV-01")).toBe("PROV");
  });
  it("maps other prefixes correctly", () => {
    expect(getCategoryFromId("CL-001")).toBe("SC");
    expect(getCategoryFromId("EX-001")).toBe("TM");
    expect(getCategoryFromId("CE-001")).toBe("CE");
    expect(getCategoryFromId("SC-001")).toBe("SC");
    expect(getCategoryFromId("TM-001")).toBe("TM");
    expect(getCategoryFromId("BM-001")).toBe("BM");
  });
});

describe("getAsiFromId", () => {
  it("maps PI to ASI01", () => {
    expect(getAsiFromId("PI-001")).toBe("ASI01");
  });
  it("maps PII to ASI03 (not shadowed by PI)", () => {
    // Before the fix this returned "ASI01" — the PI check shadowed the PII check.
    expect(getAsiFromId("PII-001")).toBe("ASI03");
  });
  it("maps PEX to ASI02", () => {
    expect(getAsiFromId("PEX01")).toBe("ASI02");
  });
  it("maps PROV to ASI04", () => {
    expect(getAsiFromId("PROV-01")).toBe("ASI04");
  });
});

describe("auditSecurity output schema", () => {
  it("findings use the 'asi' key (not 'asixx') for OWASP codes", () => {
    const skill = { name: "schema-test", path: "/tmp/sa-regression/bad", agent: "test", files: ["SKILL.md"] };
    const result = auditSecurity(skill as any);
    const pi = result.findings.find(f => f.id === "PI-001");
    expect(pi).toBeDefined();
    expect(pi!.asi).toBe("ASI01");                // correct key, correct value
    expect((pi as any).asixx).toBeUndefined();    // old key gone
  });
});
