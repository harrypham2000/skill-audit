import { describe, expect, it } from "vitest";
import { getCategoryFromId, getASIXXFromId } from "./security.js";

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

describe("getASIXXFromId", () => {
  it("maps PI to ASI01", () => {
    expect(getASIXXFromId("PI-001")).toBe("ASI01");
  });
  it("maps PII to ASI03 (not shadowed by PI)", () => {
    // Before the fix this returned "ASI01" — the PI check shadowed the PII check.
    expect(getASIXXFromId("PII-001")).toBe("ASI03");
  });
  it("maps PEX to ASI02", () => {
    expect(getASIXXFromId("PEX01")).toBe("ASI02");
  });
  it("maps PROV to ASI04", () => {
    expect(getASIXXFromId("PROV-01")).toBe("ASI04");
  });
});
