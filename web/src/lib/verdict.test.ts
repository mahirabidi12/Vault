import { describe, expect, it } from "vitest";
import {
  verdictStyle,
  statusStyle,
  severityClass,
  DECIDED_BY_LABEL,
  LAYER_LABEL,
  SEVERITY_ORDER,
  SEVERITY_LABEL,
} from "./verdict";

describe("BRIEF.md §5.4 wording rules", () => {
  it('never says "Safe" as a guarantee — SAFE renders as "No issues found"', () => {
    const style = verdictStyle("SAFE");
    expect(style.label).toBe("No issues found");
    expect(style.shortLabel).toBe("No issues found");
    expect(style.label.toLowerCase()).not.toBe("safe");
  });

  it("SUSPICIOUS and MALICIOUS render as their plain names", () => {
    expect(verdictStyle("SUSPICIOUS").label).toBe("Suspicious");
    expect(verdictStyle("MALICIOUS").label).toBe("Malicious");
  });

  it("every decidedBy value has a human label (never shown as the raw enum)", () => {
    for (const value of ["intel", "rules", "ai", "human"] as const) {
      expect(DECIDED_BY_LABEL[value]).toBeTruthy();
      expect(DECIDED_BY_LABEL[value]).not.toBe(value);
    }
  });

  it("every finding layer has a human label (intel/metadata/static are internal names)", () => {
    expect(LAYER_LABEL.intel).toBe("Threat intelligence");
    expect(LAYER_LABEL.metadata).toBe("Package info");
    expect(LAYER_LABEL.static).toBe("Code");
  });
});

describe("verdictStyle", () => {
  it("falls back to an 'Unknown'/pending style for null or undefined (no verdict yet)", () => {
    expect(verdictStyle(null).colorVar).toBe("pending");
    expect(verdictStyle(undefined).colorVar).toBe("pending");
  });

  it("pairs each verdict with a distinct color token (color is never the only signal, but it must still exist)", () => {
    expect(verdictStyle("SAFE").colorVar).toBe("safe");
    expect(verdictStyle("SUSPICIOUS").colorVar).toBe("suspicious");
    expect(verdictStyle("MALICIOUS").colorVar).toBe("malicious");
  });
});

describe("statusStyle", () => {
  it("SCANNING spins its icon (visually distinct from PENDING)", () => {
    expect(statusStyle("SCANNING").spin).toBe(true);
    expect(statusStyle("PENDING").spin).toBeUndefined();
  });

  it("has a label for every scan status", () => {
    for (const status of ["PENDING", "SCANNING", "COMPLETE", "FAILED", "SKIPPED"] as const) {
      expect(statusStyle(status).label).toBeTruthy();
    }
  });
});

describe("severity", () => {
  it("orders HIGH before MEDIUM before LOW", () => {
    expect(SEVERITY_ORDER.HIGH).toBeLessThan(SEVERITY_ORDER.MEDIUM);
    expect(SEVERITY_ORDER.MEDIUM).toBeLessThan(SEVERITY_ORDER.LOW);
  });

  it("every severity has a label", () => {
    for (const severity of ["HIGH", "MEDIUM", "LOW"] as const) {
      expect(SEVERITY_LABEL[severity]).toBeTruthy();
    }
  });

  it("HIGH borrows the malicious color, MEDIUM the suspicious color, LOW stays neutral", () => {
    expect(severityClass("HIGH")).toContain("malicious");
    expect(severityClass("MEDIUM")).toContain("suspicious");
    expect(severityClass("LOW")).toContain("muted");
  });
});
