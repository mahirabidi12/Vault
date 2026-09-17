import { describe, expect, it } from "vitest";
import { decideOne, exitCode, formatDetail, summarize } from "../src/decide.js";
import type { VerdictRecord } from "../src/types.js";

function record(overrides: Partial<VerdictRecord> = {}): VerdictRecord {
  return {
    package: { ecosystem: "npm", name: "example", version: "1.0.0" },
    status: "COMPLETE",
    scanId: "01SCAN000000000000000000",
    requestedAt: "2026-09-17T00:00:00Z",
    signals: [],
    ...overrides,
  };
}

describe("decideOne", () => {
  it("blocks MALICIOUS", () => {
    expect(decideOne(record({ verdict: "MALICIOUS", confidence: "HIGH", decidedBy: "intel" })).recommendation).toBe("block");
  });

  it("warns on SUSPICIOUS", () => {
    expect(decideOne(record({ verdict: "SUSPICIOUS", confidence: "MEDIUM", decidedBy: "ai" })).recommendation).toBe("warn");
  });

  it("allows a clean SAFE verdict", () => {
    expect(decideOne(record({ verdict: "SAFE", confidence: "HIGH", decidedBy: "rules" })).recommendation).toBe("allow");
  });

  it("downgrades a needs-review SAFE verdict to warn", () => {
    expect(decideOne(record({ verdict: "SAFE", confidence: "MEDIUM", decidedBy: "ai", needsReview: true })).recommendation).toBe("warn");
  });

  it("treats FAILED/SKIPPED as warnings, not allows", () => {
    expect(decideOne(record({ status: "FAILED", verdict: undefined })).recommendation).toBe("warn");
    expect(decideOne(record({ status: "SKIPPED", verdict: undefined })).recommendation).toBe("warn");
  });

  it("says wait while pending or scanning", () => {
    expect(decideOne(record({ status: "PENDING", verdict: undefined })).recommendation).toBe("wait");
    expect(decideOne(record({ status: "SCANNING", verdict: undefined })).recommendation).toBe("wait");
  });
});

describe("summarize", () => {
  it("blocks if any package is blocked, regardless of the others", () => {
    const decisions = [
      decideOne(record({ verdict: "SAFE", confidence: "HIGH", decidedBy: "rules" })),
      decideOne(record({ verdict: "MALICIOUS", confidence: "HIGH", decidedBy: "intel" })),
    ];
    expect(summarize(decisions)).toBe("block");
  });

  it("waits if nothing is blocked but something is still scanning", () => {
    const decisions = [
      decideOne(record({ verdict: "SAFE", confidence: "HIGH", decidedBy: "rules" })),
      decideOne(record({ status: "SCANNING", verdict: undefined })),
    ];
    expect(summarize(decisions)).toBe("wait");
  });

  it("warns if nothing is blocked or waiting but something needs a look", () => {
    const decisions = [
      decideOne(record({ verdict: "SAFE", confidence: "HIGH", decidedBy: "rules" })),
      decideOne(record({ verdict: "SUSPICIOUS", confidence: "LOW", decidedBy: "rules" })),
    ];
    expect(summarize(decisions)).toBe("warn");
  });

  it("allows an empty batch", () => {
    expect(summarize([])).toBe("allow");
  });
});

describe("exitCode", () => {
  it("maps each recommendation to a distinct exit code", () => {
    expect(exitCode("allow")).toBe(0);
    expect(exitCode("warn")).toBe(1);
    expect(exitCode("block")).toBe(2);
    expect(exitCode("wait")).toBe(3);
  });
});

describe("formatDetail", () => {
  it("includes signals and the report link", () => {
    const decision = decideOne(record({ verdict: "MALICIOUS", confidence: "HIGH", decidedBy: "intel", signals: ["Flagged as malware"] }));
    const text = formatDetail(decision, "https://pkgguard.example/npm/example?version=1.0.0");
    expect(text).toContain("MALICIOUS");
    expect(text).toContain("Flagged as malware");
    expect(text).toContain("https://pkgguard.example/npm/example?version=1.0.0");
  });
});
