import { describe, expect, it } from "vitest";
import { decide, formatText } from "../src/format.js";
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

describe("decide", () => {
  it("blocks a MALICIOUS verdict", () => {
    const result = decide(record({ verdict: "MALICIOUS", confidence: "HIGH", decidedBy: "intel" }), false);
    expect(result.recommendation).toBe("block");
  });

  it("warns on a SUSPICIOUS verdict", () => {
    const result = decide(record({ verdict: "SUSPICIOUS", confidence: "MEDIUM", decidedBy: "ai" }), false);
    expect(result.recommendation).toBe("warn");
  });

  it("allows a clean SAFE verdict", () => {
    const result = decide(record({ verdict: "SAFE", confidence: "HIGH", decidedBy: "rules" }), false);
    expect(result.recommendation).toBe("allow");
  });

  it("downgrades a SAFE verdict to warn when flagged for human review", () => {
    const result = decide(record({ verdict: "SAFE", confidence: "MEDIUM", decidedBy: "ai", needsReview: true }), false);
    expect(result.recommendation).toBe("warn");
  });

  it("treats FAILED as a warning, not a block or an allow", () => {
    const result = decide(record({ status: "FAILED", verdict: undefined, failureReason: "tampered tarball" }), false);
    expect(result.recommendation).toBe("warn");
  });

  it("treats SKIPPED as a warning", () => {
    const result = decide(record({ status: "SKIPPED", verdict: undefined, failureReason: "package too large" }), false);
    expect(result.recommendation).toBe("warn");
  });

  it("says wait while a scan is pending or scanning", () => {
    expect(decide(record({ status: "PENDING", verdict: undefined }), false).recommendation).toBe("wait");
    expect(decide(record({ status: "SCANNING", verdict: undefined }), false).recommendation).toBe("wait");
  });

  it("carries the timedOut flag through", () => {
    const result = decide(record({ status: "SCANNING", verdict: undefined }), true);
    expect(result.recommendation).toBe("wait");
    expect(result.timedOut).toBe(true);
  });
});

describe("formatText", () => {
  it("tells the agent to refuse on a block", () => {
    const result = decide(record({ verdict: "MALICIOUS", confidence: "HIGH", decidedBy: "intel", summary: "Known malware." }), false);
    const text = formatText(result, "https://pkgguard.example/npm/example?version=1.0.0");
    expect(text).toMatch(/BLOCK/);
    expect(text).toMatch(/Refuse to install/);
    expect(text).toContain("Known malware.");
    expect(text).toContain("https://pkgguard.example/npm/example?version=1.0.0");
  });

  it("tells the agent to get confirmation on a warn", () => {
    const result = decide(record({ verdict: "SUSPICIOUS", confidence: "LOW", decidedBy: "rules" }), false);
    const text = formatText(result, undefined);
    expect(text).toMatch(/WARN/);
    expect(text).toMatch(/confirmation/);
  });

  it("explains a timed-out wait differently from a fresh scan", () => {
    const fresh = formatText(decide(record({ status: "PENDING", verdict: undefined }), false), undefined);
    const stale = formatText(decide(record({ status: "SCANNING", verdict: undefined }), true), undefined);
    expect(fresh).toMatch(/analyzing this package now/);
    expect(stale).toMatch(/taking longer than usual/);
  });

  it("flags a needs-review SAFE verdict without calling it a block or a plain allow", () => {
    const text = formatText(decide(record({ verdict: "SAFE", confidence: "MEDIUM", decidedBy: "ai", needsReview: true }), false), undefined);
    expect(text).toMatch(/WARN/);
    expect(text).toMatch(/flagged this scan for human review/);
  });
});

describe("decide with a scan still running", () => {
  it("copes with the explicit nulls the API sends and asks the agent to wait", () => {
    const pending = { ...record({ status: "SCANNING" }), verdict: null, confidence: null, decidedBy: null, summary: null } as unknown as VerdictRecord;
    const result = decide(pending, true);
    expect(result.recommendation).toBe("wait");
    expect(result.verdict).toBeUndefined();
    expect(result.summary).toBeUndefined();
  });
});
