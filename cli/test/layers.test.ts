import { describe, expect, it } from "vitest";
import { formatLayerLine, formatSummary, layerLines, type ReportLite } from "../src/layers.js";

const NOW = new Date("2026-09-20T00:00:00Z");
const byName = (lines: ReturnType<typeof layerLines>, name: string) => lines.find((l) => l.name === name)!;

describe("layerLines", () => {
  it("shows all five layers for a clean package", () => {
    const report: ReportLite = {
      intel: { osv: { maliciousIds: [] }, safedep: { isMalware: false } },
      metadata: { installScripts: {}, publishedAt: "2024-01-01T00:00:00Z" },
      codeScan: { filesScanned: 247 },
      sandbox: { status: "COMPLETE", canaryHits: [] },
      aiReview: { verdict: "SAFE", confidence: "HIGH" },
      findings: [],
    };
    const lines = layerLines(report, NOW);
    expect(lines.map((l) => l.name)).toEqual(["Threat intel", "Package info", "Static scan", "Sandbox", "AI review"]);
    expect(lines.every((l) => l.mark === "ok")).toBe(true);
    expect(byName(lines, "Package info").text).toBe("no install scripts · 2 years old");
    expect(byName(lines, "Static scan").text).toBe("247 files, 0 findings");
    expect(byName(lines, "AI review").text).toBe("SAFE (high confidence)");
  });

  it("flags known malware, install scripts and stolen fake credentials", () => {
    const report: ReportLite = {
      intel: { safedep: { isMalware: true } },
      metadata: { installScripts: { postinstall: "node x.js" } },
      sandbox: { status: "COMPLETE", canaryHits: [{ sink: "http collector.example.invalid" }] },
      findings: [{ layer: "static" }, { layer: "static" }],
    };
    const lines = layerLines(report, NOW);
    expect(byName(lines, "Threat intel").mark).toBe("bad");
    expect(byName(lines, "Package info").text).toContain("postinstall script");
    expect(byName(lines, "Static scan").text).toContain("2 findings");
    expect(byName(lines, "Sandbox")).toMatchObject({ mark: "bad", text: "sent fake credentials to collector.example.invalid" });
  });

  it("marks layers that did not run instead of failing on old reports", () => {
    const lines = layerLines({}, NOW);
    expect(byName(lines, "Sandbox").mark).toBe("off");
    expect(byName(lines, "AI review").text).toBe("not run");
  });
});

describe("formatting", () => {
  it("formats a layer line and the summary", () => {
    expect(formatLayerLine({ mark: "ok", name: "Sandbox", text: "fine" })).toBe("  ✓ Sandbox       fine");
    expect(formatSummary(1, 0, 3.24)).toBe("1 package checked · 0 issues · 3.2s");
    expect(formatSummary(66, 2, 10)).toBe("66 packages checked · 2 issues · 10.0s");
  });
});
