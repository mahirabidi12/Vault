import type { VerdictRecord } from "./types.js";

export type Recommendation = "allow" | "warn" | "block" | "wait";

export interface PackageDecision {
  recommendation: Recommendation;
  record: VerdictRecord;
}

/** Pure decision: turns one verdict record into a recommendation, mirroring mcp/src/format.ts. */
export function decideOne(record: VerdictRecord): PackageDecision {
  if (record.status === "PENDING" || record.status === "SCANNING") {
    return { recommendation: "wait", record };
  }
  if (record.status === "FAILED" || record.status === "SKIPPED") {
    return { recommendation: "warn", record };
  }
  if (record.verdict === "MALICIOUS") return { recommendation: "block", record };
  if (record.verdict === "SUSPICIOUS") return { recommendation: "warn", record };
  // SAFE, but downgrade to a warning if PkgGuard flagged the scan for human review.
  return { recommendation: record.needsReview ? "warn" : "allow", record };
}

const PRIORITY: Record<Recommendation, number> = { block: 0, wait: 1, warn: 2, allow: 3 };

/** Worst-case recommendation across a batch: one MALICIOUS blocks everything. */
export function summarize(decisions: PackageDecision[]): Recommendation {
  if (decisions.length === 0) return "allow";
  return decisions.reduce((worst, d) => (PRIORITY[d.recommendation] < PRIORITY[worst] ? d.recommendation : worst), "allow" as Recommendation);
}

export function exitCode(recommendation: Recommendation): number {
  return { allow: 0, warn: 1, block: 2, wait: 3 }[recommendation];
}

const ICON: Record<Recommendation, string> = { block: "🛑", warn: "⚠️ ", allow: "✅", wait: "⏳" };

export function formatLine(decision: PackageDecision): string {
  const { record, recommendation } = decision;
  const ref = `${record.package.name}@${record.package.version}`;
  if (recommendation === "wait") return `${ICON.wait} ${ref} — still scanning`;
  if (record.status === "FAILED" || record.status === "SKIPPED") {
    return `${ICON.warn}${ref} — ${record.status.toLowerCase()}: ${record.failureReason ?? "no reason given"}`;
  }
  const conf = record.confidence && record.decidedBy ? ` (${record.confidence}, ${record.decidedBy})` : "";
  return `${ICON[recommendation]} ${ref} — ${record.verdict}${conf}${record.summary ? `: ${record.summary}` : ""}`;
}

export function formatDetail(decision: PackageDecision, reportUrl: string | undefined): string {
  const lines = [formatLine(decision)];
  if (decision.record.signals?.length) lines.push(`   Signals: ${decision.record.signals.join("; ")}`);
  if (decision.record.needsReview && decision.recommendation === "warn" && decision.record.verdict !== "SUSPICIOUS") {
    lines.push("   Note: flagged for human review even though the automated verdict is SAFE.");
  }
  if (reportUrl) lines.push(`   Report: ${reportUrl}`);
  return lines.join("\n");
}
