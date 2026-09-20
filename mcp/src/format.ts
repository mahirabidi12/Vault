import type { VerdictRecord } from "./types.js";

export type Recommendation = "allow" | "warn" | "block" | "wait";

export interface CheckPackageResult {
  recommendation: Recommendation;
  status: VerdictRecord["status"];
  package: VerdictRecord["package"];
  verdict?: VerdictRecord["verdict"];
  confidence?: VerdictRecord["confidence"];
  decidedBy?: VerdictRecord["decidedBy"];
  summary?: string;
  signals: string[];
  scanId: string;
  reportUrl?: string;
  needsReview: boolean;
  timedOut: boolean;
}

/** Pure decision: turns one verdict record into a recommendation an agent can act on. */
export function decide(record: VerdictRecord, timedOut: boolean): CheckPackageResult {
  const base = {
    status: record.status,
    package: record.package,
    // The API sends explicit nulls while a scan is still running; treat those as "not there".
    verdict: record.verdict ?? undefined,
    confidence: record.confidence ?? undefined,
    decidedBy: record.decidedBy ?? undefined,
    summary: record.summary ?? record.failureReason ?? undefined,
    signals: record.signals ?? [],
    scanId: record.scanId,
    needsReview: record.needsReview ?? false,
    timedOut,
  };

  if (record.status === "PENDING" || record.status === "SCANNING") {
    return { ...base, recommendation: "wait" };
  }
  if (record.status === "FAILED" || record.status === "SKIPPED") {
    return { ...base, recommendation: "warn" };
  }
  // COMPLETE
  if (record.verdict === "MALICIOUS") return { ...base, recommendation: "block" };
  if (record.verdict === "SUSPICIOUS") return { ...base, recommendation: "warn" };
  // SAFE, but downgrade to a warning if PkgGuard itself flagged the scan for human review
  // (e.g. the AI and the rules disagreed, or the package tried to prompt-inject the reviewer).
  return { ...base, recommendation: base.needsReview ? "warn" : "allow" };
}

const RECOMMENDATION_HEADER: Record<Recommendation, string> = {
  block: "🛑 BLOCK — do not install this package",
  warn: "⚠️  WARN — confirm with the user before installing",
  allow: "✅ ALLOW — no issues found",
  wait: "⏳ WAIT — scan still running, don't install yet",
};

export function formatText(result: CheckPackageResult, reportUrl: string | undefined): string {
  const ref = `${result.package.name}@${result.package.version}`;
  const lines = [`${RECOMMENDATION_HEADER[result.recommendation]}: ${ref}`];

  if (result.recommendation === "wait") {
    lines.push(
      result.timedOut
        ? `PkgGuard is still analyzing this package (scan ${result.scanId}). It's taking longer than usual — call check_package again in a bit before installing.`
        : "PkgGuard is analyzing this package now. Don't install it yet."
    );
  } else if (result.status === "FAILED" || result.status === "SKIPPED") {
    lines.push(`PkgGuard could not produce a verdict (${result.status.toLowerCase()}): ${result.summary ?? "no reason given"}.`);
    lines.push("Treat this as unverified, not as safe. Ask the user before installing.");
  } else {
    if (result.confidence && result.decidedBy) {
      lines.push(`Verdict: ${result.verdict} (${result.confidence} confidence, decided by ${result.decidedBy}).`);
    }
    if (result.summary) lines.push(result.summary);
    if (result.signals.length) lines.push(`Signals: ${result.signals.join("; ")}.`);
    if (result.needsReview && result.verdict !== "MALICIOUS" && result.verdict !== "SUSPICIOUS") {
      lines.push("Note: PkgGuard flagged this scan for human review even though the verdict is SAFE — treat with a little extra caution.");
    }
  }

  if (result.recommendation === "block") {
    lines.push("Refuse to install this package and tell the user why. Do not attempt a workaround.");
  } else if (result.recommendation === "warn") {
    lines.push("Warn the user about this and get explicit confirmation before installing.");
  }

  if (reportUrl) lines.push(`Full report: ${reportUrl}`);
  return lines.join("\n");
}
