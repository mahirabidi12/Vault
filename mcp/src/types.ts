/**
 * Minimal mirror of the fields this tool reads from schema/verdict-record.schema.json
 * (source of truth: analyzer/src/pkgguard_analyzer/schema.py). Kept intentionally small —
 * this package doesn't need the full report shape, only the verdict record.
 */

export type Ecosystem = "npm";
export type ScanStatus = "PENDING" | "SCANNING" | "COMPLETE" | "FAILED" | "SKIPPED";
export type Verdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS";
export type Confidence = "HIGH" | "MEDIUM" | "LOW";
export type DecidedBy = "intel" | "rules" | "ai" | "human";

export interface PackageRef {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

export interface VerdictRecord {
  package: PackageRef;
  status: ScanStatus;
  scanId: string;
  verdict?: Verdict;
  confidence?: Confidence;
  decidedBy?: DecidedBy;
  summary?: string;
  signals?: string[];
  requestedAt: string;
  analyzedAt?: string;
  reportS3Key?: string;
  aiFailed?: boolean;
  failureReason?: string;
  needsReview?: boolean;
  iocCount?: number;
}
