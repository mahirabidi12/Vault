/**
 * Hand-written types layered on top of the generated schema types.
 *
 * `Report.intel` / `Report.metadata` / `Report.codeScan` are typed as open
 * objects in schema/report.schema.json ("typed as those steps settle" per
 * its own description). These interfaces describe the real shapes the
 * analyzer actually produces, inferred from schema/examples/. If the
 * scanner agent tightens the schema later, prefer the generated type and
 * delete the matching interface here.
 */
import type { Report as GeneratedReport } from "./report";

export type ConfidenceLevel = "HIGH" | "MEDIUM" | "LOW";

export interface OsvIntel {
  maliciousIds: string[];
  vulnerabilityIds: string[];
  error?: string;
}

export interface SafeDepIntel {
  found: boolean;
  isMalware?: boolean;
  confidence?: string;
  humanVerified?: boolean;
  analysisId?: string;
  error?: string;
}

export interface IntelResult {
  osv?: OsvIntel;
  safedep?: SafeDepIntel;
}

export interface PackageMetadata {
  description?: string | null;
  license?: string | null;
  publisher?: string | null;
  trustedPublishing?: boolean;
  provenance?: boolean;
  maintainers?: string[];
  publishedAt?: string | null;
  previousVersion?: string | null;
  installScripts?: Record<string, string>;
  repository?: string | null;
  dependencies?: Record<string, string>;
  sha256?: string;
  fileCount?: number;
  unpackedBytes?: number;
}

export interface CodeScanSummary {
  filesScanned?: number;
  filesParsed?: number;
  filesWithParseErrors?: number;
  installTimeFiles?: string[];
  entryFiles?: string[];
  executables?: string[];
  skipped?: string[];
  findingsTruncated?: boolean;
}

export type Report = Omit<
  GeneratedReport,
  "intel" | "metadata" | "codeScan"
> & {
  intel?: IntelResult;
  metadata?: PackageMetadata;
  codeScan?: CodeScanSummary;
};

export type {
  Finding,
  FindingLayer,
  Severity,
  AIReview,
  AIEvidence,
  FindingAssessment,
  Assessment,
  ReviewMode,
  PackageRef,
} from "./report";

export type {
  VerdictRecord,
  ScanStatus,
  Verdict,
  DecidedBy,
  RanOn,
  RecordSource,
  Confidence,
  Ecosystem,
} from "./verdict-record";
