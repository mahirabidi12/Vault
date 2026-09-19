/**
 * AUTO-GENERATED from schema/*.json. Do not edit by hand.
 * Regenerate with `npm run gen:types` after the scanner agent updates the schema.
 */

export type Ecosystem = "npm";
export type Name = string;
export type Version = string;
export type ScanStatus = "PENDING" | "SCANNING" | "COMPLETE" | "FAILED" | "SKIPPED";
export type Scanid = string;
export type Verdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS";
export type Confidence = "HIGH" | "MEDIUM" | "LOW";
export type DecidedBy = "intel" | "rules" | "ai" | "human" | "sandbox";
export type Summary = string | null;
export type Signals = string[];
export type Sha256 = string | null;
export type Integrity = string | null;
export type Tarballurl = string | null;
export type Publishedat = string | null;
export type Requestedat = string;
export type Analyzedat = string | null;
export type Model = string | null;
export type RanOn = "local" | "cloud";
export type Analyzerversion = string;
export type RecordSource = "pkgguard" | "osv-import";
export type Reports3Key = string | null;
export type Aifailed = boolean;
export type Failurereason = string | null;
export type Needsreview = boolean;
export type Ioccount = number;
export type Settingshash = string | null;
export type SandboxStatus = "COMPLETE" | "PARTIAL" | "SKIPPED" | "FAILED" | "NOT_RUN";

/**
 * Summary stored in DynamoDB and returned by the API.
 */
export interface VerdictRecord {
  package: PackageRef;
  status: ScanStatus;
  scanId: Scanid;
  verdict?: Verdict | null;
  confidence?: Confidence | null;
  decidedBy?: DecidedBy | null;
  summary?: Summary;
  signals?: Signals;
  sha256?: Sha256;
  integrity?: Integrity;
  tarballUrl?: Tarballurl;
  publishedAt?: Publishedat;
  requestedAt: Requestedat;
  analyzedAt?: Analyzedat;
  model?: Model;
  ranOn: RanOn;
  analyzerVersion: Analyzerversion;
  source?: RecordSource;
  reportS3Key?: Reports3Key;
  aiFailed?: Aifailed;
  failureReason?: Failurereason;
  needsReview?: Needsreview;
  iocCount?: Ioccount;
  settingsHash?: Settingshash;
  sandboxStatus?: SandboxStatus | null;
}
export interface PackageRef {
  ecosystem: Ecosystem;
  name: Name;
  version: Version;
}
