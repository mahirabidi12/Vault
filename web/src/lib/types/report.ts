/**
 * AUTO-GENERATED from schema/*.json. Do not edit by hand.
 * Regenerate with `npm run gen:types` after the scanner agent updates the schema.
 */

export type Ecosystem = "npm";
export type Name = string;
export type Version = string;
export type Analyzerversion = string;
export type Generatedat = string;
export type Ruleid = string;
export type FindingLayer = "intel" | "metadata" | "static";
export type Severity = "HIGH" | "MEDIUM" | "LOW";
export type Confidence = "HIGH" | "MEDIUM" | "LOW";
export type Title = string;
export type File = string | null;
export type Line = number | null;
export type Snippet = string | null;
export type Installtime = boolean;
export type Occurrences = number;
export type Findings = Finding[];
export type Verdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS";
/**
 * One or two plain sentences for developers
 */
export type Summary = string;
/**
 * A few short paragraphs explaining what the code does and why
 */
export type Reasoning = string;
export type File1 = string;
export type Line1 = number | null;
export type Explanation = string;
/**
 * Only files and lines you actually read
 */
export type Evidence = AIEvidence[];
export type Ruleid1 = string;
export type File2 = string | null;
export type Assessment = "benign" | "malicious" | "uncertain";
export type Explanation1 = string;
export type Findingassessments = FindingAssessment[];
export type Model = string;
export type ReviewMode = "quick_look" | "deep_dive";
export type Filesread = string[];
export type Toolcalls = number;
export type Inputtokens = number | null;
export type Outputtokens = number | null;
export type Durationseconds = number;
export type Aierror = string | null;
export type Humanreview = {
  [k: string]: unknown;
} | null;

/**
 * Full report stored in S3. Intel, metadata and code scan sections get typed as those steps settle.
 */
export interface Report {
  package: PackageRef;
  analyzerVersion: Analyzerversion;
  generatedAt: Generatedat;
  findings?: Findings;
  intel?: Intel;
  metadata?: Metadata;
  codeScan?: Codescan;
  aiReview?: AIReview | null;
  aiError?: Aierror;
  humanReview?: Humanreview;
}
export interface PackageRef {
  ecosystem: Ecosystem;
  name: Name;
  version: Version;
}
export interface Finding {
  ruleId: Ruleid;
  layer: FindingLayer;
  severity: Severity;
  confidence: Confidence;
  title: Title;
  file?: File;
  line?: Line;
  snippet?: Snippet;
  installTime?: Installtime;
  occurrences?: Occurrences;
}
export interface Intel {
  [k: string]: unknown;
}
export interface Metadata {
  [k: string]: unknown;
}
export interface Codescan {
  [k: string]: unknown;
}
/**
 * AI verdict plus facts recorded by PkgGuard (never taken from the model's own claims).
 */
export interface AIReview {
  verdict: Verdict;
  confidence: Confidence;
  summary: Summary;
  reasoning: Reasoning;
  evidence?: Evidence;
  findingAssessments?: Findingassessments;
  model: Model;
  mode: ReviewMode;
  filesRead?: Filesread;
  toolCalls?: Toolcalls;
  inputTokens?: Inputtokens;
  outputTokens?: Outputtokens;
  durationSeconds: Durationseconds;
}
export interface AIEvidence {
  file: File1;
  line?: Line1;
  explanation: Explanation;
}
export interface FindingAssessment {
  ruleId: Ruleid1;
  file?: File2;
  assessment: Assessment;
  explanation: Explanation1;
}
