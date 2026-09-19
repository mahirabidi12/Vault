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
export type FindingLayer = "intel" | "metadata" | "static" | "sandbox";
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
/**
 * First line number, exactly as shown in the numbered code
 */
export type Line1 = number | null;
/**
 * Last line number of the relevant code (same as line for one line)
 */
export type Endline = number | null;
/**
 * Short label, e.g. 'Sends NPM_TOKEN to remote server'
 */
export type Title1 = string | null;
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
export type ReviewMode = "quick_look" | "deep_dive" | "full_audit";
export type Filesread = string[];
export type Toolcalls = number;
export type Inputtokens = number | null;
export type Outputtokens = number | null;
export type Durationseconds = number;
export type Filestotal = number;
export type Filesanalyzed = number;
export type Bytestotal = number;
export type Bytesanalyzed = number;
export type Duplicatesskipped = number;
export type Chunks = number;
export type Chunksfailed = number;
export type Workermodel = string;
export type Path = string;
export type Reason = string;
export type Skippedfiles = SkippedFile[];
export type Step = number;
export type Tool = string;
export type Outcome = string;
export type Resultchars = number;
export type Seconds = number;
export type Trace = ToolCall[];
export type Part = number;
export type Files = string[];
/**
 * Two or three sentences: what this code does
 */
export type Summary1 = string;
/**
 * Any of: network, exec, dynamic_code, env_access, sensitive_files, obfuscation, crypto, filesystem_write, none
 */
export type Capabilities = string[];
export type File3 = string;
/**
 * First line number, exactly as shown in the numbered code
 */
export type Line2 = number | null;
/**
 * Last line number of the relevant code
 */
export type Endline1 = number | null;
/**
 * Short label, e.g. 'reads NPM_TOKEN', 'spawns shell', 'decodes base64 and evals'
 */
export type Behavior = string;
export type Explanation2 = string;
export type Suspiciousitems = WorkerItem[];
/**
 * Where data comes from, e.g. 'process.env.NPM_TOKEN', '~/.npmrc', 'os.hostname()'
 */
export type Source = string;
/**
 * Where it goes, e.g. 'HTTPS request to https://api.example.com/collect', 'eval', 'child_process'
 */
export type Sink = string;
export type File4 = string;
export type Line3 = number | null;
export type Description = string;
export type Dataflows = DataFlow[];
/**
 * Full URLs, hosts or IPs the code contacts
 */
export type Externalendpoints = string[];
/**
 * Names of environment variables read (names only, never values)
 */
export type Envvars = string[];
export type WorkerAssessment = "benign" | "suspicious" | "malicious";
export type Error = string | null;
export type Inputtokens1 = number;
export type Outputtokens1 = number;
export type Durationseconds1 = number;
export type Workerreports = WorkerPartReport[];
export type Coordinatorinputtokens = number;
export type Coordinatoroutputtokens = number;
export type Coordinatorseconds = number;
export type Workerinputtokens = number;
export type Workeroutputtokens = number;
export type Workercalls = number;
export type Workerseconds = number;
export type Aierror = string | null;
export type Networkmodules = string[];
export type Hosts = string[];
export type Ipaddresses = string[];
export type Envvars1 = string[];
export type Readsallenv = boolean;
export type Sensitivepaths = string[];
export type Runscommands = boolean;
export type Dynamiccode = boolean;
export type Decodesdata = boolean;
export type Readsmachineinfo = boolean;
export type Nativeexecutables = string[];
export type Network = boolean;
export type Commands = boolean;
export type Files1 = string[];
export type IndicatorType = "url" | "domain" | "ip" | "webhook";
export type Value = string;
export type File5 = string | null;
export type Line4 = number | null;
export type Source1 = string;
export type Iocs = Indicator[];
export type Path1 = string;
export type Size = number;
export type Sha256 = string;
export type Filehashes = FileHash[];
export type Filehashestruncated = boolean;
export type Analyzerversion1 = string;
export type Ruleshash = string;
export type Settingshash = string;
export type Downloadseconds = number;
export type Unpackseconds = number;
export type Intelseconds = number;
export type Metadataseconds = number;
export type Codescanseconds = number;
export type Sandboxseconds = number;
export type Aiseconds = number;
export type Totalseconds = number;
export type Rulesaidisagree = boolean;
export type Workercoordinatordisagree = boolean;
export type Promptinjectiondetected = boolean;
export type Lowcoverage = boolean;
export type Aifailed = boolean;
export type Needshumanreview = boolean;
export type Reasons = string[];
export type Id = string;
export type File6 = string;
export type Linestart = number | null;
export type Lineend = number | null;
export type IssueCategory =
  | "secret_theft"
  | "network"
  | "commands"
  | "hidden_code"
  | "secrets_access"
  | "install_script"
  | "prompt_injection"
  | "mining"
  | "remote_control"
  | "binary"
  | "archive"
  | "other";
export type Title2 = string;
export type Whyitmatters = string | null;
export type Analysis = string | null;
export type Sources = string[];
export type Ruleids = string[];
export type Installtime1 = boolean;
export type Startline = number;
export type Endline2 = number;
export type Highlightstart = number;
export type Highlightend = number;
export type Number = number;
export type Text = string;
export type Highlighted = boolean;
export type Clipped = boolean;
export type Lines = ExcerptLine[];
export type Codeissues = CodeIssue[];
export type Version1 = string;
export type SandboxStatus = "COMPLETE" | "PARTIAL" | "SKIPPED" | "FAILED" | "NOT_RUN";
export type Skipreason = string | null;
export type Durationseconds2 = number;
export type Rawtraces3Key = string | null;
export type Installed = boolean;
export type Installscriptsran = boolean;
export type Entryloaded = boolean | null;
export type Entryerror = string | null;
export type Binsrun = number;
export type Timedout = boolean;
export type Dependenciesstripped = boolean;
export type Dependenciesprovided = boolean;
export type Dependenciescount = number;
export type Dependenciesnote = string | null;
export type Name1 = string;
export type Ci = boolean;
export type Clockoffsetdays = number;
export type Hostname = string;
export type User = string;
export type Name2 = string;
export type Exitcode = number | null;
export type Timedout1 = boolean;
export type Seconds1 = number;
export type Cpuseconds = number;
export type Phases = SandboxPhaseResult[];
export type Notes = string[];
export type Runs = SandboxRunSummary[];
export type Run = string;
export type NetworkKind = "dns" | "connect" | "http" | "tcp" | "udp";
export type NetworkClass =
  "expected" | "unexpected" | "oast" | "webhook" | "paste" | "tunnel" | "metadata" | "stratum" | "raw_ip";
export type Host = string | null;
export type Ip = string | null;
export type Port = number | null;
export type Method = string | null;
export type Url = string | null;
export type Bodypreview = string | null;
export type Canaryhit = boolean;
export type Phase = string | null;
export type Count = number;
export type Network1 = SandboxNetworkEvent[];
export type Run1 = string;
export type Pid = number;
export type Ppid = number | null;
export type Exe = string;
export type Argv = string[];
export type Phase1 = string | null;
export type Processes = SandboxProcess[];
export type Run2 = string;
export type Op = string;
export type Path2 = string;
export type Decoy = boolean;
export type Category = string | null;
export type Executable = boolean;
export type Sha2561 = string | null;
export type Preview = string | null;
export type Phase2 = string | null;
export type Files2 = SandboxFileEvent[];
export type Run3 = string;
export type Api = string;
export type Length = number;
export type Sha2562 = string;
export type Preview1 = string;
export type Phase3 = string | null;
export type Evalpayloads = SandboxEval[];
export type Canaryid = string;
export type Decoypath = string | null;
export type Sink1 = string;
export type Run4 = string;
export type Canaryhits = CanaryHit[];
export type Description1 = string;
export type Onlyinrun = string;
export type Conditional = ConditionalBehavior[];
export type Peakcpuseconds = number;
export type Peakmemorymb = number;
export type Timedoutphases = string[];
export type Findings1 = Finding[];
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
  behavior?: BehaviorProfile | null;
  iocs?: Iocs;
  fileHashes?: Filehashes;
  fileHashesTruncated?: Filehashestruncated;
  settings?: ScanSettings | null;
  timings?: StageTimings | null;
  reviewFlags?: ReviewFlags | null;
  codeIssues?: Codeissues;
  sandbox?: SandboxReport | null;
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
  coverage?: AuditCoverage | null;
  trace?: Trace;
  workerReports?: Workerreports;
  cost?: AICost | null;
}
export interface AIEvidence {
  file: File1;
  line?: Line1;
  endLine?: Endline;
  title?: Title1;
  /**
   * Set only for real problems; leave empty for context explaining why code is fine
   */
  severity?: Severity | null;
  explanation: Explanation;
}
export interface FindingAssessment {
  ruleId: Ruleid1;
  file?: File2;
  assessment: Assessment;
  explanation: Explanation1;
}
/**
 * How much of the package a full audit actually read.
 */
export interface AuditCoverage {
  filesTotal: Filestotal;
  filesAnalyzed: Filesanalyzed;
  bytesTotal: Bytestotal;
  bytesAnalyzed: Bytesanalyzed;
  duplicatesSkipped?: Duplicatesskipped;
  chunks: Chunks;
  chunksFailed?: Chunksfailed;
  workerModel: Workermodel;
  skippedFiles?: Skippedfiles;
}
export interface SkippedFile {
  path: Path;
  reason: Reason;
}
/**
 * One step of the agent's investigation. Arguments only; file contents are never stored.
 */
export interface ToolCall {
  step: Step;
  tool: Tool;
  arguments: Arguments;
  outcome: Outcome;
  resultChars: Resultchars;
  seconds: Seconds;
}
export interface Arguments {
  [k: string]: string | number;
}
export interface WorkerPartReport {
  part: Part;
  files: Files;
  report?: WorkerReport | null;
  error?: Error;
  inputTokens?: Inputtokens1;
  outputTokens?: Outputtokens1;
  durationSeconds?: Durationseconds1;
}
/**
 * What one full-audit worker returns for one part of the code.
 */
export interface WorkerReport {
  summary: Summary1;
  capabilities: Capabilities;
  suspiciousItems?: Suspiciousitems;
  dataFlows?: Dataflows;
  externalEndpoints?: Externalendpoints;
  envVars?: Envvars;
  assessment: WorkerAssessment;
}
export interface WorkerItem {
  file: File3;
  line?: Line2;
  endLine?: Endline1;
  behavior: Behavior;
  severity: Severity;
  explanation: Explanation2;
}
export interface DataFlow {
  source: Source;
  sink: Sink;
  file: File4;
  line?: Line3;
  description: Description;
}
export interface AICost {
  coordinatorInputTokens?: Coordinatorinputtokens;
  coordinatorOutputTokens?: Coordinatoroutputtokens;
  coordinatorSeconds?: Coordinatorseconds;
  workerInputTokens?: Workerinputtokens;
  workerOutputTokens?: Workeroutputtokens;
  workerCalls?: Workercalls;
  workerSeconds?: Workerseconds;
}
/**
 * What the package's code can do, from deterministic rules. Stable across runs, so versions can be compared.
 */
export interface BehaviorProfile {
  networkModules?: Networkmodules;
  hosts?: Hosts;
  ipAddresses?: Ipaddresses;
  envVars?: Envvars1;
  readsAllEnv?: Readsallenv;
  sensitivePaths?: Sensitivepaths;
  runsCommands?: Runscommands;
  dynamicCode?: Dynamiccode;
  decodesData?: Decodesdata;
  readsMachineInfo?: Readsmachineinfo;
  nativeExecutables?: Nativeexecutables;
  installTime?: InstallTimeBehavior;
  filesByCapability?: Filesbycapability;
}
export interface InstallTimeBehavior {
  network?: Network;
  commands?: Commands;
  files?: Files1;
}
export interface Filesbycapability {
  [k: string]: string[];
}
/**
 * Indicator of compromise: something an attacker controls (a collection URL, webhook, IP).
 */
export interface Indicator {
  type: IndicatorType;
  value: Value;
  file?: File5;
  line?: Line4;
  source: Source1;
}
export interface FileHash {
  path: Path1;
  size: Size;
  sha256: Sha256;
}
/**
 * Everything that affects results, so we know which scans to redo after changing rules, prompts or models.
 */
export interface ScanSettings {
  analyzerVersion: Analyzerversion1;
  rulesHash: Ruleshash;
  promptHashes?: Prompthashes;
  ai?: Ai;
  settingsHash: Settingshash;
}
export interface Prompthashes {
  [k: string]: string;
}
export interface Ai {
  [k: string]: unknown;
}
export interface StageTimings {
  downloadSeconds?: Downloadseconds;
  unpackSeconds?: Unpackseconds;
  intelSeconds?: Intelseconds;
  metadataSeconds?: Metadataseconds;
  codeScanSeconds?: Codescanseconds;
  sandboxSeconds?: Sandboxseconds;
  aiSeconds?: Aiseconds;
  totalSeconds?: Totalseconds;
}
/**
 * Signals that a human should look at this result.
 */
export interface ReviewFlags {
  rulesAiDisagree?: Rulesaidisagree;
  workerCoordinatorDisagree?: Workercoordinatordisagree;
  promptInjectionDetected?: Promptinjectiondetected;
  lowCoverage?: Lowcoverage;
  aiFailed?: Aifailed;
  needsHumanReview?: Needshumanreview;
  reasons?: Reasons;
}
/**
 * One problem at an exact place in the code, merged from rules and AI. Built for the report page.
 */
export interface CodeIssue {
  id: Id;
  file: File6;
  lineStart?: Linestart;
  lineEnd?: Lineend;
  severity: Severity;
  category: IssueCategory;
  title: Title2;
  whyItMatters?: Whyitmatters;
  analysis?: Analysis;
  sources?: Sources;
  ruleIds?: Ruleids;
  aiAssessment?: Assessment | null;
  installTime?: Installtime1;
  excerpt?: CodeExcerpt | null;
}
/**
 * Real lines copied from the package file (never from model output), with context around the issue.
 */
export interface CodeExcerpt {
  startLine: Startline;
  endLine: Endline2;
  highlightStart: Highlightstart;
  highlightEnd: Highlightend;
  lines: Lines;
}
export interface ExcerptLine {
  number: Number;
  text: Text;
  highlighted?: Highlighted;
  clipped?: Clipped;
}
/**
 * What the package did when it was actually run in the locked-down sandbox (see SANDBOX.md).
 */
export interface SandboxReport {
  version: Version1;
  status: SandboxStatus;
  skipReason?: Skipreason;
  durationSeconds?: Durationseconds2;
  rawTraceS3Key?: Rawtraces3Key;
  coverage?: SandboxCoverage;
  runs?: Runs;
  network?: Network1;
  processes?: Processes;
  files?: Files2;
  evalPayloads?: Evalpayloads;
  canaryHits?: Canaryhits;
  conditional?: Conditional;
  resources?: SandboxResources;
  findings?: Findings1;
}
/**
 * What was actually observed. A quiet sandbox result means little if nothing loaded.
 */
export interface SandboxCoverage {
  installed?: Installed;
  installScriptsRan?: Installscriptsran;
  entryLoaded?: Entryloaded;
  entryError?: Entryerror;
  binsRun?: Binsrun;
  timedOut?: Timedout;
  dependenciesStripped?: Dependenciesstripped;
  dependenciesProvided?: Dependenciesprovided;
  dependenciesCount?: Dependenciescount;
  dependenciesNote?: Dependenciesnote;
}
export interface SandboxRunSummary {
  name: Name1;
  ci?: Ci;
  clockOffsetDays?: Clockoffsetdays;
  hostname?: Hostname;
  user?: User;
  phases?: Phases;
  notes?: Notes;
}
export interface SandboxPhaseResult {
  name: Name2;
  exitCode?: Exitcode;
  timedOut?: Timedout1;
  seconds?: Seconds1;
  cpuSeconds?: Cpuseconds;
}
export interface SandboxNetworkEvent {
  run: Run;
  kind: NetworkKind;
  classification: NetworkClass;
  host?: Host;
  ip?: Ip;
  port?: Port;
  method?: Method;
  url?: Url;
  bodyPreview?: Bodypreview;
  canaryHit?: Canaryhit;
  phase?: Phase;
  count?: Count;
}
export interface SandboxProcess {
  run: Run1;
  pid: Pid;
  ppid?: Ppid;
  exe: Exe;
  argv?: Argv;
  phase?: Phase1;
}
export interface SandboxFileEvent {
  run: Run2;
  op: Op;
  path: Path2;
  decoy?: Decoy;
  category?: Category;
  executable?: Executable;
  sha256?: Sha2561;
  preview?: Preview;
  phase?: Phase2;
}
export interface SandboxEval {
  run: Run3;
  api: Api;
  length: Length;
  sha256: Sha2562;
  preview: Preview1;
  phase?: Phase3;
}
/**
 * A planted fake credential found leaving the sandbox: proof of exfiltration, not a guess.
 */
export interface CanaryHit {
  canaryId: Canaryid;
  decoyPath?: Decoypath;
  sink: Sink1;
  run: Run4;
}
export interface ConditionalBehavior {
  description: Description1;
  onlyInRun: Onlyinrun;
}
export interface SandboxResources {
  peakCpuSeconds?: Peakcpuseconds;
  peakMemoryMb?: Peakmemorymb;
  timedOutPhases?: Timedoutphases;
}
