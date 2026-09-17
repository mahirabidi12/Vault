"""Shared data contract. JSON uses camelCase; exported to /schema for TypeScript."""

import re
from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

# npm package names, including scoped ones like @babel/core
NPM_NAME_RE = re.compile(r"^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$")
# Exact semver only. Ranges and tags like "latest" must be resolved before lookup.
EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


class Model(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


class Ecosystem(StrEnum):
    NPM = "npm"


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    SCANNING = "SCANNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class Verdict(StrEnum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Severity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DecidedBy(StrEnum):
    INTEL = "intel"
    RULES = "rules"
    AI = "ai"
    HUMAN = "human"


class RanOn(StrEnum):
    LOCAL = "local"
    CLOUD = "cloud"


class RecordSource(StrEnum):
    PKGGUARD = "pkgguard"
    OSV_IMPORT = "osv-import"


class FindingLayer(StrEnum):
    INTEL = "intel"
    METADATA = "metadata"
    STATIC = "static"


class ReviewMode(StrEnum):
    QUICK_LOOK = "quick_look"
    DEEP_DIVE = "deep_dive"
    FULL_AUDIT = "full_audit"


class Assessment(StrEnum):
    BENIGN = "benign"
    MALICIOUS = "malicious"
    UNCERTAIN = "uncertain"


class PackageRef(Model):
    ecosystem: Ecosystem
    name: str = Field(max_length=214)
    version: str

    @field_validator("name")
    @classmethod
    def valid_name(cls, v: str) -> str:
        if not NPM_NAME_RE.fullmatch(v):
            raise ValueError(f"invalid npm package name: {v!r}")
        return v

    @field_validator("version")
    @classmethod
    def exact_version(cls, v: str) -> str:
        if not EXACT_VERSION_RE.fullmatch(v):
            raise ValueError(f"version must be exact (e.g. 1.2.3), got {v!r}")
        return v


class Finding(Model):
    rule_id: str
    layer: FindingLayer
    severity: Severity
    confidence: Confidence
    title: str
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    snippet: str | None = None
    install_time: bool = False
    occurrences: int = Field(default=1, ge=1)


class AIEvidence(Model):
    file: str
    line: int | None = Field(default=None, ge=1, description="First line number, exactly as shown in the numbered code")
    end_line: int | None = Field(default=None, ge=1, description="Last line number of the relevant code (same as line for one line)")
    title: str | None = Field(default=None, description="Short label, e.g. 'Sends NPM_TOKEN to remote server'")
    severity: Severity | None = Field(default=None, description="Set only for real problems; leave empty for context explaining why code is fine")
    explanation: str


class FindingAssessment(Model):
    rule_id: str
    file: str | None = None
    assessment: Assessment
    explanation: str


class AIVerdict(Model):
    """What the AI reviewer returns."""

    verdict: Verdict
    confidence: Confidence
    summary: str = Field(description="One or two plain sentences for developers")
    reasoning: str = Field(description="A few short paragraphs explaining what the code does and why")
    evidence: list[AIEvidence] = Field(default_factory=list, description="Only files and lines you actually read")
    finding_assessments: list[FindingAssessment] = Field(default_factory=list)


class SkippedFile(Model):
    path: str
    reason: str


class AuditCoverage(Model):
    """How much of the package a full audit actually read."""

    files_total: int
    files_analyzed: int
    bytes_total: int
    bytes_analyzed: int
    duplicates_skipped: int = 0
    chunks: int
    chunks_failed: int = 0
    worker_model: str
    skipped_files: list[SkippedFile] = Field(default_factory=list)


class WorkerItem(Model):
    file: str
    line: int | None = Field(default=None, description="First line number, exactly as shown in the numbered code")
    end_line: int | None = Field(default=None, description="Last line number of the relevant code")
    behavior: str = Field(description="Short label, e.g. 'reads NPM_TOKEN', 'spawns shell', 'decodes base64 and evals'")
    severity: Severity
    explanation: str


class DataFlow(Model):
    source: str = Field(description="Where data comes from, e.g. 'process.env.NPM_TOKEN', '~/.npmrc', 'os.hostname()'")
    sink: str = Field(description="Where it goes, e.g. 'HTTPS request to https://api.example.com/collect', 'eval', 'child_process'")
    file: str
    line: int | None = None
    description: str


class WorkerAssessment(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class WorkerReport(Model):
    """What one full-audit worker returns for one part of the code."""

    summary: str = Field(description="Two or three sentences: what this code does")
    capabilities: list[str] = Field(
        description="Any of: network, exec, dynamic_code, env_access, sensitive_files, obfuscation, crypto, filesystem_write, none"
    )
    suspicious_items: list[WorkerItem] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    external_endpoints: list[str] = Field(default_factory=list, description="Full URLs, hosts or IPs the code contacts")
    env_vars: list[str] = Field(default_factory=list, description="Names of environment variables read (names only, never values)")
    assessment: WorkerAssessment


class WorkerPartReport(Model):
    part: int
    files: list[str]
    report: WorkerReport | None = None
    error: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    duration_seconds: float = 0.0


class ToolCall(Model):
    """One step of the agent's investigation. Arguments only; file contents are never stored."""

    step: int
    tool: str
    arguments: dict[str, str | int]
    outcome: str  # ok | empty | not_found | binary | budget_exhausted
    result_chars: int
    seconds: float


class AICost(Model):
    coordinator_input_tokens: int = 0
    coordinator_output_tokens: int = 0
    coordinator_seconds: float = 0.0
    worker_input_tokens: int = 0
    worker_output_tokens: int = 0
    worker_calls: int = 0
    worker_seconds: float = 0.0


class AIReview(AIVerdict):
    """AI verdict plus facts recorded by PkgGuard (never taken from the model's own claims)."""

    model: str
    mode: ReviewMode
    files_read: list[str] = Field(default_factory=list)
    tool_calls: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    duration_seconds: float
    coverage: AuditCoverage | None = None
    trace: list[ToolCall] = Field(default_factory=list)
    worker_reports: list[WorkerPartReport] = Field(default_factory=list)
    cost: AICost | None = None


class IndicatorType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    WEBHOOK = "webhook"


class Indicator(Model):
    """Indicator of compromise: something an attacker controls (a collection URL, webhook, IP)."""

    type: IndicatorType
    value: str
    file: str | None = None
    line: int | None = None
    source: str  # rules | ai


class FileHash(Model):
    path: str
    size: int
    sha256: str


class InstallTimeBehavior(Model):
    network: bool = False
    commands: bool = False
    files: list[str] = Field(default_factory=list)


class BehaviorProfile(Model):
    """What the package's code can do, from deterministic rules. Stable across runs, so versions can be compared."""

    network_modules: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    ip_addresses: list[str] = Field(default_factory=list)
    env_vars: list[str] = Field(default_factory=list)
    reads_all_env: bool = False
    sensitive_paths: list[str] = Field(default_factory=list)
    runs_commands: bool = False
    dynamic_code: bool = False
    decodes_data: bool = False
    reads_machine_info: bool = False
    native_executables: list[str] = Field(default_factory=list)
    install_time: InstallTimeBehavior = Field(default_factory=InstallTimeBehavior)
    files_by_capability: dict[str, list[str]] = Field(default_factory=dict)


class ScanSettings(Model):
    """Everything that affects results, so we know which scans to redo after changing rules, prompts or models."""

    analyzer_version: str
    rules_hash: str
    prompt_hashes: dict[str, str] = Field(default_factory=dict)
    ai: dict[str, Any] = Field(default_factory=dict)
    settings_hash: str


class StageTimings(Model):
    download_seconds: float = 0.0
    unpack_seconds: float = 0.0
    intel_seconds: float = 0.0
    metadata_seconds: float = 0.0
    code_scan_seconds: float = 0.0
    ai_seconds: float = 0.0
    total_seconds: float = 0.0


class ReviewFlags(Model):
    """Signals that a human should look at this result."""

    rules_ai_disagree: bool = False
    worker_coordinator_disagree: bool = False
    prompt_injection_detected: bool = False
    low_coverage: bool = False
    ai_failed: bool = False
    needs_human_review: bool = False
    reasons: list[str] = Field(default_factory=list)


class IssueCategory(StrEnum):
    SECRET_THEFT = "secret_theft"
    NETWORK = "network"
    COMMANDS = "commands"
    HIDDEN_CODE = "hidden_code"
    SECRETS_ACCESS = "secrets_access"
    INSTALL_SCRIPT = "install_script"
    PROMPT_INJECTION = "prompt_injection"
    MINING = "mining"
    REMOTE_CONTROL = "remote_control"
    BINARY = "binary"
    ARCHIVE = "archive"
    OTHER = "other"


class ExcerptLine(Model):
    number: int
    text: str
    highlighted: bool = False
    clipped: bool = False  # long (e.g. minified) line cut down around the relevant spot


class CodeExcerpt(Model):
    """Real lines copied from the package file (never from model output), with context around the issue."""

    start_line: int
    end_line: int
    highlight_start: int
    highlight_end: int
    lines: list[ExcerptLine]


class CodeIssue(Model):
    """One problem at an exact place in the code, merged from rules and AI. Built for the report page."""

    id: str
    file: str
    line_start: int | None = None
    line_end: int | None = None
    severity: Severity
    category: IssueCategory
    title: str
    why_it_matters: str | None = None
    analysis: str | None = None  # what the AI saw in this specific code
    sources: list[str] = Field(default_factory=list)  # rules | ai | ai-worker
    rule_ids: list[str] = Field(default_factory=list)
    ai_assessment: Assessment | None = None  # the AI's judgment of a rule finding
    install_time: bool = False
    excerpt: CodeExcerpt | None = None


class VerdictRecord(Model):
    """Summary stored in DynamoDB and returned by the API."""

    package: PackageRef
    status: ScanStatus
    scan_id: str = Field(min_length=1)
    verdict: Verdict | None = None
    confidence: Confidence | None = None
    decided_by: DecidedBy | None = None
    summary: str | None = None
    signals: list[str] = Field(default_factory=list)
    sha256: str | None = None
    integrity: str | None = None
    tarball_url: str | None = None
    published_at: AwareDatetime | None = None
    requested_at: AwareDatetime
    analyzed_at: AwareDatetime | None = None
    model: str | None = None
    ran_on: RanOn
    analyzer_version: str
    source: RecordSource = RecordSource.PKGGUARD
    report_s3_key: str | None = None
    ai_failed: bool = False
    failure_reason: str | None = None
    needs_review: bool = False
    ioc_count: int = 0
    settings_hash: str | None = None

    @model_validator(mode="after")
    def fields_match_status(self) -> "VerdictRecord":
        if self.status == ScanStatus.COMPLETE:
            required = ("verdict", "confidence", "decided_by", "summary", "analyzed_at")
            missing = [f for f in required if getattr(self, f) is None]
            if missing:
                raise ValueError(f"COMPLETE record is missing: {', '.join(missing)}")
        elif self.verdict is not None:
            raise ValueError(f"{self.status} record must not have a verdict")
        if self.status in (ScanStatus.FAILED, ScanStatus.SKIPPED) and not self.failure_reason:
            raise ValueError(f"{self.status} record needs a failure_reason")
        return self


class Report(Model):
    """Full report stored in S3. Intel, metadata and code scan sections get typed as those steps settle."""

    package: PackageRef
    analyzer_version: str
    generated_at: AwareDatetime
    findings: list[Finding] = Field(default_factory=list)
    intel: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    code_scan: dict[str, Any] = Field(default_factory=dict)
    ai_review: AIReview | None = None
    ai_error: str | None = None
    behavior: BehaviorProfile | None = None
    iocs: list[Indicator] = Field(default_factory=list)
    file_hashes: list[FileHash] = Field(default_factory=list)
    file_hashes_truncated: bool = False
    settings: ScanSettings | None = None
    timings: StageTimings | None = None
    review_flags: ReviewFlags | None = None
    code_issues: list[CodeIssue] = Field(default_factory=list)
    human_review: dict[str, Any] | None = None
