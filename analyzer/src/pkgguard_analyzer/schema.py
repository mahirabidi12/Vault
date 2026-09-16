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
    """Full report stored in S3. Intel, metadata and AI sections get typed as those steps are built."""

    package: PackageRef
    analyzer_version: str
    generated_at: AwareDatetime
    findings: list[Finding] = Field(default_factory=list)
    intel: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    ai_review: dict[str, Any] | None = None
    human_review: dict[str, Any] | None = None
