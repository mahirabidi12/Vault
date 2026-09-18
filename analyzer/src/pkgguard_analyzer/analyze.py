"""Scans one package version end to end. The same code runs locally and on AWS."""

import hashlib
import json
import shutil
import tarfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from ulid import ULID

from pkgguard_analyzer import ANALYZER_VERSION
from pkgguard_analyzer.ai.config import AIMode
from pkgguard_analyzer.ai.reviewer import Reviewer, review_mode, run_review
from pkgguard_analyzer.code_scan import scan_code
from pkgguard_analyzer.insights import ai_indicators, hash_files, merge_indicators, review_flags, scan_settings
from pkgguard_analyzer.issues import build_code_issues
from pkgguard_analyzer.extract import ArchiveTooLarge, safe_extract
from pkgguard_analyzer.intel import run_intel
from pkgguard_analyzer.metadata_checks import check_metadata, parse_time
from pkgguard_analyzer.npm_registry import (
    IntegrityError,
    TarballTooLarge,
    download_tarball,
    fetch_packument,
    resolve_version,
    verify_integrity,
)
from pkgguard_analyzer.schema import (
    NPM_NAME_RE,
    Ecosystem,
    PackageRef,
    RanOn,
    Report,
    SandboxReport,
    SandboxStatus,
    ScanStatus,
    StageTimings,
    VerdictRecord,
)
from pkgguard_analyzer.scoring import decide, signals


@dataclass
class ScanResult:
    record: VerdictRecord
    report: Report | None
    scan_dir: Path


def make_client() -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(30.0),
        follow_redirects=True,
        headers={"User-Agent": f"pkgguard-analyzer/{ANALYZER_VERSION}"},
    )


def parse_spec(spec: str) -> tuple[str, str | None]:
    """Split "name@version" (scoped names start with "@", so look for a later one)."""
    at = spec.rfind("@")
    if at > 0:
        return spec[:at], spec[at + 1 :] or None
    return spec, None


def analyze(
    name: str,
    version: str | None = None,
    *,
    out_dir: Path,
    ran_on: RanOn = RanOn.LOCAL,
    client: httpx.Client | None = None,
    now: datetime | None = None,
    reviewer: Reviewer | None = None,
    ai_mode: AIMode = AIMode.OFF,
    scan_id: str | None = None,
    auditor=None,
    sandbox_runner: Callable[[bytes], SandboxReport] | None = None,
) -> ScanResult:
    """auditor: optional FullAuditor. When given, it replaces the quick look / deep dive with a full-package audit.
    sandbox_runner: runs the verified tarball in the isolated sandbox and returns its report. Only the AWS
    sandbox is meant to be plugged in here; real packages are never run on a developer machine."""
    if not NPM_NAME_RE.fullmatch(name):
        raise ValueError(f"invalid npm package name: {name!r}")
    owns_client = client is None
    client = client or make_client()
    try:
        return _analyze(
            client,
            name,
            version,
            out_dir,
            ran_on,
            now or datetime.now(UTC),
            reviewer if ai_mode != AIMode.OFF else None,
            ai_mode,
            scan_id or str(ULID()),
            auditor,
            sandbox_runner,
        )
    finally:
        if owns_client:
            client.close()


def _analyze(
    client: httpx.Client,
    name: str,
    version: str | None,
    out_dir: Path,
    ran_on: RanOn,
    now: datetime,
    reviewer: Reviewer | None,
    ai_mode: AIMode,
    scan_id: str,
    auditor,
    sandbox_runner: Callable[[bytes], SandboxReport] | None = None,
) -> ScanResult:
    started = time.monotonic()
    timings = StageTimings()

    def lap(field: str, since: float) -> float:
        now = time.monotonic()
        setattr(timings, field, round(now - since, 3))
        return now

    packument = fetch_packument(client, name)
    resolved = resolve_version(packument, version)
    package = PackageRef(ecosystem=Ecosystem.NPM, name=name, version=resolved)
    scan_dir = out_dir / name / resolved

    dist = packument["versions"][resolved].get("dist", {})
    base = {
        "package": package,
        "scan_id": scan_id,
        "requested_at": now,
        "ran_on": ran_on,
        "analyzer_version": ANALYZER_VERSION,
        "integrity": dist.get("integrity"),
        "tarball_url": dist.get("tarball"),
        "published_at": parse_time(packument.get("time", {}).get(resolved)),
    }

    def stopped(status: ScanStatus, reason: str, **extra) -> ScanResult:
        return ScanResult(VerdictRecord(**base, **extra, status=status, failure_reason=reason), None, scan_dir)

    if not dist.get("tarball"):
        return stopped(ScanStatus.FAILED, "registry metadata has no tarball URL")
    try:
        tarball = download_tarball(client, dist["tarball"])
        verify_integrity(tarball, dist.get("integrity"), dist.get("shasum"))
    except TarballTooLarge as error:
        return stopped(ScanStatus.SKIPPED, str(error))
    except (IntegrityError, httpx.HTTPError) as error:
        return stopped(ScanStatus.FAILED, str(error))

    mark = lap("download_seconds", started)
    sha256 = hashlib.sha256(tarball).hexdigest()
    files_dir = scan_dir / "files"
    if files_dir.exists():
        shutil.rmtree(files_dir)
    try:
        extracted = safe_extract(tarball, files_dir)
    except ArchiveTooLarge as error:
        return stopped(ScanStatus.SKIPPED, str(error), sha256=sha256)
    except (tarfile.TarError, EOFError, OSError) as error:
        return stopped(ScanStatus.FAILED, f"could not unpack tarball: {error}", sha256=sha256)

    file_hashes, hashes_truncated = hash_files(files_dir)
    mark = lap("unpack_seconds", mark)
    tarball_manifest = _read_manifest(files_dir / "package.json")
    intel = run_intel(client, name, resolved)
    mark = lap("intel_seconds", mark)
    metadata, metadata_findings = check_metadata(packument, resolved, tarball_manifest, extracted.skipped, now)
    mark = lap("metadata_seconds", mark)
    # The tarball's package.json is what npm actually runs; fall back to registry metadata if it's missing.
    code = scan_code(files_dir, tarball_manifest or packument["versions"][resolved])
    mark = lap("code_scan_seconds", mark)
    sandbox_report: SandboxReport | None = None
    if sandbox_runner is not None:
        try:
            sandbox_report = sandbox_runner(tarball)
        except Exception as error:  # a sandbox failure must never fail the whole scan
            sandbox_report = SandboxReport(version="0", status=SandboxStatus.FAILED, skip_reason=str(error)[:300])
        mark = lap("sandbox_seconds", mark)
    findings = intel.findings + metadata_findings + code.findings + (sandbox_report.findings if sandbox_report else [])
    report = Report(
        package=package,
        analyzer_version=ANALYZER_VERSION,
        generated_at=datetime.now(UTC),
        findings=findings,
        intel=intel.summary,
        metadata={
            **metadata,
            "sha256": sha256,
            "fileCount": extracted.file_count,
            "unpackedBytes": extracted.unpacked_bytes,
        },
        code_scan=code.summary,
        behavior=code.behavior,
        sandbox=sandbox_report,
        file_hashes=file_hashes,
        file_hashes_truncated=hashes_truncated,
    )

    ai_review, ai_error = None, None
    if auditor is not None:
        ai_review, ai_error = auditor.audit(files_dir, report)
    elif reviewer is not None and (mode := review_mode(findings, ai_mode)):
        ai_review, ai_error = run_review(files_dir, report, reviewer, mode)
    ai_model = (auditor or reviewer).model_id if (ai_review or ai_error) else None

    lap("ai_seconds", mark)

    decision = decide(findings, ai_review)
    flags = review_flags(findings, decide(findings), decision, ai_review, ai_error)
    indicators = merge_indicators(code.indicators or [], ai_indicators(ai_review))
    settings = scan_settings(ai_mode, reviewer, auditor)
    timings.total_seconds = round(time.monotonic() - started, 3)
    analyzed_at = datetime.now(UTC)
    report = report.model_copy(
        update={
            "generated_at": analyzed_at,
            "ai_review": ai_review,
            "ai_error": ai_error,
            "iocs": indicators,
            "settings": settings,
            "timings": timings,
            "review_flags": flags,
            "code_issues": build_code_issues(files_dir, findings, ai_review, code.summary.get("installTimeFiles")),
        }
    )
    record = VerdictRecord(
        **base,
        status=ScanStatus.COMPLETE,
        verdict=decision.verdict,
        confidence=decision.confidence,
        decided_by=decision.decided_by,
        summary=decision.summary,
        signals=signals(findings),
        sha256=sha256,
        analyzed_at=analyzed_at,
        model=ai_model,
        ai_failed=ai_error is not None,
        needs_review=flags.needs_human_review,
        ioc_count=len(indicators),
        settings_hash=settings.settings_hash,
        sandbox_status=sandbox_report.status if sandbox_report else SandboxStatus.NOT_RUN,
    )
    return ScanResult(record, report, scan_dir)


def _read_manifest(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None
