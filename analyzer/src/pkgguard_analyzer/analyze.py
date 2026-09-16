"""Scans one package version end to end. The same code runs locally and on AWS."""

import hashlib
import json
import shutil
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from ulid import ULID

from pkgguard_analyzer import ANALYZER_VERSION
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
    ScanStatus,
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
) -> ScanResult:
    if not NPM_NAME_RE.fullmatch(name):
        raise ValueError(f"invalid npm package name: {name!r}")
    owns_client = client is None
    client = client or make_client()
    try:
        return _analyze(client, name, version, out_dir, ran_on, now or datetime.now(UTC))
    finally:
        if owns_client:
            client.close()


def _analyze(
    client: httpx.Client, name: str, version: str | None, out_dir: Path, ran_on: RanOn, now: datetime
) -> ScanResult:
    packument = fetch_packument(client, name)
    resolved = resolve_version(packument, version)
    package = PackageRef(ecosystem=Ecosystem.NPM, name=name, version=resolved)
    scan_dir = out_dir / name / resolved

    dist = packument["versions"][resolved].get("dist", {})
    base = {
        "package": package,
        "scan_id": str(ULID()),
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

    intel = run_intel(client, name, resolved)
    metadata, metadata_findings = check_metadata(
        packument, resolved, _read_manifest(files_dir / "package.json"), extracted.skipped, now
    )
    findings = intel.findings + metadata_findings
    decision = decide(findings)
    analyzed_at = datetime.now(UTC)

    report = Report(
        package=package,
        analyzer_version=ANALYZER_VERSION,
        generated_at=analyzed_at,
        findings=findings,
        intel=intel.summary,
        metadata={
            **metadata,
            "sha256": sha256,
            "fileCount": extracted.file_count,
            "unpackedBytes": extracted.unpacked_bytes,
        },
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
    )
    return ScanResult(record, report, scan_dir)


def _read_manifest(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None
