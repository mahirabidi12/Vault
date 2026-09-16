"""Red-flag checks on registry metadata and the package manifest. Reads no code and runs nothing."""

from datetime import datetime, timedelta
from functools import cache
from importlib.resources import files
from typing import Any

from pkgguard_analyzer.extract import SkippedEntry
from pkgguard_analyzer.schema import Confidence, Finding, FindingLayer, Severity

INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
FRESH_PUBLISH_WINDOW = timedelta(hours=48)
SUSPICIOUS_MAJOR_VERSION = 99


@cache
def popular_packages() -> frozenset[str]:
    text = files("pkgguard_analyzer").joinpath("data/popular_packages.txt").read_text()
    return frozenset(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))


def levenshtein(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def _squash(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


def typosquat_target(name: str, popular: frozenset[str]) -> str | None:
    """Return the popular package this name imitates, if any."""
    if name in popular:
        return None
    for candidate in sorted(popular):
        if _squash(name) == _squash(candidate):
            return candidate
        if len(name) >= 5 and levenshtein(name, candidate) == 1:
            return candidate
    return None


def install_scripts(manifest: dict) -> dict[str, str]:
    scripts = manifest.get("scripts") or {}
    return {hook: scripts[hook] for hook in INSTALL_SCRIPTS if isinstance(scripts.get(hook), str)}


def parse_time(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def previous_version(packument: dict, version: str) -> str | None:
    times = packument.get("time", {})
    current = parse_time(times.get(version))
    if current is None:
        return None
    earlier = [
        (published, v)
        for v in packument.get("versions", {})
        if v != version and (published := parse_time(times.get(v))) and published < current
    ]
    return max(earlier)[1] if earlier else None


def _finding(rule_id: str, severity: Severity, confidence: Confidence, title: str, **extra: Any) -> Finding:
    return Finding(rule_id=rule_id, layer=FindingLayer.METADATA, severity=severity, confidence=confidence, title=title, **extra)


def check_metadata(
    packument: dict,
    version: str,
    tarball_manifest: dict | None,
    skipped_entries: list[SkippedEntry],
    now: datetime,
    popular: frozenset[str] | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    popular = popular if popular is not None else popular_packages()
    manifest = packument["versions"][version]
    name = packument["name"]
    findings: list[Finding] = []

    scripts = install_scripts(manifest)
    for hook, command in scripts.items():
        findings.append(
            _finding(
                "metadata.install_script",
                Severity.MEDIUM,
                Confidence.HIGH,
                f"Runs a '{hook}' script during install",
                file="package.json",
                snippet=command[:500],
            )
        )

    if tarball_manifest is None:
        findings.append(_finding("metadata.missing_package_json", Severity.MEDIUM, Confidence.HIGH, "Tarball has no readable package.json"))
    elif install_scripts(tarball_manifest) != scripts:
        findings.append(
            _finding(
                "metadata.manifest_mismatch",
                Severity.HIGH,
                Confidence.HIGH,
                "Install scripts in the tarball differ from the registry metadata",
                file="package.json",
            )
        )

    published_at = parse_time(packument.get("time", {}).get(version))
    if published_at and now - published_at < FRESH_PUBLISH_WINDOW:
        findings.append(_finding("metadata.fresh_publish", Severity.MEDIUM, Confidence.HIGH, "Published less than 48 hours ago"))

    if target := typosquat_target(name, popular):
        findings.append(
            _finding("metadata.typosquat", Severity.MEDIUM, Confidence.MEDIUM, f"Name is very similar to popular package '{target}'")
        )

    if int(version.split(".")[0]) >= SUSPICIOUS_MAJOR_VERSION:
        findings.append(
            _finding(
                "metadata.high_version",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "Unusually high version number (dependency confusion pattern)",
            )
        )

    npm_user = manifest.get("_npmUser") or {}
    publisher = npm_user.get("name")
    trusted = bool(npm_user.get("trustedPublisher"))
    previous = previous_version(packument, version)
    previous_manifest = packument["versions"][previous] if previous else {}
    previous_trusted = bool((previous_manifest.get("_npmUser") or {}).get("trustedPublisher"))

    if previous_trusted and not trusted:
        findings.append(
            _finding(
                "metadata.trusted_publishing_dropped",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                f"Previous version ({previous}) was published from CI with trusted publishing, but this one was not",
            )
        )

    # Trusted publishing (verified CI identity like "GitHub Actions") is not a new person.
    if previous and publisher and not trusted:
        previous_maintainers = {m.get("name") for m in previous_manifest.get("maintainers", []) if isinstance(m, dict)}
        previous_maintainers.add((previous_manifest.get("_npmUser") or {}).get("name"))
        if previous_maintainers - {None} and publisher not in previous_maintainers:
            findings.append(
                _finding(
                    "metadata.new_publisher",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    f"Published by '{publisher}', who was not a maintainer of the previous version ({previous})",
                )
            )

    repository = manifest.get("repository")
    repository_url = repository.get("url") if isinstance(repository, dict) else repository
    if not repository_url:
        findings.append(_finding("metadata.no_repository", Severity.LOW, Confidence.HIGH, "No source repository linked"))

    for entry in skipped_entries:
        findings.append(
            _finding(
                f"archive.{entry.reason}",
                Severity.HIGH if entry.reason == "path_traversal" else Severity.MEDIUM,
                Confidence.HIGH,
                f"Tarball contains an unsafe entry ({entry.reason.replace('_', ' ')})",
                file=entry.path,
            )
        )

    metadata = {
        "description": manifest.get("description"),
        "license": manifest.get("license") if isinstance(manifest.get("license"), str) else None,
        "publisher": publisher,
        "trustedPublishing": trusted,
        "provenance": bool((manifest.get("dist") or {}).get("attestations")),
        "maintainers": [m.get("name") for m in manifest.get("maintainers", []) if isinstance(m, dict)],
        "publishedAt": published_at.isoformat() if published_at else None,
        "previousVersion": previous,
        "installScripts": scripts,
        "repository": repository_url,
        "dependencies": manifest.get("dependencies") or {},
    }
    return metadata, findings
