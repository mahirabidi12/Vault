"""Extra facts stored with every scan: file fingerprints, AI indicators, settings used and review flags."""

import hashlib
import json
import re
from functools import cache
from pathlib import Path

from pkgguard_analyzer import ANALYZER_VERSION
from pkgguard_analyzer.code_scan.behavior import IGNORED_HOSTS, URL_RE, classify, host_of
from pkgguard_analyzer.code_scan.rules import _public_ip
from pkgguard_analyzer.schema import (
    AIReview,
    DecidedBy,
    FileHash,
    Finding,
    Indicator,
    ReviewFlags,
    ScanSettings,
    Severity,
    Verdict,
    WorkerAssessment,
)

MAX_FILE_HASHES = 5_000
LOW_COVERAGE_RATIO = 0.8
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?$")
NOT_HOST_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".json", ".node", ".sh", ".md", ".env", ".map", ".lock", ".txt", ".yml", ".yaml", ".npmrc")
PACKAGE_ROOT = Path(__file__).parent
RULE_FILES = (
    "code_scan/rules/patterns.yar",
    "code_scan/rules.py",
    "code_scan/js_facts.py",
    "code_scan/files.py",
    "metadata_checks.py",
    "scoring.py",
    "data/popular_packages.txt",
)


def hash_files(files_dir: Path, limit: int = MAX_FILE_HASHES) -> tuple[list[FileHash], bool]:
    """sha256 of every file, so versions can be diffed and unchanged files recognized later."""
    paths = sorted(p for p in files_dir.rglob("*") if p.is_file())
    hashes = [
        FileHash(path=p.relative_to(files_dir).as_posix(), size=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest())
        for p in paths[:limit]
    ]
    return hashes, len(paths) > limit


def _short_hash(text: str | bytes) -> str:
    return hashlib.sha256(text if isinstance(text, bytes) else text.encode()).hexdigest()[:12]


@cache
def rules_hash() -> str:
    return _short_hash(b"".join((PACKAGE_ROOT / name).read_bytes() for name in RULE_FILES))


@cache
def prompt_hashes() -> dict[str, str]:
    from pkgguard_analyzer.ai.audit.prompts import COORDINATOR_SYSTEM_PROMPT, WORKER_SYSTEM_PROMPT
    from pkgguard_analyzer.ai.prompts import SYSTEM_PROMPT

    return {"reviewer": _short_hash(SYSTEM_PROMPT), "worker": _short_hash(WORKER_SYSTEM_PROMPT), "coordinator": _short_hash(COORDINATOR_SYSTEM_PROMPT)}


def scan_settings(ai_mode: str, reviewer=None, auditor=None) -> ScanSettings:
    ai: dict = {"mode": "off"}
    if auditor is not None:
        ai = {"mode": "full_audit", **getattr(auditor, "settings", {})}
    elif reviewer is not None and ai_mode != "off":
        ai = {"mode": str(ai_mode), **getattr(reviewer, "settings", {})}
    prompts = prompt_hashes() if ai["mode"] != "off" else {}
    fingerprint = json.dumps({"analyzer": ANALYZER_VERSION, "rules": rules_hash(), "prompts": prompts, "ai": ai}, sort_keys=True, default=str)
    return ScanSettings(analyzer_version=ANALYZER_VERSION, rules_hash=rules_hash(), prompt_hashes=prompts, ai=ai, settings_hash=_short_hash(fingerprint))


def _values_in_text(text: str) -> list[str]:
    urls = [url.rstrip(".,;:") for url in URL_RE.findall(text)]
    ips = [ip for ip in IP_RE.findall(text) if _public_ip(ip)]
    return urls + ips


def _endpoint_values(endpoint: str) -> list[str]:
    value = endpoint.strip().rstrip(".,;")
    lowered = value.lower()
    if URL_RE.fullmatch(value):
        return [value]
    if _public_ip(lowered.split(":")[0]):
        return [value]
    if HOST_RE.fullmatch(lowered) and not lowered.endswith(NOT_HOST_SUFFIXES):
        return [value]
    return []


def ai_indicators(review: AIReview | None) -> list[Indicator]:
    """Indicators the AI tied to suspicious behavior (worker data flows, suspicious items, non-benign endpoints, evidence)."""
    if review is None:
        return []
    found: dict[tuple[str, str], Indicator] = {}

    def add(value: str, file: str | None, line: int | None) -> None:
        host = host_of(value) if value.lower().startswith("http") else value.lower().split(":")[0]
        if host in IGNORED_HOSTS:
            return
        kind = classify(value)
        found.setdefault((kind.value, value), Indicator(type=kind, value=value, file=file, line=line, source="ai"))

    for part in review.worker_reports:
        report = part.report
        if report is None:
            continue
        for flow in report.data_flows:
            for value in _values_in_text(f"{flow.sink} {flow.description}"):
                add(value, flow.file, flow.line)
        for item in report.suspicious_items:
            if item.severity != Severity.LOW:
                for value in _values_in_text(f"{item.behavior} {item.explanation}"):
                    add(value, item.file, item.line)
        if report.assessment != WorkerAssessment.BENIGN:
            for endpoint in report.external_endpoints:
                for value in _endpoint_values(endpoint):
                    add(value, None, None)
    if review.verdict != Verdict.SAFE:
        for evidence in review.evidence:
            for value in _values_in_text(evidence.explanation):
                add(value, evidence.file, evidence.line)
    return list(found.values())


def merge_indicators(*groups: list[Indicator]) -> list[Indicator]:
    merged: dict[tuple[str, str], Indicator] = {}
    for group in groups:
        for indicator in group:
            merged.setdefault((indicator.type.value, indicator.value), indicator)
    return list(merged.values())


def review_flags(findings: list[Finding], rules, final, ai: AIReview | None, ai_error: str | None) -> ReviewFlags:
    """rules and final are scoring.Decision objects: the rules-only verdict and the final verdict."""
    flags = ReviewFlags()
    reasons: list[str] = []

    if ai is not None and ai.verdict != rules.verdict:
        flags.rules_ai_disagree = True
        reasons.append(f"Automated rules said {rules.verdict}, AI said {ai.verdict}.")
    if ai is not None and ai.verdict == Verdict.SAFE and any(p.report and p.report.assessment == WorkerAssessment.MALICIOUS for p in ai.worker_reports):
        flags.worker_coordinator_disagree = True
        reasons.append("A worker agent judged part of the code malicious, but the coordinator said SAFE.")
    injection_rule = any(f.rule_id == "code.pattern.llm_prompt_injection" for f in findings)
    injection_ai = ai is not None and any(
        "prompt injection" in f"{item.behavior} {item.explanation}".lower() for p in ai.worker_reports if p.report for item in p.report.suspicious_items
    )
    if injection_rule or injection_ai:
        flags.prompt_injection_detected = True
        reasons.append("Text aimed at AI reviewers (prompt injection) was found.")
    coverage = ai.coverage if ai else None
    if coverage and coverage.bytes_total and coverage.bytes_analyzed / coverage.bytes_total < LOW_COVERAGE_RATIO:
        flags.low_coverage = True
        reasons.append(f"The full audit covered only {coverage.bytes_analyzed / coverage.bytes_total:.0%} of the code.")
    if ai_error:
        flags.ai_failed = True
        reasons.append("The AI review failed; the verdict comes from rules only.")
    if final.verdict == Verdict.SUSPICIOUS:
        reasons.append("The final verdict is SUSPICIOUS.")

    flags.needs_human_review = (
        final.verdict == Verdict.SUSPICIOUS
        or flags.rules_ai_disagree
        or flags.worker_coordinator_disagree
        or flags.prompt_injection_detected
        or flags.ai_failed
        or (flags.low_coverage and final.decided_by != DecidedBy.INTEL)
    )
    flags.reasons = reasons if flags.needs_human_review else []
    return flags
