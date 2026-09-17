from datetime import UTC, datetime

from pkgguard_analyzer.insights import ai_indicators, hash_files, merge_indicators, review_flags, scan_settings
from pkgguard_analyzer.schema import AIReview, AuditCoverage, Finding, Indicator, WorkerPartReport, WorkerReport
from pkgguard_analyzer.scoring import Decision

NOW = datetime(2026, 9, 17, tzinfo=UTC)


def review(verdict="SAFE", workers=(), evidence=(), coverage=None):
    return AIReview(
        verdict=verdict, confidence="HIGH", summary="s", reasoning="r", model="m", mode="full_audit", duration_seconds=1,
        worker_reports=list(workers), evidence=list(evidence), coverage=coverage,
    )


def worker(assessment="benign", **fields):
    return WorkerPartReport(part=1, files=["a.js"], report=WorkerReport.model_validate({"summary": "x", "capabilities": ["network"], "assessment": assessment, **fields}))


def decision(verdict, decided_by="rules"):
    return Decision(verdict=verdict, confidence="HIGH", decided_by=decided_by, summary="s")


def test_hash_files_and_truncation(tmp_path):
    (tmp_path / "a.js").write_text("a")
    (tmp_path / "b.js").write_text("b")
    hashes, truncated = hash_files(tmp_path)
    assert [h.path for h in hashes] == ["a.js", "b.js"] and not truncated
    assert hashes[0].sha256 == "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    assert hash_files(tmp_path, limit=1)[1] is True


def test_ai_indicators_from_suspicious_context_only():
    malicious = worker(
        "malicious",
        data_flows=[{"source": "process.env.NPM_TOKEN", "sink": "HTTPS POST to https://collect.evil.invalid/t", "file": "a.js", "line": 3, "description": "sends token"}],
        suspicious_items=[{"file": "a.js", "line": 9, "behavior": "beacon", "severity": "HIGH", "explanation": "calls 45.33.32.156"}],
        external_endpoints=["collect.evil.invalid", "index.js", "https://localhost:3000"],
    )
    benign = worker("benign", external_endpoints=["registry.npmjs.org"])
    values = {(i.type.value, i.value) for i in ai_indicators(review("MALICIOUS", [malicious, benign]))}
    assert ("url", "https://collect.evil.invalid/t") in values
    assert ("ip", "45.33.32.156") in values
    assert ("domain", "collect.evil.invalid") in values
    assert not any(v in ("index.js", "registry.npmjs.org", "https://localhost:3000") for _, v in values)
    assert ai_indicators(None) == []


def test_merge_indicators_dedupes():
    a = Indicator(type="ip", value="1.1.1.1", source="rules")
    b = Indicator(type="ip", value="1.1.1.1", source="ai")
    assert merge_indicators([a], [b]) == [a]


def test_settings_hash_changes_with_models():
    class Reviewer:
        settings = {"model": "gpt-5-mini"}

    class Other:
        settings = {"model": "gpt-5.5"}

    first, second = scan_settings("always", Reviewer()), scan_settings("always", Other())
    assert first.settings_hash != second.settings_hash
    assert first.ai["model"] == "gpt-5-mini" and first.prompt_hashes["reviewer"]
    off = scan_settings("off")
    assert off.ai == {"mode": "off"} and off.prompt_hashes == {}


def test_review_flags():
    finding = Finding(rule_id="code.pattern.llm_prompt_injection", layer="static", severity="MEDIUM", confidence="MEDIUM", title="t")
    flags = review_flags([finding], decision("SUSPICIOUS"), decision("SUSPICIOUS"), review("SAFE", [worker("malicious")]), None)
    assert flags.rules_ai_disagree and flags.worker_coordinator_disagree and flags.prompt_injection_detected
    assert flags.needs_human_review and len(flags.reasons) >= 3

    clean = review_flags([], decision("SAFE"), decision("SAFE", "ai"), review("SAFE"), None)
    assert not clean.needs_human_review and clean.reasons == []

    coverage = AuditCoverage(files_total=10, files_analyzed=2, bytes_total=1000, bytes_analyzed=100, chunks=1, worker_model="w")
    low = review_flags([], decision("SAFE"), decision("SAFE", "ai"), review("SAFE", coverage=coverage), None)
    assert low.low_coverage and low.needs_human_review

    failed = review_flags([], decision("SAFE"), decision("SAFE"), None, "timeout")
    assert failed.ai_failed and failed.needs_human_review
