from pkgguard_analyzer.schema import Confidence, DecidedBy, Finding, Severity, Verdict
from pkgguard_analyzer.scoring import decide, signals


def finding(rule_id="metadata.x", severity="MEDIUM", confidence="HIGH", layer="metadata", title=None):
    return Finding(rule_id=rule_id, layer=layer, severity=severity, confidence=confidence, title=title or rule_id)


def test_osv_malicious_wins():
    decision = decide([finding("intel.osv.malicious", "HIGH", layer="intel")])
    assert (decision.verdict, decision.decided_by) == (Verdict.MALICIOUS, DecidedBy.INTEL)


def test_strong_safedep_is_malicious():
    assert decide([finding("intel.safedep.malware", "HIGH", "HIGH", "intel")]).verdict == Verdict.MALICIOUS


def test_weak_safedep_is_suspicious():
    assert decide([finding("intel.safedep.malware", "HIGH", "MEDIUM", "intel")]).verdict == Verdict.SUSPICIOUS


def test_high_severity_is_suspicious():
    assert decide([finding(severity="HIGH")]).verdict == Verdict.SUSPICIOUS


def test_two_warnings_are_suspicious():
    decision = decide([finding("a"), finding("b")])
    assert (decision.verdict, decision.confidence) == (Verdict.SUSPICIOUS, Confidence.LOW)


def test_one_warning_is_safe_low_confidence():
    decision = decide([finding("metadata.install_script")])
    assert (decision.verdict, decision.confidence) == (Verdict.SAFE, Confidence.LOW)


def test_nothing_found_is_safe():
    decision = decide([finding(severity="LOW")])
    assert (decision.verdict, decision.confidence) == (Verdict.SAFE, Confidence.MEDIUM)


def test_signals_skip_low_and_dedupe():
    found = [finding("a", title="Same"), finding("b", title="Same"), finding("c", severity="LOW", title="Minor")]
    assert signals(found) == ["Same"]


from datetime import UTC, datetime  # noqa: E402

from pkgguard_analyzer.schema import AIReview  # noqa: E402


def ai(verdict="SAFE", confidence="HIGH"):
    return AIReview(verdict=verdict, confidence=confidence, summary=f"AI says {verdict}", reasoning="r", model="m", mode="deep_dive", duration_seconds=1.0)


def test_ai_clears_rule_warnings():
    # esbuild-like: several MEDIUM warnings about downloading and running a binary at install time.
    found = [finding("metadata.install_script"), finding("code.install_download_exec"), finding("code.exec")]
    decision = decide(found, ai("SAFE", "HIGH"))
    assert (decision.verdict, decision.decided_by, decision.summary) == (Verdict.SAFE, DecidedBy.AI, "AI says SAFE")


def test_confident_ai_clears_high_severity_finding():
    # e.g. a real HIGH finding that's actually normal minified/bundled code: trust a HIGH-confidence AI.
    decision = decide([finding("code.exfiltration", "HIGH", "MEDIUM", layer="static")], ai("SAFE", "HIGH"))
    assert (decision.verdict, decision.decided_by) == (Verdict.SAFE, DecidedBy.AI)


def test_unsure_ai_cannot_clear_high_severity_finding():
    decision = decide([finding("code.exfiltration", "HIGH", "MEDIUM", layer="static")], ai("SAFE", "MEDIUM"))
    assert (decision.verdict, decision.decided_by) == (Verdict.SUSPICIOUS, DecidedBy.RULES)


def test_ai_can_clear_low_confidence_high_findings():
    assert decide([finding("code.exfiltration", "HIGH", "LOW", layer="static")], ai("SAFE", "HIGH")).verdict == Verdict.SAFE


def test_ai_cannot_clear_prompt_injection():
    decision = decide([finding("code.pattern.llm_prompt_injection", "MEDIUM", "MEDIUM", layer="static")], ai("SAFE", "HIGH"))
    assert decision.verdict == Verdict.SUSPICIOUS


def test_ai_cannot_downgrade_threat_intel():
    assert decide([finding("intel.osv.malicious", "HIGH", layer="intel")], ai("SAFE", "HIGH")).decided_by == DecidedBy.INTEL
    weak_safedep = finding("intel.safedep.malware", "HIGH", "MEDIUM", "intel")
    assert decide([weak_safedep], ai("SAFE", "HIGH")).verdict == Verdict.SUSPICIOUS


def test_ai_escalates_clean_package():
    decision = decide([], ai("MALICIOUS", "HIGH"))
    assert (decision.verdict, decision.decided_by) == (Verdict.MALICIOUS, DecidedBy.AI)
    assert decide([], ai("MALICIOUS", "MEDIUM")).verdict == Verdict.SUSPICIOUS
    assert decide([], ai("SUSPICIOUS", "MEDIUM")).verdict == Verdict.SUSPICIOUS


def test_unsure_ai_falls_back_to_rules():
    found = [finding("a"), finding("b")]
    assert decide(found, ai("SAFE", "LOW")) == decide(found)
