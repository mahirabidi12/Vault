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
