from pkgguard_analyzer.intel import parse_osv, parse_safedep
from pkgguard_analyzer.schema import Confidence


def test_osv_separates_malware_from_vulnerabilities():
    summary, findings = parse_osv({"vulns": [{"id": "MAL-2025-123"}, {"id": "GHSA-xxxx"}]})
    assert summary == {"maliciousIds": ["MAL-2025-123"], "vulnerabilityIds": ["GHSA-xxxx"]}
    assert [f.rule_id for f in findings] == ["intel.osv.malicious"]


def test_osv_empty_response():
    summary, findings = parse_osv({})
    assert summary["maliciousIds"] == [] and findings == []


def test_safedep_human_verified_malware_is_high_confidence():
    data = {
        "analysisId": "a1",
        "report": {"inference": {"isMalware": True, "confidence": "CONFIDENCE_MEDIUM"}},
        "verificationRecord": {"id": "v1"},
    }
    summary, findings = parse_safedep(data)
    assert summary["humanVerified"] is True
    assert findings[0].confidence == Confidence.HIGH


def test_safedep_unverified_medium_is_medium_confidence():
    data = {"report": {"inference": {"isMalware": True, "confidence": "CONFIDENCE_MEDIUM"}}}
    _, findings = parse_safedep(data)
    assert findings[0].confidence == Confidence.MEDIUM


def test_safedep_trusts_boolean_not_prose():
    # Real SafeDep case: human override set isMalware=true but the old AI text still says "not a malware".
    data = {
        "report": {"inference": {"isMalware": True, "confidence": "CONFIDENCE_HIGH", "details": "The package is not a malware."}},
        "verificationRecord": {"id": "v1"},
    }
    _, findings = parse_safedep(data)
    assert len(findings) == 1


def test_safedep_benign_has_no_findings():
    summary, findings = parse_safedep({"report": {"inference": {"isMalware": False}}})
    assert summary["found"] is True and findings == []
