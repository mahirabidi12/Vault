from datetime import UTC, datetime

import pytest

from pkgguard_analyzer.ai.audit import auditor as auditor_module
from pkgguard_analyzer.ai.audit.auditor import FullAuditor, WorkerOutput
from pkgguard_analyzer.ai.audit.chunking import LINE_SEGMENT_CHARS, AuditFile, pack_chunks, plan_audit, render_lines
from pkgguard_analyzer.ai.audit.prompts import WorkerReport, build_coordinator_task
from pkgguard_analyzer.ai.config import AIConfig
from pkgguard_analyzer.ai.reviewer import ReviewerOutput
from pkgguard_analyzer.schema import AIVerdict, Finding, PackageRef, Report, ReviewMode

NOW = datetime(2026, 9, 17, tzinfo=UTC)


def make_package(root, files: dict[str, str | bytes]):
    for path, content in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode())
    return root


def make_report(code_scan=None, findings=()):
    return Report(
        package=PackageRef(ecosystem="npm", name="demo-pkg", version="1.0.0"),
        analyzer_version="0.1.0",
        generated_at=NOW,
        findings=list(findings),
        metadata={"description": "Demo package", "fileCount": 3},
        code_scan=code_scan or {"filesScanned": 3, "installTimeFiles": ["install.js"], "entryFiles": ["index.js"]},
    )


def test_plan_prioritizes_and_skips_junk(tmp_path):
    make_package(
        tmp_path,
        {
            "package.json": "{}",
            "lib/a.js": "const a = 1;",
            "lib/copy.js": "const a = 1;",
            "index.js": "module.exports = 1;",
            "install.js": "require('https');",
            "dist/lib.js": "x",
            "dist/lib.min.js": "x",
            "types.d.ts": "export {}",
            "lib/a.js.map": "{}",
            "README.md": "docs",
            "prebuilt.node": b"\x00\x01binary",
            "flagged.js": "eval(x)",
        },
    )
    findings = [Finding(rule_id="code.dynamic_code", layer="static", severity="LOW", confidence="HIGH", title="t", file="flagged.js")]
    plan = plan_audit(tmp_path, make_report().code_scan, findings)
    analyzed_order = [f for chunk in plan.chunks for f in chunk.files]
    assert analyzed_order[:4] == ["package.json", "install.js", "index.js", "flagged.js"]
    reasons = {s.path: s.reason for s in plan.skipped}
    assert reasons["dist/lib.min.js"] == "minified copy of another file"
    assert reasons["lib/copy.js"] == "exact duplicate of another file"
    assert plan.duplicates_skipped == 1
    assert "types.d.ts" not in analyzed_order and "README.md" not in analyzed_order and "lib/a.js.map" not in analyzed_order
    assert "===== FILE: install.js [runs at install time]" in plan.chunks[0].text


def test_plan_respects_size_limit(tmp_path):
    make_package(tmp_path, {"index.js": "a" * 100, "big.js": "b" * 500})
    plan = plan_audit(tmp_path, {"entryFiles": ["index.js"]}, [], max_chars=300)
    assert plan.files_analyzed == 1
    assert [(s.path, s.reason) for s in plan.skipped] == [("big.js", "audit size limit reached")]


def test_long_lines_are_segmented():
    lines = render_lines("short\n" + "x" * (LINE_SEGMENT_CHARS * 2 + 5))
    assert lines[0] == "     1| short"
    assert [line.split("|")[0].strip() for line in lines[1:]] == ["2.1", "2.2", "2.3"]


def test_chunks_split_large_files_and_keep_every_line():
    text = "\n".join(f"line {i}" for i in range(1, 501))
    chunks = pack_chunks([AuditFile("big.js", text, []), AuditFile("small.js", "tiny", [])], chunk_chars=1_000)
    assert len(chunks) > 1
    assert "===== FILE: big.js (continued) =====" in chunks[1].text
    joined = "\n".join(c.text for c in chunks)
    assert all(f"| line {i}" in joined for i in range(1, 501))
    assert chunks[-1].files[-1] == "small.js"
    assert all(len(c.text) <= 1_000 for c in chunks)


def worker_report(assessment="benign", summary="normal code"):
    return WorkerReport(summary=summary, capabilities=["none"], assessment=assessment)


class FakeCoordinator:
    model_id = "coordinator-model"

    def __init__(self, verdict="SAFE"):
        self.tasks = []
        self.verdict = verdict

    def review(self, workspace, task, mode):
        self.tasks.append((task, mode))
        workspace.read_file("install.js")
        return ReviewerOutput(AIVerdict(verdict=self.verdict, confidence="HIGH", summary="done", reasoning="r"), 1000, 100)


def test_full_audit_runs_workers_then_coordinator(tmp_path):
    make_package(tmp_path, {"package.json": "{}", "install.js": "x\n" * 50, "index.js": "y\n" * 50})
    worker_tasks = []

    def worker(task):
        worker_tasks.append(task)
        return WorkerOutput(worker_report("suspicious", "reads NPM_TOKEN and sends it"), 500, 50)

    coordinator = FakeCoordinator("MALICIOUS")
    auditor = FullAuditor(coordinator, worker, "worker-model", parallel=2)
    auditor_module_chunk = auditor_module.plan_audit
    review, error = auditor.audit(tmp_path, make_report())

    assert error is None
    assert review.mode == ReviewMode.FULL_AUDIT and review.verdict == "MALICIOUS"
    assert review.coverage.files_analyzed == 3 and review.coverage.chunks == len(worker_tasks)
    assert review.coverage.worker_model == "worker-model"
    assert review.input_tokens == 1000 + 500 * len(worker_tasks)
    assert review.files_read == ["install.js"]
    task, mode = coordinator.tasks[0]
    assert mode == ReviewMode.FULL_AUDIT
    assert "reads NPM_TOKEN and sends it" in task and "Audit coverage: 3 of 3 code files" in task
    assert '<package_content source="package code" part="1/' in worker_tasks[0]
    assert auditor_module_chunk is not None
    assert [p.part for p in review.worker_reports] == list(range(1, len(worker_tasks) + 1))
    assert review.worker_reports[0].report.summary == "reads NPM_TOKEN and sends it"
    assert review.cost.worker_calls == len(worker_tasks) and review.cost.coordinator_input_tokens == 1000
    assert review.cost.worker_input_tokens == 500 * len(worker_tasks)
    assert [c.tool for c in review.trace] == ["read_file"]


def test_worker_retries_then_tolerates_minority_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(auditor_module, "WORKER_ATTEMPTS", 2)
    make_package(tmp_path, {f"f{i}.js": "z\n" * 40 for i in range(3)})
    monkeypatch.setattr(auditor_module, "plan_audit", lambda d, c, f: plan_audit(d, c, f, chunk_chars=200))
    calls = {"n": 0}

    def flaky(task):
        calls["n"] += 1
        if "f0.js" in task and "(continued)" not in task:
            raise TimeoutError("rate limited")
        return WorkerOutput(worker_report())

    review, error = FullAuditor(FakeCoordinator(), flaky, "w", parallel=1, retry_delay=0).audit(tmp_path, make_report({"entryFiles": []}))
    assert error is None
    assert review.coverage.chunks_failed >= 1
    assert review.coverage.chunks_failed * 2 <= review.coverage.chunks


def test_majority_worker_failure_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(auditor_module, "WORKER_ATTEMPTS", 1)
    make_package(tmp_path, {"index.js": "x"})

    def broken(task):
        raise ConnectionError("down")

    review, error = FullAuditor(FakeCoordinator(), broken, "w", retry_delay=0).audit(tmp_path, make_report())
    assert review is None and "worker parts failed" in error


def test_coordinator_task_lists_failed_parts_and_uncovered_files(tmp_path):
    make_package(tmp_path, {"index.js": "a" * 50, "huge.js": "b" * 500})
    plan = plan_audit(tmp_path, {"entryFiles": ["index.js"]}, [], max_chars=100)

    class Result:
        chunk = plan.chunks[0]
        report = None
        error = "TimeoutError: slow"

    task = build_coordinator_task(make_report(), plan, [Result()])
    assert "WORKER FAILED: TimeoutError: slow" in task
    assert "huge.js: audit size limit reached" in task


def test_audit_config_defaults():
    config = AIConfig.from_env({"OPENAI_API_KEY": "k", "OPENAI_MODEL": "gpt-5-mini", "OPENAI_AUDIT_MODEL": "gpt-5.5", "OPENAI_AUDIT_REASONING_EFFORT": "medium"})
    assert (config.audit_model_id, config.audit_reasoning_effort, config.worker_model_id) == ("gpt-5.5", "medium", None)


@pytest.mark.parametrize("mode", ["full_audit"])
def test_ai_review_accepts_full_audit_mode(mode):
    assert ReviewMode(mode) == ReviewMode.FULL_AUDIT
