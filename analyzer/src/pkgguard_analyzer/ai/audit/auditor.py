"""Runs a full audit: parallel workers read every chunk, then the coordinator agent decides."""

import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from pkgguard_analyzer.ai.audit.chunking import CHUNK_CHARS, MAX_AUDIT_CHARS, Chunk, plan_audit
from pkgguard_analyzer.ai.audit.prompts import COORDINATOR_SYSTEM_PROMPT, WORKER_SYSTEM_PROMPT, WorkerReport, build_coordinator_task, build_worker_task
from pkgguard_analyzer.ai.config import AIConfig
from pkgguard_analyzer.ai.reviewer import TOOL_BUDGET, Reviewer, StrandsReviewer, build_review, install_and_entry_labels, make_model
from pkgguard_analyzer.ai.workspace import PackageWorkspace
from pkgguard_analyzer.schema import AICost, AIReview, AuditCoverage, Report, ReviewMode, WorkerPartReport

WORKER_PARALLEL = 6
WORKER_ATTEMPTS = 3
log = logging.getLogger(__name__)


@dataclass
class WorkerOutput:
    report: WorkerReport
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class WorkerResult:
    chunk: Chunk
    report: WorkerReport | None
    error: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    seconds: float = 0.0

    def part_report(self) -> WorkerPartReport:
        return WorkerPartReport(
            part=self.chunk.index + 1,
            files=self.chunk.files,
            report=self.report,
            error=self.error,
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            duration_seconds=round(self.seconds, 2),
        )


class StrandsWorker:
    """One structured AI call per chunk. No tools: the whole chunk is in the prompt, which is much faster than an agent loop."""

    def __init__(self, model_factory: Callable[[], object], model_id: str):
        self.model_factory = model_factory
        self.model_id = model_id

    def __call__(self, task: str) -> WorkerOutput:
        from strands import Agent

        agent = Agent(model=self.model_factory(), tools=[], system_prompt=WORKER_SYSTEM_PROMPT, callback_handler=None)
        result = agent(task, structured_output_model=WorkerReport)
        if not isinstance(result.structured_output, WorkerReport):
            raise RuntimeError(f"worker stopped without a report ({result.stop_reason})")
        usage = result.metrics.accumulated_usage or {}
        return WorkerOutput(result.structured_output, usage.get("inputTokens", 0), usage.get("outputTokens", 0))


class FullAuditor:
    def __init__(
        self,
        coordinator: Reviewer,
        worker: Callable[[str], WorkerOutput],
        worker_model_id: str,
        parallel: int = WORKER_PARALLEL,
        retry_delay: float = 5.0,
        settings: dict | None = None,
    ):
        self.coordinator = coordinator
        self.worker = worker
        self.worker_model_id = worker_model_id
        self.parallel = parallel
        self.retry_delay = retry_delay
        self.settings = settings or {"coordinator_model": coordinator.model_id, "worker_model": worker_model_id}

    @property
    def model_id(self) -> str:
        return self.coordinator.model_id

    def _run_worker(self, report: Report, chunk: Chunk, total: int) -> WorkerResult:
        task = build_worker_task(report, chunk.text, chunk.index, total)
        error = None
        started = time.monotonic()
        for attempt in range(WORKER_ATTEMPTS):
            try:
                output = self.worker(task)
                return WorkerResult(chunk, output.report, None, output.input_tokens, output.output_tokens, time.monotonic() - started)
            except Exception as exc:  # rate limits, timeouts, malformed output
                error = f"{type(exc).__name__}: {exc}"[:300]
                log.warning("worker part %d attempt %d failed: %s", chunk.index + 1, attempt + 1, error)
                if attempt + 1 < WORKER_ATTEMPTS:
                    time.sleep(self.retry_delay * (attempt + 1))
        return WorkerResult(chunk, None, error, seconds=time.monotonic() - started)

    def audit(self, files_dir: Path, report: Report) -> tuple[AIReview | None, str | None]:
        started = time.monotonic()
        plan = plan_audit(files_dir, report.code_scan, report.findings)
        with ThreadPoolExecutor(max_workers=self.parallel) as pool:
            results = list(pool.map(lambda chunk: self._run_worker(report, chunk, len(plan.chunks)), plan.chunks))

        failed = sum(r.report is None for r in results)
        if results and failed * 2 > len(results):
            return None, f"full audit failed: {failed} of {len(results)} worker parts failed ({results[0].error or 'see logs'})"

        workspace = PackageWorkspace(files_dir, TOOL_BUDGET[ReviewMode.FULL_AUDIT], install_and_entry_labels(report))
        coordinator_started = time.monotonic()
        try:
            output = self.coordinator.review(workspace, build_coordinator_task(report, plan, results), ReviewMode.FULL_AUDIT)
        except Exception as error:
            return None, f"full audit coordinator failed: {type(error).__name__}: {error}"[:500]

        cost = AICost(
            coordinator_input_tokens=output.input_tokens or 0,
            coordinator_output_tokens=output.output_tokens or 0,
            coordinator_seconds=round(time.monotonic() - coordinator_started, 2),
            worker_input_tokens=sum(r.input_tokens for r in results),
            worker_output_tokens=sum(r.output_tokens for r in results),
            worker_calls=len(results),
            worker_seconds=round(sum(r.seconds for r in results), 2),
        )
        output.input_tokens = cost.coordinator_input_tokens + cost.worker_input_tokens
        output.output_tokens = cost.coordinator_output_tokens + cost.worker_output_tokens
        coverage = AuditCoverage(
            files_total=plan.files_total,
            files_analyzed=plan.files_analyzed,
            bytes_total=plan.bytes_total,
            bytes_analyzed=plan.bytes_analyzed,
            duplicates_skipped=plan.duplicates_skipped,
            chunks=len(plan.chunks),
            chunks_failed=failed,
            worker_model=self.worker_model_id,
            skipped_files=plan.skipped_for_report,
        )
        review = build_review(
            output,
            workspace,
            self.coordinator.model_id,
            ReviewMode.FULL_AUDIT,
            started,
            coverage=coverage,
            worker_reports=[r.part_report() for r in results],
            cost=cost,
        )
        return review, None


def make_full_auditor(config: AIConfig) -> FullAuditor:
    if problem := config.problem():
        raise ValueError(problem)
    audit_model_id = config.audit_model_id or config.model_id
    worker_model_id = config.worker_model_id or config.model_id
    audit_effort = config.audit_reasoning_effort or config.reasoning_effort
    worker_effort = config.worker_reasoning_effort or config.reasoning_effort
    coordinator = StrandsReviewer(make_model(config, audit_model_id, audit_effort, responses_api=True), audit_model_id, COORDINATOR_SYSTEM_PROMPT)
    worker = StrandsWorker(lambda: make_model(config, worker_model_id, worker_effort, responses_api=True), worker_model_id)
    settings = {
        "provider": config.provider.value,
        "coordinator_model": audit_model_id,
        "coordinator_reasoning_effort": audit_effort,
        "worker_model": worker_model_id,
        "worker_reasoning_effort": worker_effort,
        "worker_parallel": config.audit_worker_parallel,
        "coordinator_tool_budget": TOOL_BUDGET[ReviewMode.FULL_AUDIT],
        "max_audit_chars": MAX_AUDIT_CHARS,
        "chunk_chars": CHUNK_CHARS,
    }
    return FullAuditor(coordinator, worker, worker_model_id, parallel=config.audit_worker_parallel, settings=settings)
