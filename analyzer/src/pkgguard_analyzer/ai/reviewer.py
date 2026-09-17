"""Runs the AI review: picks quick look or deep dive, drives the agent, and records what it actually did."""

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pkgguard_analyzer.ai.config import AIConfig, AIMode, Provider
from pkgguard_analyzer.ai.prompts import SYSTEM_PROMPT, build_task
from pkgguard_analyzer.ai.workspace import PackageWorkspace
from pkgguard_analyzer.schema import AICost, AIReview, AIVerdict, Finding, Report, ReviewMode, Severity

TOOL_BUDGET = {ReviewMode.QUICK_LOOK: 6, ReviewMode.DEEP_DIVE: 15, ReviewMode.FULL_AUDIT: 15}
TOKEN_BUDGET = {ReviewMode.QUICK_LOOK: 80_000, ReviewMode.DEEP_DIVE: 250_000, ReviewMode.FULL_AUDIT: 400_000}
FINAL_ANSWER_PROMPT = "Your investigation budget is used up. Give your final assessment now, based only on what you have read."


@dataclass
class ReviewerOutput:
    verdict: AIVerdict
    input_tokens: int | None = None
    output_tokens: int | None = None


class Reviewer(Protocol):
    model_id: str

    def review(self, workspace: PackageWorkspace, task: str, mode: ReviewMode) -> ReviewerOutput: ...


class StrandsReviewer:
    def __init__(self, model, model_id: str, system_prompt: str = SYSTEM_PROMPT, settings: dict | None = None):
        self.model = model
        self.model_id = model_id
        self.system_prompt = system_prompt
        self.settings = settings or {"model": model_id}

    def review(self, workspace: PackageWorkspace, task: str, mode: ReviewMode) -> ReviewerOutput:
        from strands import Agent
        from strands.types.agent import Limits

        from pkgguard_analyzer.ai.tools import build_tools

        agent = Agent(model=self.model, tools=build_tools(workspace), system_prompt=self.system_prompt, callback_handler=None)
        limits = Limits(turns=TOOL_BUDGET[mode] + 4, total_tokens=TOKEN_BUDGET[mode])
        result = agent(task, structured_output_model=AIVerdict, limits=limits)
        if result.structured_output is None:
            result = agent(FINAL_ANSWER_PROMPT, structured_output_model=AIVerdict, limits=Limits(turns=2))
        if not isinstance(result.structured_output, AIVerdict):
            raise RuntimeError(f"agent stopped without an assessment ({result.stop_reason})")
        usage = result.metrics.accumulated_usage or {}
        return ReviewerOutput(result.structured_output, usage.get("inputTokens"), usage.get("outputTokens"))


OPENAI_CLIENT_ARGS = {"max_retries": 6, "timeout": 300}


def make_model(config: AIConfig, model_id: str, reasoning_effort: str | None, responses_api: bool = False):
    """Build a Strands model. The Responses API is needed for newer OpenAI models that combine tools with reasoning effort."""
    if config.provider == Provider.OPENAI:
        client_args = {"api_key": config.openai_api_key, **OPENAI_CLIENT_ARGS}
        if responses_api:
            from strands.models.openai_responses import OpenAIResponsesModel

            params = {"reasoning": {"effort": reasoning_effort}} if reasoning_effort else None
            return OpenAIResponsesModel(client_args=client_args, model_id=model_id, params=params)
        from strands.models.openai import OpenAIModel

        params = {"reasoning_effort": reasoning_effort} if reasoning_effort else None
        return OpenAIModel(client_args=client_args, model_id=model_id, params=params)
    from strands.models.bedrock import BedrockModel

    return BedrockModel(model_id=model_id, region_name=config.aws_region)


def make_reviewer(config: AIConfig) -> StrandsReviewer:
    if problem := config.problem():
        raise ValueError(problem)
    settings = {"provider": config.provider.value, "model": config.model_id, "reasoning_effort": config.reasoning_effort, "tool_budget": {m.value: b for m, b in TOOL_BUDGET.items()}}
    return StrandsReviewer(make_model(config, config.model_id, config.reasoning_effort), config.model_id, settings=settings)


def review_mode(findings: list[Finding], ai_mode: AIMode) -> ReviewMode | None:
    if ai_mode == AIMode.OFF:
        return None
    if any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings):
        return ReviewMode.DEEP_DIVE
    return ReviewMode.QUICK_LOOK if ai_mode == AIMode.ALWAYS else None


def run_review(files_dir: Path, report: Report, reviewer: Reviewer, mode: ReviewMode) -> tuple[AIReview | None, str | None]:
    """Returns (review, None) on success or (None, error message). A failed review never stops a scan."""
    workspace = PackageWorkspace(files_dir, TOOL_BUDGET[mode], install_and_entry_labels(report))
    started = time.monotonic()
    try:
        output = reviewer.review(workspace, build_task(report, mode, TOOL_BUDGET[mode]), mode)
    except Exception as error:  # provider outages, auth errors, malformed output
        return None, f"{type(error).__name__}: {error}"[:500]

    return build_review(output, workspace, reviewer.model_id, mode, started), None


def build_review(output: ReviewerOutput, workspace: PackageWorkspace, model_id: str, mode: ReviewMode, started: float, **extra) -> AIReview:
    verdict = output.verdict
    duration = round(time.monotonic() - started, 2)
    extra.setdefault(
        "cost",
        AICost(coordinator_input_tokens=output.input_tokens or 0, coordinator_output_tokens=output.output_tokens or 0, coordinator_seconds=duration),
    )
    return AIReview(
        **verdict.model_dump(exclude={"evidence"}),
        # Drop evidence pointing at files that don't exist in the package (model mistakes).
        evidence=[item for item in verdict.evidence if workspace.exists(item.file)],
        model=model_id,
        mode=mode,
        files_read=workspace.files_read,
        tool_calls=workspace.tool_calls,
        input_tokens=output.input_tokens,
        output_tokens=output.output_tokens,
        duration_seconds=duration,
        trace=workspace.trace,
        **extra,
    )


def install_and_entry_labels(report: Report) -> dict[str, str]:
    labels = {path: "runs at install time" for path in report.code_scan.get("installTimeFiles", [])}
    for path in report.code_scan.get("entryFiles", []):
        labels.setdefault(path, "runs on import")
    return labels
