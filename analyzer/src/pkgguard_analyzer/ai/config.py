"""AI settings from environment variables (.env locally, Lambda environment / Secrets Manager on AWS)."""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class AIMode(StrEnum):
    ALWAYS = "always"  # quick look on every package, deep dive when something is flagged
    FLAGGED = "flagged"  # deep dive only when something is flagged
    OFF = "off"


class Provider(StrEnum):
    OPENAI = "openai"
    BEDROCK = "bedrock"


@dataclass(frozen=True)
class AIConfig:
    mode: AIMode
    provider: Provider
    model_id: str | None
    openai_api_key: str | None = None
    aws_region: str | None = None
    reasoning_effort: str | None = None  # OpenAI reasoning models: minimal | low | medium | high
    # Full audit (optional): a stronger coordinator model and a cheaper worker model. Default to model_id.
    audit_model_id: str | None = None
    audit_reasoning_effort: str | None = None
    worker_model_id: str | None = None
    worker_reasoning_effort: str | None = None
    audit_worker_parallel: int = 4

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "AIConfig":
        provider = Provider(env.get("MODEL_PROVIDER", "openai").strip().lower() or "openai")
        model_key = "OPENAI_MODEL" if provider == Provider.OPENAI else "BEDROCK_MODEL_ID"
        return cls(
            mode=AIMode(env.get("AI_MODE", "always").strip().lower() or "always"),
            provider=provider,
            model_id=env.get(model_key, "").strip() or None,
            openai_api_key=env.get("OPENAI_API_KEY", "").strip() or None,
            aws_region=env.get("AWS_REGION", "").strip() or None,
            reasoning_effort=env.get("OPENAI_REASONING_EFFORT", "").strip().lower() or None,
            audit_model_id=env.get("OPENAI_AUDIT_MODEL" if provider == Provider.OPENAI else "BEDROCK_AUDIT_MODEL_ID", "").strip() or None,
            audit_reasoning_effort=env.get("OPENAI_AUDIT_REASONING_EFFORT", "").strip().lower() or None,
            worker_model_id=env.get("OPENAI_WORKER_MODEL" if provider == Provider.OPENAI else "BEDROCK_WORKER_MODEL_ID", "").strip() or None,
            worker_reasoning_effort=env.get("OPENAI_WORKER_REASONING_EFFORT", "").strip().lower() or None,
            audit_worker_parallel=int(env.get("AUDIT_WORKER_PARALLEL", "").strip() or 4),
        )

    def problem(self) -> str | None:
        """Why the AI review can't run with these settings, or None if it can."""
        if self.mode == AIMode.OFF:
            return "AI_MODE is off"
        if self.provider == Provider.OPENAI and not self.openai_api_key:
            return "OPENAI_API_KEY is not set"
        if not self.model_id:
            return f"{'OPENAI_MODEL' if self.provider == Provider.OPENAI else 'BEDROCK_MODEL_ID'} is not set"
        if self.provider == Provider.BEDROCK and not self.aws_region:
            return "AWS_REGION is not set"
        return None
