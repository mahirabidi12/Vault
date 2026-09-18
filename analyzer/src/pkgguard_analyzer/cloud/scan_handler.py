"""Step Functions task: scan one package version, upload the report to S3 and save the verdict."""

import logging
import os
import shutil
from dataclasses import dataclass, replace
from functools import cache
from pathlib import Path
from typing import Any

import boto3
import httpx
from botocore.exceptions import ClientError

from pkgguard_analyzer.ai.config import AIConfig, AIMode, Provider
from pkgguard_analyzer.ai.reviewer import Reviewer, make_reviewer
from pkgguard_analyzer.analyze import analyze
from pkgguard_analyzer.cloud.sandbox_runner import FargateSandbox, SandboxConfig
from pkgguard_analyzer.cloud.store import VerdictStore
from pkgguard_analyzer.schema import RanOn

WORK_ROOT = Path(os.environ.get("PKGGUARD_WORK_DIR", "/tmp/pkgguard"))
log = logging.getLogger()
log.setLevel(logging.INFO)


@dataclass
class ScanServices:
    store: VerdictStore
    s3: Any
    bucket: str
    reviewer: Reviewer | None = None
    ai_mode: AIMode = AIMode.OFF
    http: httpx.Client | None = None
    sandbox: FargateSandbox | None = None


def report_key(name: str, version: str, analyzer_version: str) -> str:
    return f"reports/npm/{name}/{version}/{analyzer_version}.json"


def load_ai(secrets_client: Any = None) -> tuple[Reviewer | None, AIMode]:
    """Build the AI reviewer, reading the OpenAI key from Secrets Manager. Scans continue without AI if it can't run."""
    config = AIConfig.from_env()
    secret_name = os.environ.get("OPENAI_SECRET_NAME")
    if config.mode != AIMode.OFF and config.provider == Provider.OPENAI and not config.openai_api_key and secret_name:
        try:
            secrets_client = secrets_client or boto3.client("secretsmanager")
            key = secrets_client.get_secret_value(SecretId=secret_name)["SecretString"].strip()
            config = replace(config, openai_api_key=key or None)
        except ClientError:
            log.exception("could not read secret %s; AI review disabled", secret_name)
    if problem := config.problem():
        log.warning("AI review disabled: %s", problem)
        return None, AIMode.OFF
    return make_reviewer(config), config.mode


@cache
def default_services() -> ScanServices:
    reviewer, ai_mode = load_ai()
    s3 = boto3.client("s3")
    sandbox_config = SandboxConfig.from_env(dict(os.environ))
    return ScanServices(
        store=VerdictStore(boto3.resource("dynamodb"), os.environ["TABLE_NAME"]),
        s3=s3,
        sandbox=FargateSandbox(sandbox_config, boto3.client("ecs"), s3) if sandbox_config else None,
        bucket=os.environ["BUCKET_NAME"],
        reviewer=reviewer,
        ai_mode=ai_mode,
    )


def handler(event: dict, context: object, services: ScanServices | None = None) -> dict:
    services = services or default_services()
    if event.get("action") == "fetch_samples":
        from pkgguard_analyzer.cloud.sample_handler import fetch_samples

        return fetch_samples(event, services.s3, services.bucket)
    if event.get("action") == "analyze_sample":
        from pkgguard_analyzer.cloud.sample_handler import analyze_sample

        try:
            return analyze_sample(event, services, WORK_ROOT)
        finally:
            shutil.rmtree(WORK_ROOT, ignore_errors=True)
    name, version, scan_id = event["name"], event["version"], event["scanId"]

    pending = services.store.mark_scanning(name, version, scan_id)
    if pending is None:
        log.info("scan %s for %s@%s is no longer current; skipping", scan_id, name, version)
        return {"scanId": scan_id, "status": "SUPERSEDED"}

    work_dir = WORK_ROOT / scan_id
    try:
        result = analyze(
            name,
            version,
            out_dir=work_dir,
            ran_on=RanOn.CLOUD,
            client=services.http,
            now=pending.requested_at,
            reviewer=services.reviewer,
            ai_mode=services.ai_mode,
            scan_id=scan_id,
            sandbox_runner=services.sandbox.runner_for(scan_id, name, version) if services.sandbox else None,
        )
        record = result.record
        if result.report is not None:
            key = report_key(name, version, result.report.analyzer_version)
            services.s3.put_object(
                Bucket=services.bucket,
                Key=key,
                Body=result.report.model_dump_json(by_alias=True).encode(),
                ContentType="application/json",
            )
            record = record.model_copy(update={"report_s3_key": key})

        if services.store.save_result(record):
            services.store.record_completed(record)
        else:
            log.info("scan %s finished but a newer scan replaced it", scan_id)
        log.info("scanned %s@%s: %s %s", name, version, record.status, record.verdict)
        return {"scanId": scan_id, "status": record.status.value, "verdict": record.verdict.value if record.verdict else None}
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
