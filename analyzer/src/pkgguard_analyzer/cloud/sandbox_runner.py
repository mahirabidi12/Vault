"""Runs a package in the AWS sandbox: two Fargate tasks (baseline + hostile) in the isolated VPC.

The scan Lambda stages the verified tarball in S3, starts both tasks, waits, reads their raw traces back
and turns them into a SandboxReport. Anything that goes wrong becomes a FAILED/PARTIAL report; it never
fails the scan. Tasks are always stopped and the staged tarball deleted, even on errors."""

import gzip
import io
import json
import logging
import os
import tarfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config

from pkgguard_analyzer.sandbox.build import build_report
from pkgguard_analyzer.schema import SandboxReport, SandboxStatus

log = logging.getLogger()
SANDBOX_VERSION = "0.1.0"
RUNS = ("baseline", "hostile")
WAIT_SECONDS = 150
POLL_SECONDS = 3
CONTAINER = "sandbox"


def make_s3(region: str | None = None) -> Any:
    """S3 client that signs with SigV4 and always uses the regional hostname (bucket.s3.<region>.amazonaws.com).
    The pre-signed links handed to the sandbox must use that name: it is the only S3 name its DNS Firewall allows."""
    region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "ap-south-1"
    return boto3.client("s3", region_name=region, endpoint_url=f"https://s3.{region}.amazonaws.com", config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}))


@dataclass
class SandboxConfig:
    cluster: str
    task_definition: str
    subnets: list[str]
    security_groups: list[str]
    bucket: str
    wait_seconds: int = WAIT_SECONDS

    @classmethod
    def from_env(cls, env: dict) -> "SandboxConfig | None":
        if env.get("SANDBOX_ENABLED", "").lower() not in ("1", "true", "yes") or not env.get("SANDBOX_CLUSTER"):
            return None
        return cls(
            cluster=env["SANDBOX_CLUSTER"],
            task_definition=env["SANDBOX_TASK_DEFINITION"],
            subnets=[s for s in env["SANDBOX_SUBNETS"].split(",") if s],
            security_groups=[s for s in env["SANDBOX_SECURITY_GROUPS"].split(",") if s],
            bucket=env["BUCKET_NAME"],
        )


def _read_manifest(tarball: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:*") as tar:
        names = [m for m in tar.getmembers() if m.isfile() and m.name.endswith("package.json")]
        member = min(names, key=lambda m: m.name.count("/"))
        data = json.loads(tar.extractfile(member).read().decode("utf-8", "replace"))
    return data if isinstance(data, dict) else {}


class FargateSandbox:
    def __init__(self, config: SandboxConfig, ecs: Any, s3: Any, *, sleep=time.sleep, clock=time.monotonic, deps_fetcher: Callable[[dict], Any] | None = None) -> None:
        self.config, self.ecs, self.s3 = config, ecs, s3
        self._sleep, self._clock = sleep, clock
        self.deps_fetcher = deps_fetcher  # fetches the package's dependencies outside the sandbox (see cloud/deps.py)

    def runner_for(self, scan_id: str, name: str, version: str):
        return lambda tarball: self.run(tarball, scan_id, name, version)

    def _keys(self, scan_id: str, name: str, version: str) -> tuple[str, str]:
        return f"sandbox-in/{scan_id}.tgz", f"sandbox-traces/npm/{name}/{version}/{scan_id}"

    def run(self, tarball: bytes, scan_id: str, name: str, version: str) -> SandboxReport:
        key_in, prefix = self._keys(scan_id, name, version)
        deps_key = f"sandbox-in/{scan_id}.deps.tgz"
        cfg = self.config
        task_arns: dict[str, str] = {}
        deps_note: str | None = None
        deps_sent = False
        try:
            self.s3.put_object(Bucket=cfg.bucket, Key=key_in, Body=tarball, ContentType="application/gzip")
            if self.deps_fetcher is not None:
                try:
                    result = self.deps_fetcher(_read_manifest(tarball))
                    deps_note = result.note or None
                    if result.tarball:
                        self.s3.put_object(Bucket=cfg.bucket, Key=deps_key, Body=result.tarball, ContentType="application/gzip")
                        deps_sent = True
                except Exception as error:  # the sandbox still runs without dependencies
                    deps_note = f"dependency fetch failed: {type(error).__name__}"
            problems: list[str] = []
            for run in RUNS:
                arn, why = self._start(run, key_in, f"{prefix}/{run}.json.gz", deps_key if deps_sent else None)
                if arn:
                    task_arns[run] = arn
                else:
                    problems.append(f"{run}: {why}")
            if not task_arns:
                return SandboxReport(version=SANDBOX_VERSION, status=SandboxStatus.FAILED, skip_reason="; ".join(problems)[:300] or "no sandbox task could be started")
            problems += self._wait(task_arns)
            traces = self._read_traces(prefix, list(task_arns))
            if not traces:
                return SandboxReport(version=SANDBOX_VERSION, status=SandboxStatus.FAILED, skip_reason=("; ".join(problems) or "sandbox produced no trace")[:300])
            report = build_report(traces, raw_trace_key=prefix + "/", version=SANDBOX_VERSION)
            if deps_note:
                report = report.model_copy(update={"coverage": report.coverage.model_copy(update={"dependencies_note": deps_note})})
            if problems or len(traces) < len(RUNS):
                report = report.model_copy(update={"status": SandboxStatus.PARTIAL})
            return report
        except Exception as error:
            log.exception("sandbox run failed for %s@%s", name, version)
            return SandboxReport(version=SANDBOX_VERSION, status=SandboxStatus.FAILED, skip_reason=f"{type(error).__name__}: {error}"[:300])
        finally:
            self._cleanup(task_arns, key_in, deps_key)

    def _presign(self, key: str, method: str) -> str:
        params = {"Bucket": self.config.bucket, "Key": key}
        if method == "put_object":
            params["ContentType"] = "application/gzip"
        return self.s3.generate_presigned_url(method, Params=params, ExpiresIn=900)

    def _start(self, run: str, source_key: str, target_key: str, deps_key: str | None = None) -> tuple[str | None, str]:
        cfg = self.config
        environment = [{"name": "SBX_INPUT_URL", "value": self._presign(source_key, "get_object")}, {"name": "SBX_OUTPUT_URL", "value": self._presign(target_key, "put_object")}]
        if deps_key:
            candidate = [*environment, {"name": "SBX_DEPS_URL", "value": self._presign(deps_key, "get_object")}]
            if len(json.dumps(candidate)) < 6500:  # ECS limits the size of run-task overrides
                environment = candidate
        for attempt in range(3):
            resp = self.ecs.run_task(
                cluster=cfg.cluster,
                taskDefinition=cfg.task_definition,
                launchType="FARGATE",
                count=1,
                networkConfiguration={"awsvpcConfiguration": {"subnets": cfg.subnets, "securityGroups": cfg.security_groups, "assignPublicIp": "DISABLED"}},
                overrides={"containerOverrides": [{"name": CONTAINER, "command": ["--input", "env", "--output", "env", "--run", run], "environment": environment}]},
            )
            if resp.get("tasks"):
                return resp["tasks"][0]["taskArn"], ""
            reason = "; ".join(f.get("reason", "unknown") for f in resp.get("failures", [])) or "no task started"
            if attempt < 2:
                self._sleep(2 * (attempt + 1))
        return None, reason

    def _wait(self, task_arns: dict[str, str]) -> list[str]:
        problems: list[str] = []
        deadline = self._clock() + self.config.wait_seconds
        pending = dict(task_arns)
        while pending and self._clock() < deadline:
            described = self.ecs.describe_tasks(cluster=self.config.cluster, tasks=list(pending.values()))
            for task in described.get("tasks", []):
                if task.get("lastStatus") == "STOPPED":
                    run = next(r for r, a in pending.items() if a == task["taskArn"])
                    del pending[run]
                    code = next((c.get("exitCode") for c in task.get("containers", []) if c.get("name") == CONTAINER), None)
                    if code not in (0, None):
                        problems.append(f"{run}: sandbox exited {code} ({task.get('stoppedReason', '')})"[:200])
            if pending:
                self._sleep(POLL_SECONDS)
        problems += [f"{run}: timed out after {self.config.wait_seconds}s" for run in pending]
        return problems

    def _read_traces(self, prefix: str, runs: list[str]) -> list[dict]:
        traces = []
        for run in runs:
            for attempt in range(4):
                try:
                    body = self.s3.get_object(Bucket=self.config.bucket, Key=f"{prefix}/{run}.json.gz")["Body"].read()
                    traces.append(json.loads(gzip.decompress(body)))
                    break
                except self.s3.exceptions.NoSuchKey:
                    log.warning("no trace for run %s", run)  # the task really produced nothing
                    break
                except Exception:  # a network blip must not look like a missing trace
                    if attempt == 3:
                        log.warning("could not read the trace for run %s after 4 tries", run)
                    else:
                        self._sleep(2 * (attempt + 1))
        return traces

    def _cleanup(self, task_arns: dict[str, str], key_in: str, deps_key: str | None = None) -> None:
        for arn in task_arns.values():
            try:
                self.ecs.stop_task(cluster=self.config.cluster, task=arn, reason="pkgguard sandbox cleanup")
            except Exception:
                pass
        for key in (key_in, deps_key):
            if not key:
                continue
            try:
                self.s3.delete_object(Bucket=self.config.bucket, Key=key)
            except Exception:
                pass
