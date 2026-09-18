"""Runs a package in the AWS sandbox: two Fargate tasks (baseline + hostile) in the isolated VPC.

The scan Lambda stages the verified tarball in S3, starts both tasks, waits, reads their raw traces back
and turns them into a SandboxReport. Anything that goes wrong becomes a FAILED/PARTIAL report; it never
fails the scan. Tasks are always stopped and the staged tarball deleted, even on errors."""

import gzip
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from pkgguard_analyzer.sandbox.build import build_report
from pkgguard_analyzer.schema import SandboxReport, SandboxStatus

log = logging.getLogger()
SANDBOX_VERSION = "0.1.0"
RUNS = ("baseline", "hostile")
WAIT_SECONDS = 150
POLL_SECONDS = 3
CONTAINER = "sandbox"


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


class FargateSandbox:
    def __init__(self, config: SandboxConfig, ecs: Any, s3: Any, *, sleep=time.sleep, clock=time.monotonic) -> None:
        self.config, self.ecs, self.s3 = config, ecs, s3
        self._sleep, self._clock = sleep, clock

    def runner_for(self, scan_id: str, name: str, version: str):
        return lambda tarball: self.run(tarball, scan_id, name, version)

    def _keys(self, scan_id: str, name: str, version: str) -> tuple[str, str]:
        return f"sandbox-in/{scan_id}.tgz", f"sandbox-traces/npm/{name}/{version}/{scan_id}"

    def run(self, tarball: bytes, scan_id: str, name: str, version: str) -> SandboxReport:
        key_in, prefix = self._keys(scan_id, name, version)
        cfg = self.config
        task_arns: dict[str, str] = {}
        try:
            self.s3.put_object(Bucket=cfg.bucket, Key=key_in, Body=tarball, ContentType="application/gzip")
            problems: list[str] = []
            for run in RUNS:
                arn, why = self._start(run, f"s3://{cfg.bucket}/{key_in}", f"s3://{cfg.bucket}/{prefix}/{run}.json.gz")
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
            if problems or len(traces) < len(RUNS):
                report = report.model_copy(update={"status": SandboxStatus.PARTIAL})
            return report
        except Exception as error:
            log.exception("sandbox run failed for %s@%s", name, version)
            return SandboxReport(version=SANDBOX_VERSION, status=SandboxStatus.FAILED, skip_reason=f"{type(error).__name__}: {error}"[:300])
        finally:
            self._cleanup(task_arns, key_in)

    def _start(self, run: str, source: str, target: str) -> tuple[str | None, str]:
        cfg = self.config
        for attempt in range(3):
            resp = self.ecs.run_task(
                cluster=cfg.cluster,
                taskDefinition=cfg.task_definition,
                launchType="FARGATE",
                count=1,
                networkConfiguration={"awsvpcConfiguration": {"subnets": cfg.subnets, "securityGroups": cfg.security_groups, "assignPublicIp": "DISABLED"}},
                overrides={"containerOverrides": [{"name": CONTAINER, "command": ["--input", source, "--output", target, "--run", run]}]},
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
            try:
                body = self.s3.get_object(Bucket=self.config.bucket, Key=f"{prefix}/{run}.json.gz")["Body"].read()
                traces.append(json.loads(gzip.decompress(body)))
            except Exception:
                log.warning("no trace for run %s", run)
        return traces

    def _cleanup(self, task_arns: dict[str, str], key_in: str) -> None:
        for arn in task_arns.values():
            try:
                self.ecs.stop_task(cluster=self.config.cluster, task=arn, reason="pkgguard sandbox cleanup")
            except Exception:
                pass
        try:
            self.s3.delete_object(Bucket=self.config.bucket, Key=key_in)
        except Exception:
            pass
