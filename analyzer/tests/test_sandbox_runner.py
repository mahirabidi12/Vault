"""The AWS sandbox launcher, against moto S3 and a fake ECS that 'runs' tasks by writing a real captured trace."""

import gzip
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from pkgguard_analyzer.cloud.sandbox_runner import FargateSandbox, SandboxConfig
from pkgguard_analyzer.schema import SandboxStatus, Severity

DATA = Path(__file__).parent / "data" / "sandbox"
BUCKET = "reports"


class FakeEcs:
    def __init__(self, s3, fixture: str, *, fail_run: str | None = None, never_stop: bool = False, no_capacity: bool = False, exit_code: int = 0) -> None:
        self.s3, self.fixture, self.fail_run, self.never_stop, self.no_capacity, self.exit_code = s3, fixture, fail_run, never_stop, no_capacity, exit_code
        self.tasks: dict[str, str] = {}
        self.stopped: list[str] = []
        self.calls = 0

    def run_task(self, **kw):
        self.calls += 1
        if self.no_capacity:
            return {"tasks": [], "failures": [{"reason": "RESOURCE:CPU"}]}
        cmd = kw["overrides"]["containerOverrides"][0]["command"]
        assert kw["networkConfiguration"]["awsvpcConfiguration"]["assignPublicIp"] == "DISABLED"
        source, target, run = cmd[1], cmd[3], cmd[5]
        assert self.s3.get_object(Bucket=BUCKET, Key=source.split(f"{BUCKET}/", 1)[1])["Body"].read()  # tarball was staged first
        arn = f"arn:task/{run}"
        self.tasks[arn] = run
        if run != self.fail_run:
            self.s3.put_object(Bucket=BUCKET, Key=target.split(f"{BUCKET}/", 1)[1], Body=(DATA / f"{self.fixture}.{run}.json.gz").read_bytes())
        return {"tasks": [{"taskArn": arn}], "failures": []}

    def describe_tasks(self, cluster, tasks):
        status = "RUNNING" if self.never_stop else "STOPPED"
        return {"tasks": [{"taskArn": a, "lastStatus": status, "containers": [{"name": "sandbox", "exitCode": self.exit_code if self.tasks[a] == self.fail_run or self.exit_code else 0}], "stoppedReason": "x"} for a in tasks]}

    def stop_task(self, cluster, task, reason):
        self.stopped.append(task)


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield client


def make(s3, ecs, wait=6):
    cfg = SandboxConfig(cluster="c", task_definition="td", subnets=["subnet-1"], security_groups=["sg-1"], bucket=BUCKET, wait_seconds=wait)
    clock = iter(range(0, 10_000, 3))
    return FargateSandbox(cfg, ecs, s3, sleep=lambda _s: None, clock=lambda: next(clock))


def keys(s3) -> list[str]:
    return [o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET).get("Contents", [])]


def test_happy_path_builds_a_report_and_cleans_up(s3) -> None:
    ecs = FakeEcs(s3, "01-postinstall-env-exfil")
    report = make(s3, ecs).run(b"tarball-bytes", "SCAN1", "pkg", "1.0.0")
    assert report.status == SandboxStatus.COMPLETE
    assert any(f.rule_id == "sandbox.canary_exfil" and f.severity == Severity.HIGH for f in report.findings)
    assert report.raw_trace_s3_key == "sandbox-traces/npm/pkg/1.0.0/SCAN1/"
    assert sorted(ecs.stopped) == ["arn:task/baseline", "arn:task/hostile"]
    left = keys(s3)
    assert "sandbox-in/SCAN1.tgz" not in left  # staged tarball deleted
    assert {"sandbox-traces/npm/pkg/1.0.0/SCAN1/baseline.json.gz", "sandbox-traces/npm/pkg/1.0.0/SCAN1/hostile.json.gz"} <= set(left)


def test_one_run_failing_gives_a_partial_report(s3) -> None:
    ecs = FakeEcs(s3, "s08-conditional", fail_run="hostile", exit_code=1)
    report = make(s3, ecs).run(b"x", "SCAN2", "pkg", "1.0.0")
    assert report.status == SandboxStatus.PARTIAL
    assert len(report.runs) == 1


def test_timeout_stops_tasks_and_reports_failure(s3) -> None:
    ecs = FakeEcs(s3, "s08-conditional", fail_run="baseline", never_stop=True)
    ecs.fail_run = None  # tasks "run" forever and never write a trace
    report = FargateSandbox(SandboxConfig("c", "td", ["s"], ["g"], BUCKET, wait_seconds=6), FakeNoTrace(ecs), s3, sleep=lambda _s: None, clock=iter(range(0, 1000, 3)).__next__).run(b"x", "SCAN3", "pkg", "1.0.0")
    assert report.status == SandboxStatus.FAILED and "timed out" in (report.skip_reason or "")
    assert len(ecs.stopped) == 2


class FakeNoTrace:
    """Same as FakeEcs but tasks never write anything."""

    def __init__(self, inner: FakeEcs) -> None:
        self.inner = inner

    def run_task(self, **kw):
        cmd = kw["overrides"]["containerOverrides"][0]["command"]
        arn = f"arn:task/{cmd[5]}"
        self.inner.tasks[arn] = cmd[5]
        return {"tasks": [{"taskArn": arn}], "failures": []}

    def describe_tasks(self, cluster, tasks):
        return self.inner.describe_tasks(cluster, tasks)

    def stop_task(self, cluster, task, reason):
        self.inner.stop_task(cluster, task, reason)


def test_no_capacity_fails_the_sandbox_not_the_scan(s3) -> None:
    ecs = FakeEcs(s3, "s08-conditional", no_capacity=True)
    report = make(s3, ecs).run(b"x", "SCAN4", "pkg", "1.0.0")
    assert report.status == SandboxStatus.FAILED and "RESOURCE:CPU" in (report.skip_reason or "")
    assert ecs.calls == 6  # three attempts per run
    assert "sandbox-in/SCAN4.tgz" not in keys(s3)


def test_config_from_env() -> None:
    env = {"SANDBOX_ENABLED": "true", "SANDBOX_CLUSTER": "c", "SANDBOX_TASK_DEFINITION": "td", "SANDBOX_SUBNETS": "a,b", "SANDBOX_SECURITY_GROUPS": "g", "BUCKET_NAME": "b"}
    cfg = SandboxConfig.from_env(env)
    assert cfg and cfg.subnets == ["a", "b"]
    assert SandboxConfig.from_env({**env, "SANDBOX_ENABLED": "false"}) is None
    assert SandboxConfig.from_env({}) is None


def test_analyze_survives_a_crashing_sandbox_runner(tmp_path) -> None:
    import io
    import tarfile
    from datetime import UTC, datetime, timedelta

    import httpx

    from pkgguard_analyzer.analyze import analyze
    from pkgguard_analyzer.eval import _build_packument, _mock_transport

    manifest = {"name": "sbx-crash", "version": "1.0.0"}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b'{"name":"sbx-crash","version":"1.0.0"}'
        info = tarfile.TarInfo("package/package.json")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    tarball = buf.getvalue()
    url = "https://registry.npmjs.org/sbx-crash/-/sbx-crash-1.0.0.tgz"
    client = httpx.Client(transport=_mock_transport(_build_packument(manifest, tarball, url, datetime.now(UTC) - timedelta(days=200)), tarball, url))

    def boom(_tarball):
        raise RuntimeError("fargate is down")

    result = analyze("sbx-crash", "1.0.0", out_dir=tmp_path, client=client, sandbox_runner=boom)
    assert result.record.status.value == "COMPLETE"
    assert result.record.sandbox_status == SandboxStatus.FAILED
    assert "fargate is down" in (result.report.sandbox.skip_reason or "")
