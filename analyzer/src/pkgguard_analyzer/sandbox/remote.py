"""Runs a package in the AWS sandbox (the deployed Fargate stack) and prints what it found.

  uv run pkgguard-sandbox-remote --fixture ../sandbox/fixtures/s13-isolation-probe --show-probe
  uv run pkgguard-sandbox-remote --tarball sample.tgz          # real samples: run here, never locally

This is the ONLY way real (possibly malicious) packages should ever be executed. Needs the stack deployed
with SandboxEnabled=true and the image pushed (sandbox/push.sh)."""

import argparse
import gzip
import json
import re
import sys
from pathlib import Path

import boto3

from pkgguard_analyzer.cloud.sandbox_runner import FargateSandbox, SandboxConfig
from pkgguard_analyzer.sandbox.local_runner import UnsafeInput, ensure_harmless, pack_fixture
from pkgguard_analyzer.schema import Severity


def stack_config(stack: str, region: str) -> SandboxConfig:
    outputs = {o["OutputKey"]: o["OutputValue"] for o in boto3.client("cloudformation", region_name=region).describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
    if "SandboxCluster" not in outputs:
        sys.exit("The stack has no sandbox: deploy it with SandboxEnabled=true first (see SANDBOX.md).")
    return SandboxConfig(
        cluster=outputs["SandboxCluster"],
        task_definition=outputs["SandboxTaskDefinition"],
        subnets=outputs["SandboxSubnets"].split(","),
        security_groups=[outputs["SandboxSecurityGroup"]],
        bucket=outputs["ReportsBucketName"],
    )


def main() -> None:
    ap = argparse.ArgumentParser(prog="pkgguard-sandbox-remote")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--fixture", type=Path, help="a harmless fixture directory from this repo")
    src.add_argument("--tarball", type=Path, help="an npm .tgz to run in the AWS sandbox (never executed locally)")
    ap.add_argument("--stack", default="pkgguard")
    ap.add_argument("--region", default="ap-south-1")
    ap.add_argument("--name", default="sample")
    ap.add_argument("--show-probe", action="store_true", help="print the isolation-probe results from the raw trace")
    ap.add_argument("--wait", type=int, default=150)
    args = ap.parse_args()

    try:
        tarball = pack_fixture(ensure_harmless(args.fixture)) if args.fixture else args.tarball.read_bytes()
    except UnsafeInput as exc:
        sys.exit(f"refused: {exc}")
    config = stack_config(args.stack, args.region)
    config.wait_seconds = args.wait
    s3 = boto3.client("s3", region_name=args.region)
    scan_id = f"remote-{args.name}".replace("/", "_")[:60]
    report = FargateSandbox(config, boto3.client("ecs", region_name=args.region), s3).run(tarball, scan_id, args.name, "0.0.0")
    print(f"status={report.status} duration={report.duration_seconds}s coverage={report.coverage.model_dump(by_alias=True)}")
    if report.skip_reason:
        print("reason:", report.skip_reason)
    for f in sorted(report.findings, key=lambda f: list(Severity).index(f.severity)):
        print(f"  {f.severity:6} {f.rule_id:34} {f.title[:100]}")
    if args.show_probe and report.raw_trace_s3_key:
        body = s3.get_object(Bucket=config.bucket, Key=f"{report.raw_trace_s3_key}baseline.json.gz")["Body"].read()
        trace = json.loads(gzip.decompress(body))
        out = " ".join(p.get("stdoutTail", "") + p.get("stderrTail", "") for p in trace["phases"])
        m = re.search(r"SBX_PROBE (\{.*\})", out)
        if not m:
            print("no probe output found")
            sys.exit(1)
        results = json.loads(m.group(1))
        breaches = {k: v for k, v in results.items() if v != "blocked"}
        print(f"isolation probe: {len(results)} checks, {'ALL BLOCKED' if not breaches else 'BREACHES: ' + str(breaches)}")
        sys.exit(1 if breaches else 0)


if __name__ == "__main__":
    main()
