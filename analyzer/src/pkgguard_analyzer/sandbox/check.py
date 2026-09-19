"""Checks that each harmless fixture triggers exactly the sandbox rules it was written to trigger.

  uv run pkgguard-sandbox-eval            # runs every fixture in the local sandbox image (Docker, harmless fixtures only)
  uv run pkgguard-sandbox-eval --remote   # same fixtures, but in the deployed AWS sandbox

Fixture expectations live in each fixture's fixture.json: "expect" (rule ids that must fire) and
"forbid" (rule ids that must not). Benign fixtures ("benign": true) must not produce HIGH findings."""

import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pkgguard_analyzer.sandbox.build import build_report
from pkgguard_analyzer.sandbox.local_runner import REPO, pack_fixture, run_tarball
from pkgguard_analyzer.schema import SandboxReport, Severity

# eval/fixtures were written for the static scanner; these are the ones that also behave visibly at runtime.
EVAL_EXPECT: dict[str, dict] = {
    "01-postinstall-env-exfil": {"expect": ["sandbox.canary_exfil"]},
    "04-install-curl-pipe-sh": {"expect": ["sandbox.suspicious_process"]},
    "11-benign-downloader": {"expect": [], "benign": True},
    "13-ci-only-trigger": {"expect": ["sandbox.conditional_behavior"]},
    "15-clean-control": {"expect": [], "benign": True},
}


def expectations(fixture: Path) -> dict | None:
    meta = fixture / "fixture.json"
    if fixture.parent.name == "fixtures" and fixture.parent.parent.name == "eval":
        return EVAL_EXPECT.get(fixture.name)
    try:
        data = json.loads(meta.read_text())
    except (OSError, ValueError):
        return None
    return None if data.get("diagnostic") else data


def check_report(expect: dict, report: SandboxReport) -> list[str]:
    fired = {f.rule_id for f in report.findings}
    problems = [f"missing {rule}" for rule in expect.get("expect", []) if rule not in fired]
    problems += [f"unexpected {rule}" for rule in expect.get("forbid", []) if rule in fired]
    if expect.get("benign"):
        loud = [f.rule_id for f in report.findings if f.severity == Severity.HIGH]
        problems += [f"benign fixture raised HIGH {rule}" for rule in loud]
    if expect.get("isolationProbe"):
        out = " ".join(p.get("stdoutTail", "") for p in expect.get("_phases", []))
        m = re.search(r"SBX_PROBE (\{.*\})", out)
        if not m:
            problems.append("isolation probe printed no results")
        else:
            problems += [f"isolation breach: {k}={v}" for k, v in json.loads(m.group(1)).items() if v != "blocked" and not k.startswith("info_")]
    return problems


def run_and_check(fixture: Path) -> tuple[Path, list[str], SandboxReport | None]:
    expect = expectations(fixture)
    if expect is None:
        return fixture, ["no expectations"], None
    tarball = pack_fixture(fixture)
    traces = [run_tarball(tarball, run, harmless_fixture=True) for run in ("baseline", "hostile")]
    report = build_report(traces)
    if expect.get("isolationProbe"):
        expect = {**expect, "_phases": traces[0]["phases"]}
    return fixture, check_report(expect, report), report


def run_and_check_remote(fixture: Path, runner) -> tuple[Path, list[str], SandboxReport | None]:
    expect = expectations(fixture)
    if expect is None:
        return fixture, ["no expectations"], None
    report = runner.run(pack_fixture(fixture), f"check-{fixture.name}", fixture.name, "0.0.0")
    expect = {k: v for k, v in expect.items() if k != "isolationProbe"}  # the probe is checked with pkgguard-sandbox-remote
    problems = check_report(expect, report) if report.status.value in ("COMPLETE", "PARTIAL") else [f"sandbox {report.status.value}: {report.skip_reason}"]
    return fixture, problems, report


def main() -> None:
    remote = "--remote" in sys.argv
    runner = None
    if remote:
        import boto3

        from pkgguard_analyzer.cloud.sandbox_runner import FargateSandbox, make_s3
        from pkgguard_analyzer.sandbox.remote import stack_config

        cfg = stack_config("pkgguard", "ap-south-1")
        runner = FargateSandbox(cfg, boto3.client("ecs", region_name="ap-south-1"), make_s3("ap-south-1"))
    fixtures = sorted(p for root in (REPO / "sandbox" / "fixtures", REPO / "eval" / "fixtures") for p in root.iterdir() if p.is_dir() and expectations(p) is not None)
    failed = 0
    with ThreadPoolExecutor(max_workers=2 if remote else 3) as pool:
        for fixture, problems, report in pool.map((lambda f: run_and_check_remote(f, runner)) if remote else run_and_check, fixtures):
            status = "ok  " if not problems else "FAIL"
            failed += bool(problems)
            rules = sorted({f.rule_id.removeprefix("sandbox.") for f in report.findings if f.severity != Severity.LOW}) if report else []
            print(f"[{status}] {fixture.name:32} {', '.join(rules)}" + (f"   <- {'; '.join(problems)}" if problems else ""))
    print(f"\n{len(fixtures) - failed}/{len(fixtures)} fixtures behaved as expected")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
