"""Sandbox tests. The golden traces in tests/data/sandbox/ were captured by really running the harmless
fixtures in the sandbox image, so detection rules can be tested (and changed) without Docker."""

import gzip
import json
from pathlib import Path

import pytest

from pkgguard_analyzer.sandbox import strace
from pkgguard_analyzer.sandbox.build import build_report
from pkgguard_analyzer.sandbox.canary import Canary, CanarySet, canaries_from_trace
from pkgguard_analyzer.sandbox.check import EVAL_EXPECT, check_report, expectations
from pkgguard_analyzer.sandbox.classify import classify
from pkgguard_analyzer.sandbox.local_runner import REPO, UnsafeInput, docker_command, ensure_harmless, pack_fixture, run_tarball
from pkgguard_analyzer.schema import (
    Confidence,
    DecidedBy,
    Finding,
    FindingLayer,
    NetworkClass,
    SandboxReport,
    SandboxStatus,
    Severity,
    Verdict,
)
from pkgguard_analyzer.scoring import decide

DATA = Path(__file__).parent / "data" / "sandbox"


def load(name: str) -> list[dict]:
    return [json.loads(gzip.open(DATA / f"{name}.{run}.json.gz").read()) for run in ("baseline", "hostile")]


def fixture_dirs() -> list[Path]:
    roots = (REPO / "sandbox" / "fixtures", REPO / "eval" / "fixtures")
    return sorted(p for root in roots for p in root.iterdir() if p.is_dir() and expectations(p) is not None)


@pytest.mark.parametrize("fixture", fixture_dirs(), ids=lambda p: p.name)
def test_fixture_traces_produce_the_expected_findings(fixture: Path) -> None:
    traces = load(fixture.name)
    expect = expectations(fixture)
    if expect.get("isolationProbe"):
        expect = {**expect, "_phases": traces[0]["phases"]}
    assert check_report(expect, build_report(traces)) == []


def test_every_eval_expectation_has_a_golden_trace() -> None:
    for name in EVAL_EXPECT:
        assert (DATA / f"{name}.baseline.json.gz").exists()


def test_report_validates_and_roundtrips() -> None:
    report = build_report(load("01-postinstall-env-exfil"))
    assert report.status == SandboxStatus.COMPLETE
    assert report.coverage.installed
    assert SandboxReport.model_validate_json(report.model_dump_json(by_alias=True)) == report
    assert report.canary_hits and all(f.layer == FindingLayer.SANDBOX for f in report.findings)


def test_conditional_behavior_only_when_it_differs_between_runs() -> None:
    assert any(f.rule_id == "sandbox.conditional_behavior" and f.severity == Severity.HIGH for f in build_report(load("s08-conditional")).findings)
    assert not any(f.rule_id == "sandbox.conditional_behavior" for f in build_report(load("01-postinstall-env-exfil")).findings)


def test_benign_registry_download_is_not_flagged() -> None:
    findings = build_report(load("s09-benign-downloader")).findings
    assert not [f for f in findings if f.severity != Severity.LOW]


def test_npm_own_reads_and_bash_history_are_not_attributed_to_the_package() -> None:
    for name in ("15-clean-control", "s09-benign-downloader", "s04b-reverse-shell-bash"):
        findings = build_report(load(name)).findings
        assert not any(f.rule_id == "sandbox.decoy_read" for f in findings), name


def test_dropper_is_high_only_after_contacting_an_outside_host() -> None:
    finding = next(f for f in build_report(load("s03-dropper")).findings if f.rule_id == "sandbox.dropper_exec")
    assert finding.severity == Severity.HIGH


def test_isolation_probe_found_no_breach() -> None:
    expect = {**expectations(REPO / "sandbox" / "fixtures" / "s13-isolation-probe"), "_phases": load("s13-isolation-probe")[0]["phases"]}
    assert check_report(expect, build_report(load("s13-isolation-probe"))) == []


# ---- canaries
def test_canary_matches_encodings_and_partial_copies() -> None:
    import base64
    import urllib.parse

    token = "tok_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    cs = CanarySet([Canary("npmrc", token, "/home/sandbox/.npmrc")])
    assert cs.find(f"Authorization: Bearer {token}")
    assert cs.find(urllib.parse.quote(f"token={token}&x=1"))
    for pad in ("", "a", "ab"):
        assert cs.find(base64.b64encode((pad + f"//registry:_authToken={token}\n").encode()).decode()), pad
    assert cs.find(token.encode().hex()[:60] + ".x.example.test")
    assert cs.find(".".join(token.encode().hex()[i : i + 20] for i in range(0, 60, 20)))  # split across DNS labels
    assert not cs.find("tok_SomethingElseEntirelyDifferent000000000")
    assert not cs.find("")


def test_short_values_are_never_canaries() -> None:
    assert not CanarySet([Canary("x", "short")]).canaries


def test_canaries_come_from_the_trace() -> None:
    cs = canaries_from_trace(load("01-postinstall-env-exfil")[0]["decoys"])
    assert {c.id for c in cs.canaries} >= {"npmrc", "ssh_key", "env:NPM_TOKEN"}


# ---- strace parsing
def test_strace_rejoins_split_calls_and_tracks_threads() -> None:
    lines = [
        '10 1.000000 execve("/usr/bin/setpriv", ["setpriv"], 0x0 /* 1 vars */) = 0',
        '10 1.100000 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD|SIGCHLD) = 11',
        '10 1.200000 execve("/tmp/.svc", ["/tmp/.svc", "-x"], 0x1 /* 2 vars */ <unfinished ...>',
        '10 1.300000 <... execve resumed>) = 0',
    ]
    events, procs = strace.parse({"install": lines})
    assert strace.group_of(procs, 11) == 10
    assert procs[10].exe == "/tmp/.svc" and procs[10].argv == ["/tmp/.svc", "-x"]
    assert any(e.call == "execve" and e.ok and e.args.startswith('"/tmp/.svc"') for e in events)


def test_strace_socket_address_parsing() -> None:
    assert strace.sock_addr('3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("127.1.0.7")}, 16') == ("127.1.0.7", 4444)
    assert strace.sock_addr('3, {sa_family=AF_UNIX, sun_path="/dev/log"}, 110') is None


# ---- classification
@pytest.mark.parametrize(
    ("host", "port", "expected"),
    [
        ("registry.npmjs.org", 443, NetworkClass.EXPECTED),
        ("abc.oastify.com", 443, NetworkClass.OAST),
        ("discord.com", 443, NetworkClass.WEBHOOK),
        ("169.254.169.254", 80, NetworkClass.METADATA),
        ("pool.minexmr.com", 3333, NetworkClass.STRATUM),
        ("8.8.8.8", 443, NetworkClass.RAW_IP),
        ("collector.example.invalid", 443, NetworkClass.UNEXPECTED),
        ("abc.ngrok.io", 443, NetworkClass.TUNNEL),
    ],
)
def test_classify(host: str, port: int, expected: NetworkClass) -> None:
    assert classify(host, port) == expected


# ---- scoring
def _f(rule: str, severity=Severity.HIGH, confidence=Confidence.HIGH) -> Finding:
    return Finding(rule_id=rule, layer=FindingLayer.SANDBOX, severity=severity, confidence=confidence, title=f"{rule} happened")


def test_sandbox_proof_is_malicious_and_decided_by_sandbox() -> None:
    for rule in ("sandbox.canary_exfil", "sandbox.reverse_shell"):
        d = decide([_f(rule)])
        assert (d.verdict, d.confidence, d.decided_by) == (Verdict.MALICIOUS, Confidence.HIGH, DecidedBy.SANDBOX)


def test_ai_cannot_clear_sandbox_proof() -> None:
    from pkgguard_analyzer.schema import AIReview, ReviewMode

    ai = AIReview(verdict=Verdict.SAFE, confidence=Confidence.HIGH, summary="fine", reasoning="fine", model="m", mode=ReviewMode.QUICK_LOOK, files_read=[], tool_calls=1, input_tokens=1, output_tokens=1, duration_seconds=1.0)
    assert decide([_f("sandbox.canary_exfil")], ai).verdict == Verdict.MALICIOUS


def test_weaker_sandbox_findings_only_suspect() -> None:
    assert decide([_f("sandbox.persistence")]).verdict == Verdict.SUSPICIOUS
    assert decide([_f("sandbox.decoy_read", Severity.MEDIUM)]).verdict == Verdict.SAFE


# ---- safety guards on the local runner
def test_local_runner_refuses_anything_outside_the_harmless_fixtures(tmp_path: Path) -> None:
    for bad in (tmp_path, Path("/tmp"), REPO / "README.md", REPO / "eval" / "fixtures" / ".." / ".."):
        with pytest.raises(UnsafeInput):
            ensure_harmless(bad)
    assert ensure_harmless(REPO / "eval" / "fixtures" / "01-postinstall-env-exfil").is_dir()


def test_run_tarball_needs_the_fixture_flag() -> None:
    with pytest.raises(UnsafeInput):
        run_tarball(b"anything")


def test_docker_command_has_the_isolation_flags() -> None:
    cmd = docker_command("n", "baseline")
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "--cap-drop" in cmd and "ALL" in cmd and "no-new-privileges" in cmd
    assert "-v" not in cmd and "--volume" not in cmd and "--privileged" not in cmd


def test_pack_fixture_replaces_the_time_gate_and_skips_metadata() -> None:
    import io
    import tarfile

    tar = tarfile.open(fileobj=io.BytesIO(pack_fixture(REPO / "sandbox" / "fixtures" / "s08-conditional")))
    names = tar.getnames()
    assert "package/gate.js" in names and "package/fixture.json" not in names
    assert b"__GATE_DAYS_30__" not in tar.extractfile("package/gate.js").read()


def test_cpu_hog_is_caught_even_on_a_half_cpu_task() -> None:
    traces = load("s06-miner-shaped")
    for trace in traces:
        for phase in trace["phases"]:
            if phase["timedOut"]:
                phase["cpuSeconds"] = round(phase["seconds"] * 0.5, 2)  # a Fargate task only has 0.5 vCPU
    assert any(f.rule_id == "sandbox.resource_abuse" for f in build_report(traces).findings)


def test_a_child_npm_reading_npmrc_is_not_credential_theft() -> None:
    report = build_report(load("smoke-esbuild"))  # esbuild's installer runs `npm install` itself
    assert not any(f.rule_id == "sandbox.decoy_read" for f in report.findings)
    assert not [f for f in report.findings if f.severity != Severity.LOW]


def test_entry_that_fails_on_a_missing_dependency_makes_the_report_partial() -> None:
    report = build_report(load("smoke-sharp"))  # needs detect-libc, which the sandbox does not install
    assert report.status == SandboxStatus.PARTIAL
    assert any(f.rule_id == "sandbox.coverage_gap" and "entry file" in f.title for f in report.findings)
    assert not [f for f in report.findings if f.severity != Severity.LOW]


def test_a_package_with_no_entry_file_is_not_a_coverage_problem() -> None:
    assert build_report(load("s10-decoy-read")).status == SandboxStatus.COMPLETE  # scripts only, nothing to require
