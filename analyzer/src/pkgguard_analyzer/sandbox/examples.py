"""Writes example records/reports that include sandbox results, for the UI (`schema/examples/sandbox-*`).

Built from real captured traces of the harmless fixtures (tests/data/sandbox), scored by the real
pipeline. The package names are fixtures, not real npm packages."""

import gzip
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from pkgguard_analyzer.analyze import analyze
from pkgguard_analyzer.eval import _build_packument, _build_tarball, _mock_transport
from pkgguard_analyzer.sandbox.build import build_report
from pkgguard_analyzer.sandbox.local_runner import REPO
from pkgguard_analyzer.schema import RanOn

TRACES = REPO / "analyzer" / "tests" / "data" / "sandbox"
EXAMPLES = REPO / "schema" / "examples"
CASES = {
    "sandbox-malicious-exfil": REPO / "eval" / "fixtures" / "01-postinstall-env-exfil",
    "sandbox-conditional-ci-gate": REPO / "sandbox" / "fixtures" / "s08-conditional",
    "sandbox-dropper": REPO / "sandbox" / "fixtures" / "s03-dropper",
    "sandbox-persistence": REPO / "sandbox" / "fixtures" / "s02-persistence",
    "sandbox-clean": REPO / "eval" / "fixtures" / "15-clean-control",
}


def build(fixture: Path, out_dir: Path) -> tuple[dict, dict]:
    traces = [json.loads(gzip.open(TRACES / f"{fixture.name}.{run}.json.gz").read()) for run in ("baseline", "hostile")]
    manifest = json.loads((fixture / "package.json").read_text())
    tarball = _build_tarball(fixture)
    url = f"https://registry.npmjs.org/{manifest['name']}/-/{manifest['name']}-{manifest['version']}.tgz"
    packument = _build_packument(manifest, tarball, url, datetime.now(UTC) - timedelta(days=200))
    client = httpx.Client(transport=_mock_transport(packument, tarball, url))
    key = f"sandbox-traces/npm/{manifest['name']}/{manifest['version']}/0.1.0.json"
    scan = analyze(manifest["name"], manifest["version"], out_dir=out_dir, ran_on=RanOn.CLOUD, client=client, sandbox_runner=lambda _t: build_report(traces, raw_trace_key=key))
    client.close()
    return scan.record.model_dump(mode="json", by_alias=True), scan.report.model_dump(mode="json", by_alias=True)


def main() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        for name, fixture in CASES.items():
            record, report = build(fixture, Path(tmp))
            target = EXAMPLES / name
            target.mkdir(parents=True, exist_ok=True)
            (target / "record.json").write_text(json.dumps(record, indent=2) + "\n")
            (target / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(f"{name}: {record['verdict']} / {record['confidence']} / decidedBy {record['decidedBy']} / sandbox {record['sandboxStatus']}")


if __name__ == "__main__":
    main()
